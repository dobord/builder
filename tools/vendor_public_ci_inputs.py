#!/usr/bin/env python3
"""Vendor only the exact PUBLIC compiler-test inputs already pinned by the tests.

Operator maintenance tool, never imported by workers/tests. Parse declarative
constants without importing test modules or executing their network acquisition.
No credentials, mutable refs, archive extraction or private inputs are used.
"""
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('accessibility', 'affiliated', 'backend_error', 'layout', 'lock', 'pdfium',
           'permission', 'profile_launch', 'speech_callback', 'string', 'vertical_tab')


def constant(node, values):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return values[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(constant(item, values) for item in node.elts)
    if isinstance(node, ast.Dict):
        return {constant(k, values): constant(v, values) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return constant(node.left, values) + constant(node.right, values)
    raise ValueError('Not a declarative fixture constant')


def constants(path):
    values = {}
    for node in ast.parse(path.read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                values[node.targets[0].id] = constant(node.value, values)
            except (ValueError, KeyError, TypeError):
                pass  # Never evaluate calls, attributes, imports or runtime paths.
    return values


def inventory():
    records = {}
    def add(repository, revision, path, size, sha256=None, blob=None):
        url = f'https://raw.githubusercontent.com/{repository}/{revision}/{path}'
        record = {'url': url, 'size': size, 'sha256': sha256, 'git_blob': blob}
        if url in records and records[url] != record:
            raise ValueError('Conflicting public fixture pins')
        records[url] = record
    for module in MODULES:
        values = constants(ROOT / f'tests/cef_windows_{module}_inputs.py')
        if module == 'layout':
            repository, revision = 'v8/v8', values['V8']
        elif module == 'pdfium':
            repository, revision = 'chromium/pdfium', values['PDFIUM']
        else:
            repository, revision = 'chromium/chromium', values['CHROMIUM']
        if 'INPUTS' in values:
            for path, pins in values['INPUTS'].items():
                add(repository, revision, values.get('PREFIX', '') + path, *pins)
        else:
            add(repository, revision, values.get('PATH', values.get('PUBLIC_PATH')),
                values['SIZE'], values['SHA256'], values['BLOB'])
    dom = constants(ROOT / 'tests/test_cef_windows_dom_memory_repair.py')
    chromium = constants(ROOT / 'tests/cef_windows_string_inputs.py')['CHROMIUM']
    for name, (path, size, blob) in dom['PUBLIC'].items():
        if name != 'dom_builder.h':  # Existing committed fixture already owns this input.
            add('chromium/chromium', chromium, path, size, blob=blob)
    return list(records.values())


def download(url, size):
    parts = url.split('/')
    origin = {'chromium/chromium': 'https://chromium.googlesource.com/chromium/src',
              'chromium/pdfium': 'https://pdfium.googlesource.com/pdfium',
              'v8/v8': 'https://chromium.googlesource.com/v8/v8'}['/'.join(parts[3:5])]
    alternate = origin + '/+/' + '/'.join(parts[5:]) + '?format=TEXT'
    for attempt in range(4):
        try:
            selected = url if attempt % 2 == 0 else alternate
            with urllib.request.urlopen(selected, timeout=20) as stream:
                if stream.geturl() != selected:
                    raise ValueError('Unexpected public fixture redirect')
                raw = stream.read(size + 1 if selected == url else 4 * ((size + 2) // 3) + 8)
                return raw if selected == url else base64.b64decode(raw.strip(), validate=True)
        except urllib.error.HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == 3:
                raise
            time.sleep(2 ** attempt)
    raise AssertionError('Unreachable download state')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.parent.is_dir() or args.output.exists():
        raise ValueError('Output needs an existing parent and a fresh path')
    records, contents = inventory(), {}
    for record in records:
        raw = download(record['url'], record['size'])
        sha256 = hashlib.sha256(raw).hexdigest()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if (len(raw) != record['size'] or (record['sha256'] and record['sha256'] != sha256)
                or (record['git_blob'] and record['git_blob'] != blob)):
            raise ValueError('Existing public fixture pin mismatch')
        record.update(sha256=sha256, git_blob=blob)
        contents[hashlib.sha256(record['url'].encode()).hexdigest() + '.bin'] = raw
    repositories = {(r['url'].split('/')[3], r['url'].split('/')[4], r['url'].split('/')[5]) for r in records}
    licenses = []
    for owner, repository, revision in sorted(repositories):
        paths = ['LICENSE']
        if (owner, repository) == ('chromium', 'chromium'):
            paths += ['third_party/rust/chromium_crates_io/vendor/cxx-v1/LICENSE-MIT',
                      'third_party/rust/chromium_crates_io/vendor/cxx-v1/LICENSE-APACHE']
        for index, path in enumerate(paths):
            url = f'https://raw.githubusercontent.com/{owner}/{repository}/{revision}/{path}'
            raw = download(url, 65536)
            if not 0 < len(raw) <= 65536:
                raise ValueError('Invalid public fixture license')
            name = f'licenses/{owner}-{repository}-{index}.txt'
            contents[name] = raw
            licenses.append({'url': url, 'name': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    contents['manifest.json'] = (json.dumps({'schema': 1, 'files': sorted(records, key=lambda r: r['url']),
                                           'licenses': licenses}, sort_keys=True, indent=2) + '\n').encode()
    with zipfile.ZipFile(args.output, 'x', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    print(f'Vendored {len(records)} public inputs; archive SHA-256 {hashlib.sha256(args.output.read_bytes()).hexdigest()}')


if __name__ == '__main__':
    main()
