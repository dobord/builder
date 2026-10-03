#!/usr/bin/env python3
"""Non-executing private publication gate, after signed builder verification.

Engine-static SDKs may be privately inspected but cannot become fully-static
releases. This gate does not replace the builder's signature/provenance checks.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zipfile


def require(value, message):
    if not value:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def decode(data):
    require(len(data) <= 4 * 1024**2, 'JSON exceeds policy limit')
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON value')))


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'Nonregular publication file')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def inspect(staging: Path, expected: str, policy: dict) -> dict:
    require(re.fullmatch(r'[0-9a-f]{64}', expected) is not None, 'Missing staging digest')
    require(set(policy) == {'schema', 'required_profile', 'admitted_contracts'} and type(policy['schema']) is int
            and policy['schema'] == 1 and policy['required_profile'] == 'static-third-party', 'Invalid CEF publication policy')
    admitted = policy['admitted_contracts']
    require(isinstance(admitted, dict) and set(admitted) == {'linux', 'windows'}, 'Both policy platforms are required')
    for values in admitted.values():
        require(isinstance(values, list) and len(values) == len(set(values)) and all(
            isinstance(v, str) and re.fullmatch(r'[0-9a-f]{64}', v) for v in values), 'Invalid qualified contract inventory')
    sums = staging / 'SHA256SUMS'
    require(sums.stat().st_size <= 16384 and digest(sums) == expected, 'Staging checksum list changed')
    files = {}
    for line in sums.read_text('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        require(match is not None, 'Invalid checksum entry')
        sha, name = match.groups()
        require(name not in files and '..' not in name, 'Ambiguous publication filename')
        require(digest(staging / name) == sha, 'Publication file changed')
        files[name] = sha
    require('release-manifest.json' in files, 'Missing release manifest')
    require({p.name for p in staging.iterdir()} == set(files) | {'SHA256SUMS'}, 'Unexpected staging files')
    manifest = decode((staging / 'release-manifest.json').read_bytes())
    require(isinstance(manifest.get('platforms'), dict) and set(manifest['platforms']) == {'linux', 'windows'}, 'Both SDKs are required')
    tag = manifest.get('source_tag', '')
    require(isinstance(tag, str) and re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag), 'Invalid release tag')
    expected_files = {'release-manifest.json'} | {f'vcpkg-{tag}-{p}-x64-static-release.zip' for p in ('linux', 'windows')}
    require(set(files) == expected_files, 'Unexpected SDK assets')
    found, reasons = {}, []
    for platform, data in manifest['platforms'].items():
        triplet = f'x64-{platform}-static-release'
        require(data.get('triplet') == triplet and data.get('platform') == platform, 'Mismatched target triplet')
        name = f'vcpkg-{tag}-{platform}-x64-static-release.zip'
        require(data.get('sdk_sha256') == files[name], 'SDK digest is not bound to platform manifest')
        prefix = f'installed/{triplet}/share/cef-static/'
        with zipfile.ZipFile(staging / name) as archive:
            entries = archive.infolist()
            require(len(entries) <= 200000, 'Too many SDK entries')
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), 'Duplicate SDK member')
            contains = any(n.startswith(prefix) for n in names)
            evidence = data.get('cef')
            require(contains == (evidence is not None), 'CEF payload/evidence mismatch')
            found[platform] = contains
            if not contains:
                continue
            path = prefix + 'build-contract.json'
            require(path in names, 'Missing installed CEF acquisition contract')
            entry = archive.getinfo(path)
            require(entry.file_size <= 65536 and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                    and not entry.flag_bits & 1, 'Invalid CEF contract member')
            contract = decode(archive.read(entry))
            inventory = None
            inventory_bytes = None
            if platform == 'linux' and contract.get('profile') == policy['required_profile']:
                inventory_path = prefix + 'static-platform-inventory.json'
                require(inventory_path in names, 'Missing strict Linux platform inventory')
                inventory_entry = archive.getinfo(inventory_path)
                require(inventory_entry.file_size <= 4 * 1024**2
                        and stat.S_IFMT(inventory_entry.external_attr >> 16) in (0, stat.S_IFREG)
                        and not inventory_entry.flag_bits & 1,
                        'Invalid strict Linux platform inventory member')
                inventory_bytes = archive.read(inventory_entry)
                inventory = decode(inventory_bytes)
                require(isinstance(inventory, dict)
                        and set(inventory) == {'schema', 'kind', 'manifest_sha256', 'archives', 'runtime_verified'}
                        and inventory.get('schema') == 1
                        and inventory.get('kind') == 'external-vcpkg-archives'
                        and inventory.get('runtime_verified') is False,
                        'Invalid strict Linux platform inventory')
                inputs_path = prefix + 'platform-build-inputs.json'
                require(inputs_path in names, 'Missing strict Linux platform build-input manifest')
                inputs_entry = archive.getinfo(inputs_path)
                require(inputs_entry.file_size <= 64 * 1024**2
                        and stat.S_IFMT(inputs_entry.external_attr >> 16) in (0, stat.S_IFREG)
                        and not inputs_entry.flag_bits & 1,
                        'Invalid strict Linux platform build-input manifest member')
                require(hashlib.sha256(archive.read(inputs_entry)).hexdigest() == inventory.get('manifest_sha256'),
                        'Strict Linux platform build-input manifest changed')
                records = inventory.get('archives')
                require(isinstance(records, list) and records, 'Empty strict Linux archive inventory')
                seen_archives = set()
                for record in records:
                    require(isinstance(record, dict) and set(record) == {'path', 'size', 'sha256'},
                            'Invalid strict Linux archive record')
                    relative = record.get('path')
                    require(isinstance(relative, str)
                            and re.fullmatch(r'lib/[A-Za-z0-9][A-Za-z0-9_+./-]*\.a', relative)
                            and '..' not in relative and '//' not in relative,
                            'Unsafe strict Linux archive path')
                    require(relative not in seen_archives, 'Duplicate strict Linux archive record')
                    seen_archives.add(relative)
                    require(type(record.get('size')) is int and record['size'] > 0
                            and isinstance(record.get('sha256'), str)
                            and re.fullmatch(r'[0-9a-f]{64}', record['sha256']),
                            'Invalid strict Linux archive digest record')
                    member = f'installed/{triplet}/{relative}'
                    require(member in names, 'Strict Linux dependency archive is missing from SDK')
                    library_entry = archive.getinfo(member)
                    require(library_entry.file_size == record['size']
                            and stat.S_IFMT(library_entry.external_attr >> 16) in (0, stat.S_IFREG)
                            and not library_entry.flag_bits & 1,
                            'Invalid strict Linux dependency archive member')
                    require(hashlib.sha256(archive.read(library_entry)).hexdigest() == record['sha256'],
                            'Strict Linux dependency archive changed')
        require(isinstance(evidence, dict) and isinstance(contract, dict), 'Invalid CEF evidence')
        key = hashlib.sha256(canonical(contract)).hexdigest()
        require(evidence.get('build_contract_sha256') == key and contract.get('triplet') == triplet
                and evidence.get('profile') == contract.get('profile'), 'Installed CEF contract mismatch')
        consumer = evidence.get('consumer', {})
        require(consumer.get('kind') == 'consumer-verification' and consumer.get('engine_linkage') == 'static'
                and consumer.get('capi_only') is True, 'No independently verified static CEF consumer')
        if contract.get('profile') == policy['required_profile']:
            require(consumer.get('third_party_libraries_static') is True,
                    'Strict CEF consumer did not prove static third-party linkage')
            smoke = consumer.get('smoke', {})
            require(smoke.get('third_party_modules_static') is True
                    and smoke.get('browser_modules_clean') is True
                    and smoke.get('renderer_modules_clean') is True,
                    'Strict CEF runtime module closure is incomplete')
            audit = consumer.get('target_archive_audit', {})
            require(audit.get('kind') == 'target-archive-audit-summary'
                    and audit.get('target_archives_static') is True
                    and audit.get('violation_count') == 0,
                    'Strict CEF final SDK archive audit is incomplete')
            closure = consumer.get('platform_closure', {})
            preflight = evidence.get('platform_preflight')
            if platform == 'linux':
                require(closure.get('kind') == 'linux-frozen-vcpkg'
                        and isinstance(closure.get('manifest_sha256'), str)
                        and re.fullmatch(r'[0-9a-f]{64}', closure['manifest_sha256'])
                        and isinstance(closure.get('inventory_sha256'), str)
                        and re.fullmatch(r'[0-9a-f]{64}', closure['inventory_sha256'])
                        and isinstance(closure.get('qualification_sha256'), str)
                        and re.fullmatch(r'[0-9a-f]{64}', closure['qualification_sha256'])
                        and closure.get('full_platform_graph_qualified') is True
                        and type(closure.get('archive_count')) is int and closure['archive_count'] > 0,
                        'Strict Linux platform closure evidence is incomplete')
                require(contract.get('platform_sha256') == closure['manifest_sha256'],
                        'Strict Linux acquisition contract is not bound to its frozen platform digest')
                require(isinstance(preflight, dict)
                        and preflight.get('schema') == 1
                        and preflight.get('kind') == 'cef-static-platform-preflight'
                        and preflight.get('status') == 'success'
                        and preflight.get('full_platform_graph_qualified') is True
                        and preflight.get('cef_runtime_verified') is False
                        and preflight.get('gpu_runtime_qualified') is False
                        and preflight.get('module_count') == 36
                        and preflight.get('manifest_sha256') == closure['manifest_sha256']
                        and hashlib.sha256(canonical(preflight) + b'\n').hexdigest()
                            == closure['qualification_sha256'],
                        'Strict Linux full-platform preflight is missing or changed')
                require(inventory is not None and inventory_bytes is not None
                        and inventory.get('manifest_sha256') == closure['manifest_sha256']
                        and hashlib.sha256(inventory_bytes).hexdigest() == closure['inventory_sha256']
                        and len(inventory['archives']) == closure['archive_count'],
                        'Strict Linux platform inventory is not bound to consumer evidence')
            else:
                require(closure == {'kind': 'windows-native-os-abi', 'manifest_sha256': None},
                        'Strict Windows platform closure evidence is incomplete')
                require(preflight is None,
                        'Strict Windows publication cannot carry a Linux platform preflight')
                require(contract.get('platform_sha256') is None,
                        'Strict Windows acquisition contract cannot carry a Linux platform digest')
        if contract.get('profile') != policy['required_profile']:
            require(evidence.get('platform_preflight') is None,
                    'Engine-static evidence cannot carry strict platform qualification')
            reasons.append(platform + ': engine-static is not the required third-party-static profile')
        if key not in admitted[platform]:
            reasons.append(platform + ': acquisition contract has not been admitted after full qualification')
    require(found['linux'] == found['windows'], 'One-sided CEF SDK pair')
    return {'schema': 1, 'cef_present': found['linux'], 'publication_allowed': not reasons,
            'required_profile': policy['required_profile'], 'reasons': reasons,
            'staging_sha256': expected, 'sdk_code_executed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    report = inspect(args.staging, os.environ.get('STAGING_DIGEST', ''), decode(args.policy.read_bytes()))
    print(json.dumps(report, sort_keys=True))
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write('cef_publication_allowed=' + str(report['publication_allowed']).lower() + '\n')
    if args.publish:
        require(report['publication_allowed'], 'CEF publication is blocked until strict dependency qualification')


if __name__ == '__main__':
    main()
