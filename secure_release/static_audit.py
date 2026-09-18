"""Non-executing audit of target libraries in a vcpkg raw-export ZIP.

A .lib extension is NOT a static-linkage certificate. Inspect ordinary ar
members, ELF relocatable objects and both forms of COFF import libraries.
This is a structural audit, not a replacement for native link/runtime tests.
No SDK code, external tools, credentials or network are used.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from typing import BinaryIO
import zipfile

MAX_FILES = 200_000
MAX_UNPACKED = 12 * 1024**3
MAX_MEMBER = 256 * 1024**2
MAX_MEMBERS = 1_000_000
BIGOBJ_CLASS = bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')
SHARED_NAME = re.compile(r'\.(?:so(?:\..*)?|dll|dylib)def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def u(data: bytes, offset: int, fmt: str):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(data) - size, 'truncated binary header')
    return struct.unpack_from(fmt, data, offset)


def coff_kind(data: bytes) -> str:
    require(len(data) >= 20, 'truncated COFF header')
    if data[:4] == b'\0\0\xff\xff':
        version, machine = u(data, 4, '<HH')
        require(machine == 0x8664, 'non-x64 COFF member')
        if version == 0:
            size, = u(data, 12, '<I')
            require(size <= len(data) - 20, 'truncated short import object')
            return 'coff-import'
        require(version == 2 and len(data) >= 56 and data[12:28] == BIGOBJ_CLASS,
                'unsupported anonymous COFF object')
        sections, symbols, count = u(data, 44, '<III')
        table, symbol_size = 56, 20
    else:
        machine, sections, _, symbols, count, optional, characteristics = u(data, 0, '<HHIIIHH')
        require(machine == 0x8664 and optional == 0 and not characteristics & 0x2002,
                'non-x64 object or PE image in archive')
        table, symbol_size = 20, 18
    require(0 <= sections <= 1_000_000 and table + sections * 40 <= len(data), 'invalid COFF sections')
    imported = False
    for index in range(sections):
        start = table + index * 40
        name = data[start:start + 8].split(b'\0', 1)[0]
        if name.startswith(b'/'):
            require(name[1:].isdigit() and symbols > 0, 'invalid COFF section name')
            strings = symbols + count * symbol_size
            size, = u(data, strings, '<I')
            require(4 <= size <= len(data) - strings, 'invalid COFF string table')
            position = int(name[1:])
            require(4 <= position < size, 'invalid COFF string offset')
            end = data.find(b'\0', strings + position, strings + size)
            require(end != -1, 'unterminated COFF section name')
            name = data[strings + position:end]
        if name.startswith((b'.idata', b'.didat')):
            imported = True
        size, pointer = u(data, start + 16, '<II')
        require(pointer == 0 or pointer + size <= len(data), 'COFF section outside object')
    return 'coff-import' if imported else 'coff-object'


def short_import_dll(data: bytes) -> str | None:
    """Return the DLL bound by an IMAGE_IMPORT_OBJECT_HEADER short member."""
    if len(data) < 20 or data[:4] != b'\0\0\xff\xff':
        return None
    version, machine = u(data, 4, '<HH')
    if version != 0 or machine != 0x8664:
        return None
    size, = u(data, 12, '<I')
    require(0 < size <= len(data) - 20, 'truncated short import object')
    payload = data[20:20 + size]
    fields = payload.split(b'\0')
    require(len(fields) >= 2 and fields[0] and fields[1],
            'short import object lacks symbol/DLL strings')
    dll = fields[1].decode('ascii', errors='strict').casefold()
    require(re.fullmatch(r'[a-z0-9_.-]+\.(?:dll|drv)', dll) is not None,
            'unsafe short import DLL name')
    return dll


def allowed_windows_os_import(dll: str) -> bool:
    return dll in WINDOWS_OS_IMPORT_DLLS or WINDOWS_API_SET.fullmatch(dll) is not None


def object_kind(data: bytes, name: str, platform: str) -> str:
    if data.startswith(b'\x7fELF'):
        require(platform == 'linux' and len(data) >= 64 and data[4:7] == b'\x02\x01\x01',
                'wrong ELF platform/class/endianness')
        kind, machine, version = u(data, 16, '<HHI')
        require(machine == 62 and version == 1, 'non-x64 ELF member')
        return 'elf-object' if kind == 1 else 'elf-image'
    if data.startswith(b'MZ'):
        return 'pe-image'
    if data.startswith((b'!<arch>\n', b'!<thin>\n')):
        return 'nested-archive'
    if data.startswith((b'BC\xc0\xde', b'\xde\xc0\x17\x0b')):
        return 'llvm-bitcode-unqualified'
    # Rust metadata is not executable and is a normal rlib member. Its extension
    # alone is insufficient; require the rustc metadata magic too.
    if name.endswith('.rmeta') and data.startswith(b'rust'):
        return 'rust-metadata'
    if platform == 'windows':
        return coff_kind(data)
    raise ValueError('unrecognized Linux archive member')


def exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    require(len(data) == size, 'truncated archive member')
    return data


def inspect_archive(stream: BinaryIO, size: int, platform: str,
                    *, allow_windows_os_imports: bool = False) -> dict:
    require(platform in ('linux', 'windows'), 'unsupported target platform')
    require(size >= 8 and exact(stream, 8) == b'!<arch>\n', 'not a self-contained ordinary archive')
    consumed, count, longnames = 8, 0, b''
    kinds = Counter()
    system_imports = Counter()
    samples = []
    while consumed < size:
        require(size - consumed >= 60 and count < MAX_MEMBERS, 'invalid archive member count/header')
        header = exact(stream, 60)
        require(header[58:] == b'`\n' and header[48:58].strip().isdigit(), 'invalid archive header')
        length = int(header[48:58])
        require(length <= MAX_MEMBER and length <= size - consumed - 60, 'archive member exceeds bounds')
        name = header[:16].rstrip(b' ')
        payload = exact(stream, length)
        consumed += 60 + length
        if length & 1:
            require(consumed < size and exact(stream, 1) == b'\n', 'invalid archive padding')
            consumed += 1
        count += 1
        if name == b'//':
            require(not longnames, 'duplicate archive name table')
            longnames = payload
            continue
        if name in (b'/', b'/SYM64/'):
            continue
        if name.startswith(b'#1/'):
            require(name[3:].isdigit(), 'invalid BSD member name')
            width = int(name[3:])
            require(0 < width <= len(payload), 'invalid BSD name length')
            name, payload = payload[:width].rstrip(b'\0'), payload[width:]
        elif name.startswith(b'/'):
            require(name[1:].isdigit(), 'invalid GNU/COFF member name')
            offset = int(name[1:])
            require(offset < len(longnames), 'archive name outside table')
            ends = [p for p in (longnames.find(b'/\n', offset), longnames.find(b'\0', offset)) if p >= 0]
            require(ends, 'unterminated archive member name')
            name = longnames[offset:min(ends)]
        else:
            name = name.removesuffix(b'/')
        require(name and not any(b < 32 for b in name), 'invalid object member name')
        text = name.decode('utf-8', errors='replace')
        kind = object_kind(payload, text, platform)
        if kind == 'coff-import' and allow_windows_os_imports:
            dll = short_import_dll(payload)
            if dll is not None and allowed_windows_os_import(dll):
                kinds['coff-os-import'] += 1
                system_imports[dll] += 1
                continue
        kinds[kind] += 1
        if kind not in ('elf-object', 'coff-object', 'rust-metadata') and len(samples) < 8:
            sample = {'member': text, 'kind': kind}
            if kind == 'coff-import':
                dll = short_import_dll(payload)
                if dll is not None:
                    sample['dll'] = dll
            samples.append(sample)
    require(consumed == size, 'archive size mismatch')
    return {'members': sum(kinds.values()), 'kinds': dict(sorted(kinds.items())),
            'system_imports': dict(sorted(system_imports.items())),
            'qualified_objects_only': not samples, 'unqualified_samples': samples}


def safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    entries = archive.infolist()
    require(len(entries) <= MAX_FILES, 'too many SDK ZIP entries')
    seen, nodes, total = set(), {}, 0
    for entry in entries:
        raw = entry.filename.rstrip('/')
        parts = raw.split('/')
        require(raw and not any(c in raw for c in '\\:\x00') and not any(ord(c) < 32 for c in raw)
                and all(p not in ('', '.', '..') for p in parts), 'unsafe SDK ZIP path')
        folded = tuple(p.casefold() for p in parts)
        require(folded not in seen, 'duplicate SDK ZIP path')
        seen.add(folded)
        for i in range(1, len(parts) + 1):
            key = folded[:i]
            node = (tuple(parts[:i]), i < len(parts) or entry.is_dir())
            require(key not in nodes or nodes[key] == node, 'SDK path case/type collision')
            nodes[key] = node
        kind = stat.S_IFMT(entry.external_attr >> 16)
        require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not entry.flag_bits & 1, 'nonregular/encrypted SDK member')
        require((kind != stat.S_IFDIR or entry.is_dir()) and (kind != stat.S_IFREG or not entry.is_dir()), 'ZIP type mismatch')
        total += entry.file_size
        require(entry.file_size >= 0 and total <= MAX_UNPACKED, 'oversized SDK ZIP')
    return entries


def inspect_sdk(path: Path, platform: str) -> dict:
    require(platform in ('linux', 'windows'), 'unsupported target platform')
    require(path.is_file() and not path.is_symlink(), 'SDK is not a regular file')
    prefix = f'installed/x64-{platform}-static-release/'
    checked, violations, target_files = [], [], 0
    with path.open('rb') as source:
        sdk_digest = hashlib.file_digest(source, 'sha256').hexdigest()
    with zipfile.ZipFile(path) as archive:
        entries = safe_members(archive)
        for entry in entries:
            if entry.is_dir() or not entry.filename.startswith(prefix):
                continue
            relative = entry.filename[len(prefix):]
            parts = PurePosixPath(relative).parts
            if not parts or parts[0] not in ('lib', 'bin'):
                continue
            target_files += 1
            reason = None
            if SHARED_NAME.search(relative):
                reason = 'shared-library-file'
            elif relative.lower().endswith(('.a', '.lib', '.rlib')):
                try:
                    with archive.open(entry) as stream:
                        allow_os = (
                            platform == 'windows'
                            and re.fullmatch(r'lib/cef-static/cef_[0-9]{4,}_[0-9a-f]{12}\.lib',
                                             relative, re.I) is not None
                        )
                        result = inspect_archive(
                            stream, entry.file_size, platform,
                            allow_windows_os_imports=allow_os,
                        )
                    checked.append({'path': relative, **result})
                    if not result['qualified_objects_only']:
                        reason = 'unqualified-archive-members'
                except (ValueError, struct.error) as error:
                    reason = 'invalid-static-archive: ' + str(error)
            else:
                with archive.open(entry) as stream:
                    magic = stream.read(64)
                if magic.startswith(b'MZ') or magic.startswith(b'\x7fELF'):
                    reason = 'target-image-requires-separate-linkage-audit'
            if reason:
                violations.append({'path': relative, 'reason': reason})
    native_objects = sum(r['kinds'].get('elf-object', 0) + r['kinds'].get('coff-object', 0) for r in checked)
    require(target_files > 0 and checked, 'SDK has no auditable target archives')
    if not native_objects:
        violations.append({'path': '', 'reason': 'no-native-target-objects'})
    return {'schema': 1, 'kind': 'target-archive-audit', 'platform': platform,
            'triplet': f'x64-{platform}-static-release', 'sdk_sha256': sdk_digest,
            'target_files': target_files, 'native_objects': native_objects, 'archives': checked, 'violations': violations,
            'target_archives_static': not violations,
            'runtime_dependencies_verified': False, 'sdk_code_executed': False}


def summarize(report: dict) -> dict:
    """Bind bounded manifest evidence to the full encrypted diagnostic report."""
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return {"schema": 1, "kind": "target-archive-audit-summary",
            "sdk_sha256": report["sdk_sha256"], "report_sha256": hashlib.sha256(encoded).hexdigest(),
            "platform": report["platform"], "native_objects": report["native_objects"],
            "violation_count": len(report["violations"]),
            "target_archives_static": report["target_archives_static"],
            "runtime_dependencies_verified": False, "sdk_code_executed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--platform', choices=('linux', 'windows'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-static-archives', action='store_true')
    args = parser.parse_args()
    require(args.output.resolve() != args.sdk.resolve(), 'report cannot overwrite SDK')
    report = inspect_sdk(args.sdk, args.platform)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    if args.require_static_archives:
        require(report['target_archives_static'], 'target SDK contains shared or unqualified archives')


if __name__ == '__main__':
    main()
, re.I)
WINDOWS_API_SET = re.compile(r'(?:api|ext)-ms-win-[a-z0-9-]+\.dll\Z', re.I)
# OS ABI imports observed/reviewed for the pinned CEF/Rust Windows closure.
# This is deliberately not a generic "any DLL under System32" policy.
WINDOWS_OS_IMPORT_DLLS = frozenset({
    'advapi32.dll', 'bcrypt.dll', 'kernel32.dll', 'ntdll.dll',
    'ole32.dll', 'rpcrt4.dll', 'secur32.dll', 'shell32.dll',
    'user32.dll', 'userenv.dll', 'ws2_32.dll',
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def u(data: bytes, offset: int, fmt: str):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(data) - size, 'truncated binary header')
    return struct.unpack_from(fmt, data, offset)


def coff_kind(data: bytes) -> str:
    require(len(data) >= 20, 'truncated COFF header')
    if data[:4] == b'\0\0\xff\xff':
        version, machine = u(data, 4, '<HH')
        require(machine == 0x8664, 'non-x64 COFF member')
        if version == 0:
            size, = u(data, 12, '<I')
            require(size <= len(data) - 20, 'truncated short import object')
            return 'coff-import'
        require(version == 2 and len(data) >= 56 and data[12:28] == BIGOBJ_CLASS,
                'unsupported anonymous COFF object')
        sections, symbols, count = u(data, 44, '<III')
        table, symbol_size = 56, 20
    else:
        machine, sections, _, symbols, count, optional, characteristics = u(data, 0, '<HHIIIHH')
        require(machine == 0x8664 and optional == 0 and not characteristics & 0x2002,
                'non-x64 object or PE image in archive')
        table, symbol_size = 20, 18
    require(0 <= sections <= 1_000_000 and table + sections * 40 <= len(data), 'invalid COFF sections')
    imported = False
    for index in range(sections):
        start = table + index * 40
        name = data[start:start + 8].split(b'\0', 1)[0]
        if name.startswith(b'/'):
            require(name[1:].isdigit() and symbols > 0, 'invalid COFF section name')
            strings = symbols + count * symbol_size
            size, = u(data, strings, '<I')
            require(4 <= size <= len(data) - strings, 'invalid COFF string table')
            position = int(name[1:])
            require(4 <= position < size, 'invalid COFF string offset')
            end = data.find(b'\0', strings + position, strings + size)
            require(end != -1, 'unterminated COFF section name')
            name = data[strings + position:end]
        if name.startswith((b'.idata', b'.didat')):
            imported = True
        size, pointer = u(data, start + 16, '<II')
        require(pointer == 0 or pointer + size <= len(data), 'COFF section outside object')
    return 'coff-import' if imported else 'coff-object'


def object_kind(data: bytes, name: str, platform: str) -> str:
    if data.startswith(b'\x7fELF'):
        require(platform == 'linux' and len(data) >= 64 and data[4:7] == b'\x02\x01\x01',
                'wrong ELF platform/class/endianness')
        kind, machine, version = u(data, 16, '<HHI')
        require(machine == 62 and version == 1, 'non-x64 ELF member')
        return 'elf-object' if kind == 1 else 'elf-image'
    if data.startswith(b'MZ'):
        return 'pe-image'
    if data.startswith((b'!<arch>\n', b'!<thin>\n')):
        return 'nested-archive'
    if data.startswith((b'BC\xc0\xde', b'\xde\xc0\x17\x0b')):
        return 'llvm-bitcode-unqualified'
    # Rust metadata is not executable and is a normal rlib member. Its extension
    # alone is insufficient; require the rustc metadata magic too.
    if name.endswith('.rmeta') and data.startswith(b'rust'):
        return 'rust-metadata'
    if platform == 'windows':
        return coff_kind(data)
    raise ValueError('unrecognized Linux archive member')


def exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    require(len(data) == size, 'truncated archive member')
    return data


def inspect_archive(stream: BinaryIO, size: int, platform: str) -> dict:
    require(platform in ('linux', 'windows'), 'unsupported target platform')
    require(size >= 8 and exact(stream, 8) == b'!<arch>\n', 'not a self-contained ordinary archive')
    consumed, count, longnames = 8, 0, b''
    kinds = Counter()
    samples = []
    while consumed < size:
        require(size - consumed >= 60 and count < MAX_MEMBERS, 'invalid archive member count/header')
        header = exact(stream, 60)
        require(header[58:] == b'`\n' and header[48:58].strip().isdigit(), 'invalid archive header')
        length = int(header[48:58])
        require(length <= MAX_MEMBER and length <= size - consumed - 60, 'archive member exceeds bounds')
        name = header[:16].rstrip(b' ')
        payload = exact(stream, length)
        consumed += 60 + length
        if length & 1:
            require(consumed < size and exact(stream, 1) == b'\n', 'invalid archive padding')
            consumed += 1
        count += 1
        if name == b'//':
            require(not longnames, 'duplicate archive name table')
            longnames = payload
            continue
        if name in (b'/', b'/SYM64/'):
            continue
        if name.startswith(b'#1/'):
            require(name[3:].isdigit(), 'invalid BSD member name')
            width = int(name[3:])
            require(0 < width <= len(payload), 'invalid BSD name length')
            name, payload = payload[:width].rstrip(b'\0'), payload[width:]
        elif name.startswith(b'/'):
            require(name[1:].isdigit(), 'invalid GNU/COFF member name')
            offset = int(name[1:])
            require(offset < len(longnames), 'archive name outside table')
            ends = [p for p in (longnames.find(b'/\n', offset), longnames.find(b'\0', offset)) if p >= 0]
            require(ends, 'unterminated archive member name')
            name = longnames[offset:min(ends)]
        else:
            name = name.removesuffix(b'/')
        require(name and not any(b < 32 for b in name), 'invalid object member name')
        text = name.decode('utf-8', errors='replace')
        kind = object_kind(payload, text, platform)
        kinds[kind] += 1
        if kind not in ('elf-object', 'coff-object', 'rust-metadata') and len(samples) < 8:
            samples.append({'member': text, 'kind': kind})
    require(consumed == size, 'archive size mismatch')
    return {'members': sum(kinds.values()), 'kinds': dict(sorted(kinds.items())),
            'qualified_objects_only': not samples, 'unqualified_samples': samples}


def safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    entries = archive.infolist()
    require(len(entries) <= MAX_FILES, 'too many SDK ZIP entries')
    seen, nodes, total = set(), {}, 0
    for entry in entries:
        raw = entry.filename.rstrip('/')
        parts = raw.split('/')
        require(raw and not any(c in raw for c in '\\:\x00') and not any(ord(c) < 32 for c in raw)
                and all(p not in ('', '.', '..') for p in parts), 'unsafe SDK ZIP path')
        folded = tuple(p.casefold() for p in parts)
        require(folded not in seen, 'duplicate SDK ZIP path')
        seen.add(folded)
        for i in range(1, len(parts) + 1):
            key = folded[:i]
            node = (tuple(parts[:i]), i < len(parts) or entry.is_dir())
            require(key not in nodes or nodes[key] == node, 'SDK path case/type collision')
            nodes[key] = node
        kind = stat.S_IFMT(entry.external_attr >> 16)
        require(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not entry.flag_bits & 1, 'nonregular/encrypted SDK member')
        require((kind != stat.S_IFDIR or entry.is_dir()) and (kind != stat.S_IFREG or not entry.is_dir()), 'ZIP type mismatch')
        total += entry.file_size
        require(entry.file_size >= 0 and total <= MAX_UNPACKED, 'oversized SDK ZIP')
    return entries


def inspect_sdk(path: Path, platform: str) -> dict:
    require(platform in ('linux', 'windows'), 'unsupported target platform')
    require(path.is_file() and not path.is_symlink(), 'SDK is not a regular file')
    prefix = f'installed/x64-{platform}-static-release/'
    checked, violations, target_files = [], [], 0
    with path.open('rb') as source:
        sdk_digest = hashlib.file_digest(source, 'sha256').hexdigest()
    with zipfile.ZipFile(path) as archive:
        entries = safe_members(archive)
        for entry in entries:
            if entry.is_dir() or not entry.filename.startswith(prefix):
                continue
            relative = entry.filename[len(prefix):]
            parts = PurePosixPath(relative).parts
            if not parts or parts[0] not in ('lib', 'bin'):
                continue
            target_files += 1
            reason = None
            if SHARED_NAME.search(relative):
                reason = 'shared-library-file'
            elif relative.lower().endswith(('.a', '.lib', '.rlib')):
                try:
                    with archive.open(entry) as stream:
                        result = inspect_archive(stream, entry.file_size, platform)
                    checked.append({'path': relative, **result})
                    if not result['qualified_objects_only']:
                        reason = 'unqualified-archive-members'
                except (ValueError, struct.error) as error:
                    reason = 'invalid-static-archive: ' + str(error)
            else:
                with archive.open(entry) as stream:
                    magic = stream.read(64)
                if magic.startswith(b'MZ') or magic.startswith(b'\x7fELF'):
                    reason = 'target-image-requires-separate-linkage-audit'
            if reason:
                violations.append({'path': relative, 'reason': reason})
    native_objects = sum(r['kinds'].get('elf-object', 0) + r['kinds'].get('coff-object', 0) for r in checked)
    require(target_files > 0 and checked, 'SDK has no auditable target archives')
    if not native_objects:
        violations.append({'path': '', 'reason': 'no-native-target-objects'})
    return {'schema': 1, 'kind': 'target-archive-audit', 'platform': platform,
            'triplet': f'x64-{platform}-static-release', 'sdk_sha256': sdk_digest,
            'target_files': target_files, 'native_objects': native_objects, 'archives': checked, 'violations': violations,
            'target_archives_static': not violations,
            'runtime_dependencies_verified': False, 'sdk_code_executed': False}


def summarize(report: dict) -> dict:
    """Bind bounded manifest evidence to the full encrypted diagnostic report."""
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return {"schema": 1, "kind": "target-archive-audit-summary",
            "sdk_sha256": report["sdk_sha256"], "report_sha256": hashlib.sha256(encoded).hexdigest(),
            "platform": report["platform"], "native_objects": report["native_objects"],
            "violation_count": len(report["violations"]),
            "target_archives_static": report["target_archives_static"],
            "runtime_dependencies_verified": False, "sdk_code_executed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--platform', choices=('linux', 'windows'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-static-archives', action='store_true')
    args = parser.parse_args()
    require(args.output.resolve() != args.sdk.resolve(), 'report cannot overwrite SDK')
    report = inspect_sdk(args.sdk, args.platform)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    if args.require_static_archives:
        require(report['target_archives_static'], 'target SDK contains shared or unqualified archives')


if __name__ == '__main__':
    main()
