"""Keep pre-existing local-signature COMDAT groups intact in CEF objcopy passes.

LLVM 53d18800 GroupSection::finalize clears GRP_COMDAT whenever the signature
is local, even if it was already local on input. That is a semantic mutation,
not a difference our comparison may ignore. In a disposable, byte-identical
archive copy only, temporarily present those group headers as SHT_PROGBITS.
The same pinned objcopy restores their SHT_GROUP type while carrying the exact
opaque payload. No relocation, symbol, group flag or membership is invented.
The original archive is never modified here. All groups (not just staged ones)
are verified after the tool, including signature identity and physical order.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from . import cef_crel as elf

GROUP = 17
PROGBITS = 1
COMDAT = 1
SHF_GROUP = 0x200
WORD = struct.Struct('<I')


def members(path: Path, limit: int):
    """Read bounded regular GNU ar members; names are never filesystem paths."""
    elf.require(type(limit) is int and 1024**3 <= limit <= elf.MAX_ARCHIVE,
                'Invalid CEF group archive budget')
    elf.require(path.is_file() and not path.is_symlink(), 'Invalid CEF group archive')
    size = path.stat().st_size
    elf.require(8 <= size <= limit, 'CEF group archive exceeds bound')
    names = b''
    count = 0
    with path.open('rb') as stream:
        elf.require(stream.read(8) == b'!<arch>\n', 'CEF group input is not regular ar')
        while stream.tell() < size:
            header = stream.read(60)
            elf.require(len(header) == 60 and header[58:] == b'`\n', 'Invalid CEF group ar header')
            field = header[48:58].strip()
            elf.require(field.isdigit(), 'Invalid CEF group ar length')
            length = int(field)
            start = stream.tell()
            elf.require(length <= size-start-(length & 1), 'Truncated CEF group ar member')
            raw = header[:16].rstrip()
            count += 1
            elf.require(count <= elf.MAX_RECORDS, 'CEF group member inventory exceeds bound')
            if raw in (b'/', b'/SYM64/'):
                stream.seek(length, os.SEEK_CUR)
            elif raw == b'//':
                elf.require(length <= elf.MAX_MEMBER, 'CEF group name table exceeds bound')
                names = stream.read(length)
            else:
                if raw.startswith(b'/') and raw[1:].isdigit():
                    off = int(raw[1:])
                    elf.require(off < len(names) and (off == 0 or names[off-1:off] == b'\n'),
                                'Invalid CEF group long name')
                    end = names.find(b'/\n', off)
                    elf.require(end >= 0, 'Unterminated CEF group long name')
                    raw = names[off:end]
                else:
                    elf.require(raw.endswith(b'/') and not raw.startswith(b'#1/'),
                                'Unsupported CEF group name encoding')
                    raw = raw[:-1]
                elf.require(length <= elf.MAX_MEMBER, 'CEF group object exceeds bound')
                data = stream.read(length)
                elf.require(len(data) == length, 'Truncated CEF group object')
                yield raw, data, start
            if length & 1:
                elf.require(stream.read(1) == b'\n', 'Invalid CEF group ar padding')


def _groups(data: bytes, reverse: dict[str, str]):
    """Return a group-only semantic inventory plus exact temporary header sites."""
    if not data.startswith(b'\x7fELF'):
        return [], [], set()
    elf.require(len(data) >= elf.HEADER.size, 'Truncated CEF group ELF')
    h = elf.HEADER.unpack_from(data)
    elf.require(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (1, 62, 1)
                and h[8] == elf.HEADER.size and h[9:11] == (0, 0)
                and h[11] == elf.SECTION.size and 0 < h[13] < h[12] < 65535
                and h[6] + h[12]*elf.SECTION.size <= len(data), 'Invalid CEF group ELF')
    sections = [elf.SECTION.unpack_from(data, h[6]+i*elf.SECTION.size) for i in range(h[12])]

    def payload(s):
        elf.require(s[4]+s[5] <= len(data), 'CEF group payload escapes object')
        return data[s[4]:s[4]+s[5]]

    def text(table, pos):
        elf.require(0 <= pos < len(table), 'Invalid CEF group string offset')
        end = table.find(b'\0', pos)
        elf.require(end >= 0, 'Unterminated CEF group string')
        return table[pos:end].decode('utf-8', errors='strict')

    elf.require(sections[h[13]][1] == 3, 'Invalid CEF group section-name table')
    names = payload(sections[h[13]])
    records, patches, other_names = [], [], set()
    occupied = set()
    for i, s in enumerate(sections[1:], 1):
        name = text(names, s[0])
        if s[1] != GROUP:
            # Hashes bound memory independently of very long C++ section names.
            other_names.add(hashlib.sha256(name.encode('utf-8')).digest())
            continue
        elf.require(s[5] >= 8 and s[5] % 4 == 0 and s[9] == 4
                    and 0 < s[6] < len(sections), 'Invalid CEF ELF group metadata')
        words = tuple(v[0] for v in WORD.iter_unpack(payload(s)))
        elf.require(words[0] in (0, COMDAT), 'Unsupported CEF ELF group flags')
        elf.require(len(set(words[1:])) == len(words)-1, 'Duplicate CEF group member')
        for index in words[1:]:
            elf.require(0 < index < len(sections) and index != i
                        and sections[index][2] & SHF_GROUP and index not in occupied,
                        'Invalid CEF group membership')
            occupied.add(index)
        syms = sections[s[6]]
        elf.require(syms[1] == 2 and syms[9] == elf.SYMBOL.size
                    and syms[5] % elf.SYMBOL.size == 0
                    and 0 < s[7] < syms[5]//elf.SYMBOL.size
                    and 0 < syms[6] < len(sections) and sections[syms[6]][1] == 3,
                    'Invalid CEF group signature table')
        sym = elf.SYMBOL.unpack_from(payload(syms), s[7]*elf.SYMBOL.size)
        signature = text(payload(sections[syms[6]]), sym[0])
        # Section file offsets and packed string offsets may move. Every group
        # semantic field, raw flag/member vector and referenced symbol is exact.
        records.append([i, name, s[1], s[2], s[3], s[5], s[6], s[7], s[8], s[9],
                        words, [reverse.get(signature, signature), *sym[1:]]])
        if words[0] == COMDAT and sym[1] >> 4 == 0:
            elf.require(re.fullmatch(r'[A-Za-z0-9_.$+\-]+', name) is not None,
                        'Unsafe CEF group option name')
            patches.append((h[6]+i*elf.SECTION.size+4, name))
    return records, patches, other_names


def profile(path: Path, limit: int, reverse: dict[str, str] | None = None):
    hasher = hashlib.sha256()
    patches, names, others = [], set(), set()
    count = objects = 0
    for raw, data, offset in members(path, limit):
        records, sites, other_names = _groups(data, reverse or {})
        elf._feed(hasher, [raw.hex(), records])
        count += len(records)
        objects += 1
        patches.extend((offset+pos, name) for pos, name in sites)
        names.update(name for _, name in sites)
        others.update(other_names)
        elf.require(count <= elf.MAX_RECORDS and len(others) <= elf.MAX_RECORDS,
                    'CEF group inventory exceeds bound')
    elf.require(not any(hashlib.sha256(n.encode('utf-8')).digest() in others for n in names),
                'CEF group name collides with a non-group section')
    return {'sha256': hasher.hexdigest(), 'groups': count, 'members': objects,
            'patches': patches, 'names': sorted(names)}


@contextmanager
def _input_copy(source: Path, before: dict):
    """Stage only 4-byte section-type tags; all original payload bytes stay intact."""
    if not before['patches']:
        yield source, []
        return
    original_sha = elf.digest(source)
    with tempfile.TemporaryDirectory(prefix='.cef-group-input-', dir=source.parent) as temp:
        staged = Path(temp)/'input.a'
        with source.open('rb') as src, staged.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024**2)
        staged.chmod(0o600)
        elf.require(elf.digest(staged) == original_sha, 'CEF group staging source changed')
        with staged.open('r+b') as stream:
            for pos, _ in before['patches']:
                stream.seek(pos)
                elf.require(stream.read(4) == WORD.pack(GROUP), 'CEF group staging site changed')
                stream.seek(pos)
                stream.write(WORD.pack(PROGBITS))
        options = ['--set-section-type='+name+'=17' for name in before['names']]
        elf.require(sum(len(v) for v in options) <= elf.MAX_OPTIONS, 'CEF group options exceed bound')
        arguments = Path(temp)/'restore.options'
        arguments.write_text('\n'.join(options)+'\n', encoding='ascii')
        arguments.chmod(0o600)
        yield staged, ['@'+str(arguments)]
        elf.require(elf.digest(source) == original_sha, 'CEF group source changed during conversion')


def run(objcopy: Path, options: list[str], source: Path, output: Path, *,
        limit: int, reverse: dict[str, str] | None = None) -> dict:
    """Use the caller's exact writer/options, without losing pre-existing groups."""
    elf.require(not output.exists() and not output.is_symlink(), 'CEF group output already exists')
    before = profile(source, limit)
    if before['patches']:
        elf.require(elf.digest(objcopy) == elf.TOOL_SHA256, 'Unreviewed CEF group-preserving writer')
    with _input_copy(source, before) as (staged, restore):
        subprocess.run([str(objcopy), *options, *restore, str(staged), str(output)],
                       check=True, timeout=600)
        after = profile(output, limit, reverse)
        elf.require(after['sha256'] == before['sha256']
                    and after['groups'] == before['groups'] and after['members'] == before['members'],
                    'CEF objcopy changed group semantics')
    return {'groups': before['groups'], 'preserved_local_comdat': len(before['patches']),
            'group_sha256': before['sha256']}
