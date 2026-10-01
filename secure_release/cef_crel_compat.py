"""Preserve CEF relocations when exporting to the fixed LLD18 consumer.

Only the already-owned CEF archives are passed by cef_boringssl_isolation.
The pinned Chromium llvm-objcopy performs CREL -> RELA; Python only inventories
and verifies relocation semantics. No target, symbol, code or constructor is
removed, invented, or approved by this module.

Encoding reference: llvmorg-20.1.8 llvm/include/llvm/Object/ELF.h decodeCrel,
llvm/lib/ObjCopy/ELF/ELFObject.cpp RelocationSection reader/sizer/writer, and
ELFObjcopy.cpp setSectionType. Only explicit-addend ELF64/x86-64 SHT_CREL
0x40000014 is accepted. A future/older experimental encoding fails closed.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile

HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
SECTION = struct.Struct('<IIQQQQIIQQ')
SYMBOL = struct.Struct('<IBBHQQ')
RELA = struct.Struct('<QQq')
SHT_CREL = 0x40000014
ENCODING = "elf64-x86-64-crel-to-rela-v1"
MAX_SECTIONS = 65535
MAX_RELOCATIONS = 20_000_000
MAX_RSP_BYTES = 32 * 1024**2
NAME = re.compile(r'[A-Za-z0-9_.$@+\-]+\Z')
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _leb(data: bytes, pos: int, *, signed: bool = False) -> tuple[int, int]:
    value = shift = 0
    for _ in range(10):
        require(pos < len(data), 'Truncated CREL LEB128')
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        shift += 7
        if not byte & 128:
            if signed and byte & 64:
                value -= 1 << shift
            require(-(1 << 63) <= value < (1 << 63) if signed else 0 <= value <= MASK64,
                    'Oversized CREL LEB128')
            return value, pos
    raise ValueError('Oversized CREL LEB128')


def decode(data: bytes):
    """Yield exact (offset, symbol index, relocation type, signed addend)."""
    header, pos = _leb(data, 0)
    count, shift = header >> 3, header & 3
    require(header & 4 == 4, 'Implicit-addend CREL is outside the x86-64 SDK profile')
    require(count <= MAX_RELOCATIONS and count <= len(data) - pos,
            'CREL relocation inventory exceeds bounds')
    offset = symbol = kind = addend = 0
    for _ in range(count):
        require(pos < len(data), 'Truncated CREL entry')
        byte = data[pos]
        pos += 1
        delta = (byte & 127) >> 3
        if byte & 128:
            tail, pos = _leb(data, pos)
            delta += tail << 4
        offset += delta
        require(offset <= MASK64 >> shift, 'CREL offset overflow')
        if byte & 1:
            delta, pos = _leb(data, pos, signed=True)
            symbol = (symbol + delta) & MASK32
        if byte & 2:
            delta, pos = _leb(data, pos, signed=True)
            kind = (kind + delta) & MASK32
        if byte & 4:
            delta, pos = _leb(data, pos, signed=True)
            addend = (addend + delta) & MASK64
        yield offset << shift, symbol, kind, addend if addend < 1 << 63 else addend - (1 << 64)
    require(pos == len(data), 'Trailing bytes in CREL relocation section')


class ELF:
    def __init__(self, data: bytes):
        require(len(data) >= HEADER.size, 'Truncated CREL ELF member')
        self.data = data
        h = HEADER.unpack_from(data)
        require(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (1, 62, 1),
                'CREL conversion requires ELF64 x86-64 ET_REL')
        require(h[8] == HEADER.size and h[11] == SECTION.size
                and 0 < h[12] < MAX_SECTIONS and 0 < h[13] < h[12]
                and HEADER.size <= h[6] <= len(data) - h[12] * SECTION.size,
                'Invalid CREL ELF section table')
        self.sections = [SECTION.unpack_from(data, h[6] + i * SECTION.size)
                         for i in range(h[12])]
        require(self.sections[h[13]][1] == 3, 'Invalid CREL ELF string table')
        names = self.payload(self.sections[h[13]])
        self.names = [self.string(names, section[0]) for section in self.sections]
        self._target_identities = {}
        for name, section in zip(self.names, self.sections):
            require(not name.startswith('.crel') or section[1] == SHT_CREL,
                    'Unknown experimental CREL encoding')

    def payload(self, section):
        require(section[4] + section[5] <= len(self.data), 'CREL ELF section escapes member')
        return self.data[section[4]:section[4] + section[5]]

    @staticmethod
    def string(table, offset):
        require(0 <= offset < len(table), 'Invalid CREL ELF string offset')
        end = table.find(b'\0', offset)
        require(end >= 0, 'Unterminated CREL ELF string')
        return table[offset:end].decode('utf-8', errors='strict')

    def describe(self, index: int, *, reverse: dict[str, str]):
        """Hash target identity and *all* ordered relocation tuples, not indices."""
        sec = self.sections[index]
        name = self.names[index]
        require(sec[1] in (4, SHT_CREL) and not sec[2] & 2,
                'Unexpected allocated or unsupported CREL relocation section')
        require(0 < sec[6] < len(self.sections) and 0 < sec[7] < len(self.sections),
                'Invalid CREL relocation links')
        target = self.sections[sec[7]]
        require(target[1] != 8, 'Unexpected CREL target without file contents')
        syms = self.sections[sec[6]]
        require(syms[1] == 2 and syms[9] == SYMBOL.size and syms[5] % SYMBOL.size == 0
                and 0 < syms[6] < len(self.sections)
                and self.sections[syms[6]][1] == 3,
                'Invalid CREL symbol table')
        symbols, strings = self.payload(syms), self.payload(self.sections[syms[6]])
        if sec[1] == SHT_CREL:
            require(sec[9] == 1 and sec[8] == 1 and name.startswith('.crel'),
                    'Unexpected CREL section layout')
            entries = decode(self.payload(sec))
            canonical_name = '.rela' + name[5:]
        else:
            require(sec[9] == RELA.size and sec[8] == 8 and sec[5] % RELA.size == 0,
                    'Invalid converted RELA section layout')
            entries = ((o, info >> 32, info & MASK32, a)
                       for o, info, a in RELA.iter_unpack(self.payload(sec)))
            canonical_name = name
        state = hashlib.sha256()
        def record(value):
            state.update(json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n')
        # Target contents and attributes must survive namespace conversion.
        # Do not tie this proof to symbol-table indices renumbered by objcopy.
        target_name = self.names[sec[7]]
        # The independently checked pre-existing init-array normalization may
        # lower alignment to 8 in the same objcopy invocation. Nothing else
        # about the target is normalized by this semantic comparison.
        alignment = min(target[8], 8) if (target_name == '.init_array' or
            target_name.startswith('.init_array.')) else target[8]
        record([canonical_name, sec[2], target_name, target[1], target[2],
                target[3], target[5], alignment, target[9],
                hashlib.sha256(self.payload(target)).hexdigest()])
        count = 0
        for offset, symbol, kind, addend in entries:
            count += 1
            require(count <= MAX_RELOCATIONS and offset < target[5],
                    'CREL relocation escapes target/bounded inventory')
            require(symbol < len(symbols) // SYMBOL.size, 'CREL symbol index escapes table')
            sym = SYMBOL.unpack_from(symbols, symbol * SYMBOL.size)
            sym_name = self.string(strings, sym[0]) if sym[0] else ''
            sym_name = reverse.get(sym_name, sym_name)
            if 0 < sym[3] < len(self.sections):
                section_index = sym[3]
                if section_index not in self._target_identities:
                    target_section = self.sections[section_index]
                    target_hash = (None if target_section[1] == 8 else
                        hashlib.sha256(self.payload(target_section)).hexdigest())
                    self._target_identities[section_index] = [
                        self.names[section_index], target_section[1], target_section[2],
                        target_section[5],
                        (min(target_section[8], 8) if
                         self.names[section_index] == '.init_array' or
                         self.names[section_index].startswith('.init_array.')
                         else target_section[8]), target_hash,
                    ]
                identity = self._target_identities[section_index]
            else:
                require(sym[3] == 0 or sym[3] in (0xfff1, 0xfff2),
                        'Unsupported CREL symbol section index')
                identity = sym[3]
            record([offset, kind, addend, sym_name, sym[1], sym[2], identity, sym[4], sym[5]])
        return canonical_name, count, state.hexdigest()


def inventory(members, *, plan: dict | None = None, reverse: dict | None = None) -> dict:
    """members is the existing bounded regular-ar reader, physical index + ELF."""
    state = hashlib.sha256()
    total = sections = 0
    selected = {}
    seen = set()
    names = set()
    for member, payload in members:
        elf = ELF(payload)
        crel = [i for i, s in enumerate(elf.sections) if s[1] == SHT_CREL]
        if plan is None:
            indices = crel
        else:
            require(not crel, 'CEF archive retains CREL unsupported by LLD18')
            wanted = plan['selected'].get(member, [])
            indices = [i for i, name in enumerate(elf.names) if name in wanted]
            require(len(indices) == len(wanted), 'Converted CEF relocation section is missing/ambiguous')
        indices.sort(key=lambda i: ('.rela' + elf.names[i][5:])
                     if elf.sections[i][1] == SHT_CREL else elf.names[i])
        member_names = []
        for i in indices:
            key, count, sha = elf.describe(i, reverse=reverse or {})
            require(key not in member_names, 'Ambiguous CEF relocation section')
            member_names.append(key)
            if plan is None:
                require(key not in elf.names, 'CREL to RELA section name collision')
                original_name = elf.names[i]
                require(NAME.fullmatch(original_name) is not None and len(original_name) <= 4096,
                        'Invalid CEF relocation section identifier')
                names.add(original_name)
            total += count
            sections += 1
            require(total <= MAX_RELOCATIONS and sections <= MAX_RELOCATIONS,
                    'CEF relocation inventory exceeds bounds')
            state.update(json.dumps([member, key, count, sha], separators=(',', ':')).encode() + b'\n')
        if member_names:
            seen.add(member)
            selected[member] = member_names
    if plan is not None:
        require(seen == set(plan['selected']), 'Converted CEF archive member is missing')
    result = {'section_count': sections, 'relocation_count': total, 'sha256': state.hexdigest(),
              'selected': selected, 'names': sorted(names)}
    if plan is not None:
        require(all(result[k] == plan[k] for k in ('section_count', 'relocation_count', 'sha256', 'selected')),
                'CEF relocation semantics changed during CREL to RELA conversion')
    return result


@contextmanager
def options(plan: dict, directory: Path):
    """Exact-name response file; no shell, wildcard, reinterpretation or removal."""
    if not plan['section_count']:
        yield []
        return
    fd, value = tempfile.mkstemp(prefix='.cef-crel-', suffix='.rsp', dir=directory)
    path = Path(value)
    try:
        with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as stream:
            count = 0
            for name in plan['names']:
                require(NAME.fullmatch(name) is not None and name.startswith('.crel'),
                        'Invalid CEF relocation option')
                text = f'--set-section-type={name}=4\n--rename-section={name}=.rela{name[5:]}\n'
                count += len(text)
                require(count <= MAX_RSP_BYTES, 'CREL response file exceeds bound')
                stream.write(text)
        yield ['@' + str(path)]
    finally:
        path.unlink(missing_ok=True)


def validate_receipt(encoding: str, records: dict, names: set[str]) -> None:
    """Validate the mandatory semantic receipt before transport can pass."""
    require(encoding == ENCODING and isinstance(records, dict)
            and set(records) <= names, 'CEF CREL conversion receipt changed')
    for record in records.values():
        require(isinstance(record, dict)
                and set(record) == {'section_count', 'relocation_count', 'sha256'}
                and type(record['section_count']) is int
                and 0 < record['section_count'] <= MAX_RELOCATIONS
                and type(record['relocation_count']) is int
                and 0 <= record['relocation_count'] <= MAX_RELOCATIONS
                and isinstance(record['sha256'], str)
                and re.fullmatch(r'[0-9a-f]{64}', record['sha256']) is not None,
                'Invalid CEF CREL semantic receipt')
