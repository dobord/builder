"""Fail-closed ELF64 x86-64 startup-constructor audit for final Linux consumers."""
from __future__ import annotations

import hashlib
import json
import mmap
from pathlib import Path
import struct

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
RELA = struct.Struct("<QQq")
SYMBOL = struct.Struct("<IBBHQQ")
DYNAMIC = struct.Struct("<qQ")

ET_EXEC = 2
ET_DYN = 3
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4
SHN_UNDEF = 0
STB_WEAK = 2

R_X86_64_64 = 1
R_X86_64_GLOB_DAT = 6
R_X86_64_RELATIVE = 8
R_X86_64_IRELATIVE = 37

DT_NULL = 0
DT_INIT = 12
DT_INIT_ARRAY = 25
DT_INIT_ARRAYSZ = 27
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33

MAX_ELF_BYTES = 6 * 1024**3
MAX_SECTIONS = 65535
MAX_CONSTRUCTORS = 1_000_000
MAX_RELOCATIONS = 10_000_000
MAX_SYMBOLS = 20_000_000


def _slice(data: mmap.mmap, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("ELF " + label + " escapes file")
    return data[offset:offset + size]


def _cstring(table: bytes, offset: int, label: str) -> str:
    if not 0 <= offset < len(table):
        raise ValueError("ELF " + label + " string offset is invalid")
    end = table.find(b"\0", offset)
    if end < 0:
        raise ValueError("ELF " + label + " string is unterminated")
    try:
        return table[offset:end].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("ELF " + label + " string is not UTF-8") from error


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _section_table(data: mmap.mmap):
    if len(data) < ELF_HEADER.size:
        raise ValueError("ELF header is truncated")
    header = ELF_HEADER.unpack_from(data, 0)
    ident = header[0]
    if ident[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("constructor audit requires little-endian ELF64")
    e_type = header[1]
    e_machine = header[2]
    e_version = header[3]
    e_shoff = header[6]
    e_ehsize = header[8]
    e_shentsize = header[11]
    e_shnum = header[12]
    e_shstrndx = header[13]
    if e_type not in {ET_EXEC, ET_DYN} or e_machine != 62 or e_version != 1:
        raise ValueError("constructor audit requires native x86-64 executable")
    if (
        e_ehsize != ELF_HEADER.size
        or e_shentsize != SECTION_HEADER.size
        or not 1 <= e_shnum <= MAX_SECTIONS
        or not 0 < e_shstrndx < e_shnum
        or e_shoff < ELF_HEADER.size
        or e_shoff + e_shnum * e_shentsize > len(data)
    ):
        raise ValueError("invalid ELF section table")

    raw = []
    for index in range(e_shnum):
        values = SECTION_HEADER.unpack_from(data, e_shoff + index * e_shentsize)
        item = {
            "index": index,
            "name_offset": values[0],
            "type": values[1],
            "flags": values[2],
            "addr": values[3],
            "offset": values[4],
            "size": values[5],
            "link": values[6],
            "info": values[7],
            "align": values[8],
            "entsize": values[9],
        }
        if item["type"] != 8:  # SHT_NOBITS has no file payload.
            _slice(data, item["offset"], item["size"], "section")
        raw.append(item)

    names = raw[e_shstrndx]
    name_table = _slice(data, names["offset"], names["size"], "section-name table")
    for item in raw:
        item["name"] = _cstring(name_table, item["name_offset"], "section")
    return e_type, raw


def _symbol_table(data: mmap.mmap, sections, section_index: int):
    if not 0 <= section_index < len(sections):
        raise ValueError("ELF relocation symbol table index is invalid")
    section = sections[section_index]
    if section["type"] not in {SHT_SYMTAB, SHT_DYNSYM}:
        raise ValueError("ELF relocation does not reference a symbol table")
    if section["entsize"] != SYMBOL.size or section["size"] % SYMBOL.size:
        raise ValueError("invalid ELF symbol table")
    count = section["size"] // SYMBOL.size
    if count > MAX_SYMBOLS or not 0 <= section["link"] < len(sections):
        raise ValueError("oversized or unlinked ELF symbol table")
    strings = sections[section["link"]]
    table = _slice(data, strings["offset"], strings["size"], "symbol string table")
    result = []
    for index in range(count):
        values = SYMBOL.unpack_from(data, section["offset"] + index * SYMBOL.size)
        result.append({
            "index": index,
            "name": _cstring(table, values[0], "symbol") if values[0] else "",
            "binding": values[1] >> 4,
            "type": values[1] & 0x0F,
            "shndx": values[3],
            "value": values[4],
            "size": values[5],
        })
    return result


def _exec_ranges(sections):
    return [
        (section["addr"], section["addr"] + section["size"], section["name"])
        for section in sections
        if section["flags"] & SHF_EXECINSTR and section["size"] > 0
    ]


def _in_exec(value: int, ranges) -> bool:
    return any(start <= value < end for start, end, _ in ranges)


def audit(path: Path) -> dict:
    """Return private details plus a bounded public startup-constructor summary."""
    path = path.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("constructor audit input must be a regular executable")
    size = path.stat().st_size
    if not 64 <= size <= MAX_ELF_BYTES:
        raise ValueError("constructor audit executable size is outside bounds")

    with path.open("rb") as stream, mmap.mmap(
        stream.fileno(), 0, access=mmap.ACCESS_READ
    ) as data:
        e_type, sections = _section_table(data)
        by_name = {section["name"]: section for section in sections}
        if len(by_name) != len(sections):
            raise ValueError("duplicate ELF section name")
        ranges = _exec_ranges(sections)
        if not ranges:
            raise ValueError("ELF executable has no executable section")

        startup_sections = []
        for name in (".preinit_array", ".init_array"):
            section = by_name.get(name)
            if section is None:
                continue
            if section["size"] % 8 or section["align"] not in {0, 8}:
                raise ValueError("invalid ELF startup array layout")
            count = section["size"] // 8
            if count > MAX_CONSTRUCTORS:
                raise ValueError("ELF startup array is oversized")
            startup_sections.append(section)

        relocs: dict[int, list[dict]] = {}
        symbol_cache = {}
        relocation_count = 0
        for section in sections:
            if section["type"] != SHT_RELA:
                continue
            if section["entsize"] != RELA.size or section["size"] % RELA.size:
                raise ValueError("invalid ELF RELA section")
            count = section["size"] // RELA.size
            relocation_count += count
            if relocation_count > MAX_RELOCATIONS:
                raise ValueError("ELF relocation inventory is oversized")
            symbols = None
            for index in range(count):
                offset, info, addend = RELA.unpack_from(
                    data, section["offset"] + index * RELA.size
                )
                target = next(
                    (
                        item for item in startup_sections
                        if item["addr"] <= offset < item["addr"] + item["size"]
                    ),
                    None,
                )
                if target is None:
                    continue
                if (offset - target["addr"]) % 8:
                    raise ValueError("ELF startup relocation is not slot-aligned")
                sym_index = info >> 32
                relocation_type = info & 0xFFFFFFFF
                symbol = None
                if sym_index:
                    if symbols is None:
                        if section["link"] not in symbol_cache:
                            symbol_cache[section["link"]] = _symbol_table(
                                data, sections, section["link"]
                            )
                        symbols = symbol_cache[section["link"]]
                    if sym_index >= len(symbols):
                        raise ValueError("ELF relocation symbol index is invalid")
                    symbol = symbols[sym_index]
                relocs.setdefault(offset, []).append({
                    "type": relocation_type,
                    "addend": addend,
                    "symbol": symbol,
                    "relocation_section": section["name"],
                })

        details = {
            "schema": 1,
            "kind": "elf-startup-constructor-audit",
            "elf_type": "dyn" if e_type == ET_DYN else "exec",
            "sections": [],
            "dt_init": None,
            "dynamic_arrays": {},
            "bad": [],
        }
        counts = {
            "entries": 0,
            "relocations": 0,
            "zero_unrelocated": 0,
            "undefined_weak": 0,
            "undefined_global": 0,
            "invalid_target": 0,
            "duplicate_relocation": 0,
            "unsupported_relocation": 0,
            "irelative": 0,
        }

        for section in startup_sections:
            section_record = {"name": section["name"], "entries": []}
            for slot in range(section["size"] // 8):
                offset = section["offset"] + slot * 8
                address = section["addr"] + slot * 8
                raw_value = struct.unpack_from("<Q", data, offset)[0]
                slot_relocs = relocs.get(address, [])
                counts["entries"] += 1
                counts["relocations"] += len(slot_relocs)
                record = {
                    "slot": slot,
                    "address": address,
                    "raw_value": raw_value,
                    "relocations": [],
                }
                if len(slot_relocs) > 1:
                    counts["duplicate_relocation"] += 1
                    details["bad"].append({
                        "section": section["name"],
                        "slot": slot,
                        "reason": "multiple-relocations",
                    })
                if not slot_relocs:
                    if raw_value == 0:
                        counts["zero_unrelocated"] += 1
                        details["bad"].append({
                            "section": section["name"],
                            "slot": slot,
                            "reason": "zero-unrelocated",
                        })
                    elif not _in_exec(raw_value, ranges):
                        counts["invalid_target"] += 1
                        details["bad"].append({
                            "section": section["name"],
                            "slot": slot,
                            "reason": "raw-target-outside-exec",
                            "target": raw_value,
                        })
                for relocation in slot_relocs:
                    rtype = relocation["type"]
                    symbol = relocation["symbol"]
                    item = {
                        "type": rtype,
                        "addend": relocation["addend"],
                        "symbol": "" if symbol is None else symbol["name"],
                        "symbol_binding": None if symbol is None else symbol["binding"],
                        "symbol_shndx": None if symbol is None else symbol["shndx"],
                    }
                    record["relocations"].append(item)
                    target_value = None
                    if rtype == R_X86_64_RELATIVE:
                        target_value = relocation["addend"]
                    elif rtype == R_X86_64_IRELATIVE:
                        counts["irelative"] += 1
                        target_value = relocation["addend"]
                    elif rtype in {R_X86_64_64, R_X86_64_GLOB_DAT}:
                        if symbol is None:
                            target_value = relocation["addend"]
                        elif symbol["shndx"] == SHN_UNDEF:
                            if symbol["binding"] == STB_WEAK:
                                counts["undefined_weak"] += 1
                                reason = "undefined-weak"
                            else:
                                counts["undefined_global"] += 1
                                reason = "undefined-global"
                            details["bad"].append({
                                "section": section["name"],
                                "slot": slot,
                                "reason": reason,
                                "symbol": symbol["name"],
                                "addend": relocation["addend"],
                            })
                        else:
                            target_value = symbol["value"] + relocation["addend"]
                    else:
                        counts["unsupported_relocation"] += 1
                        details["bad"].append({
                            "section": section["name"],
                            "slot": slot,
                            "reason": "unsupported-relocation",
                            "type": rtype,
                            "symbol": "" if symbol is None else symbol["name"],
                        })
                    if target_value is not None and not _in_exec(target_value, ranges):
                        counts["invalid_target"] += 1
                        details["bad"].append({
                            "section": section["name"],
                            "slot": slot,
                            "reason": "relocated-target-outside-exec",
                            "type": rtype,
                            "target": target_value,
                            "symbol": "" if symbol is None else symbol["name"],
                        })
                section_record["entries"].append(record)
            details["sections"].append(section_record)

        dynamic = by_name.get(".dynamic")
        if dynamic is not None:
            if dynamic["entsize"] not in {0, DYNAMIC.size} or dynamic["size"] % DYNAMIC.size:
                raise ValueError("invalid ELF dynamic section")
            tags = {}
            for offset in range(dynamic["offset"], dynamic["offset"] + dynamic["size"], DYNAMIC.size):
                tag, value = DYNAMIC.unpack_from(data, offset)
                if tag == DT_NULL:
                    break
                tags.setdefault(tag, []).append(value)
            if len(tags.get(DT_INIT, [])) > 1:
                raise ValueError("duplicate DT_INIT")
            if tags.get(DT_INIT):
                target = tags[DT_INIT][0]
                details["dt_init"] = target
                if not _in_exec(target, ranges):
                    counts["invalid_target"] += 1
                    details["bad"].append({
                        "reason": "dt-init-outside-exec",
                        "target": target,
                    })
            for label, address_tag, size_tag, section_name in (
                ("preinit", DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, ".preinit_array"),
                ("init", DT_INIT_ARRAY, DT_INIT_ARRAYSZ, ".init_array"),
            ):
                addresses = tags.get(address_tag, [])
                sizes = tags.get(size_tag, [])
                if len(addresses) > 1 or len(sizes) > 1:
                    raise ValueError("duplicate dynamic startup array tag")
                if addresses or sizes:
                    if len(addresses) != 1 or len(sizes) != 1:
                        raise ValueError("incomplete dynamic startup array tags")
                    details["dynamic_arrays"][label] = {
                        "address": addresses[0],
                        "size": sizes[0],
                    }
                    section = by_name.get(section_name)
                    if (
                        section is None
                        or addresses[0] != section["addr"]
                        or sizes[0] != section["size"]
                    ):
                        counts["invalid_target"] += 1
                        details["bad"].append({
                            "reason": "dynamic-array-section-mismatch",
                            "array": label,
                        })

        metadata_sha = hashlib.sha256(_canonical(details)).hexdigest()
        verified = not any(
            counts[name]
            for name in (
                "zero_unrelocated",
                "undefined_weak",
                "undefined_global",
                "invalid_target",
                "duplicate_relocation",
                "unsupported_relocation",
            )
        )
        summary = {
            "constructor_elf_type": details["elf_type"],
            "constructor_entry_count": counts["entries"],
            "constructor_relocation_count": counts["relocations"],
            "constructor_zero_unrelocated_count": counts["zero_unrelocated"],
            "constructor_undefined_weak_count": counts["undefined_weak"],
            "constructor_undefined_global_count": counts["undefined_global"],
            "constructor_invalid_target_count": counts["invalid_target"],
            "constructor_duplicate_relocation_count": counts["duplicate_relocation"],
            "constructor_unsupported_relocation_count": counts["unsupported_relocation"],
            "constructor_irelative_count": counts["irelative"],
            "constructor_dt_init_present": details["dt_init"] is not None,
            "constructor_metadata_sha256": metadata_sha,
            "constructor_integrity_verified": verified,
        }
        return {"summary": summary, "details": details}
