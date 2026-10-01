"""Read-only relocation evidence for rejected CEF constructor input slots.

Only the already-relocated CEF archive subtree is read. Member names from an
LLD map are identifiers, never extraction paths. No constructor is changed or
approved here; symbols and section details stay in encrypted diagnostic JSON.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import struct

HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
RELA = struct.Struct("<QQq")
ARCHIVE = re.compile(r"(?:cef_objects|cef_[0-9]{4}_[0-9a-f]{12})\.a\Z")
MAX_ARCHIVE = 12 * 1024**3
MAX_MEMBER = 128 * 1024**2
MAX_NAMES = 16 * 1024**2
MAX_MEMBERS = 2_000_000
MAX_CANDIDATES = 64
MAX_SLOTS = 1024


def _check(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _regular(path: Path, root: Path) -> Path:
    _check(path.is_absolute() and path.parent == root and path.resolve(strict=True) == path,
           "Constructor archive escaped relocated CEF subtree")
    for part in (path, *path.parents):
        _check(not part.is_symlink(), "Redirected constructor archive")
    _check(path.is_file(), "Missing constructor archive")
    return path


def _members(path: Path, wanted: set[str]):
    """Read GNU regular ar in physical order, including its long-name table."""
    size = path.stat().st_size
    _check(8 <= size <= (MAX_ARCHIVE if path.name == "cef_objects.a" else 1024**3),
           "Constructor archive size outside bounds")
    names = b""
    with path.open("rb") as stream:
        _check(stream.read(8) == b"!<arch>\n", "Expected regular constructor archive")
        index = 0
        while stream.tell() < size:
            header = stream.read(60)
            _check(len(header) == 60 and header[58:] == b"`\n",
                   "Malformed constructor archive header")
            field = header[48:58].strip()
            _check(field.isdigit(), "Invalid constructor member size")
            length = int(field)
            _check(length <= size - stream.tell() - (length & 1),
                   "Truncated constructor archive member")
            index += 1
            _check(index <= MAX_MEMBERS, "Too many constructor archive members")
            raw = header[:16].rstrip(b" ")
            payload = None
            name = None
            if raw == b"//":
                _check(length <= MAX_NAMES, "Constructor ar name table oversized")
                names = stream.read(length)
            elif raw in (b"/", b"/SYM64/"):
                stream.seek(length, os.SEEK_CUR)
            else:
                if raw.startswith(b"/") and raw[1:].isdigit():
                    offset = int(raw[1:])
                    _check(offset < len(names) and (offset == 0 or names[offset-1:offset] == b"\n"),
                           "Invalid constructor long-name offset")
                    end = names.find(b"/\n", offset)
                    _check(end >= 0, "Unterminated constructor archive name")
                    raw = names[offset:end]
                else:
                    _check(raw.endswith(b"/") and not raw.startswith(b"#1/"),
                           "Unsupported constructor archive name")
                    raw = raw[:-1]
                name = raw.decode("utf-8", errors="strict")
                if name in wanted:
                    _check(length <= MAX_MEMBER, "Constructor object exceeds bound")
                    payload = stream.read(length)
                    _check(len(payload) == length, "Truncated constructor object")
                else:
                    stream.seek(length, os.SEEK_CUR)
            if length & 1:
                _check(stream.read(1) == b"\n", "Invalid constructor archive padding")
            if payload is not None:
                yield index, name, payload


def inspect_object(data: bytes, section_name: str, offset: int, size: int,
                   alignment: int) -> dict | None:
    """Describe exactly one mapped slot and all relocations applying to it."""
    _check(len(data) >= HEADER.size, "Truncated constructor ELF object")
    h = HEADER.unpack_from(data)
    _check(h[0][:7] == b"\x7fELF\x02\x01\x01" and h[1:4] == (1, 62, 1),
           "Constructor input must be ELF64 x86-64 ET_REL")
    _check(h[8] == HEADER.size and h[11] == SECTION.size and 0 < h[12] < 65535
           and 0 < h[13] < h[12] and h[6] + h[12]*SECTION.size <= len(data),
           "Invalid constructor ELF section table")
    sections = [SECTION.unpack_from(data, h[6]+i*SECTION.size) for i in range(h[12])]

    def payload(s):
        _check(s[4]+s[5] <= len(data), "Constructor ELF section escapes member")
        return data[s[4]:s[4]+s[5]]

    def string(table, pos):
        _check(0 <= pos < len(table), "Invalid constructor ELF string offset")
        end = table.find(b"\0", pos)
        _check(end >= 0, "Unterminated constructor ELF string")
        return table[pos:end].decode("utf-8", errors="strict")

    names = payload(sections[h[13]])
    section_names = [string(names, s[0]) for s in sections]
    indices = [i for i, name in enumerate(section_names) if name == section_name]
    if not indices:
        return None
    _check(len(indices) == 1, "Ambiguous constructor input section")
    index = indices[0]
    selected = sections[index]
    if (selected[5], selected[8]) != (size, alignment):
        return None
    _check(offset % 8 == 0 and 0 <= offset <= size-8,
           "Mapped constructor offset escapes input section")
    _check(selected[1] == 14, "Constructor input section is not SHT_INIT_ARRAY")

    def groups_for(section_index):
        groups = []
        for group in sections:
            if group[1] != 17:
                continue
            raw = payload(group)
            _check(len(raw) >= 4 and len(raw) % 4 == 0,
                   "Invalid constructor ELF section group")
            values = struct.unpack("<" + "I" * (len(raw)//4), raw)
            _check(all(0 < i < len(sections) for i in values[1:]),
                   "Constructor ELF group index escapes table")
            if section_index not in values[1:]:
                continue
            _check(0 < group[6] < len(sections), "Invalid constructor group symtab")
            table = sections[group[6]]
            _check(table[1] == 2 and table[9] == SYMBOL.size and table[5] % SYMBOL.size == 0
                   and 0 < table[6] < len(sections) and group[7] < table[5]//SYMBOL.size,
                   "Invalid constructor group signature")
            symbol = SYMBOL.unpack_from(payload(table), group[7]*SYMBOL.size)
            groups.append({"flags": values[0], "signature": string(payload(sections[table[6]]), symbol[0]),
                           "signature_binding": symbol[1] >> 4})
        return groups

    slot = payload(selected)[offset:offset+8]
    result = {"member_sha256": hashlib.sha256(data).hexdigest(),
              "section_index": index, "section_type": selected[1],
              "section_flags": selected[2], "raw_value": int.from_bytes(slot, "little"),
              "groups": groups_for(index), "relocations": []}
    for rel in sections:
        if rel[1] not in (4, 9) or rel[7] != index:
            continue
        _check(rel[1] == 4 and rel[9] == RELA.size and rel[5] % RELA.size == 0,
               "Unsupported constructor relocation table")
        _check(0 < rel[6] < len(sections), "Invalid constructor relocation symtab")
        symtab = sections[rel[6]]
        _check(symtab[1] == 2 and symtab[9] == SYMBOL.size and symtab[5] % SYMBOL.size == 0
               and 0 < symtab[6] < len(sections), "Invalid constructor symbol table")
        symbols, strings = payload(symtab), payload(sections[symtab[6]])
        for r_offset, info, addend in RELA.iter_unpack(payload(rel)):
            if not offset <= r_offset < offset+8:
                continue
            sym_index, kind = info >> 32, info & 0xffffffff
            _check(sym_index < len(symbols)//SYMBOL.size,
                   "Constructor relocation symbol escapes table")
            sym = SYMBOL.unpack_from(symbols, sym_index*SYMBOL.size)
            name = string(strings, sym[0]) if sym[0] else ""
            record = {"offset": r_offset, "type": kind, "addend": addend,
                      "symbol": name, "binding": sym[1] >> 4, "symbol_type": sym[1] & 15,
                      "visibility": sym[2] & 3, "shndx": sym[3], "value": sym[4],
                      "symbol_size": sym[5], "target_section": None}
            if 0 < sym[3] < len(sections):
                target = sections[sym[3]]
                record["target_section"] = {"name": section_names[sym[3]],
                    "type": target[1], "flags": target[2], "size": target[5],
                    "alignment": target[8], "groups": groups_for(sym[3])}
            result["relocations"].append(record)
    return result


def inspect_inputs(root: Path, slots: list[dict]) -> dict:
    """Add diagnostic evidence only, restricted to exact relocated CEF paths."""
    _check(len(slots) <= MAX_SLOTS, "Too many rejected constructor slots to trace")
    counts = Counter()
    reports = []
    if not root.exists():
        return {"summary": {"constructor_input_relocations_available": False}, "details": []}
    _check(root.is_absolute() and root.is_dir() and root.resolve(strict=True) == root,
           "Invalid relocated constructor root")
    groups = {}
    for slot in slots:
        if slot["kind"] != "inside-input":
            continue
        item = slot["input"]
        owner = item["owner"]
        if not owner.endswith(")") or "(" not in owner:
            counts["unsupported_owner"] += 1
            continue
        archive_text, member = owner.rsplit("(", 1)
        member = member[:-1]
        archive = Path(archive_text)
        if not ARCHIVE.fullmatch(archive.name):
            counts["unsupported_owner"] += 1
            continue
        _check(member and "/" not in member and "\\" not in member and
               all(ord(c) >= 32 for c in member), "Unsafe constructor member identifier")
        archive = _regular(archive, root)
        groups.setdefault(archive, []).append((member, slot))
    for archive, entries in groups.items():
        before = archive.stat()
        with archive.open("rb") as stream:
            archive_sha = hashlib.file_digest(stream, "sha256").hexdigest()
        matches = {name: [] for name, _ in entries}
        for index, name, payload in _members(archive, set(matches)):
            _check(len(matches[name]) < MAX_CANDIDATES, "Too many same-name constructor members")
            candidate = []
            for member, slot in entries:
                if member == name:
                    item = slot["input"]
                    record = inspect_object(payload, item["section"], slot["offset_in_input"],
                                            item["size"], item["alignment"])
                    if record is not None:
                        candidate.append((slot["slot"], record))
            matches[name].append((index, candidate))
        for member, slot in entries:
            candidates = [{"member_index": index, **record}
                for index, values in matches[member] for slot_index, record in values
                if slot_index == slot["slot"]]
            report = {"section": slot["section"], "slot": slot["slot"],
                      "archive_sha256": archive_sha, "member": member,
                      "candidates": candidates}
            reports.append(report)
            if len(candidates) != 1:
                counts["ambiguous" if candidates else "missing"] += 1
                continue
            counts["matched"] += 1
            relocs = candidates[0]["relocations"]
            if not relocs:
                counts["without_relocation"] += 1
            elif len(relocs) != 1:
                counts["multiple_relocations"] += 1
            for rel in relocs:
                if rel["shndx"] == 0:
                    counts["undefined_weak" if rel["binding"] == 2 else "undefined_other"] += 1
                elif rel["target_section"] is not None:
                    counts["defined_target"] += 1
                    if rel["target_section"]["flags"] & 0x80000000:
                        counts["excluded_target"] += 1
                    if not rel["target_section"]["flags"] & 4:
                        counts["nonexec_target"] += 1
        after = archive.stat()
        _check((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
               "Constructor archive changed during inspection")
    return {"summary": {"constructor_input_relocations_available": True,
        **{"constructor_input_"+key+"_count": counts[key] for key in (
            "matched", "missing", "ambiguous", "unsupported_owner", "without_relocation",
            "multiple_relocations", "undefined_weak", "undefined_other", "defined_target",
            "excluded_target", "nonexec_target")}}, "details": reports}
