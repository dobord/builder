"""Convert CEF-owned ELF CREL relocations to RELA for the fixed LLD18 consumer.

Only the pinned Chromium llvm-objcopy writes objects. This reader independently
compares every logical relocation and symbol, section metadata and non-relocation
payload before/after. It neither resolves symbols nor edits constructor entries.
CREL decoding follows llvm/Object/ELF.h at Chromium's LLVM commit 53d18800.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

TOOL_SHA256 = "3253aae73aa17b32c40b3a149ddfccae46398fa7a4220bfeb8caa7e59c530b39"
FORMAT = "cef-elf64-crel-to-rela-v1"
CREL = 0x40000014
RELA = struct.Struct("<QQq")
HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
MAX_ARCHIVE = 12 * 1024**3
MAX_MEMBER = 128 * 1024**2
MAX_RECORDS = 2_000_000
MAX_OPTIONS = 32 * 1024**2
MASK64 = (1 << 64) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _feed(hasher, value):
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    hasher.update(len(data).to_bytes(8, "little"))
    hasher.update(data)


def decode_crel(data):
    """Yield exact (offset, symbol index, type, signed addend), never a writer."""
    pos = 0

    def leb(signed=False):
        nonlocal pos
        value = shift = 0
        for _ in range(10):
            require(pos < len(data), "Truncated CEF CREL integer")
            byte = data[pos]
            pos += 1
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                if signed and byte & 64:
                    value -= 1 << shift
                require(-(1 << 63) <= value < (1 << 64), "Oversized CEF CREL integer")
                return value
        raise ValueError("Oversized CEF CREL integer")

    header = leb()
    count, explicit, shift = header >> 3, bool(header & 4), header & 3
    require(count <= MAX_RECORDS and explicit, "Unsupported CEF CREL profile")
    offset = symbol = kind = addend = 0
    for _ in range(count):
        require(pos < len(data), "Truncated CEF CREL record")
        byte = data[pos]
        pos += 1
        delta = byte >> 3
        if byte & 128:
            delta += (leb() << 4) - 16
        offset = (offset + delta) & MASK64
        if byte & 1:
            symbol = (symbol + leb(True)) & 0xffffffff
        if byte & 2:
            kind = (kind + leb(True)) & 0xffffffff
        if byte & 4:
            addend = (addend + leb(True)) & MASK64
        yield ((offset << shift) & MASK64, symbol, kind,
               addend if addend < 1 << 63 else addend - (1 << 64))
    require(pos == len(data), "Trailing CEF CREL payload")


def object_profile(data):
    require(len(data) >= HEADER.size, "Truncated CEF relocation object")
    h = HEADER.unpack_from(data)
    require(h[0][:7] == b"\x7fELF\x02\x01\x01" and h[1:4] == (1, 62, 1),
            "CEF relocation conversion requires ELF64 x86-64 ET_REL")
    require(h[8] == HEADER.size and h[9] == 0 and h[10] == 0 and h[11] == SECTION.size
            and 0 < h[12] < 65535 and 0 < h[13] < h[12]
            and h[6] + h[12]*SECTION.size <= len(data), "Invalid CEF relocation ELF table")
    sections = [SECTION.unpack_from(data, h[6] + i*SECTION.size) for i in range(h[12])]

    def payload(s):
        require(s[4] + s[5] <= len(data), "CEF relocation section escapes object")
        return data[s[4]:s[4]+s[5]]

    def string(table, pos):
        require(0 <= pos < len(table), "Invalid CEF relocation string offset")
        end = table.find(b"\0", pos)
        require(end >= 0, "Unterminated CEF relocation string")
        return table[pos:end].decode("utf-8", errors="strict")

    names = payload(sections[h[13]])
    hasher = hashlib.sha256()
    _feed(hasher, [h[0].hex(), h[1], h[2], h[3], h[4], h[7], h[12], h[13]])
    crel_names = set()
    nonrel_names = set()
    count = crel_count = 0
    for index, s in enumerate(sections[1:], 1):
        name = string(names, s[0])
        kind = s[1]
        if kind == CREL:
            require(re.fullmatch(r"\.crel\.[A-Za-z0-9_.$+\-]+", name) is not None,
                    "Unsupported CEF CREL section name")
            require(s[9] == 1 and not s[2] & 0x802, "Unsupported CEF CREL section flags")
            crel_names.add(name)
            crel_count += 1
        elif kind != 4:
            nonrel_names.add(name)
        logical_kind = 4 if kind == CREL else kind
        _feed(hasher, [index, name, logical_kind, s[2], s[3], s[6], s[7],
                       8 if kind == CREL else s[8], 24 if kind == CREL else s[9]])
        if kind in (CREL, 4):
            require(0 < s[6] < len(sections) and 0 < s[7] < len(sections),
                    "Invalid CEF relocation section links")
            symbols = sections[s[6]]
            require(symbols[1] == 2 and symbols[9] == SYMBOL.size
                    and symbols[5] % SYMBOL.size == 0, "Invalid CEF relocation symbol table")
            raw = payload(s)
            if kind == 4:
                require(s[9] == RELA.size and len(raw) % RELA.size == 0,
                        "Invalid CEF RELA payload")
                records = ((off, info >> 32, info & 0xffffffff, add)
                           for off, info, add in RELA.iter_unpack(raw))
            else:
                records = decode_crel(raw)
            for record in records:
                require(record[1] < symbols[5]//SYMBOL.size,
                        "CEF relocation symbol index escaped table")
                count += 1
                require(count <= MAX_RECORDS, "CEF relocation inventory exceeds bound")
                _feed(hasher, record)
        elif kind == 2:
            require(s[9] == SYMBOL.size and s[5] % SYMBOL.size == 0
                    and 0 < s[6] < len(sections), "Invalid CEF symbol table")
            strings = payload(sections[s[6]])
            for sym in SYMBOL.iter_unpack(payload(s)):
                _feed(hasher, [string(strings, sym[0]), *sym[1:]])
        elif kind == 3:
            # LLVM may repack string tables. Every used string is authenticated
            # above through symbol records and section names; no code lives here.
            payload(s)
        elif kind == 8:
            _feed(hasher, ["nobits", s[5]])
        else:
            _feed(hasher, [s[5], hashlib.sha256(payload(s)).hexdigest()])
    require(not crel_names.intersection(nonrel_names), "Ambiguous CEF CREL section type")
    return {"sha256": hasher.hexdigest(), "names": sorted(crel_names),
            "crel_sections": crel_count, "relocations": count,
            "nonrel_names": nonrel_names}


def archive_profile(path, *, limit):
    require(type(limit) is int and 1024**3 <= limit <= MAX_ARCHIVE,
            "Invalid CEF relocation archive budget")
    require(path.is_file() and not path.is_symlink() and 8 <= path.stat().st_size <= limit,
            "Invalid CEF relocation archive")
    size = path.stat().st_size
    hasher = hashlib.sha256()
    names = b""
    options, nonrel_names = set(), set()
    objects = members = relocations = crel_sections = 0
    with path.open("rb") as stream:
        require(stream.read(8) == b"!<arch>\n", "CEF relocation input is not regular ar")
        while stream.tell() < size:
            header = stream.read(60)
            require(len(header) == 60 and header[58:] == b"`\n", "Malformed CEF ar header")
            field = header[48:58].strip()
            require(field.isdigit(), "Invalid CEF ar member length")
            length = int(field)
            require(length <= size-stream.tell()-(length & 1), "Truncated CEF ar member")
            raw = header[:16].rstrip()
            members += 1
            require(members <= MAX_RECORDS, "CEF ar member inventory exceeds bound")
            if raw in (b"/", b"/SYM64/"):
                stream.seek(length, os.SEEK_CUR)
            elif raw == b"//":
                require(length <= MAX_MEMBER, "CEF ar name table exceeds bound")
                names = stream.read(length)
            else:
                if raw.startswith(b"/") and raw[1:].isdigit():
                    off = int(raw[1:])
                    require(off < len(names) and (off == 0 or names[off-1:off] == b"\n"),
                            "Invalid CEF ar long name")
                    end = names.find(b"/\n", off)
                    require(end >= 0, "Unterminated CEF ar long name")
                    raw = names[off:end]
                else:
                    require(raw.endswith(b"/") and not raw.startswith(b"#1/"),
                            "Unsupported CEF ar name encoding")
                    raw = raw[:-1]
                require(length <= MAX_MEMBER, "CEF relocation object exceeds bound")
                data = stream.read(length)
                _feed(hasher, raw.hex())  # Identifier, never a filesystem path.
                if data.startswith(b"\x7fELF"):
                    profile = object_profile(data)
                    _feed(hasher, profile["sha256"])
                    options.update(profile["names"])
                    nonrel_names.update(profile["nonrel_names"])
                    crel_sections += profile["crel_sections"]
                    relocations += profile["relocations"]
                else:
                    _feed(hasher, hashlib.sha256(data).hexdigest())
                objects += 1
            if length & 1:
                require(stream.read(1) == b"\n", "Malformed CEF ar padding")
    require(not options.intersection(nonrel_names), "Cross-member CEF CREL name collision")
    return {"sha256": hasher.hexdigest(), "names": sorted(options),
            "crel_sections": crel_sections, "relocations": relocations,
            "members": objects}


def install(archives, objcopy):
    """Called after unique CEF ownership proof, before namespace rewriting."""
    result = {"format": FORMAT, "tool_sha256": digest(objcopy), "archives": {}}
    for name, path in archives:
        limit = MAX_ARCHIVE if path.name == "cef_objects.a" else 1024**3
        before = archive_profile(path, limit=limit)
        if not before["crel_sections"]:
            continue
        require(result["tool_sha256"] == TOOL_SHA256, "Unreviewed CEF CREL converter")
        source_sha = digest(path)
        options = "".join("--set-section-type=" + n + "=4\n" for n in before["names"])
        require(len(options.encode("ascii")) <= MAX_OPTIONS, "CEF CREL options exceed bound")
        with tempfile.TemporaryDirectory(prefix=".cef-crel-", dir=path.parent) as temp:
            root = Path(temp)
            args, output = root/"options", root/"converted.a"
            args.write_text(options, encoding="ascii")
            subprocess.run([str(objcopy), "@"+str(args), str(path), str(output)],
                           check=True, timeout=600)
            after = archive_profile(output, limit=limit)
            require(after["crel_sections"] == 0 and after["sha256"] == before["sha256"]
                    and after["members"] == before["members"]
                    and after["relocations"] == before["relocations"],
                    "CEF CREL conversion changed object semantics")
            output.chmod(path.stat().st_mode & 0o777)
            final_sha = digest(output)
            require(final_sha != source_sha and digest(path) == source_sha,
                    "CEF CREL source changed during conversion")
            os.replace(output, path)
        result["archives"][name] = {"source_sha256": source_sha, "sha256": final_sha,
            "semantic_sha256": before["sha256"], "members": before["members"],
            "crel_sections": before["crel_sections"], "relocations": before["relocations"]}
    return result


def verify_receipt(receipt):
    conversion = receipt.get("relocation_compatibility")
    require(isinstance(conversion, dict) and conversion.get("format") == FORMAT
            and conversion.get("tool_sha256") == receipt.get("objcopy_sha256")
            and isinstance(conversion.get("archives"), dict), "Missing CEF RELA receipt")
    for name, item in conversion["archives"].items():
        require(conversion["tool_sha256"] == TOOL_SHA256
                and isinstance(item, dict) and set(item) == {
                    "source_sha256", "sha256", "semantic_sha256", "members",
                    "crel_sections", "relocations"}
                and name in receipt["affected"] and name in receipt["cef_archives"]
                and item["source_sha256"] == receipt["affected"][name]["source_sha256"]
                and type(item["members"]) is int and item["members"] > 0
                and type(item["crel_sections"]) is int and item["crel_sections"] > 0
                and type(item["relocations"]) is int and item["relocations"] >= 0
                and all(isinstance(item[k], str) and re.fullmatch(r"[0-9a-f]{64}", item[k]) for k in
                        ("source_sha256", "sha256", "semantic_sha256")),
                "Invalid CEF RELA transport binding")
