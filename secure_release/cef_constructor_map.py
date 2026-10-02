"""Attribute invalid startup slots to LLD inputs without changing the executable.

Map contents and owner paths are diagnostic-only and remain in the encrypted
constructor-audit JSON. Public output contains counts and a digest, never paths
or symbols. This module cannot approve, rewrite or omit a constructor.
"""
from __future__ import annotations

from bisect import bisect_right
import hashlib
import os
from pathlib import Path
import re
import stat

from . import cef_constructor_inputs

MAP_NAME = "cef-consumer-link.map"
# LLD prints demangled symbols in the *whole* image map. A native 1.5 MiB
# ELF can produce over 512 MiB of valid rows. The map is already streamed;
# use the same 2 GiB/20M-record inventory scale as the final nm proof, not
# a captured-string cap. Retained startup inputs have a separate byte bound.
MAX_MAP_BYTES = 2 * 1024**3
MAX_MAP_ROWS = 20_000_000
MAX_INPUT_BYTES = 16 * 1024**2
MAX_MAP_LINE_BYTES = 1024**2
MAX_INPUTS = 1_000_000
STARTUP = frozenset({".init_array", ".preinit_array"})
ROW = re.compile(rb"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9]+) (.*)$")


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def inspect_map(path: Path, sections: list[dict], details: dict) -> dict:
    """Cross-check exact ELF section ranges, then attribute each rejected slot.

    A missing map is distinguishable from a map proving linker padding. Native
    ELF-only callers need not generate a map. Present but malformed/stale maps
    are fatal: their content must never be mistaken for producer evidence.
    """
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("redirected constructor link map")
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {"summary": {"constructor_source_map_available": False}, "details": {}}
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("constructor link map must be a regular file")
    if not 0 < before.st_size <= MAX_MAP_BYTES:
        # Only bounded numeric identity is public, never a map path or symbol.
        raise ValueError(
            f"constructor link map size outside bounds: bytes={before.st_size} "
            f"maximum={MAX_MAP_BYTES}"
        )
    expected = {
        s["name"]: s for s in sections
        if s["name"] in STARTUP or s["name"] in {".text", ".dynamic"}
    }
    found = {}
    inputs = {name: [] for name in STARTUP}
    current = None
    hasher = hashlib.sha256()
    total = rows = input_bytes = 0
    # Refuse a last-component redirect or FIFO swapped in after lstat. Compare
    # both the open descriptor and pathname again before publishing evidence.
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("constructor link map open failed") from None
    with os.fdopen(descriptor, "rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError("constructor link map changed before inspection")
        header = stream.readline(MAX_MAP_LINE_BYTES + 1)
        if (len(header) > MAX_MAP_LINE_BYTES or not header.endswith(b"\n")
                or header.split() != [b"VMA", b"LMA", b"Size", b"Align", b"Out", b"In", b"Symbol"]):
            raise ValueError("unexpected LLD map header")
        hasher.update(header)
        total += len(header)
        while True:
            line = stream.readline(MAX_MAP_LINE_BYTES + 1)
            if not line:
                break
            total += len(line)
            rows += 1
            if (len(line) > MAX_MAP_LINE_BYTES or total > MAX_MAP_BYTES
                    or rows > MAX_MAP_ROWS):
                raise ValueError("constructor link map exceeds bounded inventory")
            if not line.endswith(b"\n"):
                raise ValueError("constructor link map has an incomplete final row")
            hasher.update(line)
            match = ROW.fullmatch(line.rstrip(b"\r\n"))
            if match is None:
                raise ValueError("malformed LLD map row")
            if any(len(match[i]) > 16 for i in (1, 2, 3)) or len(match[4]) > 20:
                raise ValueError("constructor link map numeric field outside bounds")
            vma, lma, size = (int(match[i], 16) for i in (1, 2, 3))
            alignment = int(match[4])
            tail = match[5]
            # LLD separates Out/In/Symbol by 8-character columns. Matching the
            # Out column (not a substring) prevents a source path being treated
            # as a section declaration.
            if tail and not tail[:1].isspace():
                current = tail.decode("utf-8", errors="strict")
                if current in expected:
                    if current in found:
                        raise ValueError("duplicate constructor map output section")
                    section = expected[current]
                    if (vma, size, alignment) != (
                        section["addr"], section["size"], section["align"]
                    ):
                        raise ValueError("constructor map disagrees with final ELF")
                    found[current] = (vma, size, alignment)
                continue
            if current not in STARTUP or not tail.startswith(b"        "):
                continue
            if tail.startswith(b"                "):
                continue  # Symbol rows are not independent input sections.
            source = tail.strip().decode("utf-8", errors="strict")
            if not source.endswith(")") or ":(" not in source:
                raise ValueError("malformed constructor map input section")
            owner, input_section = source.rsplit(":(", 1)
            input_section = input_section[:-1]
            section = expected.get(current)
            if section is None or not owner or not input_section:
                raise ValueError("unbound constructor map input")
            if not (section["addr"] <= vma <= vma + size <= section["addr"] + section["size"]):
                raise ValueError("constructor map input escapes output section")
            if size:
                if size % 8 or (vma - section["addr"]) % 8:
                    raise ValueError("constructor map input is not pointer-aligned")
                input_bytes += len(tail)
                if input_bytes > MAX_INPUT_BYTES:
                    raise ValueError("constructor source inventory byte budget exceeded")
                inputs[current].append({
                    "address": vma, "size": size, "alignment": alignment,
                    "owner": owner, "section": input_section,
                })
                if sum(len(values) for values in inputs.values()) > MAX_INPUTS:
                    raise ValueError("constructor source inventory is oversized")
        # A buffered scan may retain old bytes after an in-place write. File
        # times alone are insufficient (notably st_ctime on Windows). Re-read
        # the same descriptor without Python's read buffer and require exactly
        # the scanned bytes. Never reopen a pathname or keep a whole-map copy.
        os.lseek(stream.fileno(), 0, os.SEEK_SET)
        remaining = before.st_size
        verified_hash = hashlib.sha256()
        while remaining:
            chunk = os.read(stream.fileno(), min(1024**2, remaining))
            if not chunk:
                raise ValueError("constructor link map changed during inspection")
            verified_hash.update(chunk)
            remaining -= len(chunk)
        if os.read(stream.fileno(), 1) or verified_hash.digest() != hasher.digest():
            raise ValueError("constructor link map changed during inspection")
        try:
            after = path.lstat()
        except OSError:
            raise ValueError("constructor link map changed during inspection") from None
        if (total != before.st_size or _identity(after) != _identity(before)
                or _identity(os.fstat(stream.fileno())) != _identity(before)):
            raise ValueError("constructor link map changed during inspection")
    if set(found) != set(expected):
        raise ValueError("constructor map is missing final ELF sections")

    starts = {}
    for name, values in inputs.items():
        values.sort(key=lambda row: row["address"])
        end = -1
        for value in values:
            if value["address"] < end:
                raise ValueError("overlapping constructor map inputs")
            end = value["address"] + value["size"]
        starts[name] = [value["address"] for value in values]
    attributed = []
    inside = padding = 0
    # Addresses come from the already-validated ELF, not arbitrary map names.
    for problem in details["bad"]:
        if problem["reason"] != "zero-unrelocated":
            continue
        name, slot = problem["section"], problem["slot"]
        address = expected[name]["addr"] + slot * 8
        index = bisect_right(starts[name], address) - 1
        value = inputs[name][index] if index >= 0 else None
        record = {"section": name, "slot": slot}
        if value is not None and address + 8 <= value["address"] + value["size"]:
            inside += 1
            record.update({
                "kind": "inside-input", "input": value,
                "offset_in_input": address - value["address"],
            })
        else:
            padding += 1
            record["kind"] = "linker-padding"
            record["preceding_input"] = value
            record["following_input"] = (
                inputs[name][index + 1] if index + 1 < len(inputs[name]) else None
            )
        attributed.append(record)
    relocation_evidence = cef_constructor_inputs.inspect_inputs(
        path.parent.parent / "consumer-sdk/installed/x64-linux-static-release/lib/cef-static",
        attributed,
    )
    return {
        "summary": {
            **relocation_evidence["summary"],
            "constructor_source_map_available": True,
            "constructor_source_map_sha256": hasher.hexdigest(),
            "constructor_source_map_bytes": total,
            "constructor_source_map_rows": rows,
            "constructor_source_map_scan_complete": True,
            "constructor_source_input_count": sum(len(rows) for rows in inputs.values()),
            "constructor_zero_inside_input_count": inside,
            "constructor_zero_linker_padding_count": padding,
        },
        "details": {"inputs": inputs, "zero_slots": attributed,
                    "input_relocations": relocation_evidence["details"]},
    }
