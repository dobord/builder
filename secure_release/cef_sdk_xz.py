"""Preserve the exact upstream-installed XZ documentation, not arbitrary sources.

XZ 5.8.3 installs doc/examples by default. The pinned liblzma port retains it.
Independently pin all seven companion files, require their unique vcpkg owner,
and approve only the five C examples for transport. Never alter installed files.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

from . import cef_sdk_example as checked, safeio

TRIPLET = "x64-linux-static-release"
DIRECTORY = "share/doc/xz/examples"
VERSION = "5.8.3"
ORIGINS = {
    "ports/liblzma/portfile.cmake": "5516a987e5ec2479b94c929faef97f8ffd05713d",
    "ports/liblzma/vcpkg.json": "c356d5584b69526a5f7451aee1f0e88cc0b399b1",
}
CMAKE_BLOB = "b0894e75765b8e7b321153fdc7fa638cba9b535d"
ARCHIVE_SHA512 = "8fb5e6a13397d259d8ff7484f9b63f8a6752ff1c63e1a4601170ad8175aadefb5126a1cae7f73370bfc6c2a0b4e1c0bad57a58fc5b781d3f7d45e5a483c091cc"
# size, SHA256 and Git blob identity of the COMPLETE public doc/examples tree.
FILES = {
    '00_README.txt': (1037, "f0ddaa731c89d6028f55281229e56b89f32b8c477aba4f52367488f0f42651be",
        "120e1eb7e7c507a8293a060767d60fcfac3babde"),
    '01_compress_easy.c': (9464, "7d4a9186e9121eef5924cadc913f513615de697e3a86b5b01307e8cd54d9e0d0",
        "31bcf928508afd0e63699114cf1fb2e944e7e1d8"),
    '02_decompress.c': (8844, "8c085ac46579444a4f33fbb6a4d480265dc8db43dbb05698fb58c8faf58100ab",
        "a87a5d3ece2ed6edbc6e01e77b6e48a112867e47"),
    '03_compress_custom.c': (4952, "27229e1b873e4ecac4a3f57db932a23e9729930822f7932e618a72f50499c860",
        "80ad189a5e3eab826eb17b4e97ba11b1035bbb53"),
    '04_compress_easy_mt.c': (5145, "304f9b8501e224288cfeb7c89aad34890857dd83874a5b152508f2203661a0c6",
        "c721a6618ae0f13cf63541d59b0a31824fb9e55d"),
    '11_file_info.c': (5314, "1d3e56a70ef81cb36813624b360355561932164a19184b76f5f190734ee92046",
        "caadd98072fbf0ced7e27869a6f32dd90b45d71f"),
    'Makefile': (283, "cc4018f5f9e0d0b6d46e6433cf18205f1437e587b369e35c718c88cf5a200dca",
        "f5b98788ece821f1727ec3644c30f7115bd9148f"),
}


def validate_sources(upstream: Path) -> None:
    """Run after exact checkout checks, before port guards and expensive restore."""
    for name, expected in ORIGINS.items():
        checked.require(checked.blob(checked.read(upstream / name)) == expected,
                        "Pinned XZ documentation installation policy changed")


def verify(sdk: Path) -> dict:
    """Require the entire original doc subtree and unique liblzma ownership."""
    directory = checked.clean(sdk / "installed" / TRIPLET / DIRECTORY)
    checked.require(directory.is_dir() and {p.name for p in directory.iterdir()} == set(FILES),
                    "XZ documentation file inventory changed")
    expected_paths = set()
    review = {}
    for name, (size, digest, source_blob) in FILES.items():
        data = checked.read(directory / name)
        record = {"size": size, "sha256": digest}
        checked.require(checked.record(data) == record and checked.blob(data) == source_blob,
                        "XZ documentation differs from pinned upstream bytes")
        member = TRIPLET + "/" + DIRECTORY + "/" + name
        expected_paths.add(member)
        if Path(name).suffix in safeio.SOURCE_SUFFIXES:
            review["installed/" + member] = record
    info = checked.clean(sdk / "installed/vcpkg/info")
    checked.require(info.is_dir(), "Missing XZ documentation ownership")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid XZ ownership inventory")
    found, total = set(), 0
    for listing in lists:
        data = checked.read(listing)
        total += len(data)
        checked.require(total <= 32 * 1024**2, "XZ ownership inventory exceeds limit")
        for line in data.decode().splitlines():
            if line in expected_paths:
                checked.require(line not in found, "Duplicate XZ documentation owner")
                checked.require(re.fullmatch(
                    "liblzma_" + re.escape(VERSION) + "_" + re.escape(TRIPLET) + r"\.list",
                    listing.name) is not None, "XZ documentation lost its pinned owning package")
                found.add(line)
    checked.require(found == expected_paths, "Unowned XZ documentation file")
    return review


def inventory_sources(sdk: Path, *, examples: dict, headers: dict, docs: dict,
                      aliases: dict, diagnostics: Path) -> int:
    """Record ALL source-suffix entries before ZIP; discovery grants NO approval.

    #80 revealed an upstream documentation source after earlier reviews passed.
    Persist the whole bounded inventory in encrypted-only diagnostics rather
    than finding one unknown source per expensive qualification. No file text
    is recorded and no package/export file is modified.
    """
    sdk = checked.clean(sdk)
    allowed = set(safeio._source_review(examples))
    allowed.update(safeio._source_review(headers, include_headers=True))
    allowed.update(safeio._source_review(docs, documentation=True))
    records = []
    for path in safeio._regular_files(sdk, reviewed_aliases=safeio._alias_review(aliases)):
        if path.suffix.casefold() not in safeio.SOURCE_SUFFIXES:
            continue
        name = path.relative_to(sdk).as_posix()
        records.append({"path": name, "size": path.stat().st_size, "reviewed_name": name in allowed})
        checked.require(len(records) <= 2048, "SDK source inventory exceeds limit")
    diagnostics = checked.clean(diagnostics)
    checked.require(not diagnostics.is_relative_to(sdk) and not sdk.is_relative_to(diagnostics),
                    "SDK source diagnostics overlap exported content")
    diagnostics.parent.mkdir(parents=True, exist_ok=True)
    value = {"schema": 1, "kind": "sdk-source-inventory", "entries": records}
    fd = os.open(diagnostics, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(value, sort_keys=True).encode())
    checked.require(all(r["reviewed_name"] for r in records),
                    "SDK contains unreviewed sources; see encrypted source inventory")
    return len(records)
