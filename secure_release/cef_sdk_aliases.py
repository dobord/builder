"""Materialize reviewed SDK file aliases without following arbitrary links.

libpng's static archive alias is a real linker input. libxcrypt's pkg-config
alias is metadata. Both already have reviewed native/installed policies; bind
their canonical payloads and original vcpkg owners before ZIP and after extract.
A versioned protoc tool additionally requires an external pre-export capture.
The platform manifest is authenticated by the caller, never supplied by the SDK.
No source/archive/metadata bytes or source symlinks are changed by this module.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

from . import cef_frozen_dependencies as frozen
from . import cef_harfbuzz_boundary as boundary
from . import cef_sdk_example as checked
from . import safeio, cef_sdk_protoc

TRIPLET = "x64-linux-static-release"
# Full pinned source installation rules are exercised by the existing native
# alias regressions. New aliases require independent review, not auto-discovery.
ALIASES = {
    "lib/libpng.a": ("libpng16.a", "libpng", "1.6.58"),
    "lib/pkgconfig/libcrypt.pc": ("libxcrypt.pc", "libxcrypt", "4.5.2"),
}


def inventory_links(sdk: Path, diagnostics: Path | None, *, protoc: bool = False) -> None:
    """Inventory ALL nonregular entries before ZIP, without following links.

    #78 did not identify the first rejected link. Preserve a bounded complete
    inventory in the encrypted-only diagnostic tree, so unknown entries are not
    discovered one per full SDK build. Known names alone do not approve content.
    """
    checked.clean(sdk)
    checked.require(sdk.is_dir(), "Missing SDK alias root")
    entries, count = [], 0
    allowed = {"installed/" + TRIPLET + "/" + n for n in ALIASES}
    if protoc:
        allowed.add(safeio.PROTOC_ALIAS)
    bad = False
    for current, directories, filenames in os.walk(sdk, followlinks=False):
        directories.sort(); filenames.sort()
        for label in list(directories) + filenames:
            path = Path(current) / label
            name = path.relative_to(sdk).as_posix()
            safeio.parts(name)
            info = path.lstat()
            count += 1
            checked.require(count <= safeio.MAX_FILES, "SDK alias inventory exceeds file limit")
            redirected = stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            if redirected or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                directory = label in directories
                if directory:
                    directories.remove(label)
                target = os.readlink(path) if path.is_symlink() else None
                checked.require(target is None or len(target) <= safeio.MAX_PATH,
                                "SDK link target exceeds diagnostic limit")
                known = name in allowed and not directory and path.is_symlink()
                bad |= not known
                entries.append({"path": name, "target": target, "directory": directory,
                                "kind": stat.S_IFMT(info.st_mode), "known_name": known})
                checked.require(len(entries) <= 2048, "SDK link inventory exceeds limit")
    if diagnostics is not None:
        diagnostics = checked.clean(diagnostics)
        checked.require(not diagnostics.is_relative_to(sdk.absolute())
                        and not sdk.absolute().is_relative_to(diagnostics),
                        "SDK alias diagnostics overlap exported content")
        diagnostics.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"schema": 1, "kind": "sdk-link-inventory", "files_scanned": count,
                           "entries": entries, "runtime_verified": False}, sort_keys=True).encode()
        fd = os.open(diagnostics, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
    checked.require(not bad, "SDK contains unreviewed links or special files; see encrypted inventory")


def verify(sdk: Path, manifest: Path, platform_sha256: str, *,
           expected: dict | None = None, diagnostics: Path | None = None,
           protoc_review: dict | None = None) -> dict:
    sdk = sdk.absolute()
    value = frozen.manifest_at(manifest, platform_sha256)
    inventory_links(sdk, diagnostics, protoc=protoc_review is not None)
    prefix = checked.clean(sdk / "installed" / TRIPLET)
    review, owners = {}, {}
    for name, (target_name, port, version) in ALIASES.items():
        alias, target = prefix / name, prefix / Path(name).with_name(target_name)
        checked.clean(alias.parent)
        checked.clean(target)
        if name.endswith(".a"):
            checked.require(boundary.verified_archive_alias(alias, prefix, value) == target,
                            "SDK libpng alias lacks qualified canonical archive")
            record = dict(value["files"][target.relative_to(prefix).as_posix()])
        else:
            a = value["files"].get(name)
            b = value["files"].get(target.relative_to(prefix).as_posix())
            checked.require(a is not None and a == b, "Unbound SDK libxcrypt metadata alias")
            if alias.is_symlink():
                checked.require(boundary.verified_metadata_alias(alias, prefix, value),
                                "Unreviewed SDK libxcrypt alias")
            data = checked.read(target)
            checked.require(len(data) <= 65536 and not data.startswith((b"!<arch>", b"!<thin>", b"\x7fELF"))
                            and any(l.startswith(b"Name:") for l in data.splitlines())
                            and any(l.startswith(b"Libs:") for l in data.splitlines()),
                            "SDK metadata alias is not bounded pkg-config text")
            record = checked.record(data)
        full = "installed/" + TRIPLET + "/" + name
        review[full] = {"target": target_name, **record}
        checked.require(safeio._alias_target(sdk, full, review[full]) == target,
                        "Invalid canonical SDK alias input")
        data = safeio._alias_bytes(target, record)
        if not alias.is_symlink():
            checked.require(safeio._alias_bytes(alias, record) == data, "Materialized SDK alias differs")
        for rel in (name, target.relative_to(prefix).as_posix()):
            owners[TRIPLET + "/" + rel] = (port, version)
    # vcpkg's original owning .list must cover both names, not just our review.
    info = checked.clean(sdk / "installed/vcpkg/info")
    checked.require(info.is_dir(), "Missing SDK alias ownership evidence")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid SDK alias owner inventory")
    actual, total = {}, 0
    for listing in lists:
        data = checked.read(listing)
        total += len(data)
        checked.require(total <= 32 * 1024**2, "SDK alias owner evidence exceeds limit")
        for line in data.decode().splitlines():
            if line in owners:
                checked.require(line not in actual, "Duplicate SDK alias owner")
                port, version = owners[line]
                checked.require(re.fullmatch(re.escape(port) + "_" + re.escape(version) + r"(?:#[0-9]+)?_"
                                + re.escape(TRIPLET) + r"\.list", listing.name) is not None,
                                "SDK alias lost its pinned owning package")
                actual[line] = (port, version)
    checked.require(actual == owners, "SDK alias or canonical target is unowned")
    if protoc_review is not None:
        review.update(cef_sdk_protoc.verify(sdk / "installed", protoc_review))
    safeio._alias_review(review)
    if expected is not None:
        checked.require(review == expected, "Relocated SDK alias bytes changed")
    return review
