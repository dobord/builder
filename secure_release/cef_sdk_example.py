"""Review the installed canonical CEF/FreeRDP example, never implementation trees.

The pinned port intentionally ships this consumer source. Its exact source,
helper and CMake project must survive packaging/relocation under lfc-ui's own
vcpkg file list. Only the one reviewed .cpp is passed to the ZIP source policy.
No source text or diagnostics are printed; final native consumer gates remain.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from . import safeio

TRIPLET = "x64-linux-static-release"
EXAMPLE = "share/lfc-ui/examples/freerdp-proxy-cef"
PORT_BLOB = "fe777c8d2a1da69eb76a61da813fe0c4ac7c4a17"
# Identities read from the immutable lfc-ui and vcpkg revisions already required
# by combined.main. This is not an allowlist supplied by an untrusted SDK.
ORIGINS = {
    "freerdp_proxy_web_engine_view_cef.cpp": (
        "lfc_ui", "examples/freerdp_proxy_web_engine_view_cef.cpp",
        "5b8cd72bb1c4061d0936890e2d9c0d5ff07c9ced"),
    "freerdp_graphics_mode_args.hpp": (
        "lfc_ui", "examples/freerdp_graphics_mode_args.hpp",
        "6758dacc3e406351e2f96d0fc97e6591eadc2345"),
    "CMakeLists.txt": (
        "registry", "ports/lfc-ui/freerdp-proxy-cef-example.CMakeLists.txt",
        "e74c92e1b78a38dbbe0517412e700d70ec4866f1"),
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def clean(path: Path) -> Path:
    path = path.absolute()
    for parent in (path, *path.parents):
        require(not parent.is_symlink() and not (
            parent.exists() and getattr(parent.lstat(), "st_file_attributes", 0) & 0x400),
            "Redirected SDK example path")
    return path


def read(path: Path) -> bytes:
    path = clean(path)
    require(path.is_file() and safeio.regular(path) and 0 < path.stat().st_size <= 1024**2,
            "Missing or oversized SDK example input")
    with path.open("rb") as stream:
        data = stream.read(1024**2 + 1)
    require(0 < len(data) <= 1024**2 and b"\0" not in data, "Invalid SDK example text")
    data.decode("utf-8")
    return data


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def record(data: bytes) -> dict:
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def capture(lfc_ui: Path, registry: Path) -> dict:
    """Run before source guards modify portfiles; no artifact drives this review."""
    require(blob(read(registry / "ports/lfc-ui/portfile.cmake")) == PORT_BLOB,
            "Pinned lfc-ui example installation policy changed")
    roots = {"lfc_ui": lfc_ui, "registry": registry}
    review = {}
    for name, (owner, source, expected) in ORIGINS.items():
        data = read(roots[owner] / source)
        require(blob(data) == expected, "Pinned canonical SDK example source changed")
        review[name] = record(data)
    return review


def verify(sdk: Path, review: dict) -> dict:
    """Require all three exact files and actual owning .list records, read-only."""
    require(isinstance(review, dict) and set(review) == set(ORIGINS),
            "Incomplete canonical SDK example review")
    prefix = clean(sdk / "installed" / TRIPLET)
    directory = clean(prefix / EXAMPLE)
    require(directory.is_dir() and {p.name for p in directory.iterdir()} == set(ORIGINS),
            "SDK canonical example file inventory changed")
    for name, expected in review.items():
        require(record(read(directory / name)) == expected,
                "SDK canonical example bytes differ from pinned source")
    info = clean(sdk / "installed/vcpkg/info")
    require(info.is_dir(), "Missing SDK package ownership records")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    require(0 < len(lists) <= 4096, "Invalid SDK package ownership inventory")
    expected_paths = {TRIPLET + "/" + EXAMPLE + "/" + name for name in ORIGINS}
    owners = {}
    total = 0
    for listing in lists:
        require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*_[^/]+_" + re.escape(TRIPLET) + r"\.list",
                             listing.name) is not None,
                "Invalid SDK package ownership label")
        data = read(listing)
        total += len(data)
        require(total <= 32 * 1024**2, "SDK ownership evidence exceeds limit")
        for line in data.decode().splitlines():
            if line in expected_paths:
                require(line not in owners, "Duplicate SDK example owner")
                owners[line] = listing.name.split("_", 1)[0]
    require(owners == dict.fromkeys(expected_paths, "lfc-ui"),
            "Canonical SDK example lost lfc-ui ownership")
    return {"installed/" + TRIPLET + "/" + EXAMPLE + "/" + name: dict(expected)
            for name, expected in review.items() if Path(name).suffix in safeio.SOURCE_SUFFIXES}
