"""Byte-bound installed FFmpeg examples and Xtrans shared inclusion sources.

These are source interfaces intentionally installed by the pinned ports, not
build trees. Preserve all companion files, original package ownership and exact
patched Xtrans bytes. Discovery and SDK-supplied metadata never grant approval.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from . import cef_sdk_example as checked, safeio

POLICY = Path(__file__).resolve().parents[1] / "ci/cef-sdk-source-interfaces.json"
POLICY_SHA256 = "14dce87d5f147f200e08c998632306c7b2614240481ff117aa18522bcf64ab0d"
TRIPLET = "x64-linux-static-release"


def policy() -> dict:
    data = checked.read(POLICY)
    checked.require(hashlib.sha256(data).hexdigest() == POLICY_SHA256,
                    "SDK source-interface policy changed")
    return json.loads(data)


def validate_sources(upstream: Path) -> None:
    """Validate full unmodified acquisition/installation policy before guards."""
    for name, digest in policy()["origins"].items():
        checked.require(checked.blob(checked.read(upstream / name)) == digest,
                        "Pinned FFmpeg/Xtrans installation inputs changed")


def verify(sdk: Path) -> dict:
    """Require both exact directories and unique, versioned vcpkg ownership.

    The port's two reviewed Xtrans patches are included in expected bytes.
    FFmpeg's installed Makefile is Makefile.example, not its build-tree recipe.
    No installed source, manifest or library is rewritten by this check.
    """
    prefix = checked.clean(sdk / "installed" / TRIPLET)
    expected, review = {}, {}
    for package, spec in policy()["packages"].items():
        directory = checked.clean(prefix / spec["directory"])
        checked.require(directory.is_dir() and
                        {p.name for p in directory.iterdir()} == set(spec["files"]),
                        "SDK source-interface directory inventory changed: " + package)
        for name, entry in spec["files"].items():
            data = checked.read(directory / name)
            record = {"size": entry["size"], "sha256": entry["sha256"]}
            checked.require(checked.record(data) == record and checked.blob(data) == entry["blob"],
                            "SDK source-interface bytes changed: " + package + "/" + name)
            member = TRIPLET + "/" + spec["directory"] + "/" + name
            expected[member] = package + "_" + spec["version"] + "_" + TRIPLET + ".list"
            if Path(name).suffix.casefold() in safeio.SOURCE_SUFFIXES:
                review["installed/" + member] = record
    info = checked.clean(sdk / "installed/vcpkg/info")
    checked.require(info.is_dir(), "Missing SDK source-interface owners")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid SDK source-interface owner inventory")
    found, total = set(), 0
    for listing in lists:
        checked.require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*_[^/]+_" +
                                    re.escape(TRIPLET) + r"\.list", listing.name) is not None,
                        "Invalid SDK source-interface owner label")
        data = checked.read(listing)
        total += len(data)
        checked.require(total <= 32 * 1024**2, "SDK source-interface ownership exceeds limit")
        for line in data.decode().splitlines():
            if line in expected:
                checked.require(line not in found and listing.name == expected[line],
                                "SDK source-interface owner changed or duplicated")
                found.add(line)
    checked.require(found == set(expected), "Unowned SDK source-interface file")
    checked.require(len(review) == 29, "Incomplete FFmpeg/Xtrans source-interface review")
    return review
