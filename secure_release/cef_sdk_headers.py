"""Preserve one upstream-installed inclusion header, not arbitrary C source trees.

GLib installs gobjectnotifyqueue.c through install_headers; its consumers
#include it. Pin its public source identity independently of the SDK, then
require the authenticated frozen manifest and GLib's actual vcpkg ownership.
The same exact header must survive ZIP/extraction. No archive is modified.
"""
from __future__ import annotations

from pathlib import Path
import re

from . import cef_frozen_dependencies as frozen
from . import cef_sdk_example as checked

TRIPLET = "x64-linux-static-release"
HEADER = "include/glib-2.0/gobject/gobjectnotifyqueue.c"
HEADER_BLOB = "00266730bfc02c93f8a4fca50cbbc0b70a2239ef"
HEADER_RECORD = {
    "size": 5595,
    "sha256": "7d41807e35ac05d14a275c07e19826a73dc8c3d88d019bf7af4caa76baf8fe4d",
}
# Independent public installation provenance, exercised by the required preflight.
GLIB_VERSION = "2.88.2"
MESON_BLOB = "9690e7c4583ce44525589778b723988977b20a89"
PORT_BLOB = "097adf948d4749743960728f482963b67b67017d"


def verify(sdk: Path, manifest: Path, platform_sha256: str) -> dict:
    """Validate identity and actual owner before packaging and after extraction.

    A captured .c file is NOT automatically approved. This one source-suffixed
    header is independently reviewed; the frozen file record must agree exactly.
    The caller passes its existing pinned platform digest, never an SDK policy.
    """
    inventory = frozen.manifest_at(manifest, platform_sha256)
    checked.require(inventory["files"].get(HEADER) == HEADER_RECORD,
                    "Unreviewed GLib inclusion-header identity")
    modules = inventory.get("modules")
    checked.require(isinstance(modules, dict) and all(
        isinstance(modules.get(n), dict) and modules[n].get("version") == GLIB_VERSION
        for n in ("glib-2.0", "gobject-2.0")), "Unreviewed GLib header version")
    path = checked.clean(sdk / "installed" / TRIPLET / HEADER)
    data = checked.read(path)
    checked.require(checked.record(data) == HEADER_RECORD and checked.blob(data) == HEADER_BLOB,
                    "Installed GLib inclusion-header bytes changed")
    info = checked.clean(sdk / "installed/vcpkg/info")
    checked.require(info.is_dir(), "Missing GLib header ownership records")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid GLib ownership inventory")
    member = TRIPLET + "/" + HEADER
    owners, total = [], 0
    for listing in lists:
        checked.require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*_[^/]+_"
                        + re.escape(TRIPLET) + r"\.list", listing.name) is not None,
                        "Invalid GLib ownership label")
        contents = checked.read(listing)
        total += len(contents)
        checked.require(total <= 32 * 1024**2, "GLib ownership inventory exceeds limit")
        owners.extend(listing.name for line in contents.decode().splitlines() if line == member)
    checked.require(len(owners) == 1 and re.fullmatch(
        r"glib_" + re.escape(GLIB_VERSION) + r"(?:#[0-9]+)?_" + re.escape(TRIPLET) + r"\.list",
        owners[0]) is not None, "GLib inclusion-header lost unique owning package")
    return {"installed/" + member: dict(HEADER_RECORD)}
