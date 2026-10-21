"""Preserve installed FreeRDP OBJECT-library inputs, not build-tree leftovers.

The pinned static channel install exports real CMake OBJECT IMPORTED targets.
Capture their complete object/metadata bytes in the completed installation,
BEFORE export. Require the same external receipt, CMake references and unique
vcpkg ownership before ZIP and after relocation. No CMake text is executed or
rewritten by discovery; no unknown object or arbitrary SDK policy is accepted.
"""
from __future__ import annotations

from pathlib import Path
import re

from . import cef_sdk_example as checked, safeio

TRIPLET = "x64-linux-static-release"
ORIGINS = {
    "ports/freerdp/portfile.cmake": "1490f9e214ec08f15b15417b8770d2c210173da2",
    "ports/freerdp/vcpkg.json": "2fcb445d3a766bce394a2597bd39e02d263bc050",
    "ports/freerdp/cmake-project-include.cmake": "4b8ac592ef3aa6c24d70149c5022468a613e04ad",
    "ports/freerdp/install-layout.patch": "fb8a0fd11b462818de12e749505e69dc45084e14",
    "ports/freerdp/ffmpeg.diff": "60f8fb478ebb5fdddfd84bfb9a4209f10f97962d",
    "ports/freerdp/fix-aom-target.patch": "120e2463bbb3c79dab6e217a4844f290ba721e57",
}
EXPORTS = (
    "share/freerdp-client3/FreeRDP-ClientTargets",
    "share/freerdp-server3/FreeRDP-ServerTargets",
)
OBJECT_ROOT = "lib/freerdp3/objects-Release"
TARGET = r"[A-Za-z0-9_+.-]+"


def validate_sources(registry: Path) -> None:
    """Before source guards modify the pinned port, never from the SDK itself."""
    for name, expected in ORIGINS.items():
        checked.require(checked.blob(checked.read(registry / name)) == expected,
                        "FreeRDP object installation policy changed")


def imported_objects(declarations: str, configuration: str, *, triplet: str = TRIPLET) -> dict[str, list[str]]:
    """Read the limited CMake-generated Release OBJECT export grammar only."""
    # Parse either native line ending; snapshot() still hashes the original
    # unmodified bytes, so this never canonicalizes an ownership/transport proof.
    declarations = declarations.replace("\r\n", "\n")
    configuration = configuration.replace("\r\n", "\n")
    declared = re.findall(r"^add_library\((" + TARGET + r") OBJECT IMPORTED\)$",
                          declarations, re.M)
    checked.require(len(declared) == len(set(declared)) and
                    declarations.count("OBJECT IMPORTED") == len(declared),
                    "Ambiguous FreeRDP object declarations")
    result = {}
    for target, body in re.findall(r"^set_target_properties\((" + TARGET +
                                   r") PROPERTIES\n(.*?)^\s*\)$", configuration, re.M | re.S):
        if "IMPORTED_OBJECTS" not in body:
            continue
        values = re.findall(r'^\s+IMPORTED_OBJECTS_RELEASE "([^"\n]+)"$', body, re.M)
        checked.require(target in declared and target not in result and len(values) == 1
                        and body.count("IMPORTED_OBJECTS") == 1,
                        "Unexpected FreeRDP object configuration")
        paths = []
        for value in values[0].split(";"):
            prefix = "${_IMPORT_PREFIX}/"
            checked.require(value.startswith(prefix), "Non-relocatable FreeRDP object reference")
            path = value[len(prefix):]
            member = "installed/" + triplet + "/" + path
            checked.require(safeio.object_member(member) and
                            path.startswith(OBJECT_ROOT + "/" + target + "/"),
                            "FreeRDP object escapes its imported target")
            checked.require(path not in paths, "Duplicate FreeRDP object reference")
            paths.append(path)
        checks = re.findall(r'^list\(APPEND _cmake_import_check_files_for_' +
                            re.escape(target) + r' (.*?)\s*\)$', configuration, re.M)
        expected = ["${_IMPORT_PREFIX}/" + path for path in paths]
        checked.require(len(checks) == 1 and
                        [item for quoted in re.findall(r'"([^"\n]+)"', checks[0])
                         for item in quoted.split(";")] == expected,
                        "FreeRDP CMake import check differs from its objects")
        result[target] = paths
    checked.require(set(result) == set(declared) and
                    configuration.count("IMPORTED_OBJECTS") == len(result),
                    "Incomplete FreeRDP object export")
    return result


def ownership(installed: Path, required: set[str], *, triplet: str = TRIPLET) -> None:
    info = checked.clean(installed / "vcpkg/info")
    checked.require(info.is_dir(), "Missing FreeRDP object ownership")
    lists = sorted(info.glob("*_" + triplet + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid FreeRDP owner inventory")
    found, total = set(), 0
    for listing in lists:
        data = checked.read_listing(listing); total += len(data)
        checked.require(total <= 32 * 1024**2, "FreeRDP owner inventory exceeds limit")
        for name in data.decode().splitlines():
            if name in required:
                checked.require(name not in found and re.fullmatch(
                    r"freerdp_3\.32\.2(?:#[0-9]+)?_" + re.escape(triplet) + r"\.list",
                    listing.name) is not None, "FreeRDP object or export lost its unique owner")
                found.add(name)
    checked.require(found == required, "Unowned FreeRDP object or CMake export")


def snapshot(installed: Path, *, triplet: str = TRIPLET) -> dict:
    """Bind installed object bytes AND the CMake declarations that require them."""
    checked.require(triplet in {TRIPLET, "x64-windows-static-release"}, "Invalid FreeRDP object triplet")
    prefix = checked.clean(installed / triplet)
    metadata, bindings = {}, {}
    for export in EXPORTS:
        names = (export + ".cmake", export + "-release.cmake")
        data = [checked.read(prefix / name) for name in names]
        for name, content in zip(names, data):
            metadata[name] = checked.record(content)
        targets = imported_objects(*(content.decode() for content in data), triplet=triplet)
        checked.require(not set(bindings).intersection(targets), "Duplicate FreeRDP object target")
        bindings.update(targets)
    checked.require("drdynvc-client" in bindings and 0 < len(bindings) <= 256,
                    "Missing or oversized FreeRDP channel export")
    paths = [name for group in bindings.values() for name in group]
    checked.require(len(paths) == len(set(paths)) and 0 < len(paths) <= 2048,
                    "Duplicate or oversized FreeRDP object closure")
    # An extra object is not approved merely because it appeared in an SDK.
    root = checked.clean(prefix / OBJECT_ROOT)
    checked.require(root.is_dir(), "Missing installed FreeRDP objects")
    actual = {p.relative_to(prefix).as_posix() for p in safeio._regular_files(root)}
    checked.require(actual == set(paths), "Unreferenced or missing installed FreeRDP object")
    objects, total = {}, 0
    for path in sorted(paths):
        file = checked.clean(prefix / path)
        data = safeio._object_bytes(file, platform="windows" if triplet == "x64-windows-static-release" else "linux")
        total += len(data)
        checked.require(total <= safeio.MAX_REVIEWED_OBJECT_TOTAL, "FreeRDP object closure too large")
        objects["installed/" + triplet + "/" + path] = checked.record(data)
    safeio._object_review(objects)
    ownership(installed, {triplet + "/" + p for p in (*paths, *metadata)}, triplet=triplet)
    return dict(schema=1, kind="installed-freerdp-object-closure", origins=dict(ORIGINS),
                objects=objects, metadata=metadata, bindings=bindings)


def capture(installed: Path, *, triplet: str = TRIPLET) -> dict:
    """Called after the pinned install succeeds and before vcpkg raw export."""
    return snapshot(installed, triplet=triplet)


def verify(installed: Path, receipt: dict, *, triplet: str = TRIPLET) -> dict:
    checked.require(isinstance(receipt, dict) and set(receipt) == {
        "schema", "kind", "origins", "objects", "metadata", "bindings"}
        and receipt["schema"] == 1 and receipt["kind"] == "installed-freerdp-object-closure"
        and receipt["origins"] == ORIGINS, "Missing external FreeRDP object receipt")
    safeio._object_review(receipt["objects"])
    checked.require(snapshot(installed, triplet=triplet) == receipt, "FreeRDP object or export bytes changed in transport")
    return receipt["objects"]
