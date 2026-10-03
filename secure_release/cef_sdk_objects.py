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
    "ports/freerdp/portfile.cmake": "8d68d304ce0a117c7237418a3d65fcf1588834f4",
    "ports/freerdp/vcpkg.json": "cde94ab640afd287a20a56b94098f651fc78557c",
    "ports/freerdp/install-layout.patch": "8514875506f93a9370e27cc03618619891b07113",
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


def imported_objects(declarations: str, configuration: str) -> dict[str, list[str]]:
    """Read the limited CMake-generated Release OBJECT export grammar only."""
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
            member = "installed/" + TRIPLET + "/" + path
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


def ownership(installed: Path, required: set[str]) -> None:
    info = checked.clean(installed / "vcpkg/info")
    checked.require(info.is_dir(), "Missing FreeRDP object ownership")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(lists) <= 4096, "Invalid FreeRDP owner inventory")
    found, total = set(), 0
    for listing in lists:
        data = checked.read(listing); total += len(data)
        checked.require(total <= 32 * 1024**2, "FreeRDP owner inventory exceeds limit")
        for name in data.decode().splitlines():
            if name in required:
                checked.require(name not in found and re.fullmatch(
                    r"freerdp_3\.31\.1(?:#[0-9]+)?_" + re.escape(TRIPLET) + r"\.list",
                    listing.name) is not None, "FreeRDP object or export lost its unique owner")
                found.add(name)
    checked.require(found == required, "Unowned FreeRDP object or CMake export")


def snapshot(installed: Path) -> dict:
    """Bind installed object bytes AND the CMake declarations that require them."""
    prefix = checked.clean(installed / TRIPLET)
    metadata, bindings = {}, {}
    for export in EXPORTS:
        names = (export + ".cmake", export + "-release.cmake")
        data = [checked.read(prefix / name) for name in names]
        for name, content in zip(names, data):
            metadata[name] = checked.record(content)
        targets = imported_objects(*(content.decode() for content in data))
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
        data = safeio._object_bytes(file)
        total += len(data)
        checked.require(total <= safeio.MAX_REVIEWED_OBJECT_TOTAL, "FreeRDP object closure too large")
        objects["installed/" + TRIPLET + "/" + path] = checked.record(data)
    safeio._object_review(objects)
    ownership(installed, {TRIPLET + "/" + p for p in (*paths, *metadata)})
    return dict(schema=1, kind="installed-freerdp-object-closure", origins=dict(ORIGINS),
                objects=objects, metadata=metadata, bindings=bindings)


def capture(installed: Path) -> dict:
    """Called after the pinned install succeeds and before vcpkg raw export."""
    return snapshot(installed)


def verify(installed: Path, receipt: dict) -> dict:
    checked.require(isinstance(receipt, dict) and set(receipt) == {
        "schema", "kind", "origins", "objects", "metadata", "bindings"}
        and receipt["schema"] == 1 and receipt["kind"] == "installed-freerdp-object-closure"
        and receipt["origins"] == ORIGINS, "Missing external FreeRDP object receipt")
    safeio._object_review(receipt["objects"])
    checked.require(snapshot(installed) == receipt, "FreeRDP object or export bytes changed in transport")
    return receipt["objects"]
