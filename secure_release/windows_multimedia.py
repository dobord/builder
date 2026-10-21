"""Transport the reviewed Windows FFmpeg samples and static FreeRDP objects.

No arbitrary source/object exemption: exact policy bytes, CMake references,
unique vcpkg ownership and external receipts survive export and relocation.
"""
import hashlib
from pathlib import Path
import zipfile

from . import cef_sdk_objects, cef_sdk_source_interfaces, safeio

TRIPLET = "x64-windows-static-release"


def capture(workspace: Path, installed: Path) -> dict:
    cef_sdk_objects.validate_sources(workspace)
    return cef_sdk_objects.capture(installed, triplet=TRIPLET)


def package(sdk: Path, archive: Path, objects: dict) -> dict:
    sources = cef_sdk_source_interfaces.verify(sdk, triplet=TRIPLET)
    reviewed = cef_sdk_objects.verify(sdk / "installed", objects, triplet=TRIPLET)
    safeio.sdk_zip(sdk, archive, reviewed_interface_sources=sources, reviewed_objects=reviewed)
    return sources


def relocated(sdk: Path, objects: dict, sources: dict) -> None:
    if cef_sdk_source_interfaces.verify(sdk, triplet=TRIPLET) != sources:
        raise ValueError("Windows FFmpeg source interfaces changed in transport")
    cef_sdk_objects.verify(sdk / "installed", objects, triplet=TRIPLET)


def validate_archive_sources(archive: Path, review: dict) -> set[str]:
    """Publisher uses its own pinned bytes, not self-approval from SDK metadata."""
    spec = cef_sdk_source_interfaces.policy()["packages"]["ffmpeg"]
    expected = {"installed/" + TRIPLET + "/" + spec["directory"] + "/" + name:
                {"size": entry["size"], "sha256": entry["sha256"]}
                for name, entry in spec["files"].items()
                if Path(name).suffix.casefold() in safeio.SOURCE_SUFFIXES}
    if safeio._source_review(review, shared_interfaces=True) != expected:
        raise ValueError("Windows FFmpeg source review differs from pinned policy")
    seen = set()
    with zipfile.ZipFile(archive) as sdk:
        for entry in sdk.infolist():
            if Path(entry.filename).suffix.casefold() not in safeio.SOURCE_SUFFIXES:
                continue
            record = expected.get(entry.filename)
            if record is None or entry.filename in seen or entry.file_size != record["size"]:
                raise ValueError("Unexpected Windows SDK implementation source")
            if hashlib.sha256(sdk.read(entry)).hexdigest() != record["sha256"]:
                raise ValueError("Windows FFmpeg source bytes changed")
            seen.add(entry.filename)
    if seen != set(expected):
        raise ValueError("Windows FFmpeg source review is incomplete")
    return seen
