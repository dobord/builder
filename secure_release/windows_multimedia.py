"""Transport reviewed Windows FFmpeg/XZ samples and static FreeRDP objects.

No arbitrary source/object exemption: exact policy bytes, CMake references,
unique vcpkg ownership and external receipts survive export and relocation.
"""
import hashlib
from pathlib import Path
import zipfile

from . import cef_sdk_objects, cef_sdk_source_interfaces, cef_sdk_xz, safeio

TRIPLET = "x64-windows-static-release"


def capture(workspace: Path, installed: Path, upstream: Path) -> dict:
    cef_sdk_objects.validate_sources(workspace)
    cef_sdk_xz.validate_sources(upstream)
    return cef_sdk_objects.capture(installed, triplet=TRIPLET)


def package(sdk: Path, archive: Path, objects: dict, *, diagnostics: Path | None = None) -> dict:
    sources = cef_sdk_source_interfaces.verify(sdk, triplet=TRIPLET)
    docs = cef_sdk_xz.verify(sdk, triplet=TRIPLET)
    reviewed = cef_sdk_objects.verify(sdk / "installed", objects, triplet=TRIPLET)
    # Inventory all implementation-suffix files together, not one failure per
    # expensive qualification. Inventory is diagnostic only, never approval.
    cef_sdk_xz.inventory_sources(sdk, examples=None, headers=None, docs=docs, aliases=None,
        interfaces=sources, diagnostics=diagnostics or archive.with_suffix(".sources.json"))
    safeio.sdk_zip(sdk, archive, reviewed_interface_sources=sources,
                  reviewed_doc_sources=docs, reviewed_objects=reviewed)
    return {"interfaces": sources, "docs": docs}


def relocated(sdk: Path, objects: dict, sources: dict) -> None:
    current = {"interfaces": cef_sdk_source_interfaces.verify(sdk, triplet=TRIPLET),
               "docs": cef_sdk_xz.verify(sdk, triplet=TRIPLET)}
    if current != sources:
        raise ValueError("Windows source interfaces or XZ documentation changed in transport")
    cef_sdk_objects.verify(sdk / "installed", objects, triplet=TRIPLET)


def validate_archive_sources(archive: Path, review: dict) -> set[str]:
    """Publisher uses its own pinned bytes, not self-approval from SDK metadata."""
    if not isinstance(review, dict) or set(review) != {"interfaces", "docs"}:
        raise ValueError("Missing Windows SDK source review")
    spec = cef_sdk_source_interfaces.policy()["packages"]["ffmpeg"]
    expected = {"installed/" + TRIPLET + "/" + spec["directory"] + "/" + name:
                {"size": entry["size"], "sha256": entry["sha256"]}
                for name, entry in spec["files"].items()
                if Path(name).suffix.casefold() in safeio.SOURCE_SUFFIXES}
    if safeio._source_review(review["interfaces"], shared_interfaces=True) != expected:
        raise ValueError("Windows FFmpeg source review differs from pinned policy")
    docs = {"installed/" + TRIPLET + "/" + cef_sdk_xz.DIRECTORY + "/" + name:
            {"size": record[0], "sha256": record[1]} for name, record in cef_sdk_xz.FILES.items()
            if Path(name).suffix.casefold() in safeio.SOURCE_SUFFIXES}
    if safeio._source_review(review["docs"], documentation=True) != docs:
        raise ValueError("Windows XZ documentation review differs from pinned policy")
    expected.update(docs)
    seen = set()
    with zipfile.ZipFile(archive) as sdk:
        for entry in sdk.infolist():
            if Path(entry.filename).suffix.casefold() not in safeio.SOURCE_SUFFIXES:
                continue
            record = expected.get(entry.filename)
            if record is None or entry.filename in seen or entry.file_size != record["size"]:
                raise ValueError("Unexpected Windows SDK implementation source")
            if hashlib.sha256(sdk.read(entry)).hexdigest() != record["sha256"]:
                raise ValueError("Windows reviewed source bytes changed")
            seen.add(entry.filename)
    if seen != set(expected):
        raise ValueError("Windows SDK source review is incomplete")
    return seen
