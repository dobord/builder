"""Shared release/test build policy; no project names, secrets or credentials."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import shutil

# DO NOT use --clean-after-build: it deletes every top-level downloads file,
# including prefetched private archives needed by later packages in the graph.
INSTALL_FLAGS = ("--binarysource=clear", "--clean-buildtrees-after-build", "--clean-packages-after-build")


def install_command(executable: str, packages: list[str], options: list[str]) -> list[str]:
    if any(arg.split("=", 1)[0] in {"--clean-after-build", "--clean-downloads-after-build", "--head"}
           for arg in [*options, *packages]):
        raise ValueError("unsafe release install option")
    return [executable, "install", *packages, *options, *INSTALL_FLAGS]


def protect_source_archives(workspace: Path, downloads: Path, ports: list[dict]) -> None:
    """Fail closed BEFORE vcpkg_from_git if a prepared source disappears or changes."""
    for port in ports:
        name, revision = port["name"], port["sha"]
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("invalid source archive specification")
        archive = downloads / f"{name}-{revision}.tar.gz"
        if not archive.is_file() or archive.is_symlink():
            raise ValueError("prepared source archive is missing")
        with archive.open("rb") as stream:
            expected = hashlib.file_digest(stream, "sha256").hexdigest()
        portfile = workspace / "ports" / name / "portfile.cmake"
        body = portfile.read_text(encoding="utf-8")
        if "# RELEASE_ARCHIVE_GUARD" in body:
            raise ValueError("source archive guard already installed")
        guard = f'''# RELEASE_ARCHIVE_GUARD: generated locally from authenticated input, not upstream.
set(_release_archive "${{DOWNLOADS}}/{name}-{revision}.tar.gz")
if(NOT EXISTS "${{_release_archive}}")
    message(FATAL_ERROR "RELEASE_SOURCE_ARCHIVE_MISSING")
endif()
file(SHA256 "${{_release_archive}}" _release_archive_sha256)
if(NOT _release_archive_sha256 STREQUAL "{expected}")
    message(FATAL_ERROR "RELEASE_SOURCE_ARCHIVE_MISMATCH")
endif()
unset(_release_archive)
unset(_release_archive_sha256)
'''
        portfile.write_text(guard + body, encoding="utf-8")


def build_environment(original: dict[str, str], downloads: Path, upstream: Path) -> dict[str, str]:
    result = dict(original)
    result.update({"VCPKG_ROOT": str(upstream), "VCPKG_DOWNLOADS": str(downloads),
                   "VCPKG_DISABLE_METRICS": "1", "VCPKG_BINARY_SOURCES": "clear",
                   "VCPKG_MAX_CONCURRENCY": "2", "CMAKE_BUILD_PARALLEL_LEVEL": "2",
                   "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    return result


def copy_export_triplet(sdk: Path, triplets: Path, triplet: str) -> None:
    if not re.fullmatch(r"x64-(?:linux|windows)-static-release", triplet):
        raise ValueError("unexpected release triplet")
    target = sdk / "triplets"
    target.mkdir(exist_ok=True)
    shutil.copyfile(triplets / (triplet + ".cmake"), target / (triplet + ".cmake"))
