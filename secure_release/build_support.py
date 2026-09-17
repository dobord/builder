"""Shared release/test build policy; no project names, secrets or credentials."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil

# DO NOT use --clean-after-build: it deletes every top-level downloads file,
# including prefetched private archives needed by later packages in the graph.
INSTALL_FLAGS = ("--binarysource=clear", "--clean-buildtrees-after-build", "--clean-packages-after-build")
RELEASE_TRIPLETS = frozenset({"x64-linux-static-release", "x64-windows-static-release"})


def native_host_triplet() -> str:
    """This pipeline builds native x64 SDKs, not cross-compiled host tools."""
    system = {"Linux": "linux", "Windows": "windows"}.get(platform.system())
    if system is None or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("unsupported native release host")
    return f"x64-{system}-static-release"


def native_release_options(options: list[str]) -> list[str]:
    """Pin BOTH roles. Never let host dependencies use a default Debug triplet."""
    result = list(options)
    values = {}
    for key in ("--triplet", "--host-triplet"):
        matches = [arg for arg in result if arg.split("=", 1)[0] == key]
        if len(matches) > 1 or any("=" not in arg for arg in matches):
            raise ValueError("ambiguous release triplet option")
        values[key] = matches[0].split("=", 1)[1] if matches else None
    target = native_host_triplet() if values["--triplet"] is None else values["--triplet"]
    if target not in RELEASE_TRIPLETS or target != native_host_triplet():
        raise ValueError("release target must match the native host")
    if values["--triplet"] is None:
        result.append("--triplet=" + target)
    if values["--host-triplet"] is None:
        result.append("--host-triplet=" + target)
    elif values["--host-triplet"] != target:
        raise ValueError("release host and target triplets must match")
    return result


def install_command(executable: str, packages: list[str], options: list[str]) -> list[str]:
    if (any(arg.split("=", 1)[0] in {"--clean-after-build", "--clean-downloads-after-build", "--head"}
            for arg in [*options, *packages])
            or any(arg.startswith(("-", "@")) or ":" in arg for arg in packages)):
        raise ValueError("unsafe release install option")
    return [executable, "install", *packages, *native_release_options(options), *INSTALL_FLAGS]


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
    # Pin the CLI fallback. CMake gets explicit host/target cache arguments.
    result.update({"VCPKG_ROOT": str(upstream), "VCPKG_DOWNLOADS": str(downloads),
                   "VCPKG_DEFAULT_HOST_TRIPLET": native_host_triplet(),
                   "VCPKG_DISABLE_METRICS": "1", "VCPKG_BINARY_SOURCES": "clear",
                   "VCPKG_MAX_CONCURRENCY": "2", "CMAKE_BUILD_PARALLEL_LEVEL": "2",
                   "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    return result


def copy_export_triplet(sdk: Path, triplets: Path, triplet: str) -> None:
    if triplet not in RELEASE_TRIPLETS:
        raise ValueError("unexpected release triplet")
    target = sdk / "triplets"
    target.mkdir(exist_ok=True)
    shutil.copyfile(triplets / (triplet + ".cmake"), target / (triplet + ".cmake"))


def consumer_configure_command(source: Path, build: Path, sdk: Path, triplet: str) -> list[str]:
    """Use only the exported SDK, with explicit and matching CMake triplet roles."""
    native_release_options(["--triplet=" + triplet])
    return ["cmake", "-S", str(source), "-B", str(build),
            "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
            "-DCMAKE_TOOLCHAIN_FILE=" + str(sdk / "scripts/buildsystems/vcpkg.cmake"),
            "-DVCPKG_TARGET_TRIPLET=" + triplet, "-DVCPKG_HOST_TRIPLET=" + triplet,
            "-DVCPKG_MANIFEST_MODE=OFF"]
