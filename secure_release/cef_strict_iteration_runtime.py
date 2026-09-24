"""Diagnostic entrypoint delegating to the unchanged strict iteration worker.

Install reviewed static native-link and X11 bindings immediately BEFORE GN
validation, then install reference-app instrumentation AFTER the successful
source/GN check and BEFORE its compilation slice. The original driver,
checkpoint identity, encryption and success gates remain authoritative.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re

from . import cef_elf_evidence, cef_native_link_static, cef_smoke_progress, cef_x11_static
from . import cef_strict_iteration as worker


_MODULE_FAMILY_FIELDS = ("x11", "graphics", "gtk", "cxx", "security", "xml", "audio", "font", "other")


def _module_family(name: str) -> str:
    lower = name.lower()
    if lower.startswith(("libgtk", "libgdk", "libglib", "libgobject", "libgio", "libcairo", "libpango", "libharfbuzz", "libatk", "libatspi", "libepoxy")):
        return "gtk"
    if lower.startswith(("libx11", "libxcb", "libxext", "libxcomposite", "libxdamage", "libxfixes", "libxrandr", "libxi.", "libxrender", "libxtst")):
        return "x11"
    if lower.startswith(("libgl.", "libglx", "libglapi", "libegl", "libgles", "libgbm", "libdrm", "libvulkan", "libwayland", "libxshmfence", "libpciaccess", "swrast_dri", "iris_dri")):
        return "graphics"
    if lower.startswith(("libstdc++", "libgcc_s", "libc++.", "libc++abi", "libunwind")):
        return "cxx"
    if lower.startswith(("libnss", "libnspr", "libssl", "libcrypto")):
        return "security"
    if lower.startswith(("libexpat", "libxml")):
        return "xml"
    if lower.startswith(("libasound", "libpulse")):
        return "audio"
    if lower.startswith(("libfontconfig", "libfreetype")):
        return "font"
    return "other"


def classify_public_runtime_evidence(logs: Path) -> dict:
    # Raw module basenames remain in the existing encrypted diagnostics.
    root = logs / "runtime-progress"
    if not root.is_dir() or root.is_symlink():
        return {}
    rows = []
    for path in sorted(root.glob("smoke-progress-*.json"))[:64]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
            continue
        try:
            row = json.loads(path.read_bytes())
        except (OSError, ValueError):
            continue
        if (not isinstance(row, dict) or row.get("schema") != 1
                or type(row.get("pid")) is not int or row["pid"] <= 0
                or type(row.get("role")) is not int or row["role"] not in range(6)
                or path.name != f"smoke-progress-{row['pid']}.json"):
            continue
        rows.append(row)
    result = {}
    browsers = [row for row in rows if row["role"] == 0]
    if len(browsers) == 1:
        row = browsers[0]
        for key in ("pixel_b", "pixel_g", "pixel_r", "pixel_a"):
            value = row.get(key)
            if type(value) is int and 0 <= value <= 255:
                result["runtime_fixture_" + key] = value
    for role, selected in (("browser", browsers), ("renderer", [row for row in rows if row["role"] == 1])):
        families = {name: set() for name in _MODULE_FAMILY_FIELDS}
        for row in selected:
            path = root / f"smoke-modules-{row['pid']}.txt"
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 128 * 1024:
                continue
            for name in path.read_text(errors="replace").splitlines()[:512]:
                if (re.fullmatch(r"[A-Za-z0-9_.+-]{1,192}", name) and name not in cef_smoke_progress.OS_MODULES):
                    families[_module_family(name)].add(name)
        for family in _MODULE_FAMILY_FIELDS:
            result[f"runtime_{role}_unexpected_{family}_module_count"] = len(families[family])
    return result


@contextmanager
def observed_runtime(module, workspace: Path, temp: Path):
    original_run, original_classify = module.run, module.classify_engine_runtime
    source = temp / "cef-strict-engine-work/download/chromium/src"
    recipe = workspace / "private-vcpkg/.full-cef/vcpkg/ports/cef-static"
    logs = temp / "cef-strict-engine-logs"
    progress = logs / "runtime-progress"
    previous = os.environ.get("CEF_STATIC_SMOKE_PROGRESS_DIR")
    smoke_identity = {}
    native_link_identity = {}
    x11_identity = {}
    elf_identity = {}

    def run(command, **kwargs):
        args = list(map(str, command))
        is_restore = (len(args) >= 3
                      and args[1] == str(recipe.parents[1] / "integration/driver.py")
                      and args[2] == "restore")
        if is_restore:
            # The worker has already authenticated/unsealed this exact package.
            # Restore its actual recipe state before the unchanged driver checks
            # the full identity. Never edit the manifest or ignore a mismatch.
            package = temp / "cef-strict-restored-checkpoint"
            if args.count("--checkpoint") != 1:
                raise ValueError("Unexpected native restore package")
            index = args.index("--checkpoint")
            if index + 1 >= len(args) or args[index + 1] != str(package):
                raise ValueError("Unexpected native restore package")
            cef_native_link_static.prepare_restore(recipe / "source_build.py", package)
        is_check = (len(args) >= 3 and args[1] == str(recipe / "source_build.py")
                    and args[2] == "check")
        if is_check:
            try:
                sha_index = args.index("--platform-sha256")
                expected = args[sha_index + 1]
            except (ValueError, IndexError) as error:
                raise ValueError("Static native-link repair requires the exact platform identity") from error
            native_link_identity.update(cef_native_link_static.install(
                recipe / "source_build.py", source
            ))
            x11_identity.update(cef_x11_static.install(
                source,
                temp / "cef-strict-engine-work/platform-inputs.json",
                temp / "cef-strict-engine-work/target-prefix",
                expected,
            ))
        is_build = (len(args) >= 3 and args[1] == str(recipe / "source_build.py")
                    and args[2] == "build")
        if is_build:
            elf_identity.update(cef_x11_static.audit_native(source))
            if not elf_identity["runtime_native_elf_verified"]:
                # DT_NEEDED basenames are deterministic executable metadata, not
                # log text. Publish only a bounded/sanitized list and fixed family
                # counts so the next repair can target the exact dependency.
                elf_identity.update(cef_elf_evidence.inspect(
                    source,
                    expected_needed=elf_identity["runtime_native_elf_needed_count"],
                    expected_unexpected=elf_identity["runtime_native_elf_unexpected_count"],
                ))
                raise RuntimeError("Strict engine ELF imports non-OS shared libraries")
        result = original_run(command, **kwargs)
        if is_build and result.returncode == 0:
            elf_identity.update(cef_x11_static.audit_native(source))
            if not elf_identity["runtime_native_elf_verified"]:
                elf_identity.update(cef_elf_evidence.inspect(
                    source,
                    expected_needed=elf_identity["runtime_native_elf_needed_count"],
                    expected_unexpected=elf_identity["runtime_native_elf_unexpected_count"],
                ))
                raise RuntimeError("Strict engine ELF changed during runtime verification")
        if is_check and result.returncode == 0:
            if (logs.is_symlink() or progress.is_symlink()
                    or not logs.is_dir()):
                raise ValueError("Invalid smoke progress directory")
            smoke_identity.update(cef_smoke_progress.install(source, recipe / "smoke.c"))
            progress.mkdir(mode=0o700, exist_ok=True)
            progress.chmod(0o700)
        return result

    def classify(actual_logs):
        value = original_classify(actual_logs)
        value.update(elf_identity)
        if native_link_identity:
            value["runtime_expat_backend"] = native_link_identity["expat_backend"]
            value["runtime_unwind_backend"] = native_link_identity["unwind_backend"]
            value["runtime_native_link_source_files_verified"] = native_link_identity["verified_files"]
        if elf_identity and not elf_identity["runtime_native_elf_verified"]:
            value["runtime_failure_category"] = "non-os-elf-dependencies"
        if Path(actual_logs) != logs:
            raise ValueError("Unexpected smoke diagnostic log directory")
        try:
            value.update(cef_smoke_progress.classify(logs))
            value.update(classify_public_runtime_evidence(logs))
            if smoke_identity:
                value["runtime_smoke_fixture_sha256"] = smoke_identity["patched_sha256"]
            if x11_identity:
                value["runtime_x11_backend"] = "static-x11"
                value["runtime_webrtc_x11_static"] = True
                value["runtime_gtk_rendering"] = "cairo-software"
                value["runtime_x11_direct_loader_verified"] = True
                value["runtime_x11_platform_archive_count"] = x11_identity["platform_archives"]
                value["runtime_x11_source_files_verified"] = x11_identity["verified_files"]
        except (OSError, ValueError, KeyError):
            value["runtime_progress_invalid"] = True
        return value

    os.environ["CEF_STATIC_SMOKE_PROGRESS_DIR"] = str(progress)
    module.run, module.classify_engine_runtime = run, classify
    try:
        yield
    finally:
        module.run, module.classify_engine_runtime = original_run, original_classify
        if previous is None:
            os.environ.pop("CEF_STATIC_SMOKE_PROGRESS_DIR", None)
        else:
            os.environ["CEF_STATIC_SMOKE_PROGRESS_DIR"] = previous


def main() -> None:
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    with observed_runtime(worker, workspace, temp):
        worker.main()


if __name__ == "__main__":
    main()
