"""Diagnostic entrypoint delegating to the unchanged strict iteration worker.

Install reviewed static native-link and X11 bindings immediately BEFORE GN
validation, then install reference-app instrumentation AFTER the successful
source/GN check and BEFORE its compilation slice. The original driver,
checkpoint identity, encryption and success gates remain authoritative.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from . import cef_unwind_backtrace
from . import cef_elf_evidence, cef_native_link_static, cef_smoke_progress, cef_x11_static
from . import cef_strict_iteration as worker


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
    backtrace_identity = {}

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
            backtrace_identity.update(cef_unwind_backtrace.install(source))
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
        if backtrace_identity:
            value["runtime_backtrace_backend"] = backtrace_identity["backend"]
            value["runtime_backtrace_source_files_verified"] = backtrace_identity["verified_files"]
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
