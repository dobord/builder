"""Diagnostic entrypoint delegating to the unchanged strict iteration worker.

Install the reviewed static X11 binding immediately BEFORE GN validation, then
install reference-app instrumentation AFTER the successful source/GN check and
BEFORE its compilation slice. The original driver, checkpoint identity,
encryption and success gates remain authoritative. The X11 repair removes a
proved host-shared-library path without widening the runtime allowlist.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from . import cef_smoke_progress, cef_x11_static
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
    x11_identity = {}

    def run(command, **kwargs):
        args = list(map(str, command))
        is_check = (len(args) >= 3 and args[1] == str(recipe / "source_build.py")
                    and args[2] == "check")
        if is_check:
            try:
                sha_index = args.index("--platform-sha256")
                expected = args[sha_index + 1]
            except (ValueError, IndexError) as error:
                raise ValueError("Static X11 repair requires the exact platform identity") from error
            x11_identity.update(cef_x11_static.install(
                source,
                temp / "cef-strict-engine-work/platform-inputs.json",
                temp / "cef-strict-engine-work/target-prefix",
                expected,
            ))
        result = original_run(command, **kwargs)
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
        if Path(actual_logs) != logs:
            raise ValueError("Unexpected smoke diagnostic log directory")
        try:
            value.update(cef_smoke_progress.classify(logs))
            if smoke_identity:
                value["runtime_smoke_fixture_sha256"] = smoke_identity["patched_sha256"]
            if x11_identity:
                value["runtime_x11_backend"] = "static-x11"
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
