"""Diagnostic entrypoint delegating to the unchanged strict iteration worker.

Install reference-app instrumentation AFTER the worker's successful source/GN
check and BEFORE its compilation slice. The original driver, checkpoint
identity, encryption and success gates remain authoritative. This scoped
adapter avoids modifying the pinned recipe or inferring an engine fix from an
unexplained smoke timeout.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path

from . import cef_smoke_progress
from . import cef_strict_iteration as worker


@contextmanager
def observed_runtime(module, workspace: Path, temp: Path):
    original_run, original_classify = module.run, module.classify_engine_runtime
    source = temp / "cef-strict-engine-work/download/chromium/src"
    recipe = workspace / "private-vcpkg/.full-cef/vcpkg/ports/cef-static"
    logs = temp / "cef-strict-engine-logs"
    progress = logs / "runtime-progress"
    previous = os.environ.get("CEF_STATIC_SMOKE_PROGRESS_DIR")
    identity = {}

    def run(command, **kwargs):
        result = original_run(command, **kwargs)
        args = list(map(str, command))
        if (len(args) >= 3 and args[1] == str(recipe / "source_build.py")
                and args[2] == "check" and result.returncode == 0):
            if (logs.is_symlink() or progress.is_symlink()
                    or not logs.is_dir()):
                raise ValueError("Invalid smoke progress directory")
            identity.update(cef_smoke_progress.install(source, recipe / "smoke.c"))
            progress.mkdir(mode=0o700, exist_ok=True)
            progress.chmod(0o700)
        return result

    def classify(actual_logs):
        value = original_classify(actual_logs)
        if Path(actual_logs) != logs:
            raise ValueError("Unexpected smoke diagnostic log directory")
        try:
            value.update(cef_smoke_progress.classify(logs))
            if identity:
                value["runtime_smoke_fixture_sha256"] = identity["patched_sha256"]
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
