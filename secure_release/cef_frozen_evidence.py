"""Summarize a rejected replay AFTER the authoritative combined worker fails.

This is a diagnostic-only Actions step. It does not run a build, alter any
archive, or change the failed worker result. Symbol names remain encrypted.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from . import cef_frozen_dependencies as replay


def publish_failure(temp: Path) -> bool:
    temp = replay.clean_path(temp)
    path = replay.clean_path(temp / "cef-strict-combined-summary.json")
    if not path.exists():
        return False
    replay.require(path.is_file() and path.stat().st_size <= 1024**2,
                   "Invalid combined summary for diagnostic enrichment")
    value = json.loads(path.read_bytes())
    if (not isinstance(value, dict) or value.get("kind") != "cef-strict-combined-sdk-qualification"
            or value.get("schema") != 1 or value.get("status") != "failed"
            or value.get("failure_stage") != "vcpkg-install"):
        return False
    try:
        fields = replay.mismatch_summary(temp / "cef-strict-combined/qualified-triplets",
                                         value.get("platform_sha256", ""))
    except (OSError, ValueError, TypeError, KeyError):
        fields = {"frozen_symbol_evidence_invalid": True}
    if not fields:
        return False
    value.update(fields)
    fd, name = tempfile.mkstemp(prefix=".cef-failed-summary-", dir=temp)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(replay.canonical(value))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return True


if __name__ == "__main__":
    publish_failure(Path(os.environ["RUNNER_TEMP"]))
