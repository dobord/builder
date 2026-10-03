"""Bounded Windows CEF diagnostics; never a checkpoint or qualification receipt.

Keep raw text runner-local for the existing encrypted-logs action. The separate
public report contains fixed reason labels and validated Ninja numbers/booleans,
never compiler text, paths, commands, environment values or exception messages.
This module deliberately does not import or modify the build/checkpoint worker.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import stat

CAPTURE_BYTES = 16 * 1024**2
STATUS_BYTES = 16 * 1024
STAGING = "cef-windows-iteration-diagnostics"
PUBLIC_REPORT = "cef-windows-engine-diagnostics.json"
SOURCES = (
    "cef-windows-restore.log",
    "cef-windows-source-prepare.log",
    "cef-windows-engine-slice.log",
    "cef-windows-engine-runtime.log",
    "cef-windows-engine-logs/ninja-slice.log",
    "cef-windows-engine-logs/ninja-slice.json",
    "cef-windows-engine-logs/checkpoint-preflight.json",
    "cef-windows-engine-logs/engine-build-receipt.json",
)
# Labels are constants, not regex captures. Raw diagnostics remain encrypted.
REASONS = (
    ("disk-full", r"no space left on device|not enough space on the disk|disk full"),
    ("out-of-memory", r"out of memory|compiler is out of heap|LLVM ERROR: out of memory"),
    ("compiler-crash", r"PLEASE submit a bug report|clang.*frontend command failed|LLVM ERROR:"),
    ("missing-header", r"fatal error:.*file not found|fatal error C1083:"),
    ("static-assertion", r"error: static assertion failed|error C2338:"),
    ("undeclared-identifier", r"error: use of undeclared identifier|error C2065:"),
    ("missing-member", r"error: no member named|error C2039:"),
    ("no-matching-function", r"error: no matching (?:function|constructor)|error C2665:"),
    ("type-conversion", r"error: (?:cannot|no viable) (?:convert|conversion)|error C2440:"),
    ("warning-as-error", r"\[-Werror(?:,|\])|error C2220:"),
    ("linker-error", r"lld-link: error:|(?:fatal error|error) LNK[0-9]{4}:"),
    ("missing-tool", r"is not recognized as an internal or external command|CreateProcess failed"),
    ("compiler-error", r"(?:fatal )?error:|(?:fatal error|error) C[0-9]{4}:"),
    ("ninja-failed", r"(?:^|\n)FAILED:|ninja: build stopped"),
)


def _checked_path(root: Path, relative: str) -> Path | None:
    """Reject links/junctions in every component, including hard-linked files."""
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {".", ".."} for p in parts):
        raise ValueError("Invalid diagnostic relative path")
    current = root
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return None
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise ValueError("Diagnostic links are not permitted")
        if index < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Invalid diagnostic directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Diagnostic input is not an independent regular file")
    if not current.resolve().is_relative_to(root):
        raise ValueError("Diagnostic input escaped the runner directory")
    return current


def _capture(path: Path, limit: int) -> tuple[bytes, bool]:
    """Seek instead of allocating an entire potentially very large build log."""
    with path.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        if size <= limit:
            return stream.read(limit), False
        head = stream.read(limit // 2)
        stream.seek(max(limit // 2, size - limit // 2))
        tail = stream.read(limit // 2)
    return head + b"\n[diagnostic capture: middle omitted]\n" + tail, True


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate diagnostic JSON field")
        result[key] = value
    return result


def ninja_status(data: bytes) -> dict:
    """Return only the native slice writer's bounded status fields."""
    if len(data) > STATUS_BYTES:
        raise ValueError("Oversized Ninja status")
    value = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(value, dict) or value.get("status") not in {"complete", "checkpoint", "failed"}:
        raise ValueError("Invalid Ninja status")
    code, budget, elapsed = (value.get(k) for k in ("exit_code", "slice_seconds", "elapsed_seconds"))
    if (type(code) is not int or not -(2**31) <= code < 2**32
            or type(budget) is not int or not 1 <= budget <= 10800
            or type(elapsed) not in (int, float)
            or not math.isfinite(elapsed) or not 0 <= elapsed <= 86400
            or type(value.get("timed_out")) is not bool
            or type(value.get("unsafe_stop")) is not bool):
        raise ValueError("Invalid Ninja status types or bounds")
    return {key: value[key] for key in (
        "status", "exit_code", "slice_seconds", "elapsed_seconds", "timed_out", "unsafe_stop",
    )}


def classify(text: str) -> str:
    for reason, pattern in REASONS:
        if re.search(pattern, text, re.I):
            return reason
    return "unclassified"


def collect(temp: Path) -> dict:
    temp = temp.resolve(strict=True)
    staging, public = temp / STAGING, temp / PUBLIC_REPORT
    # No overwriting prior diagnostics, links or partially written output.
    if os.path.lexists(staging) or os.path.lexists(public):
        raise ValueError("Windows diagnostics require fresh output paths")
    inputs = [(relative, _checked_path(temp, relative)) for relative in SOURCES]
    staging.mkdir(mode=0o700)
    report = {
        "schema": 1, "kind": "cef-windows-iteration-diagnostics",
        "qualification_evidence": False,
        "captured_files": 0, "truncated_files": 0,
        "ninja_status_available": False, "ninja_status_valid": False,
        "failure_reason": "unclassified",
    }
    ninja_text = None
    wrapper_text = ""
    for relative, path in inputs:
        if path is None:
            continue
        payload, truncated = _capture(path, CAPTURE_BYTES)
        target = staging / path.name
        with target.open("xb") as stream:
            stream.write(payload)
        report["captured_files"] += 1
        report["truncated_files"] += int(truncated)
        if relative.endswith("/ninja-slice.log"):
            ninja_text = payload.decode("utf-8", errors="replace")
        elif relative == "cef-windows-engine-slice.log":
            wrapper_text = payload.decode("utf-8", errors="replace")
        elif relative.endswith("/ninja-slice.json"):
            report["ninja_status_available"] = True
            try:
                report["ninja"] = ninja_status(payload)
                report["ninja_status_valid"] = True
            except (ValueError, TypeError, OverflowError):
                pass  # Invalid raw status is private evidence, not a public message.
    # The dedicated current Ninja log takes precedence over wrapper/setup text.
    report["failure_reason"] = classify(ninja_text if ninja_text is not None else wrapper_text)
    with public.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
    return report


def main() -> None:
    try:
        report = collect(Path(os.environ["RUNNER_TEMP"]))
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        # Never send raw filesystem exceptions/paths to public Actions output.
        raise SystemExit("CEF_WINDOWS_DIAGNOSTICS_FAILED") from None
    print("CEF_WINDOWS_DIAGNOSTICS_CAPTURED files=" + str(report["captured_files"]))


if __name__ == "__main__":
    main()
