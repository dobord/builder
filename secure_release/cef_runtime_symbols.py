"""Bounded final-ELF provider proof; raw nm output never enters public summaries.

Keep the existing nm -a/--defined-only scope, including local definitions.
Consume its complete output and successful exit, not just the first matches.
Names-only unsorted output removes irrelevant formatting/sorting; a bounded
line comparator retains at most the longest required name, even for huge C++
names. The total output/record budgets match the archive inventory family.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

MAX_NM_OUTPUT_BYTES = 2 * 1024**3
MAX_NM_ERROR_BYTES = 16 * 1024**2
MAX_NM_RECORDS = 20_000_000
NM_TIMEOUT_SECONDS = 180
READ_BYTES = 64 * 1024


class _Names:
    """Exact complete-line matching without accumulating unneeded names."""

    def __init__(self, required: frozenset[str]):
        if (not isinstance(required, frozenset) or not 0 < len(required) <= 256
                or any(not isinstance(name, str) or not name.isascii()
                       or not 0 < len(name) <= 128
                       or any(ch.isspace() or ord(ch) < 33 for ch in name)
                       for name in required)):
            raise ValueError("Invalid isolated runtime provider contract")
        self.required = {name.encode("ascii") for name in required}
        self.found: set[bytes] = set()
        self.longest = max(map(len, self.required))
        self.pending = b""
        self.too_long = False
        self.in_line = False
        self.records = 0
        self.bytes = 0
        self.sha256 = hashlib.sha256()

    def feed(self, data: bytes) -> None:
        self.bytes += len(data)
        if self.bytes > MAX_NM_OUTPUT_BYTES:
            raise RuntimeError("nm-output-limit")
        self.sha256.update(data)
        parts = data.split(b"\n")
        for index, part in enumerate(parts):
            if part:
                self.in_line = True
                if not self.too_long:
                    if len(self.pending) + len(part) <= self.longest:
                        self.pending += part
                    else:
                        self.pending = b""
                        self.too_long = True
            if index == len(parts) - 1:
                break
            self.records += 1
            if self.records > MAX_NM_RECORDS:
                raise RuntimeError("nm-record-limit")
            if not self.too_long and self.pending in self.required:
                self.found.add(self.pending)
            self.pending = b""
            self.too_long = False
            self.in_line = False

    def finish(self) -> None:
        # Even a truncated *unrelated* last record is not a complete inventory.
        if self.in_line:
            raise RuntimeError("nm-incomplete-output")


def _kill(process: subprocess.Popen) -> None:
    # Kill the whole isolated tool group, including a child retaining a pipe.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def verify(executable: Path, required: frozenset[str], *,
           report: dict | None = None, stderr_log: Path | None = None) -> int:
    """Return the required count only after EOF, exit zero and every definition.

    report contains only fixed classes, counts, sizes and digests. stderr_log,
    when requested by the worker, is an exclusive runner-local encrypted-log
    input; never copy its content or the command into an exception/summary.
    """
    evidence = report if report is not None else {}
    evidence.update(verified=False, scan_complete=False)
    inventory = _Names(required)
    error_hash = hashlib.sha256()
    error_bytes = 0
    process = None
    error_stream = None
    selector = None
    reason = "inspection-failed"
    try:
        if sys.platform != "linux":
            reason = "native-linux-required"
            raise RuntimeError(reason)
        if (not executable.is_file() or executable.is_symlink()
                or not stat.S_ISREG(executable.stat().st_mode)):
            reason = "executable-missing"
            raise RuntimeError(reason)
        nm = shutil.which("nm")
        if not nm:
            reason = "nm-unavailable"
            raise RuntimeError(reason)
        if stderr_log is not None:
            parent = stderr_log.parent
            if not parent.is_dir() or parent.resolve() != parent.absolute():
                reason = "stderr-parent-invalid"
                raise RuntimeError(reason)
            reason = "stderr-output-exists"
            error_stream = os.fdopen(os.open(stderr_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        with open(nm, "rb") as tool:
            evidence["tool_sha256"] = hashlib.file_digest(tool, "sha256").hexdigest()
        reason = "nm-start-failed"
        deadline = time.monotonic() + NM_TIMEOUT_SECONDS
        process = subprocess.Popen(
            [nm, "-a", "--defined-only", "--no-sort", "--no-demangle",
             "--format=just-symbols", "--", str(executable.absolute())],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C"}, start_new_session=True,
        )
        reason = "nm-read-failed"
        selector = selectors.DefaultSelector()
        for stream, role in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, role)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "nm-timeout"
                raise RuntimeError(reason)
            for event, _ in selector.select(min(0.25, remaining)):
                data = os.read(event.fd, READ_BYTES)
                if not data:
                    selector.unregister(event.fileobj)
                    continue
                if event.data == "stdout":
                    try:
                        inventory.feed(data)
                    except RuntimeError as error:
                        reason = str(error)  # Only the fixed parser classes above.
                        raise
                else:
                    error_bytes += len(data)
                    if error_bytes > MAX_NM_ERROR_BYTES:
                        reason = "nm-stderr-limit"
                        raise RuntimeError(reason)
                    error_hash.update(data)
                    if error_stream is not None:
                        error_stream.write(data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            reason = "nm-timeout"
            raise RuntimeError(reason)
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            reason = "nm-timeout"
            raise RuntimeError(reason) from None
        evidence["returncode"] = code
        if code:
            reason = "nm-exit-failure"
            raise RuntimeError(reason)
        try:
            inventory.finish()
        except RuntimeError as error:
            reason = str(error)
            raise
        evidence["scan_complete"] = True
        if inventory.required - inventory.found:
            reason = "providers-missing"
            raise RuntimeError(reason)
        evidence["verified"] = True
        reason = "verified"
        return len(required)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError("Relocated CEF isolation symbol inspection failed: " + reason) from None
    finally:
        if process is not None:
            if reason != "verified":
                _kill(process)
            if selector is not None:
                selector.close()
            process.stdout.close()
            process.stderr.close()
        if error_stream is not None:
            error_stream.close()
        evidence.update(
            failure_class=reason, stdout_bytes=inventory.bytes,
            stdout_sha256=inventory.sha256.hexdigest(), symbol_records=inventory.records,
            matched_provider_count=len(inventory.found), stderr_bytes=error_bytes,
            stderr_sha256=error_hash.hexdigest(),
        )
