"""Read-only, bounded reproduction of the canonical proxy's config-driven crash.

This is diagnostic evidence only. It never authorizes a failed runtime. The
inferior receives the same executable, config argument, cwd and environment as
normal startup; Xvfb remains outside GDB, not the inferior being debugged.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

MAX_LOG_BYTES = 4 * 1024**2
MAX_CONFIG_BYTES = 1024**2
MAX_EXECUTABLE_BYTES = 12 * 1024**3
TIMEOUT_SECONDS = 60
KILL_GRACE_SECONDS = 5
_PREFIX = "lfc_ui_freerdp_cef_backtrace_"
_BEGIN = "BUILDER_PROXY_GDB_BEGIN"
_END = "BUILDER_PROXY_GDB_END"
_STATE_BEGIN = "BUILDER_PROXY_MACHINE_STATE_BEGIN"
_STATE_END = "BUILDER_PROXY_MACHINE_STATE_END"
_DOMAINS = (
    ("logger", ("lfc::ui::detail::logImpl", "__vfprintf_internal", "vfprintf", "fprintf")),
    ("cef", ("CefExecuteProcess", "CefInitialize", "cef_execute_process", "cef_initialize")),
    ("freerdp", ("pf_server_", "freerdp_", "winpr_")),
    ("cxx-runtime", ("__cxa_", "std::", "libstdc++")),
    ("static-initializer", ("_GLOBAL__sub_I_", "call_init")),
    ("libc", ("__libc_start_main", "libc_start_main")),
)


def _regular(path: Path, limit: int) -> tuple:
    if (not path.is_absolute() or any(ch in str(path) for ch in "\0\r\n")
            or path.resolve(strict=True) != path):
        raise ValueError("Noncanonical proxy diagnostic input")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise ValueError("Invalid proxy diagnostic input")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise ValueError("Proxy diagnostic input changed before read")
        total = 0
        while chunk := stream.read(1024**2):
            total += len(chunk)
            if total > limit:
                raise ValueError("Proxy diagnostic input exceeds budget")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    snapshot = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                             item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if total != info.st_size or snapshot(before) != snapshot(after) or snapshot(after) != snapshot(path.lstat()):
        raise ValueError("Proxy diagnostic input changed during read")
    return snapshot(after), digest.hexdigest()


def command(executable: Path, config: Path, env: dict[str, str]) -> list[str]:
    """Fixed debugger program: paths are inferior argv, never GDB commands."""
    # GDB --args quotes each literal argument for its startup shell. Distro
    # GDB releases before the 2025 no-shell argv fix split whitespace/retain
    # escapes if startup-with-shell is changed after --args processing.
    # Use the supported quoting path, never interpolate paths into "run".
    if (env.get("SHELL", "/bin/sh") not in {
            "/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash"}
            or any(env.get(name) for name in ("ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS"))):
        raise ValueError("Unreviewed proxy debugger shell environment")
    tools = [shutil.which(name, path=env.get("PATH", os.defpath))
             for name in ("xvfb-run", "timeout", "gdb")]
    if any(value is None for value in tools):
        raise ValueError("Proxy diagnostic tools unavailable")
    xvfb, timeout, gdb = tools
    return [
        xvfb, "-a", timeout, "--signal=INT",
        f"--kill-after={KILL_GRACE_SECONDS}s", f"{TIMEOUT_SECONDS}s",
        gdb, "--batch", "--quiet", "--nx", "--nh",
        "-iex", "set auto-load off",
        "-iex", "set debuginfod enabled off",
        "-ex", "set pagination off",
        "-ex", "set confirm off",
        "-eiex", "set startup-with-shell on",
        "-ex", "set disable-randomization off",
        "-ex", "set follow-fork-mode parent",
        "-ex", "set print frame-arguments none",
        "-ex", f"echo {_BEGIN}\\n",
        "-ex", "run",
        "-ex", 'printf "BUILDER_GDB_PC_ZERO=%d\\n", $pc == 0',
        "-ex", "thread apply all bt 32",
        # A stack alone cannot distinguish an ABI mismatch from another fault
        # inside the same CEF entry point. Keep fixed read-only machine-state
        # commands in the same bounded, encrypted diagnostic stream. Never
        # call inferior functions or interpolate paths into debugger commands.
        "-ex", f"echo {_STATE_BEGIN}\\n",
        "-ex", "frame 0",
        "-ex", "info registers rip rdi rsi rdx rcx r8 r9 rsp rbp",
        "-ex", "x/16i $pc",
        "-ex", "disassemble /r",
        "-ex", "frame 1",
        "-ex", "disassemble /r",
        "-ex", "frame 0",
        "-ex", f"echo {_STATE_END}\\n",
        "-ex", "kill",
        "-ex", f"echo {_END}\\n",
        "--args", str(executable), str(config),
    ]


def _capture(command_line: list[str], cwd: Path, env: dict[str, str], sink) -> tuple[int, str]:
    """Cap output while draining; interrupt GDB before the hard group deadline."""
    process = subprocess.Popen(command_line, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True)
    count = 0
    status = "complete"
    deadline = time.monotonic() + TIMEOUT_SECONDS + KILL_GRACE_SECONDS + 5
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    room = MAX_LOG_BYTES - count
                    sink.write(data[:room])
                    count += len(data)
                    if count > MAX_LOG_BYTES:
                        status = "log-oversized"
                        break
                if status != "complete":
                    break
            if status == "complete":
                try:
                    code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    status = "timeout"
                else:
                    return code, "timeout" if code in (124, 137) else "complete"
        return 124 if status == "timeout" else 125, status
    finally:
        # Always reap the owned session, including a writer which outlives GDB.
        # GNU timeout first gives GDB SIGINT so it stops/kills its inferior;
        # this hard cleanup bounds Xvfb and the remaining supervisor processes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()


def capture(executable: Path, cwd: Path, env: dict[str, str], log: Path,
            *, config: Path) -> dict[str, object]:
    if sys.platform != "linux":
        raise ValueError("Proxy runtime backtrace requires Linux")
    if cwd != executable.parent or cwd.resolve(strict=True) != cwd:
        raise ValueError("Proxy backtrace must retain executable working directory")
    executable_before = _regular(executable, MAX_EXECUTABLE_BYTES)
    config_before = _regular(config, MAX_CONFIG_BYTES)
    if not log.is_absolute() or log.parent.resolve(strict=True) != log.parent:
        raise ValueError("Noncanonical proxy diagnostic output")
    argv = command(executable, config, env)
    # Exclusive creation: a diagnostic must not clobber evidence or follow a link.
    fd = os.open(log, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w+b", buffering=0) as sink:
        code, status = _capture(argv, cwd, env.copy(), sink)
        sink.seek(0)
        raw = sink.read(MAX_LOG_BYTES + 1)
        descriptor, named = os.fstat(sink.fileno()), log.lstat()
        if (not stat.S_ISREG(named.st_mode)
                or (descriptor.st_dev, descriptor.st_ino, descriptor.st_size)
                != (named.st_dev, named.st_ino, named.st_size)):
            raise ValueError("Proxy diagnostic output was replaced")
    if (_regular(executable, MAX_EXECUTABLE_BYTES) != executable_before
            or _regular(config, MAX_CONFIG_BYTES) != config_before):
        raise ValueError("Proxy diagnostic inputs changed during reproduction")
    if len(raw) > MAX_LOG_BYTES:
        raise ValueError("Proxy diagnostic output changed after capture")
    text = raw.decode("utf-8", errors="replace")
    frames = [line for line in text.splitlines() if re.match(r"^#[0-9]+\s", line)]
    frames_text = "\n".join(frames)
    segv = re.search(r"^(?:Program|Thread [^\r\n]{1,256}) received signal SIGSEGV\b", text, re.M) is not None
    pc_zero = "BUILDER_GDB_PC_ZERO=1" in text
    complete = status == "complete" and _BEGIN in text and _END in text
    category = status if status != "complete" else "debugger-incomplete"
    if complete:
        category = "not-reproduced"
        if segv and frames:
            category = "unknown"
            if pc_zero and "call_init" in frames_text:
                category = "null-pre-main-init-call"
            else:
                for domain, markers in _DOMAINS:
                    if any(marker in frames_text for marker in markers):
                        category = domain
                        break
    # Report only presence/counts. Registers, instructions and addresses must
    # never leave the encrypted diagnostic stream or become qualification gates.
    machine = text.partition(_STATE_BEGIN + "\n")[2].partition(_STATE_END + "\n")[0]
    instruction_count = len(re.findall(
        r"^\s*(?:=>\s*)?0x[0-9a-fA-F]+\s+(?:<[^>\r\n]+>)?:\s+", machine, re.M
    ))
    machine_complete = bool(
        complete and segv and _STATE_BEGIN + "\n" in text and _STATE_END + "\n" in text
        and re.search(r"^rip\s+0x[0-9a-fA-F]+\b", machine, re.M)
        and instruction_count > 0
    )
    result = {
        "machine_state_complete": machine_complete,
        "machine_state_instruction_count": instruction_count,
        "gdb_returncode": code, "class": category, "capture_status": status,
        "invocation_profile": "proxy-config-xvfb", "inferior_argument_count": 1,
        "config_sha256": config_before[1], "executable_sha256": executable_before[1],
        "inputs_unchanged": True, "complete": complete,
        "sigsegv": segv, "pc_zero": pc_zero, "frame_count": len(frames),
        "frames_sha256": hashlib.sha256(frames_text.encode()).hexdigest(),
        "log_bytes": len(raw), "log_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return {_PREFIX + key: value for key, value in result.items()}