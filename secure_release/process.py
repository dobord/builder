"""Quiet subprocess supervision. Public output is restricted to fixed stage labels."""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

STAGES = frozenset({"fetch", "bootstrap", "install", "export", "consumer-configure", "consumer-build", "consumer-test", "preflight", "tool"})


class StageFailure(RuntimeError):
    def __init__(self, stage: str, kind: str, code: int | None = None):
        if stage not in STAGES or kind not in {"exit", "timeout", "start", "interrupted"}:
            raise ValueError("invalid stage failure")
        self.stage, self.kind, self.code = stage, kind, code
        super().__init__(f"stage={stage}; category={kind}; code={code}")


def terminate_tree(process: subprocess.Popen) -> None:
    # Called while the parent is still alive, before killing it loses the PID tree.
    if os.name == "nt":
        killer = str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe")
        try:
            subprocess.run([killer, "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=30, check=False)
        finally:
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=30)


def run(args: list[str], log: Path, *, cwd: Path | None = None,
        environment: dict[str, str], timeout: float, stage: str = "tool",
        public_progress: bool = False, heartbeat: float = 60) -> None:
    if stage not in STAGES or timeout <= 0 or heartbeat <= 0:
        raise ValueError("invalid process policy")
    log.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    if public_progress:
        print(f"Release stage: {stage}", flush=True)
    # Never log argv or environment: fetch may have credentials in its environment.
    with log.open("ab", buffering=0) as sink:
        sink.write(("\nSUPERVISOR " + json.dumps({"stage": stage, "state": "start"}) + "\n").encode())
        try:
            p = subprocess.Popen(args, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=sink, stderr=subprocess.STDOUT,
                                 start_new_session=(os.name != "nt"))
        except Exception:
            raise StageFailure(stage, "start") from None
        try:
            while True:
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    terminate_tree(p)
                    raise StageFailure(stage, "timeout")
                try:
                    code = p.wait(timeout=min(heartbeat, remaining))
                    break
                except subprocess.TimeoutExpired:
                    if public_progress:
                        print(f"Release stage still running: {stage}", flush=True)
            if code:
                raise StageFailure(stage, "exit", code)
        except BaseException:
            if p.poll() is None:
                terminate_tree(p)
            sink.write(("\nSUPERVISOR " + json.dumps({"stage": stage, "state": "failed", "elapsed_seconds": int(time.monotonic() - start)}) + "\n").encode())
            raise
        sink.write(("\nSUPERVISOR " + json.dumps({"stage": stage, "state": "complete", "elapsed_seconds": int(time.monotonic() - start)}) + "\n").encode())


def remove_tree(root: Path) -> None:
    """Retry transient sharing violations; remove readonly files, never follow links."""
    import shutil
    if root.is_symlink() or (root.exists() and getattr(root.lstat(), "st_file_attributes", 0) & 0x400):
        raise ValueError("refusing linked cleanup root")
    def retry_readonly(function, path, exc_info):
        if not isinstance(exc_info[1], PermissionError):
            raise exc_info[1]
        if Path(path).is_symlink():
            Path(path).unlink()
        else:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            function(path)
    for attempt in range(4):
        if not root.exists():
            return
        try:
            shutil.rmtree(root, onerror=retry_readonly)
            return
        except PermissionError:
            if attempt == 3:
                raise
            time.sleep(0.5 * (attempt + 1))
