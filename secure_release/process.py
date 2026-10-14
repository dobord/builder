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


def spawn(args, *, cwd, env, stdout):
    """Own Windows descendants before approved source commands can execute."""
    if os.name == "nt":
        from .windows_job import spawn_owned
        return spawn_owned(args, cwd=cwd, env=env, stdout=stdout)
    return subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=stdout, stderr=subprocess.STDOUT, start_new_session=True)


def terminate_tree(process: subprocess.Popen) -> None:
    error = None
    try:
        if os.name == "nt":
            job = getattr(process, "_builder_job", None)
            if job is not None:
                # The job outlives the root process and diagnostic observers.
                job.terminate(timeout=30)
            else:
                # Compatibility for external, unowned Popen instances. This
                # PID lookup cannot guarantee descendants after parent exit.
                killer = os.path.join(os.environ["SystemRoot"], "System32", "taskkill.exe")
                result = subprocess.run([killer, "/PID", str(process.pid), "/T", "/F"],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=30, check=False)
                if result.returncode:
                    raise RuntimeError("unowned Windows process-tree retirement failed")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    except BaseException as failure:
        error = failure
    finally:
        try:
            if os.name == "nt" and process.poll() is None:
                process.kill()
        except BaseException as failure:
            if error is None:
                error = failure
        try:
            process.wait(timeout=30)  # Always attempt bounded reaping, even on error.
        except BaseException as failure:
            if error is None:
                error = failure
    if error is not None:
        raise error


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
            p = spawn(args, cwd=cwd, env=environment, stdout=sink)
        except Exception:
            raise StageFailure(stage, "start") from None
        try:
            while True:
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
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
            # Do not poll outside this protected cleanup path: a poll failure
            # must not replace the supervision exception either.
            try:
                terminate_tree(p)
            except BaseException:
                try:
                    sink.write(b"\nSUPERVISOR_RETIREMENT_FAILED\n")
                except BaseException:
                    pass
            try:
                sink.write(("\nSUPERVISOR " + json.dumps({"stage": stage, "state": "failed", "elapsed_seconds": int(time.monotonic() - start)}) + "\n").encode())
            except BaseException:
                pass
            raise
        if os.name == "nt":
            terminate_tree(p)  # Retire reusable/background nodes on normal exit too.
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
