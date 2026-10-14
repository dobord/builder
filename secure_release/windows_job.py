"""Native Windows ownership without a create/assign/source-execution race.

A trusted isolated Python launcher blocks on a one-byte channel. Assignment to
a non-inherited, kill-on-close Job Object precedes that byte, so approved source
commands and their descendants start inside the job. No breakaway permission is
granted. Nested jobs require Windows 8+ (the supported hosted Windows runners).
The supervisor retains the job after launcher exit and during timeout observers.
"""
from __future__ import annotations
import ctypes
import os
import subprocess
import sys
import time


class BasicLimits(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", ctypes.c_uint32), ("minimum_ws", ctypes.c_size_t),
                ("maximum_ws", ctypes.c_size_t), ("active_limit", ctypes.c_uint32),
                ("affinity", ctypes.c_size_t), ("priority", ctypes.c_uint32),
                ("scheduling", ctypes.c_uint32)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]


class Accounting(ctypes.Structure):
    _fields_ = [("times", ctypes.c_int64 * 4), ("page_faults", ctypes.c_uint32),
                ("total", ctypes.c_uint32), ("active", ctypes.c_uint32),
                ("terminated", ctypes.c_uint32)]


def _kernel():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    handle, pointer, number = ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32
    signatures = {
        "CreateJobObjectW": ([pointer, ctypes.c_wchar_p], handle),
        "SetInformationJobObject": ([handle, ctypes.c_int, pointer, number], ctypes.c_int),
        "AssignProcessToJobObject": ([handle, handle], ctypes.c_int),
        "TerminateJobObject": ([handle, number], ctypes.c_int),
        "QueryInformationJobObject": ([handle, ctypes.c_int, pointer, number, pointer], ctypes.c_int),
        "CloseHandle": ([handle], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(api, name)
        function.argtypes, function.restype = arguments, result
    return api


def _checked(result):
    if not result:
        code = getattr(ctypes, "get_last_error", lambda: 0)()
        raise OSError(code, "Windows process ownership operation failed")
    return result


class Job:
    def __init__(self, api=None):
        self.api = api if api is not None else _kernel()
        self.handle = _checked(self.api.CreateJobObjectW(None, None))
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        try:
            _checked(self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    def assign(self, child):
        # CPython 3.12/3.13 retains this process handle until Popen is released;
        # unlike reopening a PID, it cannot select a recycled process identity.
        _checked(self.api.AssignProcessToJobObject(self.handle, int(child._handle)))

    def active_processes(self):
        state = Accounting()
        _checked(self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(state), ctypes.sizeof(state), None))
        return state.active

    def close(self):
        if self.handle is not None:
            _checked(self.api.CloseHandle(self.handle))
            self.handle = None

    def terminate(self, timeout):
        if self.handle is None:
            return
        error = None
        try:
            _checked(self.api.TerminateJobObject(self.handle, 1))
            deadline = time.monotonic() + timeout
            while self.active_processes():
                if time.monotonic() >= deadline:
                    raise TimeoutError("Windows owned process-tree retirement timed out")
                time.sleep(.01)
        except BaseException as failure:
            error = failure
        finally:
            # Closing also requests job-wide termination if the explicit call
            # or observation failed. A failure is propagated, never waived.
            try:
                self.close()
            except BaseException as failure:
                if error is None:
                    error = failure
        if error is not None:
            raise error


def spawn_owned(args, *, cwd, env, stdout):
    job = Job()  # Non-inheritable job handle exists before launcher creation.
    child = None
    launcher = os.path.abspath(os.path.join(os.path.dirname(__file__), "windows_job_launcher.py"))
    try:
        child = subprocess.Popen([sys.executable, "-I", "-S", launcher, *map(os.fspath, args)],
                                 cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=stdout,
                                 stderr=subprocess.STDOUT, close_fds=True)
        job.assign(child)
        child._builder_job = job
        child.stdin.write(b"G")
        child.stdin.close()  # Only one byte; no output PIPE or unbounded IPC write.
        return child
    except BaseException:
        # A failed assignment cannot launch source. Also handle interruption
        # between assignment and handoff without masking the original failure.
        try:
            job.close()
        except BaseException:
            pass
        if child is not None:
            try:
                if child.poll() is None:
                    child.kill()
            except BaseException:
                pass
            try:
                child.wait(timeout=30)
            except BaseException:
                pass
            if child.stdin is not None:
                try:
                    child.stdin.close()
                except BaseException:
                    pass
        raise
