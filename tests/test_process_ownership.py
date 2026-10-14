"""Process ownership regressions, with explicit native-Windows-only checks."""
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from secure_release import process, windows_job


class FakeKernel:
    def __init__(self):
        self.events = []
        self.active = [1, 0]

    def CreateJobObjectW(self, security, name):
        self.events.append("job")
        assert security is None and name is None
        return 7

    def SetInformationJobObject(self, handle, kind, pointer, size):
        self.events.append("limits")
        limits = ctypes.cast(pointer, ctypes.POINTER(windows_job.ExtendedLimits)).contents
        assert kind == 9 and limits.basic.flags == 0x2000
        return 1

    def AssignProcessToJobObject(self, job, child):
        self.events.append("assign")
        assert child == 42
        return 1

    def TerminateJobObject(self, handle, code):
        self.events.append("terminate")
        return 1

    def QueryInformationJobObject(self, handle, kind, pointer, size, returned):
        ctypes.cast(pointer, ctypes.POINTER(windows_job.Accounting)).contents.active = self.active.pop(0)
        return 1

    def CloseHandle(self, handle):
        self.events.append("close")
        return 1


class ProcessOwnershipTests(unittest.TestCase):
    def test_source_handoff_occurs_after_job_assignment_and_job_is_retained(self):
        api = FakeKernel()
        constructor = windows_job.Job
        child = Mock()
        child._handle = 42
        child.stdin.write.side_effect = lambda data: api.events.append("handoff") if data == b"G" else self.fail()
        child.stdin.close.side_effect = lambda: api.events.append("stdin-close")
        def launch(*args, **kwargs):
            api.events.append("launcher")
            self.assertEqual(args[0][1:3], ["-I", "-S"])
            self.assertEqual(kwargs["stdin"], subprocess.PIPE)
            self.assertTrue(kwargs["close_fds"])
            return child
        with patch.object(windows_job, "Job", side_effect=lambda: constructor(api)), patch.object(windows_job.subprocess, "Popen", side_effect=launch):
            owned = windows_job.spawn_owned(["PUBLIC_TOOL"], cwd=None, env={}, stdout=subprocess.DEVNULL)
        self.assertIs(owned, child)
        self.assertEqual(api.events, ["job", "limits", "launcher", "assign", "handoff", "stdin-close"])
        self.assertEqual(owned._builder_job.handle, 7)
        owned._builder_job.close()

    def test_assignment_failure_never_sends_handoff_and_reaps_launcher(self):
        api = FakeKernel()
        error = OSError("SYNTHETIC_ASSIGN_FAILURE")
        api.AssignProcessToJobObject = Mock(side_effect=error)
        constructor = windows_job.Job
        child = Mock()
        child._handle = 42
        child.poll.return_value = None
        with patch.object(windows_job, "Job", side_effect=lambda: constructor(api)), patch.object(windows_job.subprocess, "Popen", return_value=child):
            with self.assertRaises(OSError) as caught:
                windows_job.spawn_owned(["PUBLIC_TOOL"], cwd=None, env={}, stdout=subprocess.DEVNULL)
        self.assertIs(caught.exception, error)
        child.stdin.write.assert_not_called()
        child.kill.assert_called_once()
        child.wait.assert_called_once_with(timeout=30)
        self.assertIn("close", api.events)

    def test_job_retires_all_members_before_closing_handle(self):
        api = FakeKernel()
        owned = windows_job.Job(api)
        with patch.object(windows_job.time, "sleep"):
            owned.terminate(timeout=1)
        self.assertEqual(api.active, [])
        self.assertEqual(api.events[-2:], ["terminate", "close"])
        self.assertIsNone(owned.handle)

    def test_job_error_closes_kill_on_close_handle_and_preserves_first_error(self):
        api = FakeKernel()
        owned = windows_job.Job(api)
        error = OSError("SYNTHETIC_TERMINATE_FAILURE")
        api.TerminateJobObject = Mock(side_effect=error)
        with self.assertRaises(OSError) as caught:
            owned.terminate(timeout=1)
        self.assertIs(caught.exception, error)
        self.assertIsNone(owned.handle)

    def test_job_close_failure_does_not_mask_termination_failure(self):
        api = FakeKernel()
        owned = windows_job.Job(api)
        original = OSError("SYNTHETIC_TERMINATE_FAILURE")
        api.TerminateJobObject = Mock(side_effect=original)
        api.CloseHandle = Mock(side_effect=OSError("SYNTHETIC_CLOSE_FAILURE"))
        with self.assertRaises(OSError) as caught:
            owned.terminate(timeout=1)
        self.assertIs(caught.exception, original)
        self.assertEqual(owned.handle, 7)  # Failed close must not pretend success.
        api.CloseHandle = lambda handle: 1
        owned.close()

    def test_windows_x64_struct_layouts(self):
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(windows_job.BasicLimits), 64)
            self.assertEqual(ctypes.sizeof(windows_job.ExtendedLimits), 144)
        self.assertEqual(ctypes.sizeof(windows_job.Accounting), 48)

    def test_trusted_launcher_requires_handoff_and_source_stdin_is_null(self):
        launcher = Path(windows_job.__file__).with_name("windows_job_launcher.py")
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "source-executed"
            code = "import pathlib,sys; assert sys.stdin.read()==''; pathlib.Path(" + repr(str(marker)) + ").write_text('public')"
            command = [sys.executable, "-I", "-S", str(launcher), sys.executable, "-c", code]
            denied = subprocess.run(command, input=b"", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            self.assertEqual(denied.returncode, 125)
            self.assertFalse(marker.exists())
            accepted = subprocess.run(command, input=b"G", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            self.assertEqual(accepted.returncode, 0)
            self.assertTrue(marker.exists())

    def test_legacy_windows_killer_error_still_kills_and_reaps_parent(self):
        for result in (subprocess.TimeoutExpired("PUBLIC_KILLER", 30), OSError("SYNTHETIC"), 1):
            child = Mock()
            child._builder_job = None
            child.poll.return_value = None
            child.wait.return_value = 1
            kwargs = {"side_effect": result} if isinstance(result, BaseException) else {"return_value": Mock(returncode=result)}
            with self.subTest(result=type(result).__name__), patch.object(process.os, "name", "nt"), patch.dict(process.os.environ, {"SystemRoot": "PUBLIC_WINDOWS"}), patch.object(process.subprocess, "run", **kwargs):
                with self.assertRaises(Exception):
                    process.terminate_tree(child)
            child.kill.assert_called_once()
            child.wait.assert_called_once_with(timeout=30)

    def test_owned_job_survives_parent_exit_and_never_uses_pid_lookup(self):
        child = Mock()
        child.poll.return_value = 0
        child.wait.return_value = 0
        child._builder_job = Mock()
        with patch.object(process.os, "name", "nt"), patch.object(process.subprocess, "run") as killer:
            process.terminate_tree(child)
        child._builder_job.terminate.assert_called_once_with(timeout=30)
        child.wait.assert_called_once_with(timeout=30)
        killer.assert_not_called()

    def test_job_termination_error_still_reaps_parent(self):
        child = Mock()
        error = OSError("SYNTHETIC_JOB_FAILURE")
        child._builder_job.terminate.side_effect = error
        with patch.object(process.os, "name", "nt"):
            with self.assertRaises(OSError) as caught:
                process.terminate_tree(child)
        self.assertIs(caught.exception, error)
        child.wait.assert_called_once_with(timeout=30)

    def test_sdk_interruption_preserves_exception_when_retirement_fails(self):
        error = KeyboardInterrupt()
        child = Mock()
        child.wait.side_effect = error
        child.poll.return_value = None
        with tempfile.TemporaryDirectory() as tmp, patch.object(process, "spawn", return_value=child), patch.object(process, "terminate_tree", side_effect=OSError("SYNTHETIC_CLEANUP_FAILURE")) as retire:
            with self.assertRaises(KeyboardInterrupt) as caught:
                process.run(["PUBLIC_TOOL"], Path(tmp) / "command.log", environment={}, timeout=5)
        self.assertIs(caught.exception, error)
        retire.assert_called_once_with(child)

    def test_sdk_poll_error_cannot_replace_wait_error(self):
        error = RuntimeError("SYNTHETIC_WAIT_FAILURE")
        child = Mock()
        child.wait.side_effect = error
        child.poll.side_effect = OSError("SYNTHETIC_POLL_FAILURE")
        with tempfile.TemporaryDirectory() as tmp, patch.object(process, "spawn", return_value=child), patch.object(process, "terminate_tree", side_effect=OSError("SYNTHETIC_CLEANUP_FAILURE")) as retire:
            with self.assertRaises(RuntimeError) as caught:
                process.run(["PUBLIC_TOOL"], Path(tmp) / "command.log", environment={}, timeout=5)
        self.assertIs(caught.exception, error)
        retire.assert_called_once_with(child)


@unittest.skipUnless(os.name == "nt", "requires native Windows Job Objects")
class NativeWindowsOwnershipTests(unittest.TestCase):
    def test_owned_command_can_be_cancelled_before_first_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready = root / "ready"
            code = "import pathlib,time,sys; assert sys.stdin.read()==''; pathlib.Path(" + repr(str(ready)) + ").write_text('ready'); time.sleep(60)"
            with (root / "command.log").open("wb") as log:
                owned = process.spawn([sys.executable, "-c", code], cwd=root,
                                      env=dict(os.environ), stdout=log)
                try:
                    deadline = time.monotonic() + 10
                    while not ready.exists() and time.monotonic() < deadline:
                        if owned.poll() is not None:
                            break
                        time.sleep(.01)
                    self.assertTrue(ready.exists())
                    self.assertGreater(owned._builder_job.active_processes(), 0)
                finally:
                    process.terminate_tree(owned)
                self.assertIsNotNone(owned.returncode)
                self.assertIsNone(owned._builder_job.handle)

    def test_job_retires_grandchild_after_guardian_and_source_parent_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready = root / "ready"
            release = root / "release"
            escaped = root / "escaped"
            child_code = ("import pathlib,time; r=pathlib.Path(" + repr(str(ready)) + "); "
                          "r.write_text('ready'); p=pathlib.Path(" + repr(str(release)) + "); "
                          "deadline=time.monotonic()+15\n"
                          "while not p.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                          "pathlib.Path(" + repr(str(escaped)) + ").write_text('escaped')")
            parent_code = ("import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,'-c',"
                           + repr(child_code) + "]); r=pathlib.Path(" + repr(str(ready)) + "); "
                           "deadline=time.monotonic()+10\n"
                           "while not r.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                           "assert r.exists()")
            with (root / "command.log").open("wb") as log:
                owned = process.spawn([sys.executable, "-c", parent_code], cwd=root,
                                      env=dict(os.environ), stdout=log)
                try:
                    self.assertEqual(owned.wait(timeout=12), 0)
                    self.assertTrue(ready.exists())
                    self.assertGreater(owned._builder_job.active_processes(), 0)
                finally:
                    process.terminate_tree(owned)
                release.write_text("release")
                self.assertFalse(escaped.exists())
                self.assertIsNone(owned._builder_job.handle)
