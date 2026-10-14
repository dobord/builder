"""Synthetic compiler-probe contracts; no native success is inferred from mocks."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from secure_release import project_ci as ci, project_ci_runner as runner
from secure_release import project_ci_windows as windows


class WindowsCompilerProbeTests(unittest.TestCase):
    def test_signed_recipe_preset_selects_inherited_generator_and_architecture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CMakePresets.json").write_text(json.dumps({"configurePresets": [
                {"name": "host", "generator": "Visual Studio 17 2022", "architecture": "x64"},
                {"name": "native", "inherits": "host"},
                {"name": "mingw", "generator": "MinGW Makefiles"}]}))
            self.assertEqual(windows.configuration(root, "cmake --preset native", {}, ["windows-2022"]),
                             ("Visual Studio 17 2022", "x64"))
            self.assertIsNone(windows.configuration(root, "cmake --preset mingw", {}, ["windows-2022"]))
            self.assertIsNone(windows.configuration(root, "cmake --build build", {}, ["windows-2022"]))

    def test_default_generator_is_scoped_to_reviewed_windows_2022_host(self):
        self.assertEqual(windows.configuration(Path("."), "cmake -S . -B build", {}, ["windows-2022"]),
                         ("Visual Studio 17 2022", None))
        self.assertIsNone(windows.configuration(Path("."), "cmake -S . -B build -G Ninja", {}, ["windows-2022"]))
        self.assertIsNone(windows.configuration(Path("."), "cmake -S . -B build", {}, ["ubuntu-24.04"]))

    def test_cyclic_presets_are_rejected_without_subprocess_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "CMakePresets.json").write_text(json.dumps({"configurePresets": [
                {"name": "native", "inherits": "native"}]}))
            with self.assertRaises(ValueError), patch.object(ci, "quiet") as execute:
                windows.configuration(root, "cmake --preset native", {}, ["windows-2022"])
            execute.assert_not_called()

    def test_preset_count_and_parent_fanout_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "CMakePresets.json"
            cases = [
                [{"name": f"preset-{index}"} for index in range(257)],
                [{"name": "native", "inherits": ["parent"] * 33}, {"name": "parent"}],
                [{"name": "native"}, {"name": "native"}],
            ]
            for entries in cases:
                with self.subTest(count=len(entries)):
                    path.write_text(json.dumps({"configurePresets": entries}))
                    with self.assertRaises(ValueError):
                        windows.configuration(root, "cmake --preset native", {}, ["windows-2022"])

    def test_timeout_snapshot_queries_only_process_identity_and_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(ci, "quiet", return_value=0) as execute:
            root = Path(tmp)
            windows._snapshot(root, {"PATH": "PUBLIC_TOOLS"}, 123, time.monotonic() + 200)
            command = execute.call_args.args[0][-1]
            self.assertIn("Name,ProcessId,ParentProcessId", command)
            self.assertNotIn("CommandLine", command)
            self.assertNotIn("GetOwner", command)
            self.assertNotIn("Env:", command)
            self.assertLessEqual(execute.call_args.kwargs["timeout"], 5)
            self.assertEqual(json.loads((root / "parent.json").read_text()), {"pid": 123})

    def test_timeout_status_is_retained_and_primary_failure_remains_fatal(self):
        def fail(*args, **kwargs):
            raise ValueError("private subprocess timed out")
        with tempfile.TemporaryDirectory() as tmp, patch.object(windows.shutil, "which", return_value="PUBLIC_CMAKE"), patch.object(windows.os, "environ", {}), patch.object(ci, "quiet", side_effect=fail):
            root = Path(tmp) / "probe"
            with self.assertRaisesRegex(ValueError, "Windows compiler initialization probe failed"):
                windows.probe(root, {"PATH": "PUBLIC_TOOLS"}, ("Visual Studio 17 2022", None), time.monotonic() + 600)
            summary = json.loads((root / "summary.json").read_text())
            self.assertEqual(summary["cases"][0], {"case": "primary", "status": "timeout"})

    def test_healthy_probe_is_one_command_and_does_not_mutate_recipe_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            environment = {"PATH": "PUBLIC_TOOLS", "GH_TOKEN": "SYNTHETIC_SECRET", "GITHUB_ENV": "PUBLIC_CHANNEL"}
            original = dict(environment)
            with patch.object(windows.shutil, "which", return_value="C:/Public Tools/cmake.exe"), patch.object(ci, "quiet", return_value=0) as execute:
                windows.probe(work / "probe", environment, ("Visual Studio 17 2022", "x64"), time.monotonic() + 600)
            execute.assert_called_once()
            passed = execute.call_args.args[2]
            self.assertNotIn("GH_TOKEN", passed)
            self.assertNotIn("GITHUB_ENV", passed)
            self.assertEqual(environment, original)
            self.assertLessEqual(execute.call_args.kwargs["timeout"], 90)
            self.assertTrue((work / "probe/summary.json").is_file())

    def test_successful_control_does_not_waive_failed_primary_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            console = io.StringIO()
            original = {"WINDIR": "PUBLIC_WINDOWS", "GH_TOKEN": "SYNTHETIC_SECRET"}
            with patch.object(windows.shutil, "which", return_value="C:/Public Tools/cmake.exe"), patch.object(windows.os, "environ", original), patch.object(ci, "quiet", side_effect=[1, 0, 0, 0, 0]) as execute, contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                with self.assertRaisesRegex(ValueError, "Windows compiler initialization probe failed"):
                    windows.probe(work / "probe", {"PATH": "PUBLIC_TOOLS"}, ("Visual Studio 17 2022", "x64"), time.monotonic() + 600)
            self.assertEqual(console.getvalue(), "")
            for call in execute.call_args_list:
                self.assertNotIn("GH_TOKEN", call.args[2])
            summary = json.loads((work / "probe/summary.json").read_text())
            self.assertEqual(summary["cases"][0]["status"], "failure")
            self.assertTrue(any(case["status"] == "success" for case in summary["cases"][1:]))

    def test_failure_budget_stops_controls_before_lane_deadline(self):
        clock = [0]
        def finish_primary(*args, **kwargs):
            clock[0] = 299
            return 1
        with tempfile.TemporaryDirectory() as tmp, patch.object(windows.time, "monotonic", side_effect=lambda: clock[0]), patch.object(windows.shutil, "which", return_value="PUBLIC_CMAKE"), patch.object(ci, "quiet", side_effect=finish_primary) as execute:
            with self.assertRaisesRegex(ValueError, "Windows compiler initialization probe failed"):
                windows.probe(Path(tmp) / "probe", {"PATH": "PUBLIC_TOOLS"}, ("Visual Studio 17 2022", "x64"), 600)
            execute.assert_called_once()

    def test_runner_gates_only_windows_and_caches_healthy_configuration(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(windows, "probe") as smoke:
            done = set()
            with patch.object(windows, "configuration", return_value=("Visual Studio 17 2022", "x64")):
                for index in range(2):
                    runner.windows_preflight(Path(tmp), Path(tmp), {}, "cmake -S .", ["windows-2022"],
                                             "Windows", "pwsh", 600, index, done)
                runner.windows_preflight(Path(tmp), Path(tmp), {}, "cmake -S .", ["ubuntu-24.04"],
                                         "Linux", "bash", 600, 2, done)
            smoke.assert_called_once()
            self.assertEqual(done, {("Visual Studio 17 2022", "x64")})

    def test_failed_preflight_is_not_cached(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(windows, "configuration", return_value=("Visual Studio 17 2022", None)), patch.object(windows, "probe", side_effect=ValueError("SYNTHETIC_FAILURE")):
            done = set()
            with self.assertRaises(ValueError):
                runner.windows_preflight(Path(tmp), Path(tmp), {}, "cmake -S .", ["windows-2022"],
                                         "Windows", "pwsh", 600, 0, done)
            self.assertFalse(done)

    def test_preflight_failure_prevents_recipe_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "project-ci"
            work.mkdir()
            (work / "request.json").write_text('{"suite":"release","source_sha":"synthetic","source":"dobord/synthetic","pr":0,"schema":2}')
            lane = {"id": "synthetic", "profile": "ci", "matrix": {}, "runner": ["windows-2022"],
                    "job": {"steps": [{"run": "cmake -S . -B build", "shell": "pwsh"}]}}
            values = {"GITHUB_WORKSPACE": str(root), "RUNNER_TEMP": str(root), "CI_LANE": "synthetic",
                      "RUNNER_OS": "Windows", "GITHUB_RUN_ID": "1", "GITHUB_RUN_NUMBER": "1", "GITHUB_RUN_ATTEMPT": "1"}
            with patch.dict(runner.os.environ, values), patch.object(ci, "validate_payload"), patch.object(ci, "recipes", return_value=[lane]), patch.object(windows, "probe", side_effect=ValueError("SYNTHETIC_FAILURE")), patch.object(ci, "quiet") as execute:
                with self.assertRaises(ValueError):
                    runner.run()
            execute.assert_not_called()
            self.assertFalse((work / "step-0.ps1").exists())
