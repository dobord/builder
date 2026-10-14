"""No native success is inferred from these mocked gate-policy tests."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def synthetic_contract(identity, status):
    class SyntheticContract(unittest.TestCase):
        def id(self):
            return identity

        def runTest(self):
            if status == "skip":
                self.skipTest("SYNTHETIC_SKIP")
            if status in ("failure", "expected-failure"):
                self.fail("SYNTHETIC_FAILURE")
            if status == "environment":
                self.assertNotIn("GH_TOKEN", os.environ)
                self.assertNotIn("CI_INPUT_PRIVATE_KEY_B64", os.environ)
    if status == "expected-failure":
        SyntheticContract.runTest = unittest.expectedFailure(SyntheticContract.runTest)
    return SyntheticContract("runTest")


def suite(gate, statuses=("success", "success")):
    return unittest.TestSuite(synthetic_contract(name, status) for name, status in zip(gate.EXPECTED, statuses))


class WindowsOwnershipGateTests(unittest.TestCase):
    def test_non_native_context_fails_before_loading_tests(self):
        from secure_release import windows_ownership_gate as gate
        with tempfile.TemporaryDirectory() as tmp, patch.object(gate, "native_supported", return_value=False), patch.object(gate, "native_suite") as load:
            directory = Path(tmp) / "contract"
            with self.assertRaises(ValueError):
                gate.run_contract(directory)
            load.assert_not_called()
            self.assertFalse(directory.exists())

    def test_exact_two_successes_are_required_and_output_stays_private(self):
        from secure_release import windows_ownership_gate as gate
        console = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.object(gate, "native_supported", return_value=True), patch.object(gate, "native_suite", side_effect=lambda: suite(gate)), contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
            directory = Path(tmp) / "contract"
            gate.run_contract(directory)
            report = json.loads((directory / "summary.json").read_text())
            self.assertEqual(report["tests_run"], 2)
            self.assertTrue(report["success"])
            self.assertTrue((directory / "native-ownership.log").is_file())
        self.assertEqual(console.getvalue(), "")

    def test_skip_failure_or_incomplete_inventory_cannot_pass(self):
        from secure_release import windows_ownership_gate as gate
        for statuses in (("success", "skip"), ("success", "failure"), ("success", "expected-failure"), ("success",)):
            with self.subTest(statuses=statuses), tempfile.TemporaryDirectory() as tmp, patch.object(gate, "native_supported", return_value=True), patch.object(gate, "native_suite", side_effect=lambda: suite(gate, statuses)):
                directory = Path(tmp) / "contract"
                with self.assertRaises(ValueError):
                    gate.run_contract(directory)
                self.assertFalse(json.loads((directory / "summary.json").read_text())["success"])

    def test_tests_receive_filtered_environment_and_caller_is_restored(self):
        from secure_release import windows_ownership_gate as gate
        original = {"PATH": "PUBLIC_TOOLS", "SystemRoot": "PUBLIC_WINDOWS", "GH_TOKEN": "SYNTHETIC_SECRET", "CI_INPUT_PRIVATE_KEY_B64": "SYNTHETIC_SECRET"}
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, original, clear=True), patch.object(gate, "native_supported", return_value=True), patch.object(gate, "native_suite", side_effect=lambda: suite(gate, ("environment", "environment"))):
            gate.run_contract(Path(tmp) / "contract")
            self.assertEqual(dict(os.environ), original)

    def test_workflow_gates_windows_before_download_and_materialization(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load((root / ".github/workflows/encrypted-project-ci.yml").read_text())
        self.assertEqual(set(workflow["jobs"]), {"prepare", "qualify", "required"})
        qualify = workflow["jobs"]["qualify"]
        self.assertEqual(qualify["name"], "Encrypted lane ${{ matrix.lane }}")
        steps = qualify["steps"]
        index = next(index for index, step in enumerate(steps) if step.get("run") == "python -m secure_release.windows_ownership_gate")
        self.assertEqual(steps[index]["if"], "runner.os == 'Windows'")
        self.assertFalse(steps[index].get("continue-on-error", False))
        self.assertLess(index, next(index for index, step in enumerate(steps) if step.get("uses", "").startswith("actions/download-artifact@")))
        self.assertLess(index, next(index for index, step in enumerate(steps) if step.get("run") == "python -m secure_release.project_ci materialize"))
