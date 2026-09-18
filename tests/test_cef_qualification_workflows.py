"""Source-level guards for public-builder strict CEF qualification workflows."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StrictQualificationWorkflowTests(unittest.TestCase):
    def test_full_platform_workflow_is_exact_and_keeps_native_output_private(self):
        text = (ROOT / ".github/workflows/cef-strict-platform-qualification.yml").read_text()
        self.assertIn("repository: dobord/vcpkg", text)
        self.assertIn("ref: a0ce35082136ac045c8e5cc97de4c0e4e29a5b38", text)
        self.assertIn("repository: microsoft/vcpkg", text)
        self.assertIn("ref: 9e593bb18ea69cc5095e012465dcd675a822ed0d", text)
        self.assertIn("repository: dobord/cef", text)
        self.assertIn("ref: 37729fd2b1db127c1658098d69ab63adc70e045f", text)
        self.assertIn('>"$RUNNER_TEMP/cef-strict-native.log" 2>&1', text)
        self.assertNotIn("actions/cache", text)
        self.assertNotIn("upload-artifact", text)
        self.assertIn("gh api \"repos/dobord/vcpkg/actions/artifacts/$id/zip\"", text)
        self.assertIn("sha256sum -c -", text)
        self.assertNotIn("persist-credentials: true", text)

    def test_production_build_accepts_trusted_large_disk_runner_labels(self):
        text=(ROOT/'.github/workflows/build-release.yml').read_text()
        self.assertIn('runs-on: ${{ fromJSON(matrix.runner_labels) }}',text)
        self.assertIn("vars.CEF_STATIC_LINUX_RUNNER_LABELS || '[\"ubuntu-24.04\"]'",text)
        self.assertIn("vars.CEF_STATIC_WINDOWS_RUNNER_LABELS || '[\"windows-2022\"]'",text)
        self.assertNotIn('runs-on: ${{ matrix.os }}',text)

    def test_strict_engine_iteration_uploads_only_encrypted_checkpoint(self):
        workflow=(ROOT/'.github/workflows/cef-strict-engine-iteration.yml').read_text()
        worker=(ROOT/'secure_release/cef_strict_iteration.py').read_text()
        self.assertIn('ref: fb0c27ec25ae3d9f297edb8bcd5a36378e38ce2e',workflow)
        self.assertIn('run: python -m secure_release.cef_strict_iteration',workflow)
        self.assertIn('cef-strict-checkpoint-encrypted/*.enc',workflow)
        self.assertNotIn('path: ${{ runner.temp }}/cef-strict-checkpoint/*',workflow)
        self.assertIn('cef_cache.seal(',worker)
        self.assertIn('cef_cache.unseal(',worker)
        self.assertIn('check_run(',worker)
        self.assertIn('"cef-strict-engine-iteration.yml"',worker)
        self.assertIn('"cef-checkpoint", "linux"',worker)
        self.assertIn('"slice"',worker)
        self.assertIn('"restore"',worker)
        self.assertIn('"platform_build_inputs"',worker)
        self.assertIn('"third_party_modules_static"',worker)
        self.assertIn('"platform-graph-receipt.json"',worker)
        self.assertIn('"gn_graph_qualified"',worker)
        self.assertIn('"failure_stage"',worker)
        self.assertNotIn('print(text',worker)
        lock=(ROOT/'ci/cef-strict-engine-lock.json').read_text()
        self.assertIn('"checkpoint": null',lock)
        self.assertIn('"vcpkg_commit": "fb0c27ec25ae3d9f297edb8bcd5a36378e38ce2e"',lock)

    def test_current_private_source_contract_workflow_pins_gn_gate_revision(self):
        text = (ROOT / ".github/workflows/cef-strict-source-contracts.yml").read_text()
        self.assertIn("repository: dobord/vcpkg", text)
        self.assertIn("ref: a0ce35082136ac045c8e5cc97de4c0e4e29a5b38", text)
        self.assertIn("ref: dee44a002606796afc3837ccca7120f62898691d", text)
        self.assertIn("python -I -m unittest discover -s ci/cef-full/tests -v", text)
        self.assertIn("ci/cef-full/gn_check.py", text)
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("actions/cache", text)


if __name__ == "__main__":
    unittest.main()
