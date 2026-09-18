"""Source-level guards for public-builder strict CEF qualification workflows."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StrictQualificationWorkflowTests(unittest.TestCase):
    def test_full_platform_workflow_is_exact_and_keeps_native_output_private(self):
        text = (ROOT / ".github/workflows/cef-strict-platform-qualification.yml").read_text()
        self.assertIn("repository: dobord/vcpkg", text)
        self.assertIn("ref: 8fd1ca83ba365f3fe3884d86f7ef6608c2095f2b", text)
        self.assertIn("repository: microsoft/vcpkg", text)
        self.assertIn("ref: 9e593bb18ea69cc5095e012465dcd675a822ed0d", text)
        self.assertIn("repository: dobord/cef", text)
        self.assertIn("ref: 37729fd2b1db127c1658098d69ab63adc70e045f", text)
        self.assertIn('>"$RUNNER_TEMP/cef-strict-native.log" 2>&1', text)
        self.assertNotIn("actions/cache", text)
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("persist-credentials: true", text)

    def test_current_private_source_contract_workflow_pins_gn_gate_revision(self):
        text = (ROOT / ".github/workflows/cef-strict-source-contracts.yml").read_text()
        self.assertIn("repository: dobord/vcpkg", text)
        self.assertIn("ref: 2533e026c1ec9f698303df173b4db43f81606e0c", text)
        self.assertIn("python -I -m unittest discover -s ci/cef-full/tests -v", text)
        self.assertIn("ci/cef-full/gn_check.py", text)
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("actions/cache", text)


if __name__ == "__main__":
    unittest.main()
