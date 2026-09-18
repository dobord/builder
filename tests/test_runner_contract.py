"""Public configuration regression tests; no keys, sources or API access."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class RunnerContractTests(unittest.TestCase):
    def test_release_build_runner_matrix(self):
        text = (WORKFLOWS / "build-release.yml").read_text(encoding="utf-8")
        self.assertIn("runs-on: ${{ fromJSON(matrix.runner_labels) }}", text)
        rows = re.findall(
            r"runner_labels:\s*\$\{\{\s*vars\.(CEF_STATIC_(?:LINUX|WINDOWS)_RUNNER_LABELS)"
            r"\s*\|\|\s*'([^']+)'\s*\}\}",
            text,
        )
        self.assertCountEqual(rows, [
            ("CEF_STATIC_LINUX_RUNNER_LABELS", '["ubuntu-24.04"]'),
            ("CEF_STATIC_WINDOWS_RUNNER_LABELS", '["windows-2022"]'),
        ])
        self.assertNotIn("runs-on: ${{ matrix.os }}", text)

    def test_synthetic_ci_runner_matrix(self):
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        labels = re.findall(r"^\s*(?:-\s+)?os:\s*([a-z0-9.-]+)\s*$", text, re.MULTILINE)
        self.assertCountEqual(labels, ["ubuntu-24.04", "windows-2022"])
        self.assertIn("runs-on: ${{ matrix.os }}", text)


if __name__ == "__main__":
    unittest.main()
