"""Public configuration regression tests; no keys, sources or API access."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class RunnerContractTests(unittest.TestCase):
    def check_matrix(self, name: str) -> None:
        text = (WORKFLOWS / name).read_text(encoding="utf-8")
        # Read the scalar `os` entries in our explicit matrix format without
        # adding an unpinned YAML dependency to the security-test environment.
        labels = re.findall(r"^\s*(?:-\s+)?os:\s*([a-z0-9.-]+)\s*$", text, re.MULTILINE)
        self.assertCountEqual(labels, ["ubuntu-24.04", "windows-2022"])
        self.assertIn("runs-on: ${{ matrix.os }}", text)

    def test_release_build_runner_matrix(self):
        self.check_matrix("build-release.yml")

    def test_synthetic_ci_runner_matrix(self):
        self.check_matrix("ci.yml")


if __name__ == "__main__":
    unittest.main()
