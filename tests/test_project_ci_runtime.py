"""The online crypto runtime admits only reviewed binary platform wheels."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ARM64 = {
    "tink": ("1.16.1", "tink-1.16.1-cp312-cp312-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl",
             "e453324348208e5cb81e35d506717ed83c8c4cf2473f4b31f6269fd8bca81fb2"),
    "protobuf": ("6.33.5", "protobuf-6.33.5-cp39-abi3-manylinux2014_aarch64.whl",
                 "9b71e0281f36f179d00cbcb119cb19dec4d14a81393e5ea220f64b286173e190"),
    "PyYAML": ("6.0.3", "pyyaml-6.0.3-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl",
               "9149cad251584d5fb4981be1ecde53a1ca46c891a79788c0df828d2f166bda28"),
}


class ProjectRuntimeContractTests(unittest.TestCase):
    def test_linux_arm64_official_wheels_have_exact_hash_pins(self):
        lock = (ROOT / "project-ci-requirements.lock").read_text()
        requirements = lock.replace("\\\n", " ")
        for package, (version, filename, digest) in ARM64.items():
            with self.subTest(wheel=filename):
                matched = re.search(rf"^{re.escape(package)}=={re.escape(version)} (.+)$", requirements, re.M)
                self.assertIsNotNone(matched)
                self.assertIn("--hash=sha256:" + digest, matched.group(1))

    def test_online_install_preserves_wheel_only_hash_enforcement(self):
        workflow = (ROOT / ".github/workflows/encrypted-project-ci.yml").read_text()
        self.assertEqual(workflow.count("--only-binary=:all: -r project-ci-requirements.lock"), 2)
        self.assertEqual(workflow.count("--require-hashes"), 2)
        # The offline SDK wheelhouse has a separate reviewed platform contract.
        offline = (ROOT / "requirements.lock").read_text()
        for _, _, digest in ARM64.values():
            self.assertNotIn(digest, offline)


if __name__ == "__main__":
    unittest.main()
