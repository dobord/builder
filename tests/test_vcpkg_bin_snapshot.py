"""Integrity guard for the exact vcpkg-bin policy snapshot used on builder Actions."""
from pathlib import Path
import subprocess
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "tests/vcpkg_bin_snapshot"
EXPECTED_COMMIT = "e407d6b853d908b659bea8565f8a607ce5ff637d"


def committed_blob_sha(relative: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD:" + relative],
        text=True, timeout=30,
    ).strip()


class PublisherSnapshotTests(unittest.TestCase):
    def test_snapshot_is_content_addressed_to_reviewed_publisher_commit(self):
        lock = json.loads((SNAPSHOT / "LOCK.json").read_text())
        self.assertEqual(set(lock), {"schema", "repository", "commit", "files"})
        self.assertEqual(lock["schema"], 1)
        self.assertEqual(lock["repository"], "dobord/vcpkg-bin")
        self.assertEqual(lock["commit"], EXPECTED_COMMIT)
        expected = {
            "tests/vcpkg_bin_snapshot/cef_publication.py": "ci/cef_publication.py",
            "tests/vcpkg_bin_snapshot/cef_archive_gate.py": "ci/cef_archive_gate.py",
            "tests/vcpkg_bin_snapshot/test_cef_publication.py": "ci/tests/test_cef_publication.py",
            "tests/vcpkg_bin_snapshot/test_cef_archive_gate.py": "ci/tests/test_cef_archive_gate.py",
            "tests/vcpkg_bin_snapshot/cef-policy.json": "ci/cef-policy.json",
            "tests/vcpkg_bin_snapshot/publish.yml": ".github/workflows/publish.yml",
            "tests/vcpkg_bin_snapshot/cef-policy.yml": ".github/workflows/cef-policy.yml",
        }
        self.assertEqual(set(lock["files"]), set(expected))
        for relative, source in expected.items():
            record = lock["files"][relative]
            self.assertEqual(record["source"], source)
            path = ROOT / relative
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(committed_blob_sha(relative), record["github_blob_sha"])
            subprocess.run(
                ["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", relative],
                check=True, timeout=30,
            )

    def test_snapshot_workflows_pin_the_green_builder(self):
        expected = "457fd41f39cbcff940c7af654da899d44ba5e553"
        publish = (SNAPSHOT / "publish.yml").read_text()
        policy = (SNAPSHOT / "cef-policy.yml").read_text()
        self.assertGreaterEqual(publish.count("ref: " + expected), 2)
        self.assertIn("vars.BUILDER_COMMIT_SHA == '" + expected + "'", publish)
        self.assertIn("ref: " + expected, policy)
        self.assertNotIn("dee44a002606796afc3837ccca7120f62898691d", publish + policy)

    def test_snapshot_policy_stays_fail_closed_until_real_contracts_are_admitted(self):
        policy = json.loads((SNAPSHOT / "cef-policy.json").read_text())
        self.assertEqual(policy["schema"], 1)
        self.assertEqual(policy["required_profile"], "static-third-party")
        self.assertEqual(policy["admitted_contracts"], {"linux": [], "windows": ["3dbe67fc128a861af4daf42e12f10a6a6d05e718d931df30152a519e24c3c530"]})


if __name__ == "__main__":
    unittest.main()
