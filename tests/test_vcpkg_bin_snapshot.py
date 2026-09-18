"""Integrity guard for the exact vcpkg-bin policy snapshot used on builder Actions."""
from pathlib import Path
import hashlib
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "tests/vcpkg_bin_snapshot"
EXPECTED_COMMIT = "b65ae0f43200ededcaa37acd824fff31b1c86cc9"


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


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
        }
        self.assertEqual(set(lock["files"]), set(expected))
        for relative, source in expected.items():
            record = lock["files"][relative]
            self.assertEqual(record["source"], source)
            path = ROOT / relative
            self.assertTrue(path.is_file() and not path.is_symlink())
            self.assertEqual(git_blob_sha(path.read_bytes()), record["github_blob_sha"])

    def test_snapshot_policy_stays_fail_closed_until_real_contracts_are_admitted(self):
        policy = json.loads((SNAPSHOT / "cef-policy.json").read_text())
        self.assertEqual(policy["schema"], 1)
        self.assertEqual(policy["required_profile"], "static-third-party")
        self.assertEqual(policy["admitted_contracts"], {"linux": [], "windows": []})


if __name__ == "__main__":
    unittest.main()
