import copy
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from secure_release import docker_endurance as endurance


class EnduranceAdmission(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.payload = {"schema": 1, "purpose": "docker-endurance", "builder_code_sha": self.sha,
                        "source": "dobord/synthetic-source", "source_id": 123,
                        "source_base_sha": "b" * 40, "source_digest": "c" * 64,
                        "recipe": "ci/run.py", "mode": "qualification",
                        "duration_seconds": 18000, "cycles": 100,
                        "created": 1000, "expires": 2000}

    def test_exact_five_hour_profile(self):
        endurance.validate(self.payload, self.sha, now=1500)
        for changes in ({"duration_seconds": 28800}, {"duration_seconds": 17999},
                        {"cycles": 99}, {"cycles": True}, {"schema": True},
                        {"purpose": "sdk-release"}, {"builder_code_sha": "d" * 40},
                        {"recipe": "../run.py"}, {"recipe": ".git/hooks/pre-commit.py"},
                        {"expires": 999}, {"expires": 22601}, {"unapproved": 1}):
            payload = copy.deepcopy(self.payload)
            payload.update(changes)
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                endurance.validate(payload, self.sha, now=1500)

    def test_pilot_is_explicitly_distinct(self):
        pilot = dict(self.payload, mode="pilot", duration_seconds=60, cycles=2)
        endurance.validate(pilot, self.sha, now=1500)
        with self.assertRaises(ValueError):
            endurance.validate(dict(pilot, mode="qualification"), self.sha, now=1500)

    def test_context_is_independent_of_source_metadata(self):
        context = endurance.input_context(self.sha)
        self.assertNotIn("source", context)
        self.assertNotIn("source_base_sha", context)
        self.assertEqual(context["builder_id"], 1372874997)

    def test_code_commit_cannot_change_with_ciphertext(self):
        with patch.object(subprocess, "check_output", side_effect=[self.sha + "\n", endurance.INPUT.encode() + b"\0"]):
            endurance.code_boundary(Path("."), self.sha)
        for paths in (b"secure_release/docker_endurance.py\0" + endurance.INPUT.encode() + b"\0", b""):
            with patch.object(subprocess, "check_output", side_effect=[self.sha + "\n", paths]), self.assertRaises(ValueError):
                endurance.code_boundary(Path("."), self.sha)
        with patch.object(subprocess, "check_output", side_effect=["e" * 40 + "\n", endurance.INPUT.encode() + b"\0"]), self.assertRaises(ValueError):
            endurance.code_boundary(Path("."), self.sha)

    def test_compressed_expansion_is_bounded_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                member = tarfile.TarInfo("source.txt")
                member.size = 4096
                archive.addfile(member, io.BytesIO(b"x" * 4096))
            with patch.object(endurance, "MAX_SOURCE", 1024), self.assertRaises(ValueError):
                endurance.validate_source_archive(path)
            endurance.validate_source_archive(path)

    def test_snapshot_excludes_upstream_and_rejects_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recipe.py").write_text("# public synthetic recipe\n")
            target = root / "source.tar.gz"
            names = b"recipe.py\0freerdp\0freerdp/version.h\0"
            with patch.object(subprocess, "check_output", return_value=names):
                endurance.source_tar(root, target)
            with tarfile.open(target) as archive:
                self.assertEqual(archive.getnames(), ["recipe.py"])
            for names in (b"ci/artifacts/ticket.bin\0", b"ci/.env\0"):
                with patch.object(subprocess, "check_output", return_value=names), self.assertRaises(ValueError):
                    endurance.source_tar(root, root / "rejected.tar.gz")


if __name__ == "__main__":
    unittest.main()
