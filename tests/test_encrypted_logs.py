from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest

from secure_release import crypto, encrypted_logs


class EncryptedLogArtifactTests(unittest.TestCase):
    def test_round_trip_is_ciphertext_only_and_filters_sensitive_files(self):
        private, public = crypto.generate("encrypt")
        context = {
            "schema": 1,
            "kind": "builder-encrypted-ci-logs",
            "repository": "dobord/builder",
            "workflow": "unit",
            "job": "linux",
            "run_id": 123,
            "run_attempt": 1,
            "sha": "a" * 40,
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = root / "runner"
            logs.mkdir()
            (logs / "install.log").write_text("failure detail\n", encoding="utf-8")
            (logs / "status.json").write_text('{"ok":false}\n', encoding="utf-8")
            (logs / "private-key.txt").write_text("must not archive\n", encoding="utf-8")
            (logs / "binary.o").write_bytes(b"object")
            nested = logs / "nested"
            nested.mkdir()
            (nested / "CMakeConfigureLog.yaml").write_text("cmake: error\n", encoding="utf-8")
            (nested / "LastTestsFailed.log").write_text("1:test_name\n", encoding="utf-8")
            (nested / "compiler.rsp").write_text("-Iinclude source.cpp\n", encoding="utf-8")
            (nested / "results.trx").write_text("<TestRun/>\n", encoding="utf-8")

            encrypted = root / "artifact.enc"
            manifest = encrypted_logs.collect([logs], encrypted, public, context)
            self.assertTrue(encrypted.is_file())
            self.assertEqual(manifest["file_count"], 6)
            self.assertFalse(any("private-key" in item["relative_path"] for item in manifest["files"]))

            decrypted = root / "decrypted"
            restored = encrypted_logs.decrypt_archive(encrypted, decrypted, private)
            self.assertEqual(restored["context"], context)
            self.assertEqual((decrypted / "logs/00-runner/install.log").read_text(), "failure detail\n")
            self.assertFalse(any(path.name == "private-key.txt" for path in decrypted.rglob("*")))
            self.assertFalse(any(path.suffix == ".o" for path in decrypted.rglob("*")))
            self.assertTrue(any(path.name == "compiler.rsp" for path in decrypted.rglob("*")))
            self.assertTrue(any(path.name == "results.trx" for path in decrypted.rglob("*")))

    def test_wrong_private_key_is_rejected(self):
        private, public = crypto.generate("encrypt")
        wrong_private, _ = crypto.generate("encrypt")
        context = {
            "schema": 1,
            "kind": "builder-encrypted-ci-logs",
            "repository": "dobord/builder",
            "workflow": "unit",
            "job": "linux",
            "run_id": 1,
            "run_attempt": 1,
            "sha": "b" * 40,
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            logs = root / "logs"
            logs.mkdir()
            (logs / "build.log").write_text("x", encoding="utf-8")
            encrypted = root / "logs.enc"
            encrypted_logs.collect([logs], encrypted, public, context)
            with self.assertRaises(Exception):
                encrypted_logs.decrypt_archive(encrypted, root / "bad", wrong_private)

    def test_public_key_base64_roundtrip(self):
        _, public = crypto.generate("encrypt")
        encoded = base64.b64encode(public.encode()).decode()
        self.assertEqual(encrypted_logs._decode_key_b64(encoded), public)

    def test_composite_action_uploads_only_encrypted_payload(self):
        action = (
            Path(__file__).resolve().parents[1]
            / ".github/actions/encrypted-logs/action.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("ШИФРОВАНЫЕ ЛОГИ-", action)
        self.assertIn("BUILDER_ENCRYPTED_LOGS_PUBLIC_KEY_B64", action)
        self.assertIn("builder-encrypted-logs/*.enc", action)
        self.assertIn("compression-level: 0", action)
        self.assertIn("PLAINTEXT_LEAK", action)
        self.assertIn("GITHUB_ACTION_PATH", action)
        self.assertIn("PYTHONPATH=", action)
        self.assertNotIn("*.log\n", action)


if __name__ == "__main__":
    unittest.main()
