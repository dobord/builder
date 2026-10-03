from __future__ import annotations

import base64
from pathlib import Path
import tempfile
import unittest

from secure_release import openssl_tink_logs as subject

ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def test_reader_is_openssl_only_and_decrypt_only(self):
        source = (ROOT / "secure_release/openssl_tink_logs.py").read_text()
        script = (ROOT / "scripts/decrypt-builder-logs-openssl.py").read_text()
        self.assertIn("ctypes.CDLL", source)
        self.assertIn("OpenSSL 3.0 or newer is required", source)
        self.assertIn("HPKE_SUITE", source)
        self.assertIn("AES256_GCM_HKDF_1MB", source)
        self.assertNotIn("import tink", source)
        self.assertNotIn("from tink", source)
        self.assertNotIn("cryptography", source)
        self.assertNotIn("encrypt_file", source)
        self.assertIn("decrypt_archive", script)
        self.assertIn("--openssl-library", script)

    def test_archive_path_policy_is_portable(self):
        for value in (
            "../escape.log",
            "/absolute.log",
            "logs/../../escape.log",
            "logs/C:/drive.log",
            "logs/CON.txt",
            "logs/trailing. /x.log",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    subject._safe_name(value)
        self.assertEqual(
            subject._safe_name("logs/00-root/nested/runtime.log"),
            ("logs", "00-root", "nested", "runtime.log"),
        )


class TinkInteropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.backend = subject.OpenSSLBackend()
        except (OSError, RuntimeError) as error:
            raise unittest.SkipTest(f"OpenSSL 3 libcrypto unavailable: {error}")
        try:
            from secure_release import crypto, encrypted_logs
            crypto._tink()
        except Exception as error:
            raise unittest.SkipTest(f"Tink interoperability runtime unavailable: {error}")
        cls.crypto = crypto
        cls.encrypted_logs = encrypted_logs

    def make_ciphertext(self, root: Path):
        private, public = self.crypto.generate("encrypt")
        logs = root / "input"
        logs.mkdir()
        (logs / "runtime.log").write_text("runtime evidence\n", encoding="utf-8")
        nested = logs / "nested"
        nested.mkdir()
        (nested / "configure.txt").write_text("configured\n", encoding="utf-8")
        context = {
            "schema": 1,
            "kind": "builder-encrypted-ci-logs",
            "repository": "dobord/builder",
            "workflow": "synthetic-openssl-interoperability",
            "job": "linux",
            "run_id": 123456,
            "run_attempt": 1,
            "sha": "a" * 40,
        }
        cipher = root / "logs.enc"
        manifest = self.encrypted_logs.collect([logs], cipher, public, context)
        return private, cipher, manifest

    def test_tink_ciphertext_round_trips_through_openssl(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            private, cipher, expected = self.make_ciphertext(root)
            output = root / "plain"
            actual = subject.decrypt_archive(cipher, output, private)
            self.assertEqual(actual["context"], expected["context"])
            self.assertEqual(actual["recipient"], expected["recipient"])
            self.assertEqual(actual["file_count"], 2)
            self.assertEqual(
                (output / "logs/00-input/runtime.log").read_text(),
                "runtime evidence\n",
            )
            self.assertEqual(
                (output / "logs/00-input/nested/configure.txt").read_text(),
                "configured\n",
            )

    def test_base64_transport_private_key_is_accepted(self):
        private, _ = self.crypto.generate("encrypt")
        encoded = base64.b64encode(private.encode("utf-8")).decode("ascii")
        self.assertEqual(subject.decode_private_key_text(encoded), private)
        self.assertEqual(subject.decode_private_key_text(private), private)

    def test_wrong_recipient_fails_without_plaintext_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            _, cipher, _ = self.make_ciphertext(root)
            wrong_private, _ = self.crypto.generate("encrypt")
            output = root / "wrong-output"
            with self.assertRaises(ValueError):
                subject.decrypt_archive(cipher, output, wrong_private)
            self.assertFalse(output.exists())

    def test_stream_tamper_fails_without_plaintext_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            private, cipher, _ = self.make_ciphertext(root)
            tampered = root / "tampered.enc"
            data = bytearray(cipher.read_bytes())
            data[-1] ^= 1
            tampered.write_bytes(data)
            output = root / "tampered-output"
            with self.assertRaises(ValueError):
                subject.decrypt_archive(tampered, output, private)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
