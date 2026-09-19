"""Only synthetic data and freshly generated, disposable test keys."""
import copy
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
import uuid
import zipfile
from secure_release import crypto, safeio
from secure_release.protocol import file_context, message_context, check_run, IDS, BUILDER

ROOT = Path(__file__).resolve().parents[1]

HAS_TINK = importlib.util.find_spec("tink") is not None
if os.environ.get("REQUIRE_TINK_TESTS") == "1" and not HAS_TINK:
    raise RuntimeError("Tink tests are mandatory in CI")


class PublicValidationTests(unittest.TestCase):
    def test_duplicate_json(self):
        with self.assertRaises(ValueError):
            crypto.parse('{"version":1,"version":2}')

    def test_nonfinite_json(self):
        with self.assertRaises(ValueError):
            crypto.parse('{"x":NaN}')

    def test_invalid_paths(self):
        for name in ("../escape", "/escape", "C:/secret", "a\\b", "a/../b", "a/./b", "a//b", "a:stream", "CON.txt", "a/NUL", "a/.git/config", "a./b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safeio.parts(name)

    def test_context_salt_size(self):
        with self.assertRaises(ValueError):
            message_context(str(uuid.uuid4()), crypto.b64(b"short"))

    def test_header_limits(self):
        for raw in (b"bad", crypto.MAGIC + b"\x00", crypto.MAGIC + struct.pack(">I", crypto.MAX_HEADER + 1)):
            with self.assertRaises(ValueError):
                crypto.read_header(io.BytesIO(raw))

    def test_tar_rejects_links(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for i, kind in enumerate((tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE)):
                archive = root / f"{i}.tgz"
                with tarfile.open(archive, "w:gz") as tar:
                    info = tarfile.TarInfo("link")
                    info.type = kind
                    info.linkname = "../outside"
                    tar.addfile(info)
                with self.assertRaises(ValueError):
                    safeio.extract_tar(archive, root / f"out-{i}")

    def test_zip_rejects_case_collision(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("a.txt", "one")
                z.writestr("A.txt", "two")
            with self.assertRaises(ValueError):
                safeio.zip_files(p)

    def test_zip_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.zip"
            with zipfile.ZipFile(p, "w") as z:
                info = zipfile.ZipInfo("link")
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "../outside")
            with self.assertRaises(ValueError):
                safeio.zip_files(p)

    def test_tar_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "src").mkdir()
            (root / "src/public.txt").write_text("synthetic test")
            safeio.pack_tar(root / "src", root / "a.tgz")
            safeio.extract_tar(root / "a.tgz", root / "out")
            self.assertEqual((root / "out/public.txt").read_text(), "synthetic test")

    def test_fork_run_rejected(self):
        run = {"repository": {"id": IDS[BUILDER]}, "head_repository": {"id": 999}, "path": ".github/workflows/build-release.yml",
               "head_sha": "a" * 40, "run_attempt": 1, "event": "workflow_dispatch", "status": "completed", "conclusion": "success"}
        with self.assertRaises(ValueError):
            check_run(run, BUILDER, "build-release.yml", "a" * 40, 1, "workflow_dispatch", success=True)

    def test_incomplete_run_rejected(self):
        run = {"repository": {"id": IDS[BUILDER]}, "head_repository": {"id": IDS[BUILDER]}, "path": ".github/workflows/build-release.yml",
               "head_sha": "a" * 40, "run_attempt": 1, "event": "workflow_dispatch", "status": "in_progress", "conclusion": None}
        with self.assertRaises(ValueError):
            check_run(run, BUILDER, "build-release.yml", "a" * 40, 1, "workflow_dispatch", success=True)

    def test_publication_runs_in_builder_without_destination_actions(self):
        workflow = (ROOT / ".github/workflows/request-publication.yml").read_text()
        publisher = (ROOT / "secure_release/publish.py").read_text()
        bootstrap = (ROOT / "secure_release/bootstrap.py").read_text()
        driver = (ROOT / "secure_release/__main__.py").read_text()
        tasks = (ROOT / "secure_release/tasks.py").read_text()

        self.assertIn("python -m secure_release verify", workflow)
        self.assertIn("python -m secure_release publish", workflow)
        self.assertIn("BIN_PUBLISH_TOKEN", workflow)
        self.assertIn("ARTIFACT_DECRYPTION_PRIVATE_KEY", workflow)
        self.assertIn("steps.verify.outputs.staging_digest", workflow)
        self.assertNotIn("BIN_DISPATCH_TOKEN", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("download-artifact", workflow)

        self.assertIn('guard(BUILDER, event="workflow_run")', publisher)
        self.assertIn('f"/repos/{BIN}/git/ref/heads/main"', publisher)
        self.assertIn('"target_commitish": bin_main', publisher)
        self.assertNotIn('.dispatch(BIN, "publish.yml"', publisher)
        self.assertNotIn('guard(BIN', publisher)
        self.assertNotIn('"target_commitish": sha(env("GITHUB_SHA"))', publisher)

        self.assertIn('secret(BUILDER, "ARTIFACT_DECRYPTION_PRIVATE_KEY"', bootstrap)
        self.assertIn('"BIN_PUBLISH_TOKEN"', bootstrap)
        self.assertNotIn('"BIN_DISPATCH_TOKEN"', bootstrap)
        self.assertNotIn('"notify":', driver)
        self.assertIn('process.remove_tree(temporary / "verified-release")', tasks)


@unittest.skipUnless(HAS_TINK, "Tink wheel is unavailable in this local environment")
class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private, cls.public = crypto.generate("encrypt")
        cls.other_private, cls.other_public = crypto.generate("encrypt")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.context = file_context(str(uuid.uuid4()), crypto.b64(os.urandom(32)), 10, 1, "a" * 40, "sdk", "linux")

    def tearDown(self):
        self.temp.cleanup()

    def encrypted(self, size=3 * 1024 * 1024 + 37):
        plain, cipher = self.root / "plain", self.root / "cipher"
        plain.write_bytes(os.urandom(size))
        crypto.encrypt_file(plain, cipher, self.public, self.context)
        return plain, cipher

    def test_stream_roundtrip(self):
        plain, cipher = self.encrypted()
        crypto.decrypt_file(cipher, self.root / "out", self.private, self.context)
        self.assertEqual(crypto.digest(plain), crypto.digest(self.root / "out"))

    def test_empty_roundtrip(self):
        plain, cipher = self.encrypted(0)
        crypto.decrypt_file(cipher, self.root / "out", self.private, self.context)
        self.assertEqual((self.root / "out").stat().st_size, 0)

    def test_wrong_salt(self):
        _, cipher = self.encrypted(100)
        changed = {**self.context, "salt": crypto.b64(os.urandom(32))}
        with self.assertRaises(Exception):
            crypto.decrypt_file(cipher, self.root / "out", self.private, changed)
        self.assertFalse((self.root / "out").exists())

    def test_wrong_platform(self):
        _, cipher = self.encrypted(100)
        with self.assertRaises(Exception):
            crypto.decrypt_file(cipher, self.root / "out", self.private, {**self.context, "platform": "windows"})

    def test_wrong_attempt(self):
        _, cipher = self.encrypted(100)
        with self.assertRaises(Exception):
            crypto.decrypt_file(cipher, self.root / "out", self.private, {**self.context, "attempt": 2})

    def test_wrong_key(self):
        _, cipher = self.encrypted(100)
        with self.assertRaises(Exception):
            crypto.decrypt_file(cipher, self.root / "out", self.other_private, self.context)

    def test_truncated_no_plaintext(self):
        _, cipher = self.encrypted()
        cipher.write_bytes(cipher.read_bytes()[:-1])
        with self.assertRaises(Exception):
            crypto.decrypt_file(cipher, self.root / "out", self.private, self.context)
        self.assertFalse((self.root / "out").exists())
        self.assertEqual(list(self.root.glob(".decrypt-*")), [])

    def test_modified_no_plaintext(self):
        _, cipher = self.encrypted()
        data = bytearray(cipher.read_bytes()); data[-20] ^= 1; cipher.write_bytes(data)
        with self.assertRaises(Exception):
            crypto.decrypt_file(cipher, self.root / "out", self.private, self.context)
        self.assertFalse((self.root / "out").exists())

    def test_fresh_file_keys(self):
        plain, cipher = self.encrypted(100)
        second = self.root / "second"
        crypto.encrypt_file(plain, second, self.public, self.context)
        self.assertNotEqual(cipher.read_bytes(), second.read_bytes())

    def test_private_key_not_accepted_as_public(self):
        with self.assertRaises(Exception):
            crypto.fingerprint(self.private)

    def test_signature_tampering(self):
        private, public = crypto.generate("sign")
        document = crypto.sign({"salt": "synthetic", "source": "a" * 40}, private)
        self.assertEqual(crypto.verify(document, public), document["payload"])
        document["payload"]["source"] = "b" * 40
        with self.assertRaises(Exception):
            crypto.verify(document, public)

    def test_request_context(self):
        context = message_context(str(uuid.uuid4()), crypto.b64(os.urandom(32)))
        encrypted = crypto.seal_message(b"synthetic request", self.public, context)
        self.assertEqual(crypto.open_message(encrypted, self.private, context), b"synthetic request")
        with self.assertRaises(Exception):
            crypto.open_message(encrypted, self.private, {**context, "salt": crypto.b64(os.urandom(32))})


if __name__ == "__main__":
    unittest.main()
