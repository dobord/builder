"""Cache corruption/provenance tests; disposable keys and synthetic inputs only."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from secure_release import cef_cache as cache, crypto

HAS_TINK = importlib.util.find_spec("tink") is not None
if os.environ.get("REQUIRE_TINK_TESTS") == "1" and not HAS_TINK:
    raise RuntimeError("Tink cache tests are mandatory in CI")


class PathTests(unittest.TestCase):
    def test_cache_names(self):
        cache.allowed_path("checkpoint.json", "cef-checkpoint")
        cache.allowed_path("workspace.tar.gz.part0000", "cef-checkpoint")
        cache.allowed_path("aa/" + "a" * 64 + ".zip", "vcpkg-binaries")
        for name in ("../escape", "source.c", "checkpoint.json/other", "workspace.tar.gz.part0", "secret.enc"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                cache.allowed_path(name, "cef-checkpoint")
        for name in ("../a.zip", "aa/" + "a" * 41 + ".zip", "aa/" + "a" * 64 + ".zip/secret"):
            with self.assertRaises(ValueError):
                cache.allowed_path(name, "vcpkg-binaries")

    def test_domain_separation(self):
        a = cache.context("cef-checkpoint", "linux", "a" * 64, 1, 1, "b" * 40, "index")
        b = cache.context("vcpkg-binaries", "linux", "a" * 64, 1, 1, "b" * 40, "index")
        self.assertNotEqual(a, b)
        self.assertEqual(a["purpose"], "builder-cache-v1")
        for field, val in (("run", True), ("attempt", 0), ("build_key", "main")):
            bad = dict(a, **{field: val})
            with self.assertRaises(ValueError):
                cache.context(bad["kind"], bad["platform"], bad["build_key"], bad["run"], bad["attempt"], bad["builder_sha"], "index")


@unittest.skipUnless(HAS_TINK, "Tink wheel is unavailable locally")
class EncryptedCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private, cls.public = crypto.generate("encrypt")
        cls.other_private, _ = crypto.generate("encrypt")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "checkpoint.json").write_text('{"synthetic":true}\n')
        (self.source / "workspace.tar.gz.part0000").write_bytes(bytes(range(256)) * 4097)
        self.base = cache.context("cef-checkpoint", "linux", "a" * 64, 12, 1, "b" * 40, "index")
        self.encrypted = self.root / "encrypted"
        self.destination = self.root / "restored"

    def seal(self):
        return cache.seal(self.source, self.encrypted, self.public, self.base)

    def test_roundtrip_and_only_ciphertext(self):
        result = self.seal()
        self.assertFalse(result["sdk_verified"])
        self.assertEqual({p.name for p in self.encrypted.iterdir()}, {"index.enc", "part000000.enc", "part000001.enc"})
        manifest = cache.unseal(self.encrypted, self.destination, self.private, self.base)
        self.assertFalse(manifest["sdk_verified"])
        for original in self.source.iterdir():
            self.assertEqual(original.read_bytes(), (self.destination / original.name).read_bytes())

    def test_wrong_key(self):
        self.seal()
        with self.assertRaises(Exception):
            cache.unseal(self.encrypted, self.destination, self.other_private, self.base)
        self.assertFalse(self.destination.exists())

    def test_wrong_semantic_key(self):
        self.seal()
        with self.assertRaises(Exception):
            cache.unseal(self.encrypted, self.destination, self.private, dict(self.base, build_key="c" * 64))
        self.assertFalse(self.destination.exists())

    def test_wrong_attempt(self):
        self.seal()
        with self.assertRaises(Exception):
            cache.unseal(self.encrypted, self.destination, self.private, dict(self.base, attempt=2))
        self.assertFalse(self.destination.exists())

    def test_wrong_purpose(self):
        self.seal()
        with self.assertRaises(Exception):
            cache.unseal(self.encrypted, self.destination, self.private, dict(self.base, kind="vcpkg-binaries"))
        self.assertFalse(self.destination.exists())

    def test_corruption_is_atomic(self):
        self.seal()
        part = self.encrypted / "part000001.enc"
        data = part.read_bytes()
        part.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaises(Exception):
            cache.unseal(self.encrypted, self.destination, self.private, self.base)
        self.assertFalse(self.destination.exists())

    def test_missing_member(self):
        self.seal()
        (self.encrypted / "part000001.enc").unlink()
        with self.assertRaises(ValueError):
            cache.unseal(self.encrypted, self.destination, self.private, self.base)
        self.assertFalse(self.destination.exists())

    def test_extra_member(self):
        self.seal()
        (self.encrypted / "extra.enc").write_bytes(b"untrusted")
        with self.assertRaises(ValueError):
            cache.unseal(self.encrypted, self.destination, self.private, self.base)
        self.assertFalse(self.destination.exists())

    def test_refuse_merge(self):
        self.seal()
        self.destination.mkdir()
        (self.destination / "owned").write_text("preserve")
        with self.assertRaises(ValueError):
            cache.unseal(self.encrypted, self.destination, self.private, self.base)
        self.assertEqual((self.destination / "owned").read_text(), "preserve")

    def test_unreviewed_input_is_not_published(self):
        (self.source / "credentials.json").write_text("synthetic secret")
        with self.assertRaises(ValueError):
            self.seal()
        self.assertFalse((self.encrypted / "index.enc").exists())

    def test_binary_cache_roundtrip(self):
        source = self.root / "binaries"
        (source / "ab").mkdir(parents=True)
        name = "ab" + "c" * 62 + ".zip"
        (source / "ab" / name).write_bytes(b"synthetic package; vcpkg checks actual zip")
        base = dict(self.base, kind="vcpkg-binaries")
        cache.seal(source, self.encrypted, self.public, base)
        cache.unseal(self.encrypted, self.destination, self.private, base)
        self.assertEqual((source / "ab" / name).read_bytes(), (self.destination / "ab" / name).read_bytes())

if __name__ == "__main__":
    unittest.main()
