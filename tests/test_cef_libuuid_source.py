"""Exact distfile identity and no-overwrite/no-integrity-retry source cache."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_libuuid_source as source

FIXTURE = Path(__file__).parent / "fixtures/cef-dependency-source/libuuid-portfile.cmake"


class SourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.upstream = self.root / "upstream"
        self.work = self.root / "work"
        self.work.mkdir()
        port = self.upstream / source.PORT_FILE
        port.parent.mkdir(parents=True)
        shutil.copyfile(FIXTURE, port)
        self.target = self.upstream / "downloads" / source.ARCHIVE_NAME
        self.payload = b"disposable unit-test source bytes\n"
        self.hash = hashlib.sha512(self.payload).hexdigest()
        self.summary = {}

    def fetch(self):
        return source.prefetch(self.upstream, self.work, self.summary)

    def download(self, archive, log):
        archive.write_bytes(self.payload)
        log.write_bytes(b"public unit-test diagnostic\n")

    def test_exact_independent_port_and_unchanged_sha512(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), source.PORT_BLOB)
        self.assertIn(source.SHA512.encode(), raw)
        self.assertEqual(source.ARCHIVE_NAME, "libuuid-1.0.3.tar.gz")
        self.assertEqual(source.URL, "https://distfiles.macports.org/libuuid/libuuid-1.0.3.tar.gz")
        self.assertEqual(len(source.SHA512), 128)
        source._validate_policy(self.upstream)

    def test_verified_source_published_without_port_mutation(self):
        port = self.upstream / source.PORT_FILE
        original = port.read_bytes()
        with mock.patch.object(source, "SHA512", self.hash), mock.patch.object(source, "_download", side_effect=self.download) as fetch:
            receipt = self.fetch()
            fetch.assert_called_once()
        self.assertTrue(self.summary["libuuid_source_prefetch_verified"])
        self.assertFalse(receipt["existing_cache"])
        self.assertEqual(self.target.read_bytes(), self.payload)
        self.assertEqual(receipt["sha512"], self.hash)
        self.assertEqual(port.read_bytes(), original)
        self.assertFalse(list(self.target.parent.glob(".libuuid-source-*")))
        self.assertTrue((self.work / "libuuid-source-receipt.json").is_file())

    def test_valid_existing_cache_is_verified_not_replaced(self):
        self.target.parent.mkdir()
        self.target.write_bytes(self.payload)
        stat = self.target.stat()
        with mock.patch.object(source, "SHA512", self.hash), mock.patch.object(source, "_download") as fetch:
            self.assertTrue(self.fetch()["existing_cache"])
            fetch.assert_not_called()
        self.assertEqual((self.target.stat().st_ino, self.target.stat().st_mtime_ns), (stat.st_ino, stat.st_mtime_ns))

    def test_invalid_cache_is_not_overwritten_or_refetched(self):
        self.target.parent.mkdir()
        self.target.write_bytes(b"not the pinned distfile")
        with mock.patch.object(source, "_download") as fetch:
            with self.assertRaisesRegex(ValueError, "SHA512 mismatch"):
                self.fetch()
            fetch.assert_not_called()
        self.assertEqual(self.target.read_bytes(), b"not the pinned distfile")
        self.assertFalse((self.work / "libuuid-source-receipt.json").exists())

    def test_hash_mismatch_is_fatal_without_retry_or_publication(self):
        with mock.patch.object(source, "_download", side_effect=self.download) as fetch:
            with self.assertRaisesRegex(ValueError, "SHA512 mismatch"):
                self.fetch()
            fetch.assert_called_once()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.summary["libuuid_source_prefetch_verified"])
        self.assertFalse(list(self.target.parent.glob(".libuuid-source-*")))

    def test_download_failure_cleans_partial_bytes(self):
        def fail(archive, log):
            archive.write_bytes(b"partial")
            raise RuntimeError("transport failed")
        with mock.patch.object(source, "_download", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "transport failed"):
                self.fetch()
        self.assertFalse(self.target.exists())
        self.assertFalse(list(self.target.parent.glob(".libuuid-source-*")))

    def test_oversized_input_rejected_before_hash(self):
        archive = self.root / "huge"
        with archive.open("wb") as stream:
            stream.truncate(source.MAX_ARCHIVE + 1)
        with mock.patch.object(source.hashlib, "file_digest") as digest:
            with self.assertRaisesRegex(ValueError, "size outside bounds"):
                source._validate_archive(archive)
            digest.assert_not_called()

    def test_policy_drift_rejected_before_network(self):
        port = self.upstream / source.PORT_FILE
        port.write_bytes(port.read_bytes() + b"# modified\n")
        with mock.patch.object(source, "_download") as fetch:
            with self.assertRaisesRegex(ValueError, "policy changed"):
                self.fetch()
            fetch.assert_not_called()
        self.assertFalse(self.target.parent.exists())

    @unittest.skipIf(os.name == "nt", "native symlink privilege")
    def test_symlinked_cache_or_archive_is_rejected(self):
        self.target.parent.symlink_to(self.work, target_is_directory=True)
        with mock.patch.object(source, "_download") as fetch:
            with self.assertRaisesRegex(ValueError, "Redirected"):
                self.fetch()
            fetch.assert_not_called()
        self.target.parent.unlink()
        self.target.parent.mkdir()
        other = self.work / "other"
        other.write_bytes(self.payload)
        self.target.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "Invalid.*archive"):
            self.fetch()
        self.assertEqual(other.read_bytes(), self.payload)

    def test_concurrent_cache_creator_is_not_overwritten(self):
        original = source.os.link
        def raced(src, dst):
            Path(dst).write_bytes(b"concurrent writer")
            return original(src, dst)
        with mock.patch.object(source, "SHA512", self.hash), mock.patch.object(source, "_download", side_effect=self.download), mock.patch.object(source.os, "link", side_effect=raced):
            with self.assertRaises(FileExistsError):
                self.fetch()
        self.assertEqual(self.target.read_bytes(), b"concurrent writer")
        self.assertFalse((self.work / "libuuid-source-receipt.json").exists())

    def test_curl_uses_tls_bounds_and_no_inherited_credentials(self):
        log = self.work / "curl.log"
        completed = subprocess.CompletedProcess([], 0, b"")
        with mock.patch.dict(os.environ, {"PRIVATE_KEY": "disposable-test", "CURL_CA_BUNDLE": "untrusted", "HTTPS_PROXY": "untrusted"}), mock.patch.object(source.shutil, "which", return_value="curl"), mock.patch.object(source.subprocess, "run", return_value=completed) as run:
            source._download(self.root / "temporary", log)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["curl", "--disable"])
        self.assertEqual(command[-1], source.URL)
        self.assertEqual(command[command.index("--proto") + 1], "=https")
        self.assertEqual(command[command.index("--proto-redir") + 1], "=https")
        self.assertNotIn("--insecure", command)
        self.assertNotIn("--retry", command)
        self.assertEqual(command[command.index("--max-filesize") + 1], str(source.MAX_ARCHIVE))
        self.assertFalse(set(run.call_args.kwargs["env"]) & {"PRIVATE_KEY", "HTTPS_PROXY", "CURL_CA_BUNDLE"})
        self.assertEqual(run.call_args.kwargs["timeout"], 70)

    def test_timeout_and_large_error_are_not_success(self):
        log = self.work / "curl.log"
        for outcome in (subprocess.TimeoutExpired(["curl"], 70), subprocess.CompletedProcess([], 1, b"x" * (source.MAX_LOG + 1))):
            with self.subTest(kind=type(outcome).__name__), mock.patch.object(source.shutil, "which", return_value="curl"), mock.patch.object(source.subprocess, "run", side_effect=outcome if isinstance(outcome, Exception) else None, return_value=outcome):
                with self.assertRaises((RuntimeError, ValueError)):
                    source._download(self.root / "temporary", log)
        self.assertFalse(log.exists())

    def test_existing_evidence_is_not_overwritten(self):
        log = self.work / "libuuid-source-fetch.log"
        log.write_text("existing")
        with mock.patch.object(source, "_download") as fetch:
            with self.assertRaisesRegex(ValueError, "evidence already exists"):
                self.fetch()
            fetch.assert_not_called()
        self.assertEqual(log.read_text(), "existing")


class PublicDistfileTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GITHUB_ACTIONS") == "true", "exact public distfile fetched in CI, not offline unit tests")
    def test_real_mirror_bytes_match_unchanged_vcpkg_hash(self):
        # Required on both CI platforms: no mock URL, hash, downloader or policy.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            upstream = root / "upstream"
            port = upstream / source.PORT_FILE
            port.parent.mkdir(parents=True)
            shutil.copyfile(FIXTURE, port)
            work = root / "work"
            work.mkdir()
            report = {}
            receipt = source.prefetch(upstream, work, report)
            archive = upstream / "downloads" / source.ARCHIVE_NAME
            self.assertEqual(hashlib.sha512(archive.read_bytes()).hexdigest(), source.SHA512)
            self.assertEqual(archive.read_bytes()[:2], b"\x1f\x8b")
            self.assertTrue(report["libuuid_source_prefetch_verified"])
            self.assertGreater(receipt["size"], 100000)
            self.assertEqual(port.read_bytes(), FIXTURE.read_bytes())
            print("LIBUUID_PINNED_SOURCE_VERIFIED sha512=" + receipt["sha512"])


if __name__ == "__main__":
    unittest.main()
