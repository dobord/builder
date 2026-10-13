"""Fail-closed Windows hosted-image migration for resumable CEF checkpoints."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_iteration as worker

OLD = "20260927.320.1"
NEW = "20261004.326.1"
HOST = {
    "schema": 1,
    "os_build": "20348",
    "ubr": 5622,
    "machine": "amd64",
    "python": "3.12.10",
    "vc_tools": "14.44.35207",
    "windows_sdk": "10.0.26100.0",
    "ucrt": "10.0.26100.0",
    "llvm": "20.1.8",
}
SELECTED = {
    "run": 37441180545,
    "attempt": 1,
    "producer_sha": "6bbe92014dba81e24713af905ae6be3de0c71157",
    "artifact_id": 11415367897,
    "artifact_sha256": "9e7de2213e8108033f32d1a99bc3fac412a2103cfa616e4a30a63ccc6f978d61",
    "summary_artifact_id": 11415317880,
    "summary_artifact_sha256": "f9eabc75abbb7a059fa0bf06071edbd9f2cce676f11b74e69e9c387b2afbe6d2",
    "build_key": "378126b8abd73d31b865dd7bab7fc0d9b344a0d207ecf6b7b26429b5cb587acd",
}


class ImagePolicyTests(unittest.TestCase):
    def review(self, actual, fingerprint=None, producer=None, selected=SELECTED):
        report = {}
        with mock.patch.dict(os.environ, {"ImageVersion": actual}, clear=False), \
             mock.patch.object(
                 worker, "critical_windows_host_fingerprint",
                 return_value=deepcopy(fingerprint if fingerprint is not None else HOST),
             ):
            logical = worker.checkpoint_image_identity(
                selected, deepcopy(producer) if producer is not None else {}, report
            )
        return logical, report

    def test_exact_legacy_migration_uses_logical_image_and_records_actual(self):
        logical, report = self.review(NEW)
        self.assertEqual(logical, OLD)
        self.assertEqual(report["runner_image_actual"], NEW)
        self.assertEqual(report["checkpoint_image_identity"], OLD)
        self.assertEqual(report["critical_host_fingerprint"], HOST)
        self.assertTrue(report["runner_image_migrated"])
        self.assertTrue(report["checkpoint_host_verified"])

    def test_original_image_remains_valid_without_migration(self):
        logical, report = self.review(OLD)
        self.assertEqual(logical, OLD)
        self.assertFalse(report["runner_image_migrated"])
        self.assertTrue(report["checkpoint_host_verified"])

    def test_every_critical_host_field_fails_closed(self):
        for field in HOST:
            if field == "schema":
                changed = dict(HOST, schema=2)
            elif field == "ubr":
                changed = dict(HOST, ubr=HOST["ubr"] + 1)
            else:
                changed = dict(HOST)
                changed[field] = "999" if field == "os_build" else "99.99.99"
                if field == "machine":
                    changed[field] = "arm64"
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.review(NEW, changed)

    def test_unreviewed_image_and_missing_image_fail(self):
        with self.assertRaises(ValueError):
            self.review("20269999.1.1")
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(worker, "critical_windows_host_fingerprint", return_value=deepcopy(HOST)):
            with self.assertRaisesRegex(ValueError, "ImageVersion"):
                worker.checkpoint_image_identity(SELECTED, {}, {})

    def test_future_producer_fingerprint_controls_migration(self):
        producer = {
            "checkpoint_image_identity": OLD,
            "critical_host_fingerprint": deepcopy(HOST),
        }
        logical, report = self.review(NEW, producer=producer)
        self.assertEqual(logical, OLD)
        self.assertTrue(report["checkpoint_host_verified"])
        bad = deepcopy(producer)
        bad["critical_host_fingerprint"]["vc_tools"] = "14.99.99999"
        with self.assertRaisesRegex(ValueError, "fingerprint changed"):
            self.review(NEW, producer=bad)

    def test_source_fresh_uses_actual_image_only(self):
        logical, report = self.review(NEW, selected=None)
        self.assertEqual(logical, NEW)
        self.assertFalse(report["runner_image_migrated"])


class PrivateCodecTests(unittest.TestCase):
    def codec(self):
        root = os.environ.get("CEF_REPAIR_RECIPE_DIR")
        if not root:
            self.skipTest("Pinned private CEF recipe not supplied")
        path = Path(root) / "vcpkg/static/checkpoint.py"
        spec = importlib.util.spec_from_file_location("windows_image_checkpoint_fixture", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module

    def test_unchanged_codec_rejects_actual_and_restores_reviewed_logical_identity(self):
        codec = self.codec()
        with tempfile.TemporaryDirectory(prefix="windows image migration ") as folder:
            root = Path(folder).resolve()
            source = root / "source"
            source.mkdir()
            obj = source / "out/example.obj"
            obj.parent.mkdir()
            obj.write_bytes(b"disposable-object-not-real-engine")
            timestamp = obj.stat().st_mtime_ns
            package = root / "checkpoint"
            identity = {
                "recipe": "a" * 64,
                "work": str(source),
                "repository": "dobord/builder",
                "ref": "refs/heads/feature/cef-static-integration",
                "platform": "windows-x64",
                "image": OLD,
                "schema": codec.SCHEMA,
                "build_contract": SELECTED["build_key"],
                "worker_schema": 1,
            }
            codec.save(source, package, identity)
            manifest = (package / "checkpoint.json").read_bytes()
            shutil.rmtree(source)

            actual_identity = dict(identity, image=NEW)
            with self.assertRaisesRegex(ValueError, "identity/schema mismatch"):
                codec.restore(package, source, actual_identity)
            self.assertFalse(source.exists())
            self.assertEqual((package / "checkpoint.json").read_bytes(), manifest)

            report = {}
            with mock.patch.dict(os.environ, {"ImageVersion": NEW}, clear=False), \
                 mock.patch.object(worker, "critical_windows_host_fingerprint", return_value=deepcopy(HOST)):
                logical = worker.checkpoint_image_identity(SELECTED, {}, report)
            codec.restore(package, source, dict(actual_identity, image=logical))
            self.assertEqual((source / "out/example.obj").read_bytes(),
                             b"disposable-object-not-real-engine")
            self.assertEqual((source / "out/example.obj").stat().st_mtime_ns, timestamp)
            self.assertEqual((package / "checkpoint.json").read_bytes(), manifest)
            self.assertTrue(report["checkpoint_host_verified"])

    def test_incompatible_host_is_rejected_before_codec_restore(self):
        codec = self.codec()
        bad = dict(HOST, windows_sdk="10.0.99999.0")
        with mock.patch.dict(os.environ, {"ImageVersion": NEW}, clear=False), \
             mock.patch.object(worker, "critical_windows_host_fingerprint", return_value=bad), \
             mock.patch.object(codec, "restore") as restore:
            with self.assertRaises(ValueError):
                worker.checkpoint_image_identity(SELECTED, {}, {})
            restore.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Native Windows host fingerprint")
class NativeWindowsFingerprintTests(unittest.TestCase):
    def test_current_host_matches_reviewed_critical_fingerprint(self):
        value = worker.critical_windows_host_fingerprint()
        self.assertEqual(value, HOST)
        actual = os.environ.get("ImageVersion")
        self.assertIn(actual, {OLD, NEW})
        print(
            "CEF_WINDOWS_IMAGE_MIGRATION_NATIVE "
            f"actual_image={actual} fingerprint_verified=true "
            "codec_identity_preserved=true source_fresh=false"
        )


if __name__ == "__main__":
    unittest.main()
