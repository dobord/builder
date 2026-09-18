"""Native filesystem transport and mocked GitHub provenance; no credentials."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from secure_release import cef_cache as cache, cef_build
from secure_release.protocol import BUILDER, IDS
from test_cef_contract import config


class FakeAPI:
    def __init__(self):
        self.run = {"repository": {"id": IDS[BUILDER]}, "head_repository": {"id": IDS[BUILDER]},
                    "path": ".github/workflows/build-release.yml", "head_sha": "b" * 40,
                    "run_attempt": 1, "event": "workflow_dispatch", "status": "completed"}
        self.artifact = {"id": 123, "name": "cef-checkpoint-linux-12-1", "expired": False,
                         "digest": "sha256:" + "d" * 64, "workflow_run": {"id": 12, "head_sha": "b" * 40}}
        self.current_calls = 0
        self.rerun_after_download = False
        self.names = ["index.enc"]

    def get(self, path):
        result = copy.deepcopy(self.run)
        if not "/attempts/" in path:
            self.current_calls += 1
            if self.rerun_after_download and self.current_calls > 1:
                result["run_attempt"] = 2
        return result

    def artifacts(self, repo, run):
        assert (repo, run) == (BUILDER, 12)
        return [copy.deepcopy(self.artifact)]

    def download(self, path, target, expected, **kwargs):
        assert path.endswith("/artifacts/123/zip") and expected == "d" * 64
        with zipfile.ZipFile(target, "w") as stream:
            for name in self.names:
                stream.writestr(name, b"fixture")


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.destination = Path(self.temp.name) / "restored"
        self.api = FakeAPI()
        self.selector = {"run": 12, "attempt": 1, "artifact_id": 123, "artifact_sha256": "d" * 64}
        self.decrypt_calls = []

    def fetch(self):
        def unseal(source, target, private, context):
            self.decrypt_calls.append(context)
            target.mkdir()
            (target / "checkpoint.json").write_text("synthetic")
            return {"sdk_verified": False}
        with patch.object(cache, "unseal", side_effect=unseal):
            return cache.fetch(self.api, self.selector, self.destination, platform="linux",
                               kind="cef-checkpoint", key="a" * 64, revision="b" * 40, private="synthetic")

    def test_exact_producer_and_atomic_transport(self):
        self.assertFalse(self.fetch()["sdk_verified"])
        self.assertEqual(self.decrypt_calls[0], cache.context("cef-checkpoint", "linux", "a" * 64, 12, 1, "b" * 40, "index"))
        self.assertTrue((self.destination / "checkpoint.json").is_file())

    def test_wrong_repository_workflow_event_or_revision(self):
        for key, value in (("repository", {"id": 1}), ("head_repository", {"id": 1}),
                           ("path", ".github/workflows/untrusted.yml"), ("event", "pull_request"),
                           ("head_sha", "c" * 40), ("run_attempt", 2), ("status", "in_progress")):
            self.api = FakeAPI()
            self.api.run[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.fetch()
        self.assertFalse(self.decrypt_calls)

    def test_wrong_artifact(self):
        for key, value in (("id", 999), ("name", "sdk-linux-12-1"), ("expired", True), ("digest", "sha256:" + "e" * 64)):
            self.api = FakeAPI()
            self.api.artifact[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.fetch()
        self.assertFalse(self.decrypt_calls)

    def test_rerun_during_download_does_not_publish_plaintext(self):
        self.api.rerun_after_download = True
        with self.assertRaises(ValueError):
            self.fetch()
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.destination.parent.iterdir()), [])

    def test_zip_paths_are_checked_before_decryption(self):
        for name in ("../index.enc", "sub/index.enc", "source.cpp", "index.enc:stream"):
            self.api.names = [name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.fetch()
        self.assertFalse(self.decrypt_calls)

    def test_native_evidence_accepts_exact_repetitions(self):
        cfg = config()
        for platform, count in (("linux", 1), ("windows", 3)):
            proof = {"schema": 1, "kind": "consumer-verification", "engine_linkage": "static", "capi_only": True,
                     "third_party_libraries_static": False,
                     "system_libraries_static": False, "sandbox_verified": False, "executable_sha256": "a" * 64,
                     "target_archive_audit": {"kind": "target-archive-audit-summary",
                                              "target_archives_static": True, "violation_count": 0},
                     "smoke": {"cef": "152.0.6+g708dc14+chromium-152.0.7977.83", "engine": "static", "interface": "capi",
                               "javascript": True, "paint": True, "browser_modules_clean": True, "renderer_modules_clean": True,
                               "browser_pid": 10, "renderer_pid": 20},
                     "smoke_runs": {"status": "success", "executable_sha256": "a" * 64,
                                    "engine_runtime_verified": True, "no_retry_on_failure": True,
                                    "required_runs": count, "passed_runs": count,
                                    "runs": [{"number": i, "status": "success", "engine_runtime_verified": True,
                                              "cwd": f"fresh-{i}"} for i in range(1, count + 1)]}}
            cef_build.validate_evidence(proof, cfg, platform)
            proof["smoke_runs"]["passed_runs"] = 0
            with self.assertRaises(ValueError):
                cef_build.validate_evidence(proof, cfg, platform)

    def test_strict_evidence_requires_runtime_and_closure(self):
        cfg = config(); cfg["profile"] = "static-third-party"
        proof = {"schema": 1, "kind": "consumer-verification", "engine_linkage": "static", "capi_only": True,
                 "third_party_libraries_static": True, "system_libraries_static": False,
                 "sandbox_verified": False, "executable_sha256": "a" * 64,
                 "target_archive_audit": {"kind": "target-archive-audit-summary",
                                          "target_archives_static": True, "violation_count": 0},
                 "smoke": {"cef": "152.0.6+g708dc14+chromium-152.0.7977.83", "engine": "static",
                           "interface": "capi", "javascript": True, "paint": True,
                           "browser_modules_clean": True, "renderer_modules_clean": True,
                           "third_party_modules_static": True, "browser_pid": 10, "renderer_pid": 20},
                 "smoke_runs": {"status": "success", "executable_sha256": "a" * 64,
                                "engine_runtime_verified": True, "no_retry_on_failure": True,
                                "required_runs": 1, "passed_runs": 1,
                                "runs": [{"number": 1, "status": "success",
                                          "engine_runtime_verified": True, "cwd": "fresh-1"}]},
                 "platform_closure": {"kind": "linux-frozen-vcpkg", "manifest_sha256": "b" * 64,
                                      "inventory_sha256": "c" * 64, "archive_count": 10}}
        cef_build.validate_evidence(proof, cfg, "linux")
        proof["smoke"]["third_party_modules_static"] = False
        with self.assertRaises(ValueError):
            cef_build.validate_evidence(proof, cfg, "linux")


if __name__ == "__main__":
    unittest.main()
