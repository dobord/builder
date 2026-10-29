import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import zipfile

from secure_release import cef_contract, crypto, protocol, publish, safeio, tasks, windows_sdk


class WindowsReleaseTests(unittest.TestCase):
    def configuration(self):
        selected = windows_sdk.selected_checkpoint()
        return {"schema": 1, "recipe_commit": "03abd124ebe3b8a57fb78470a75b5aa3ce064e31",
                "profile": "static-third-party", "release_lock": None, "slice_seconds": 9000, "jobs": 4,
                "platforms": {
                    "linux": {"mode": "source-fresh", "checkpoint": None, "binary_cache": None},
                    "windows": {"mode": "source-resume", "binary_cache": None,
                                "checkpoint": {k: selected[k] for k in
                                               ("run", "attempt", "artifact_id", "artifact_sha256")}}}}

    def test_windows_only_scope_is_explicit(self):
        self.assertEqual(protocol.release_platforms({"version": 2, "platforms": ["windows"]}), ("windows",))
        self.assertEqual(protocol.build_workflow(".github/workflows/build-windows-release.yml"),
                         "build-windows-release.yml")
        for platforms in (["windows", "linux"], ["windows", "windows"], [], "windows"):
            with self.assertRaises(ValueError):
                protocol.release_platforms({"version": 2, "platforms": platforms})
        self.assertEqual(protocol.release_platforms({"version": 3, "platforms": ["windows"]}), ("windows",))
        with self.assertRaises(ValueError):
            protocol.release_platforms({"version": 3, "platforms": ["linux"]})

    def test_main_retry_signs_requester_and_immutable_source_separately(self):
        private, public = crypto.generate("encrypt")
        signing, verify = crypto.generate("sign")
        plan = {"version": 1, "upstream_sha": "d" * 40, "smoke_path": "ci/smoke",
                "ports": [{"name": "test", "repository": "dobord/test", "sha": "e" * 40}],
                "platforms": {p: {"packages": ["test"]} for p in ("linux", "windows")}}
        calls = []
        class Api:
            def __init__(self, token):
                pass
            def get(self, endpoint):
                calls.append(endpoint)
                if "/git/ref/tags/" in endpoint:
                    return {"object": {"type": "commit", "sha": "c" * 40}}
                if "/contents/ci/release-windows-plan.json?ref=" + "c" * 40 in endpoint:
                    return {"content": crypto.b64(crypto.canonical(plan))}
                raise AssertionError("Unexpected retry source endpoint")
            def dispatch(self, repository, workflow, values):
                if workflow != "build-windows-release.yml":
                    raise AssertionError("Wrong retry workflow")
                document = crypto.parse(crypto.open_message(values["request"], private,
                    protocol.message_context(values["release_id"], values["salt"])))
                calls.append(protocol.verified(document, verify))
                return {"workflow_run_id": 99}
        with tempfile.TemporaryDirectory() as folder:
            env = {"GITHUB_REPOSITORY": protocol.SOURCE, "GITHUB_REPOSITORY_ID": str(protocol.IDS[protocol.SOURCE]),
                   "RELEASE_ENABLED": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main",
                   "GITHUB_SHA": "b" * 40, "BUILDER_COMMIT_SHA": "a" * 40,
                   "GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "1", "SDK_RELEASE_PLATFORMS": "windows",
                   "SOURCE_TOKEN": "fixture", "BUILDER_DISPATCH_TOKEN": "fixture",
                   "REQUEST_SIGNING_PRIVATE_KEY": signing, "BUILDER_INPUT_PUBLIC_KEY": public,
                   "ARTIFACT_ENCRYPTION_PUBLIC_KEY": public, "GITHUB_STEP_SUMMARY": str(Path(folder) / "summary")}
            event = {"repository": {"private": True}, "inputs": {"source_tag": "v0.2.5-windows"}}
            with patch.dict(os.environ, env), patch.object(tasks, "event", return_value=event), patch.object(tasks, "Client", Api):
                tasks.request()
            payload = calls[-1]
            self.assertEqual(payload["version"], 3)
            self.assertEqual(payload["requester_sha"], "b" * 40)
            self.assertEqual(payload["source_sha"], "c" * 40)
            self.assertEqual(payload["source_tag"], "v0.2.5-windows")

    def test_ready_checkpoint_is_bound_to_the_repaired_contract(self):
        cfg = self.configuration()
        self.assertEqual(cef_contract.build_key(cfg, "windows"),
                         "60a369f6b051ba651cb301af299e7dadcc99608d0db6894bccab87b953817602")
        proof = windows_sdk.binding(cfg)
        windows_sdk.validate_binding(proof, cfg)
        from secure_release import cef_cache
        for record in (cef_cache.WINDOWS_RELEASE_BINARY_CACHE, cef_cache.JOINT_COMPLETED_BINARY_CACHES['windows'],
                       cef_cache.RELEASE_050_BINARY_CACHES['windows'], cef_cache.RELEASE_051_BINARY_CACHES['windows'],
                       cef_cache.RELEASE_052_WINDOWS_PACKAGE_CONTINUATION, cef_cache.RELEASE_052_RC4_PACKAGE_CACHES['windows'],
                       cef_cache.RELEASE_052_RC6_PACKAGE_CACHES['windows'],
                       cef_cache.RELEASE_052_RC10_PACKAGE_CACHES['windows'],
                       cef_cache.RELEASE_061_WINDOWS_PACKAGE_CONTINUATION):
            cached = copy.deepcopy(cfg)
            cached['platforms']['windows']['binary_cache'] = {name: record[name] for name in ('run', 'attempt', 'artifact_id', 'artifact_sha256')}
            windows_sdk.validate_binding(windows_sdk.binding(cached), cached)
            cached['platforms']['windows']['binary_cache']['artifact_sha256'] = '0'*64
            with self.assertRaises(ValueError):
                windows_sdk.binding(cached)
        for field in ("run", "artifact_id", "artifact_sha256"):
            altered = copy.deepcopy(cfg)
            altered["platforms"]["windows"]["checkpoint"][field] = 1 if field != "artifact_sha256" else "a" * 64
            with self.assertRaises(ValueError):
                windows_sdk.binding(altered)
        for field in ("checkpoint", "source_repair", "base_build_key"):
            altered = copy.deepcopy(proof)
            altered[field] = None
            with self.assertRaises(ValueError):
                windows_sdk.validate_binding(altered, cfg)

    def test_windows_workflow_requires_sdk_before_publication(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / ".github/workflows/build-windows-release.yml").read_text()
        self.assertNotIn("matrix:", text)
        self.assertIn("TARGET_PLATFORM: windows", text)
        self.assertIn("steps.build-sdk.outputs.sdk_ready != 'true'", text)
        self.assertIn("Build static Windows SDK", (root / ".github/workflows/request-publication.yml").read_text())

    def test_windows_only_signed_sdk_verification_and_scope_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private, public = crypto.generate("encrypt")
            signing, verify = crypto.generate("sign")
            now = int(time.time())
            payload = {"version": 2, "platforms": ["windows"], "source_tag": "v0.2.5-windows",
                       "source_sha": "b" * 40, "builder_sha": "a" * 40,
                       "release_id": str(uuid.uuid4()), "salt": crypto.b64(os.urandom(32)),
                       "request_run": 1, "request_attempt": 1, "created": now, "expires": now + 300,
                       "output_key": crypto.fingerprint(public), "input_key": "0" * 64,
                       "source_id": protocol.IDS[protocol.SOURCE], "builder_id": protocol.IDS[protocol.BUILDER],
                       "bin_id": protocol.IDS[protocol.BIN],
                       "plan": {"version": 1, "upstream_sha": "c" * 40, "smoke_path": "ci/smoke",
                                "ports": [{"name": "test", "repository": "dobord/test", "sha": "d" * 40}],
                                "platforms": {p: {"packages": ["test"]} for p in ("linux", "windows")}}}
            signed = crypto.sign(payload, signing)
            protocol.verified(signed, verify)
            with self.assertRaisesRegex(ValueError, "Windows release tag"):
                protocol.verified(crypto.sign(dict(payload, platforms=["linux"]), signing), verify)
            bundle = root / "bundle"
            bundle.mkdir()
            with zipfile.ZipFile(bundle / "sdk.zip", "w") as sdk:
                sdk.writestr("scripts/buildsystems/vcpkg.cmake", "# toolchain\n")
                sdk.writestr("installed/x64-windows-static-release/lib/test.lib", b"!<arch>\n")
            manifest = {"version": 1, "platform": "windows", "triplet": "x64-windows-static-release",
                        "builder_sha": "a" * 40, "source_sha": "b" * 40, "upstream_sha": "c" * 40,
                        "build_run": 99, "build_attempt": 1,
                        "sdk_sha256": crypto.digest(bundle / "sdk.zip"),
                        "request_sha256": hashlib.sha256(crypto.canonical(signed)).hexdigest()}
            (bundle / "manifest.json").write_bytes(crypto.canonical(manifest))
            (bundle / "request.json").write_bytes(crypto.canonical(signed))
            safeio.pack_tar(bundle, root / "bundle.tgz")
            crypto.encrypt_file(root / "bundle.tgz", root / "sdk.enc", public,
                                protocol.file_context(payload["release_id"], payload["salt"], 99, 1,
                                                      "a" * 40, "sdk", "windows"))
            transport = root / "artifact.zip"
            with zipfile.ZipFile(transport, "w") as archive:
                archive.write(root / "sdk.enc", "sdk.enc")
            artifact = {"id": 12, "name": "sdk-windows-99-1", "expired": False,
                        "digest": "sha256:" + crypto.digest(transport),
                        "workflow_run": {"id": 99, "head_sha": "a" * 40}}

            class Api:
                downloads = []
                inventory = [artifact]
                def artifacts(self, repo, run):
                    return self.inventory
                def download(self, endpoint, destination, expected):
                    self.downloads.append(endpoint)
                    destination.write_bytes(transport.read_bytes())
                    assert crypto.digest(destination) == expected

            api = Api()
            env = {"RUNNER_TEMP": str(root), "STAGING_DIR": str(root / "staging"),
                   "GITHUB_OUTPUT": str(root / "outputs"), "ARTIFACT_DECRYPTION_PRIVATE_KEY": private,
                   "ARTIFACT_ENCRYPTION_PUBLIC_KEY": public, "REQUEST_VERIFY_PUBLIC_KEY": verify}
            with (patch.dict(os.environ, env), patch.object(publish, "_trusted_builder_result",
                  return_value=(api, 99, 1, "a" * 40, "build-windows-release.yml"))):
                publish.verify_result()
                release = crypto.parse((root / "staging/release-manifest.json").read_bytes())
                self.assertEqual(release["release_platforms"], ["windows"])
                self.assertEqual(set(release["platforms"]), {"windows"})
                self.assertEqual({p.name for p in (root / "staging").iterdir()}, {
                    "vcpkg-v0.2.5-windows-x64-static-release.zip", "release-manifest.json", "SHA256SUMS"})
                self.assertEqual(api.downloads, [f"/repos/{protocol.BUILDER}/actions/artifacts/12/zip"])
                api.inventory = [artifact, dict(artifact, id=13, name="sdk-linux-99-1")]
                env["STAGING_DIR"] = str(root / "bad-staging")
                with patch.dict(os.environ, env), self.assertRaisesRegex(ValueError, "unrequested platform"):
                    publish.verify_result()


if __name__ == "__main__":
    unittest.main()
