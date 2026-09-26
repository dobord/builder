"""Real-codec and orchestrator regressions for combined image identity reuse."""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from secure_release import cef_combined_identity as identity
from secure_release import cef_native_link_static as native
from secure_release import cef_strict_combined as combined
from secure_release import cef_strict_iteration as engine

ACTUAL = "20260920.314.1"
LOGICAL = "20260907.300.1"
HOST = {"schema": 1, "os_id": "ubuntu", "os_version_id": "24.04",
        "machine": "x86_64", "glibc": "2.39", "gcc14": "14.2.0",
        "gxx14": "14.2.0", "binutils": "2.42", "pkg_config": "1.8.1",
        "bison": "3.8.2", "ninja": "1.13.2", "ccache": "4.9.1"}


class SummaryAPI:
    """Disposable public summary ZIP; exercise the REAL producer validator."""
    def __init__(self, mutate=None):
        value = {
            "schema": 1, "status": "success", "ready": True,
            "runtime_verified": True, "checkpoint_ready": True,
            "platform_graph_qualified": True, "gn_graph_qualified": True,
            "build_key": "b" * 64, "platform_sha256": "c" * 64,
            "vcpkg_commit": engine.VCPKG, "cef_recipe_commit": engine.CEF,
            "progress": {"engine_compilation_complete": True},
            "critical_host_fingerprint": deepcopy(HOST),
            "checkpoint_image_identity": LOGICAL,
        }
        if mutate:
            mutate(value)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("cef-strict-iteration-summary.json", json.dumps(value))
        self.payload = stream.getvalue()
        sha = hashlib.sha256(self.payload).hexdigest()
        self.selected = {
            "run": 101, "attempt": 1, "producer_sha": "a" * 40,
            "artifact_id": 201, "artifact_sha256": "d" * 64,
            "summary_artifact_id": 301, "summary_artifact_sha256": sha,
            "build_key": "b" * 64, "platform_sha256": "c" * 64,
        }
        self.metadata = {
            "id": 301, "name": "cef-strict-iteration-summary-101-1",
            "expired": False, "digest": "sha256:" + sha,
            "workflow_run": {"id": 101, "head_sha": "a" * 40},
        }
        self.downloads = 0

    def artifacts(self, repository, run):
        assert (repository, run) == ("dobord/builder", 101)
        return [deepcopy(self.metadata)]

    def download(self, endpoint, destination, sha, *, max_size):
        assert endpoint == "/repos/dobord/builder/actions/artifacts/301/zip"
        assert max_size == 4 * 1024**2
        if hashlib.sha256(self.payload).hexdigest() != sha:
            raise ValueError("Fixture digest mismatch")
        destination.write_bytes(self.payload)
        self.downloads += 1


class EnvironmentTests(unittest.TestCase):
    def test_verified_host_uses_logical_image_only_in_copy(self):
        api, report = SummaryAPI(), {}
        env = {"ImageVersion": ACTUAL, "PATH": "fixture-path", "OTHER": "kept"}
        before = dict(env)
        with mock.patch.dict(os.environ, {"ImageVersion": ACTUAL}), \
             mock.patch.object(engine, "critical_host_fingerprint", return_value=deepcopy(HOST)):
            result = identity.prepare_environment(api.selected, env, report, api=api)
            self.assertEqual(os.environ["ImageVersion"], ACTUAL)
        self.assertEqual(env, before)
        self.assertIsNot(result, env)
        self.assertEqual(result, dict(before, ImageVersion=LOGICAL))
        self.assertTrue(report["checkpoint_host_verified"])
        self.assertTrue(report["runner_image_migrated"])
        self.assertEqual(report["runner_image_actual"], ACTUAL)
        self.assertEqual(report["checkpoint_image_identity"], LOGICAL)
        self.assertEqual(api.downloads, 1)

    def test_incompatible_tool_rejected_even_if_image_label_is_unchanged(self):
        for actual in (ACTUAL, LOGICAL):
            for name in HOST.keys() - {"schema"}:
                with self.subTest(actual=actual, field=name):
                    api, report = SummaryAPI(), {}
                    current = dict(HOST, **{name: "999.0"})
                    with mock.patch.dict(os.environ, {"ImageVersion": actual}), \
                         mock.patch.object(engine, "critical_host_fingerprint", return_value=current):
                        with self.assertRaises(ValueError):
                            identity.prepare_environment(api.selected, {"ImageVersion": actual}, report, api=api)
                    self.assertIs(report["checkpoint_host_verified"], False)

    def test_incomplete_compilation_runtime_and_untrusted_provenance_rejected(self):
        mutations = (
            lambda v: v.update(runtime_verified=False),
            lambda v: v.update(ready=False),
            lambda v: v.update(status="failed"),
            lambda v: v.update(progress={"engine_compilation_complete": False}),
            lambda v: v.pop("progress"),
            lambda v: v.update(critical_host_fingerprint=None),
            lambda v: v["critical_host_fingerprint"].update(schema=True),
            lambda v: v["critical_host_fingerprint"].update(ninja="unbounded\nprivate-text"),
            lambda v: v.update(checkpoint_image_identity="unknown-image"),
        )
        for mutate in mutations:
            api, report = SummaryAPI(mutate), {}
            with mock.patch.dict(os.environ, {"ImageVersion": ACTUAL}), \
                 mock.patch.object(engine, "critical_host_fingerprint", return_value=deepcopy(HOST)):
                with self.assertRaises(ValueError):
                    identity.prepare_environment(api.selected, {"ImageVersion": ACTUAL}, report, api=api)
            self.assertFalse(report["checkpoint_host_verified"])
        api = SummaryAPI()
        api.metadata["workflow_run"]["head_sha"] = "0" * 40
        with mock.patch.dict(os.environ, {"ImageVersion": ACTUAL}):
            with self.assertRaisesRegex(ValueError, "provenance mismatch"):
                identity.prepare_environment(api.selected, {"ImageVersion": ACTUAL}, {}, api=api)
        self.assertEqual(api.downloads, 0)

    def test_missing_token_inconsistent_environment_and_corrupted_summary_fail(self):
        api = SummaryAPI()
        with mock.patch.dict(os.environ, {"ImageVersion": ACTUAL}):
            with self.assertRaisesRegex(ValueError, "inconsistent"):
                identity.prepare_environment(api.selected, {"ImageVersion": LOGICAL}, {}, api=api)
            api.payload += b"tamper"
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                identity.prepare_environment(api.selected, {"ImageVersion": ACTUAL}, {}, api=api)
        with mock.patch.dict(os.environ, {"ImageVersion": ACTUAL}, clear=True):
            with self.assertRaisesRegex(ValueError, "GITHUB_TOKEN"):
                identity.prepare_environment(api.selected, {"ImageVersion": ACTUAL}, {})


class CombinedOrchestrationTests(unittest.TestCase):
    def exercise(self, incompatible=False, source_unavailable=False):
        api = SummaryAPI()
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder).resolve()
            workspace, temp = root / "workspace", root / "temp"
            temp.mkdir()
            registry = workspace / "private-vcpkg"
            (registry / "ci").mkdir(parents=True)
            (registry / "ci/release-plan.json").write_text(json.dumps({"cef": {
                "profile": "static-third-party", "platforms": {"linux": {"mode": "source-fresh"}},
                "recipe_commit": engine.CEF,
            }}))
            heads = {registry: combined.SDK_VCPKG,
                     workspace / "private-engine-vcpkg": combined.ENGINE_VCPKG,
                     registry / ".full-upstream": combined.UPSTREAM,
                     registry / ".full-cef": engine.CEF,
                     workspace / "private-lockfreecoro": combined.LOCKFREECORO,
                     workspace / "private-lfc-ui": combined.LFC_UI}
            events = []
            stack.enter_context(mock.patch.object(combined.sys, "platform", "linux"))
            stack.enter_context(mock.patch.dict(os.environ, {
                "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(temp),
                "ImageVersion": ACTUAL, "GITHUB_TOKEN": "disposable-test-token",
                "BUILDER_INPUT_PRIVATE_KEY": "fixture-never-decrypted",
            }))
            # Exercise Linux-only main on Windows too. Windows uppercases its
            # process-environment keys; provide the real Linux ImageVersion spelling.
            clean = combined.clean_environment
            stack.enter_context(mock.patch.object(combined, "clean_environment",
                                                  side_effect=lambda: dict(clean(), ImageVersion=ACTUAL)))
            stack.enter_context(mock.patch.object(combined, "git_head", side_effect=heads.__getitem__))
            stack.enter_context(mock.patch.object(combined, "verify_engine_registry_delta"))
            stack.enter_context(mock.patch.object(combined.cef_sdk_example, "capture", return_value={}))
            stack.enter_context(mock.patch.object(combined.cef_sdk_protoc, "validate_sources"))
            stack.enter_context(mock.patch.object(combined.cef_contract, "validate"))
            stack.enter_context(mock.patch.object(combined.cef_contract, "build_key", return_value="b"*64))
            stack.enter_context(mock.patch.object(engine, "qualification_lock", return_value={"checkpoint": api.selected}))
            stack.enter_context(mock.patch.object(identity, "Client", return_value=api))
            current = dict(HOST, ninja="99.0.0") if incompatible else deepcopy(HOST)
            def fingerprint():
                events.append("host")
                return current
            stack.enter_context(mock.patch.object(engine, "critical_host_fingerprint", side_effect=fingerprint))
            def prefetch(actual_registry, upstream, root, env, summary):
                self.assertEqual(actual_registry, registry)
                self.assertEqual(upstream, registry / ".full-upstream")
                self.assertEqual(env["ImageVersion"], ACTUAL)
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertNotIn("BUILDER_INPUT_PRIVATE_KEY", env)
                events.append("source-prefetch")
                if source_unavailable:
                    raise RuntimeError("fixture source transport unavailable")
            fetch = stack.enter_context(mock.patch.object(
                combined.cef_dependency_source, "prefetch", side_effect=prefetch))
            def unseal(selected, package, build_key, key, *, allow_resumable):
                self.assertIs(allow_resumable, False)
                self.assertEqual(selected, api.selected)
                events.append("authenticated-transport")
            transport = stack.enter_context(mock.patch.object(engine, "restore_checkpoint", side_effect=unseal))
            def recipe(*args):
                events.append("recipe")
                return {"profile": "native-link-v1", "recorded_recipe_matched": True}
            stack.enter_context(mock.patch.object(native, "prepare_restore", side_effect=recipe))
            def driver(command, **kwargs):
                self.assertEqual(command[2], "restore")
                self.assertEqual(command[1], registry / ".full-cef/vcpkg/integration/driver.py")
                self.assertEqual(kwargs["env"]["ImageVersion"], LOGICAL)
                self.assertEqual(kwargs["env"]["GITHUB_SHA"], engine.CEF)
                self.assertEqual(os.environ["ImageVersion"], ACTUAL)
                self.assertEqual(combined.clean_environment()["ImageVersion"], ACTUAL)
                self.assertNotIn("GITHUB_TOKEN", kwargs["env"])
                self.assertNotIn("BUILDER_INPUT_PRIVATE_KEY", kwargs["env"])
                events.append("unchanged-driver")
                raise RuntimeError("fixture driver rejection remains fatal")
            step = stack.enter_context(mock.patch.object(combined, "run", side_effect=driver))
            with self.assertRaises((ValueError, RuntimeError)):
                combined.main()
            value = json.loads((temp / "cef-strict-combined-summary.json").read_bytes())
            self.assertEqual(value["status"], "failed")
            self.assertIs(value["runtime_verified"], False)
            if incompatible:
                fetch.assert_not_called()
                transport.assert_not_called()
                step.assert_not_called()
                self.assertEqual(events, ["host"])
                self.assertEqual(value["failure_stage"], "checkpoint-host-identity")
            elif source_unavailable:
                transport.assert_not_called()
                step.assert_not_called()
                self.assertEqual(events, ["host", "source-prefetch"])
                self.assertEqual(value["failure_stage"], "dependency-source-prefetch")
            else:
                self.assertEqual(events, ["host", "source-prefetch", "authenticated-transport", "recipe", "unchanged-driver"])
                self.assertEqual(value["failure_stage"], "checkpoint-restore")
                self.assertEqual(value["runner_image_actual"], ACTUAL)
                self.assertEqual(value["checkpoint_image_identity"], LOGICAL)
                self.assertTrue(value["checkpoint_host_verified"])

    def test_actual_main_orders_review_unseal_recipe_driver_and_keeps_failure_fatal(self):
        self.exercise()

    def test_actual_main_rejects_host_before_large_download(self):
        self.exercise(incompatible=True)

    def test_actual_main_rejects_unavailable_source_before_large_download(self):
        self.exercise(source_unavailable=True)


def _codec_roundtrip(snapshot: Path):
    """Exercise the unchanged pinned codec, not a simulated identity comparison."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        recipe_repo = root / "recipe"
        shutil.copytree(snapshot / "vcpkg", recipe_repo / "vcpkg")
        sys.path.insert(0, str(recipe_repo / "vcpkg/static"))
        import linux_checkpoint as codec
        assert native.git_blob((recipe_repo / "vcpkg/static/linux_checkpoint.py").read_bytes()) == native.CHECKPOINT_POLICY_BLOB
        recipe = recipe_repo / "vcpkg/ports/cef-static/source_build.py"
        original = recipe.read_bytes()
        recipe.write_bytes(native.reviewed_output(original, native.RECIPE_BLOB,
                           native.patch_recipe, native.unpatch_recipe, "CEF recipe"))
        work, package = root / "work", root / "package"
        work.mkdir()
        obj = work / "preserved.o"
        obj.write_bytes(b"disposable-object-not-real-engine")
        clock = 1700000000000000123
        os.utime(obj, ns=(clock, clock))
        os.environ.update(ImageVersion=LOGICAL, GITHUB_REPOSITORY="dobord/builder",
                          GITHUB_REF="refs/heads/feature/cef-static-integration")
        recorded = codec.ci_identity(work)
        codec.save(work, package, recorded)
        manifest = (package / "checkpoint.json").read_bytes()
        shutil.rmtree(work)
        # Recreate precisely the #65 condition: recipe matches but actual image
        # is used instead of the reviewed historical checkpoint image.
        os.environ["ImageVersion"] = ACTUAL
        before = codec.ci_identity(work)
        assert [k for k in before if before[k] != recorded[k]] == ["image"]
        try:
            codec.restore(package, work, before)
        except ValueError as error:
            assert "identity/schema mismatch" in str(error)
        else:
            raise AssertionError("Mismatching image incorrectly restored")
        assert not work.exists()
        # Authentic transport is represented by this disposable local package;
        # recipe hashing/reconstruction and codec save/restore are real.
        recipe.write_bytes(original)
        with mock.patch.object(native, "_head", return_value=native.CEF_RECIPE):
            native.prepare_restore(recipe, package)
        api, report = SummaryAPI(), {}
        with mock.patch.object(engine, "critical_host_fingerprint", return_value=deepcopy(HOST)):
            child = identity.prepare_environment(api.selected, dict(os.environ), report, api=api)
        assert os.environ["ImageVersion"] == ACTUAL
        with mock.patch.dict(os.environ, child, clear=True):
            after = codec.ci_identity(work)
        assert after == recorded
        assert (package / "checkpoint.json").read_bytes() == manifest
        codec.restore(package, work, after)
        assert obj.read_bytes() == b"disposable-object-not-real-engine"
        assert obj.stat().st_mtime_ns == clock
        shutil.rmtree(work)
        for field in ("image", "recipe", "ref", "repository", "work"):
            try:
                codec.restore(package, work, dict(after, **{field: "unreviewed"}))
            except ValueError as error:
                assert "identity/schema mismatch" in str(error)
            else:
                raise AssertionError("Full identity validation was bypassed")
            assert not work.exists()
        assert (package / "checkpoint.json").read_bytes() == manifest


class PinnedCodecTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Native Linux checkpoint codec")
    def test_same_real_codec_rejects_actual_label_then_restores_reviewed_identity(self):
        builder = Path(__file__).resolve().parents[1]
        snapshot = Path(os.environ.get("CEF_NATIVE_LINK_RECIPE_FIXTURE",
                                      builder / "private-vcpkg/.full-cef")).resolve()
        if not (snapshot / "vcpkg/static/linux_checkpoint.py").is_file():
            if os.environ.get("REQUIRE_CEF_COMBINED_IDENTITY_FIXTURE") == "1":
                self.fail("Combined preflight must supply the pinned checkpoint recipe")
            self.skipTest("Pinned recipe is supplied by combined engine preflight")
        script = ("import runpy,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                  "runpy.run_path(sys.argv[2])['_codec_roundtrip'](Path(sys.argv[3]))")
        result = subprocess.run([sys.executable, "-I", "-c", script, str(builder),
                                 __file__, str(snapshot)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_workflow_preflight_is_required_and_writes_trigger_qualification(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/cef-strict-combined.yml").read_text()
        self.assertIn("- secure_release/cef_combined_identity.py", workflow)
        self.assertIn("- tests/test_cef_combined_identity.py", workflow)
        self.assertIn("REQUIRE_CEF_COMBINED_IDENTITY_FIXTURE: '1'", workflow)
        self.assertLess(workflow.index("-p test_cef_combined_identity.py"),
                        workflow.index("run: python -m secure_release.cef_strict_combined"))


if __name__ == "__main__":
    unittest.main()
