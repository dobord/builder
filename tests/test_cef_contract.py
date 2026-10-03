"""Synthetic acquisition plans; no private repositories or keys are used."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from secure_release import cef_contract as contract, cef_build, build_support, tasks
from secure_release.protocol import validate_plan


def config():
    return {"schema": 1, "recipe_commit": "a" * 40, "profile": "engine-static",
            "release_lock": None, "slice_seconds": 9000, "jobs": 4,
            "platforms": {p: {"mode": "source-fresh", "checkpoint": None, "binary_cache": None}
                          for p in ("linux", "windows")}}


def selection():
    return {"run": 12, "attempt": 1, "artifact_id": 456, "artifact_sha256": "d" * 64}


def release_lock():
    return {
        "schema": 1,
        "tag": "cef-locked",
        "tested_commit": "b" * 40,
        "platforms": {
            "x64-linux-static-release": {
                "source_triplet": "x64-linux",
                "manifest": {
                    "name": "linux.manifest.json",
                    "size": 1024,
                    "sha256": "1" * 64,
                },
            },
            "x64-windows-static-release": {
                "source_triplet": "x64-windows-static",
                "manifest": {
                    "name": "windows.manifest.json",
                    "size": 1024,
                    "sha256": "2" * 64,
                },
            },
        },
    }



class ContinuationAPI:
    def __init__(self, builder_sha="b" * 40, include_binary=True):
        self.builder_sha = builder_sha
        self.include_binary = include_binary
        self.assert_repo = None

    def get(self, path):
        if "/attempts/" in path:
            attempt = int(path.rsplit("/", 1)[1])
            return {"repository": {"id": 1372874997}, "head_repository": {"id": 1372874997},
                    "path": ".github/workflows/build-release.yml", "head_sha": self.builder_sha,
                    "run_attempt": attempt, "event": "workflow_dispatch",
                    "status": "completed", "conclusion": "failure"}
        return {"run_attempt": 2, "status": "completed"}

    def artifacts(self, repo, run):
        self.assert_repo = repo
        values = [{
            "id": 1001, "name": f"cef-checkpoint-linux-{run}-2", "expired": False,
            "digest": "sha256:" + "c" * 64,
            "workflow_run": {"id": run, "head_sha": self.builder_sha},
        }]
        if self.include_binary:
            values.append({
                "id": 1002, "name": f"vcpkg-binaries-linux-{run}-2", "expired": False,
                "digest": "sha256:" + "d" * 64,
                "workflow_run": {"id": run, "head_sha": self.builder_sha},
            })
        return values

class ContractTests(unittest.TestCase):
    def test_native_triplets(self):
        for p in ("linux", "windows"):
            self.assertEqual(contract.port_contract(config(), p)["triplet"], f"x64-{p}-static-release")

    def test_resume_is_not_an_abi_change(self):
        cfg = config()
        original = contract.build_key(cfg, "linux")
        cfg["platforms"]["linux"].update(mode="source-resume", checkpoint=selection(), binary_cache=selection())
        cfg.update(jobs=1, slice_seconds=12)
        self.assertEqual(contract.build_key(cfg, "linux"), original)

    def test_semantic_changes_invalidate(self):
        cfg = config()
        original = contract.build_key(cfg, "linux")
        cfg["recipe_commit"] = "b" * 40
        self.assertNotEqual(contract.build_key(cfg, "linux"), original)
        cfg = config()
        cfg["profile"] = "static-third-party"
        strict_a = contract.build_key(cfg, "linux", "1" * 64)
        strict_b = contract.build_key(cfg, "linux", "2" * 64)
        self.assertNotEqual(strict_a, strict_b)
        self.assertNotEqual(strict_a, original)

    def test_strict_profile_requires_source_builds_on_both_platforms(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        contract.validate(cfg)
        with self.assertRaises(ValueError):
            contract.build_key(cfg, "linux")
        self.assertEqual(
            contract.port_contract(cfg, "linux", "a" * 64)["platform_sha256"],
            "a" * 64)
        windows = contract.port_contract(cfg, "windows")
        self.assertEqual(windows["mode"], "source")
        self.assertIsNone(windows["platform_sha256"])
        self.assertIsNone(windows["release_lock"])

        for platform in ("linux", "windows"):
            bad = copy.deepcopy(cfg)
            bad["platforms"][platform]["mode"] = "release-import"
            bad["release_lock"] = release_lock()
            with self.subTest(platform=platform), self.assertRaises(ValueError):
                contract.validate(bad)

    def test_strict_windows_release_import_is_rejected(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        cfg["platforms"]["windows"]["mode"] = "release-import"
        cfg["release_lock"] = release_lock()
        with self.assertRaises(ValueError):
            contract.validate(cfg)

    def test_explicit_resume_only(self):
        cfg = config()
        cfg["platforms"]["linux"]["mode"] = "source-resume"
        with self.assertRaises(ValueError):
            contract.validate(cfg)
        cfg["platforms"]["linux"].update(mode="source-fresh", checkpoint=selection())
        with self.assertRaises(ValueError):
            contract.validate(cfg)

    def test_bad_values(self):
        for key, value in (("schema", True), ("jobs", True), ("jobs", 0), ("jobs", 65),
                           ("slice_seconds", 10801), ("recipe_commit", "main"), ("profile", "auto")):
            cfg = config()
            cfg[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                contract.validate(cfg)

    def test_missing_platform_and_unknown_field(self):
        cfg = config()
        del cfg["platforms"]["windows"]
        with self.assertRaises(ValueError):
            contract.validate(cfg)
        cfg = config()
        cfg["command"] = "unreviewed"
        with self.assertRaises(ValueError):
            contract.validate(cfg)

    def test_release_requires_lock(self):
        cfg = config()
        cfg["platforms"]["linux"]["mode"] = "release-import"
        with self.assertRaises(ValueError):
            contract.validate(cfg)

    def test_cache_selector_types(self):
        for key, value in (("run", True), ("attempt", 0), ("artifact_id", "42"), ("artifact_sha256", "latest")):
            sel = selection()
            sel[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                contract.selector(sel)

    def test_schema_two_and_legacy(self):
        plan = {"version": 1, "upstream_sha": "b" * 40,
                "ports": [{"name": "example", "repository": "dobord/example", "sha": "c" * 40}],
                "platforms": {p: {"packages": ["example"]} for p in ("linux", "windows")},
                "smoke_path": "ci/smoke"}
        validate_plan(plan)
        plan.update(version=2, cef=config())
        with self.assertRaises(ValueError):
            validate_plan(plan)
        for row in plan["platforms"].values():
            row["packages"].append("cef-static")
        validate_plan(plan)
        strict = copy.deepcopy(plan)
        strict["cef"]["profile"] = "static-third-party"
        for row in strict["platforms"].values():
            row["packages"][-1] = "cef-static[strict-platform]"
        validate_plan(strict)
        strict["platforms"]["linux"]["packages"][-1] = "cef-static"
        with self.assertRaises(ValueError):
            validate_plan(strict)
        plan["version"] = 1
        del plan["cef"]
        with self.assertRaises(ValueError):
            validate_plan(plan)

    def test_materialized_before_install(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            port = root / "ports/cef-static"
            port.mkdir(parents=True)
            (port / "portfile.cmake").write_text("# fixture\n")
            key = cef_build.materialize(root, config(), "linux")
            self.assertEqual(key, contract.build_key(config(), "linux"))
            self.assertEqual(json.loads((port / "cef-build.json").read_text()), contract.port_contract(config(), "linux"))
            strict = config(); strict["profile"] = "static-third-party"
            key = cef_build.materialize(root, strict, "linux", "f" * 64)
            self.assertEqual(key, contract.build_key(strict, "linux", "f" * 64))

    def test_source_capacity_rejects_standard_hosted_disk_before_build(self):
        cfg = config()
        usage = type("Usage", (), {"free": 14 * 1024**3})()
        with patch.object(cef_build.shutil, "disk_usage", return_value=usage):
            with self.assertRaisesRegex(RuntimeError, "80 GiB"):
                cef_build.require_source_capacity(Path("/tmp"), cfg, "linux")
        usage = type("Usage", (), {"free": 80 * 1024**3})()
        with patch.object(cef_build.shutil, "disk_usage", return_value=usage):
            cef_build.require_source_capacity(Path("/tmp"), cfg, "linux")
            cef_build.require_source_capacity(Path("/tmp"), cfg, "windows")

    def test_no_credentials_in_worker_environment(self):
        with patch.dict("os.environ", {"GITHUB_TOKEN": "secret", "GITHUB_RUN_ID": "12", "GITHUB_REF": "refs/heads/main"}):
            env = cef_build.worker_environment({}, "a" * 40)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertEqual(env["GITHUB_RUN_ID"], "12")

    def test_cache_option_is_not_overridden_by_clear(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(build_support, "native_host_triplet", return_value="x64-linux-static-release"):
            args = build_support.install_command("vcpkg", ["example"], [], binary_cache=Path(folder).resolve())
            choices = [a for a in args if a.startswith("--binarysource=")]
            self.assertEqual(len(choices), 1)
            self.assertTrue(choices[0].endswith(",readwrite"))
            self.assertNotIn("--binarysource=clear", args)


    def test_explicit_continuation_resolves_github_artifact_digests(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        plan = {"version": 2, "upstream_sha": "e" * 40,
                "ports": [{"name": "example", "repository": "dobord/example", "sha": "f" * 40}],
                "platforms": {"linux": {"packages": ["example", "cef-static[strict-platform]"]},
                              "windows": {"packages": ["example", "cef-static[strict-platform]"]}},
                "smoke_path": "ci/smoke", "cef": cfg}
        api = ContinuationAPI()
        result = tasks._apply_continuation(
            plan, {"linux_builder_run": "42", "linux_builder_attempt": "2",
                   "windows_builder_run": "", "windows_builder_attempt": ""},
            "b" * 40, api)
        selected = result["cef"]["platforms"]["linux"]
        self.assertEqual(selected["mode"], "source-resume")
        self.assertEqual(selected["checkpoint"],
                         {"run": 42, "attempt": 2, "artifact_id": 1001, "artifact_sha256": "c" * 64})
        self.assertEqual(selected["binary_cache"],
                         {"run": 42, "attempt": 2, "artifact_id": 1002, "artifact_sha256": "d" * 64})
        self.assertEqual(result["cef"]["platforms"]["windows"]["mode"], "source-fresh")
        self.assertEqual(api.assert_repo, "dobord/builder")
        self.assertEqual(plan["cef"]["platforms"]["linux"]["mode"], "source-fresh")

    def test_continuation_never_falls_back_or_crosses_builder_revision(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        plan = {"version": 2, "upstream_sha": "e" * 40,
                "ports": [{"name": "example", "repository": "dobord/example", "sha": "f" * 40}],
                "platforms": {"linux": {"packages": ["example", "cef-static[strict-platform]"]},
                              "windows": {"packages": ["example", "cef-static[strict-platform]"]}},
                "smoke_path": "ci/smoke", "cef": cfg}
        with self.assertRaises(ValueError):
            tasks._apply_continuation(
                plan, {"linux_builder_run": "42", "linux_builder_attempt": "",
                       "windows_builder_run": "", "windows_builder_attempt": ""},
                "b" * 40, ContinuationAPI())
        with self.assertRaises(ValueError):
            tasks._apply_continuation(
                plan, {"linux_builder_run": "42", "linux_builder_attempt": "2",
                       "windows_builder_run": "", "windows_builder_attempt": ""},
                "b" * 40, ContinuationAPI(builder_sha="a" * 40))
        with self.assertRaises(ValueError):
            tasks._apply_continuation(
                plan, {"linux_builder_run": "", "linux_builder_attempt": "",
                       "windows_builder_run": "", "windows_builder_attempt": ""},
                "b" * 40, ContinuationAPI())

    def test_checkpoint_iteration_persists_completed_package_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = root / "cache"
            cache.mkdir()
            (cache / "package.zip").write_bytes(b"binary-cache-fixture")
            contexts = []
            with patch.dict("os.environ", {
                    "RUNNER_TEMP": str(root / "runner"),
                    "GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_SHA": "b" * 40, "GITHUB_OUTPUT": str(root / "output")}):
                with patch.object(tasks.crypto, "public_text", return_value="public"), \
                     patch.object(tasks.cef_cache, "seal",
                                  side_effect=lambda source, target, public, context: contexts.append(context)), \
                     patch.object(tasks.cef_build, "write_output") as output:
                    self.assertTrue(tasks._persist_binary_cache(
                        cache, "a" * 64, "linux", "private"))
            self.assertEqual(len(contexts), 1)
            self.assertEqual(contexts[0], tasks.cef_cache.context(
                "vcpkg-binaries", "linux", "a" * 64, 77, 1, "b" * 40, "index"))
            output.assert_called_once_with("binary_cache_ready", True)

    def test_missing_runtime_evidence_is_rejected(self):
        for proof in ({}, {"schema": 1}, {"kind": "engine-iteration", "ready": True}):
            with self.assertRaises(ValueError):
                cef_build.validate_evidence(proof, config(), "linux")

if __name__ == "__main__":
    unittest.main()
