"""Synthetic contracts for a separate, credential-free consumer contour."""
import copy
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import shutil
import zipfile
from unittest import mock

from secure_release import consumer_ci as consumer, crypto, consumer_ci_operator as operator


def request():
    return {
        "schema": 1, "request_id": "00000000-0000-4000-8000-000000000001",
        "source": "dobord/synthetic-consumer", "source_id": 123, "operator_id": 5323024,
        "source_sha": "a" * 40, "base_sha": "b" * 40, "builder_sha": "c" * 40, "pr": 1,
        "created": int(time.time()) - 10, "expires": int(time.time()) + 3600,
        "input_ref": "refs/tags/consumer-input-00000000-0000-4000-8000-000000000001",
        "input_commit": "d" * 40, "input_blob": "e" * 40, "source_cipher_digest": "f" * 64,
    }


def policy():
    return {
        "schema": 1, "repository": "dobord/synthetic-consumer", "repository_id": 123,
        "operator_id": 5323024, "recipe_sha256": "0" * 64,
        "inputs": [
            {"name": "dependency.bundle", "kind": "git", "repository": "dobord/synthetic-library", "sha": "1" * 40},
            {"name": "sdk.zip", "kind": "asset", "repository": "dobord/synthetic-sdk",
             "tag": "v1.0.0", "asset": "sdk.zip", "sha256": "2" * 64, "max_bytes": 1024},
        ],
    }


class ConsumerContracts(unittest.TestCase):
    def test_strict_bounded_request_and_policy(self):
        consumer.validate_request(request())
        consumer.validate_policy(policy())

    def test_historical_validation_does_not_relax_live_dispatch_expiry(self):
        value = request()
        with mock.patch.object(consumer.time, "time", return_value=value["expires"] + 1):
            with self.assertRaises(ValueError):
                consumer.validate_request(value)
            consumer.validate_request(value, admitted_at=value["created"])
        for admitted in (True, -1, "2026-01-01", value["expires"] + 1):
            with self.subTest(admitted=admitted), self.assertRaises(ValueError):
                consumer.validate_request(value, admitted_at=admitted)

    def test_workflow_is_valid_yaml_and_token_is_prepare_only(self):
        import yaml
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/encrypted-consumer-ci.yml"
        value = yaml.load(workflow.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual({"workflow_dispatch"}, set(value["on"]))
        steps = value["jobs"]["prepare"]["steps"]
        self.assertTrue(any(step.get("env", {}).get("SOURCE_READ_TOKEN") == "${{ secrets.SOURCE_READ_TOKEN }}"
                            for step in steps))
        self.assertNotIn("SOURCE_READ_TOKEN", json.dumps(value["jobs"]["qualify"]))

    def test_request_rejects_unknown_fields_bad_types_expiry_and_ref(self):
        for change in ({"token": "no"}, {"pr": True}, {"source_id": True}, {"pr": -1},
                       {"source_sha": "main"}, {"expires": 1}, {"created": int(time.time()) + 1000},
                       {"expires": int(time.time()) + 30000}, {"input_ref": "refs/heads/main"},
                       {"source": "elsewhere/synthetic"}, {"operator_id": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                consumer.validate_request(dict(request(), **change))

    def test_policy_preserves_independent_boundary_and_resource_bounds(self):
        for change in ({"unknown": True}, {"operator_id": True}, {"recipe_sha256": "bad"},
                       {"inputs": []}, {"inputs": policy()["inputs"] * 8}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                consumer.validate_policy(dict(policy(), **change))
        for change in ({"name": "../escape"}, {"kind": "shell"}, {"sha": "main"},
                       {"repository": "unapproved/project"}, {"name": "sdk.zip"}):
            p = copy.deepcopy(policy())
            p["inputs"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                consumer.validate_policy(p)

    def test_recipe_requires_every_lane_once_and_exact_command_shape(self):
        recipe = {"schema": 1, "lanes": [
            {"id": name, "argv": ["bash", "ci/builder/qualify.sh", name], "timeout": 3600}
            for name in consumer.LANES]}
        self.assertEqual(consumer.validate_recipe(recipe), recipe["lanes"])
        for mutation in ("missing", "duplicate", "absolute", "unbounded", "unknown"):
            value = copy.deepcopy(recipe)
            if mutation == "missing":
                value["lanes"].pop()
            elif mutation == "duplicate":
                value["lanes"][0]["id"] = value["lanes"][1]["id"]
            elif mutation == "absolute":
                value["lanes"][0]["argv"][1] = "/tmp/script"
            elif mutation == "unbounded":
                value["lanes"][0]["timeout"] = 999999
            else:
                value["lanes"][0]["env"] = {"GH_TOKEN": "not-allowed"}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                consumer.validate_recipe(value)

    def test_only_complete_exact_run_can_qualify(self):
        value = request()
        run = {
            "repository": {"id": consumer.ci.BUILDER_ID}, "head_repository": {"id": consumer.ci.BUILDER_ID},
            "head_sha": value["builder_sha"], "path": ".github/workflows/" + consumer.WORKFLOW,
            "event": "workflow_dispatch", "run_attempt": 1, "status": "completed", "conclusion": "success",
            "display_title": "Encrypted consumer " + "0" * 64, "id": 100,
            "actor": {"id": value["operator_id"]}, "triggering_actor": {"id": value["operator_id"]},
            "html_url": "https://github.com/dobord/builder/actions/runs/100",
        }
        jobs = [{"name": name, "status": "completed", "conclusion": "success",
                 "run_id": 100, "head_sha": value["builder_sha"],
                 "steps": [{"name": "Authenticate consumer and prepare pinned inputs" if name == "prepare"
                            else "Require every consumer lane" if name == "Consumer required" else "Execute native recipe",
                            "status": "completed", "conclusion": "success"}]}
                for name in ["prepare", "Consumer required"] + ["Consumer " + lane for lane in consumer.LANES]]
        consumer.validate_result(value, "0" * 64, run, jobs)
        for mutation in ("missing", "skipped", "empty", "foreign", "rerun"):
            r, j = copy.deepcopy(run), copy.deepcopy(jobs)
            if mutation == "missing":
                j.pop()
            elif mutation == "skipped":
                j[-1]["conclusion"] = "skipped"
            elif mutation == "empty":
                j[-1]["steps"] = []
            elif mutation == "foreign":
                r["actor"]["id"] = 1
            else:
                r["run_attempt"] = 2
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                consumer.validate_result(value, "0" * 64, r, j)

    def test_skipped_required_command_cannot_qualify(self):
        value = request()
        # Even a nominally successful job must contain the required actual step.
        with self.assertRaises(ValueError):
            consumer.validate_result(value, "0" * 64, {}, [])

    def test_source_admission_binds_private_identity_and_current_pr(self):
        value, selected = request(), policy()
        repo = {"id": 123, "full_name": value["source"], "private": True}
        pr = {"state": "open", "head": {"sha": value["source_sha"], "repo": {"id": 123}},
              "base": {"sha": value["base_sha"], "repo": {"id": 123}, "ref": "main"}}
        with mock.patch.object(consumer.ci, "api_json", side_effect=[repo, pr]):
            consumer.source_identity(value, selected, "SYNTHETIC")
        for field in ("source_sha", "base_sha", "source_id"):
            altered = dict(value, **{field: 124 if field == "source_id" else "9" * 40})
            with mock.patch.object(consumer.ci, "api_json", side_effect=[repo, pr]), self.assertRaises(ValueError):
                consumer.source_identity(altered, selected, "SYNTHETIC")
        with mock.patch.object(consumer.ci, "api_json", return_value=dict(repo, private=False)), self.assertRaises(ValueError):
            consumer.source_identity(value, selected, "SYNTHETIC")

    def test_recipe_bytes_and_parent_links_are_admitted_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / consumer.RECIPE
            target.parent.mkdir(parents=True)
            target.write_text('{"schema":1,"lanes":[]}')
            selected = dict(policy(), recipe_sha256=crypto.digest(target))
            with self.assertRaises(ValueError):
                consumer.recipe(root, selected)
            selected["recipe_sha256"] = "1" * 64
            with self.assertRaises(ValueError):
                consumer.recipe(root, selected)

    def test_credential_environment_and_null_stdin_are_inherited_contracts(self):
        env = consumer.ci.build_environment({
            "PATH": "/usr/bin", "HOME": "/tmp/synthetic", "SOURCE_READ_TOKEN": "SYNTHETIC",
            "CONSUMER_INPUT_PRIVATE_KEY_B64": "SYNTHETIC", "GH_TOKEN": "SYNTHETIC",
            "CONSUMER_POLICY_B64": "SYNTHETIC",
        })
        self.assertEqual(set(env), {"PATH", "HOME"})

    def test_contexts_separate_transport_from_native_results_and_runs(self):
        value = request()
        a = consumer.context("source", value)
        self.assertNotIn("source", a)
        self.assertNotIn("source_sha", a)
        self.assertNotEqual(a, consumer.context("request", value))
        with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "100", "CONSUMER_REQUEST_DIGEST": "0" * 64}):
            hosted = consumer.context("prepared", value, hosted=True)
        self.assertEqual(hosted["run"], 100)
        self.assertNotEqual(a, hosted)

    @unittest.skipUnless(os.name == "posix", "local consumer operator requires POSIX ownership checks")
    def test_state_signature_refuses_modified_inventory(self):
        private, public = crypto.generate("sign")
        state = {"payload": request(), "request": "synthetic-ciphertext",
                 "request_digest": consumer.ci.digest_bytes(b"synthetic-ciphertext"),
                 "builder_ref": "refs/tags/synthetic-reviewed-builder"}
        state["signature"] = crypto.sign(copy.deepcopy(state), private)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            operator.operator.save(root / "state.json", state)
            self.assertEqual(operator.read_state(root, public), state)
            altered = copy.deepcopy(state)
            altered["payload"]["source_sha"] = "9" * 40
            (root / "state.json").write_text(json.dumps(altered))
            with self.assertRaises(Exception):
                operator.read_state(root, public)

    def test_shallow_dependency_bundle_can_be_checked_out_without_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, bare = root / "input", root / "bare"
            def git(*args):
                return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", str(source))
            git("-C", str(source), "config", "user.name", "Synthetic")
            git("-C", str(source), "config", "user.email", "synthetic@example.invalid")
            (source / "source.txt").write_text("synthetic\n")
            (source / "retired.txt").write_text("synthetic retired data\n")
            git("-C", str(source), "add", ".")
            git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-m", "Synthetic")
            retired = git("-C", str(source), "rev-parse", "HEAD")
            git("-C", str(source), "rm", "retired.txt")
            git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-m", "Synthetic cleanup")
            revision = git("-C", str(source), "rev-parse", "HEAD")
            git("clone", "--bare", "--depth=1", "file://" + str(source), str(bare))
            bundle = root / "dependency.bundle"
            git("-C", str(bare), "bundle", "create", str(bundle), "--all")
            consumer.checkout(bundle, root / "output", revision, root)
            self.assertEqual((root / "output/.git/shallow").read_bytes(), (revision + "\n").encode("ascii"))
            self.assertEqual((root / "output/source.txt").read_text(), "synthetic\n")
            self.assertNotIn(retired, git("-C", str(root / "output"), "rev-list", "--all"))
            self.assertFalse((root / "output/retired.txt").exists())

    @unittest.skipUnless(os.name == "posix", "native consumer execution is Linux-only")
    def test_authenticated_prepare_materialize_and_credential_free_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "synthetic-source"
            def git(*args):
                return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()
            git("init", str(source))
            git("-C", str(source), "config", "user.name", "Synthetic")
            git("-C", str(source), "config", "user.email", "synthetic@example.invalid")
            recipe = {"schema": 1, "lanes": [
                {"id": name, "argv": ["bash", "ci/builder/qualify.sh", name], "timeout": 60}
                for name in consumer.LANES]}
            path = source / consumer.RECIPE
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(recipe))
            (path.parent / "qualify.sh").write_text(
                '#!/bin/bash\nset -eu\n'
                'test -z "${SOURCE_READ_TOKEN:-}${CONSUMER_INPUT_PRIVATE_KEY_B64:-}${GH_TOKEN:-}"\n'
                'printf synthetic > "$CONSUMER_RESULTS_DIR/proof.txt"\n')
            git("-C", str(source), "add", ".")
            git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-m", "Synthetic")
            revision = git("-C", str(source), "rev-parse", "HEAD")
            bundle = root / "original.bundle"
            git("-C", str(source), "bundle", "create", str(bundle), "--all")
            asset = root / "original.zip"
            with zipfile.ZipFile(asset, "w") as archive:
                archive.writestr("synthetic.txt", "synthetic")
            private, public = crypto.generate("encrypt")
            signing_private, signing_public = crypto.generate("sign")
            value = dict(request(), source_sha=revision, base_sha=revision)
            selected = policy()
            selected["recipe_sha256"] = crypto.digest(path)
            selected["inputs"][0]["sha"] = revision
            selected["inputs"][1]["sha256"] = crypto.digest(asset)
            encrypted = root / "original.enc"
            crypto.encrypt_file(bundle, encrypted, public, consumer.context("source", value))
            value["source_cipher_digest"] = crypto.digest(encrypted)
            document = crypto.sign(value, signing_private)
            sealed = crypto.seal_message(crypto.canonical(document), public, consumer.context("request", value))
            digest = consumer.ci.digest_bytes(sealed.encode("ascii"))
            env = {
                "RUNNER_TEMP": str(root), "GITHUB_REPOSITORY": consumer.ci.BUILDER,
                "GITHUB_REPOSITORY_ID": str(consumer.ci.BUILDER_ID), "GITHUB_SHA": value["builder_sha"],
                "CONSUMER_BUILDER_SHA": value["builder_sha"], "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "100", "GITHUB_ACTOR_ID": "5323024",
                "CONSUMER_REQUEST": sealed, "CONSUMER_REQUEST_DIGEST": digest,
                "CONSUMER_REQUEST_ID": value["request_id"], "CONSUMER_LANE": "static",
                "CONSUMER_INPUT_PRIVATE_KEY_B64": crypto.b64(private.encode()),
                "CONSUMER_VERIFY_PUBLIC_KEY_B64": crypto.b64(signing_public.encode()),
                "CONSUMER_POLICY_B64": crypto.b64(crypto.canonical(selected)),
                "SOURCE_READ_TOKEN": "SYNTHETIC", "BUILDER_READ_TOKEN": "SYNTHETIC",
                "GITHUB_OUTPUT": str(root / "output"), "GH_TOKEN": "SYNTHETIC",
            }
            run = {
                "id": 100, "repository": {"id": consumer.ci.BUILDER_ID},
                "head_repository": {"id": consumer.ci.BUILDER_ID},
                "path": ".github/workflows/" + consumer.WORKFLOW, "head_sha": value["builder_sha"],
                "event": "workflow_dispatch", "run_attempt": 1, "display_title": "Encrypted consumer " + digest,
                "actor": {"id": 5323024}, "triggering_actor": {"id": 5323024},
                "html_url": "https://github.com/dobord/builder/actions/runs/100",
            }
            def fetch(value, token, path):
                shutil.copyfile(encrypted, path)
            def git_input(repository, sha, path, token, work):
                shutil.copyfile(bundle, path)
            def asset_input(item, path, token):
                shutil.copyfile(asset, path)
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(consumer, "source_identity") as admission, \
                    mock.patch.object(consumer.ci, "pages", return_value=[run]), \
                    mock.patch.object(consumer.ci, "fetch_operator_input", side_effect=fetch), \
                    mock.patch.object(consumer, "git_bundle", side_effect=git_input), \
                    mock.patch.object(consumer, "download_asset", side_effect=asset_input):
                consumer.prepare()
                self.assertEqual(2, admission.call_count)
                self.assertFalse(consumer.work_root().exists())
                consumer.materialize()
                self.assertTrue((consumer.work_root() / "staging/inputs/dependency.bundle").is_file(),
                                "authenticated Git metadata must remain available without network credentials")
                self.assertEqual((consumer.work_root() / "staging/inputs/sdk/synthetic.txt").read_text(), "synthetic")
                consumer.run()
                self.assertEqual((consumer.work_root() / "results/proof.txt").read_text(), "synthetic")
                self.assertEqual(json.loads((consumer.work_root() / "results/result.json").read_text())["source_sha"],
                                 revision)

    @unittest.skipUnless(os.name == "posix", "local consumer operator requires POSIX ownership checks")
    def test_fetch_authenticates_artifact_and_expected_lane_context(self):
        value = request()
        digest = "0" * 64
        run = {
            "id": 100, "repository": {"id": consumer.ci.BUILDER_ID},
            "head_repository": {"id": consumer.ci.BUILDER_ID}, "head_sha": value["builder_sha"],
            "path": ".github/workflows/" + consumer.WORKFLOW, "event": "workflow_dispatch",
            "run_attempt": 1, "display_title": "Encrypted consumer " + digest,
            "actor": {"id": 5323024}, "triggering_actor": {"id": 5323024},
            "status": "completed", "conclusion": "success",
            "html_url": "https://github.com/dobord/builder/actions/runs/100",
        }
        jobs = [{"name": name, "status": "completed", "conclusion": "success",
                 "run_id": 100, "head_sha": value["builder_sha"],
                 "steps": [{"name": "Authenticate consumer and prepare pinned inputs" if name == "prepare"
                            else "Require every consumer lane" if name == "Consumer required" else "Execute native recipe",
                            "status": "completed", "conclusion": "success"}]}
                for name in ["prepare", "Consumer required"] + ["Consumer " + lane for lane in consumer.LANES]]
        private, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir()
            (data / "result.json").write_text(json.dumps({
                "schema": 1, "source_sha": value["source_sha"], "builder_sha": value["builder_sha"],
                "lane": "static", "status": "success"}))
            consumer.safeio.pack_tar(data, root / "result.tar.gz")
            ctx = consumer.context("results", value)
            ctx.update(run=100, attempt=1, request_digest=digest, lane="static")
            crypto.encrypt_file(root / "result.tar.gz", root / "result.enc", public, ctx)
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                archive.writestr("results.enc", (root / "result.enc").read_bytes())
                archive.writestr("diagnostics.enc", b"synthetic-not-consumed")
            raw = content.getvalue()
            keyfile = root / "key.json"
            keyfile.write_text(private)
            keyfile.chmod(0o600)
            artifact = {"id": 1, "name": "consumer-output-static-100-1", "expired": False,
                        "size_in_bytes": len(raw), "digest": "sha256:" + consumer.ci.digest_bytes(raw)}
            state = {"payload": value, "request_digest": digest, "builder_ref": "refs/tags/synthetic"}
            args = argparse.Namespace(work=root, lane="static", output=root / "verified", output_private=keyfile)
            with mock.patch.object(operator, "matches", return_value=[run]), \
                    mock.patch.object(consumer.ci, "api_json", return_value=run), \
                    mock.patch.object(consumer.ci, "pages", side_effect=[jobs, [artifact]]), \
                    mock.patch.object(consumer.ci, "api", return_value=raw), \
                    mock.patch.object(operator.operator, "builder_ref"):
                operator.fetch(state, args, "SYNTHETIC")
            self.assertTrue((args.output / "result.json").exists())
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                archive.writestr("results.enc", (root / "result.enc").read_bytes())
                archive.writestr("diagnostics.enc", b"synthetic-not-consumed")
                archive.writestr("publisher-results.enc", b"synthetic-publisher-cipher-not-consumed")
            raw = content.getvalue()
            artifact.update(size_in_bytes=len(raw), digest="sha256:" + consumer.ci.digest_bytes(raw))
            args.output = root / "verified-with-publisher"
            with mock.patch.object(operator, "matches", return_value=[run]), \
                    mock.patch.object(consumer.ci, "api_json", return_value=run), \
                    mock.patch.object(consumer.ci, "pages", side_effect=[jobs, [artifact]]), \
                    mock.patch.object(consumer.ci, "api", return_value=raw), \
                    mock.patch.object(operator.operator, "builder_ref"):
                operator.fetch(state, args, "SYNTHETIC")
            self.assertTrue((args.output / "result.json").exists())
            args.lane, args.output = "gcc", root / "must-not-exist"
            altered_artifact = dict(artifact, name="consumer-output-gcc-100-1")
            with mock.patch.object(operator, "matches", return_value=[run]), \
                    mock.patch.object(consumer.ci, "api_json", return_value=run), \
                    mock.patch.object(consumer.ci, "pages", side_effect=[jobs, [altered_artifact]]), \
                    mock.patch.object(consumer.ci, "api", return_value=raw), \
                    mock.patch.object(operator.operator, "builder_ref"), \
                    mock.patch.object(crypto, "decrypt_file") as decrypt, self.assertRaises(ValueError):
                operator.fetch(state, args, "SYNTHETIC")
            decrypt.assert_not_called()
            self.assertFalse(args.output.exists())


if __name__ == "__main__":
    unittest.main()
