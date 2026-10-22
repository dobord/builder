"""Synthetic operator transport; no real credentials or source Actions."""
import base64
import argparse
import copy
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from secure_release import crypto, project_ci as ci, project_ci_runner as runner
from secure_release import project_ci_operator as operator
from tests.test_project_ci import payload


def operator_payload():
    value = payload()
    for name in ("source_run", "source_attempt", "source_event", "artifact_id", "artifact_digest", "baseline_run"):
        del value[name]
    value.update(schema=2, origin="local-operator", operator_id=5323024,
                 input_commit="f" * 40, input_blob="1" * 40)
    value["input_ref"] = "refs/tags/project-ci-input-" + value["request_id"]
    return value


class OperatorTests(unittest.TestCase):
    def test_signed_release_inventory_requires_exactly_40_lanes(self):
        signing, verification = crypto.generate("sign")
        value = dict(operator_payload(), suite="release")
        for count in (39, 40, 41):
            with self.subTest(count=count):
                lanes = [f"synthetic-{index}" for index in range(count)]
                state = {"payload": value, "request": "PUBLIC_SYNTHETIC_REQUEST",
                         "request_digest": ci.digest_bytes(b"PUBLIC_SYNTHETIC_REQUEST"),
                         "lanes": lanes, "builder_ref": "refs/tags/synthetic"}
                inventory = {key: state[key] for key in ("payload", "lanes", "request_digest", "builder_ref")}
                state["inventory"] = crypto.sign(inventory, signing)
                if count == 40:
                    operator.validate_state(state, verification)
                else:
                    with self.assertRaisesRegex(ValueError, "inventory incomplete"):
                        operator.validate_state(state, verification)

    def test_release_inventory_requires_all_40_native_lanes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ci/builder").mkdir(parents=True)
            for profile in ci.SUITES["release"]:
                (root / "ci/builder" / (profile + ".yml")).write_text("jobs:\n  synthetic:\n    runs-on: ubuntu-24.04\n    steps: []\n")
            with self.assertRaises(ValueError):
                ci.recipes(root, "release")

    def test_schema2_prepare_authenticates_operator_and_never_uses_source_actions(self):
        value = dict(operator_payload(), pr=151, suite="release")
        input_private, input_public = crypto.generate("encrypt")
        signing, verification = crypto.generate("sign")
        policy = {"repository": value["source"], "repository_id": value["source_id"],
                  "operator_origin": "local-operator", "operator_id": 5323024,
                  "approval_boundaries": [], "authorizer_branch": "main"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "plain").write_bytes(b"PUBLIC_SYNTHETIC_BUNDLE")
            crypto.encrypt_file(root / "plain", root / "sources.enc", input_public, ci.source_context(value))
            raw = (root / "sources.enc").read_bytes()
            value["input_blob"] = ci.git_blob_sha(raw)
            value["source_cipher_digest"] = ci.digest_bytes(raw)
            message = crypto.seal_message(crypto.canonical(crypto.sign(value, signing)), input_public,
                                          ci.message_context(value["request_id"], 2, value["builder_sha"]))
            digest = ci.digest_bytes(message.encode("ascii"))
            run = {"id": 10, "display_title": "Encrypted qualification " + digest, "actor": {"id": 5323024},
                   "triggering_actor": {"id": 5323024}, "run_attempt": 1,
                   "repository": {"id": ci.BUILDER_ID}, "head_repository": {"id": ci.BUILDER_ID},
                   "path": ".github/workflows/" + ci.WORKFLOW, "event": "workflow_dispatch", "head_sha": value["builder_sha"]}
            env = {"GITHUB_REPOSITORY": ci.BUILDER, "GITHUB_REPOSITORY_ID": str(ci.BUILDER_ID),
                   "GITHUB_SHA": value["builder_sha"], "CI_BUILDER_SHA": value["builder_sha"],
                   "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "10",
                   "GITHUB_ACTOR_ID": "5323024", "CI_REQUEST_SCHEMA": "2", "CI_REQUEST": message,
                   "CI_REQUEST_ID": value["request_id"], "CI_REQUEST_DIGEST": digest,
                   "CI_INPUT_PRIVATE_KEY_B64": crypto.b64(input_private.encode()),
                   "CI_VERIFY_PUBLIC_KEY_B64": crypto.b64(verification.encode()),
                   "CI_SOURCE_POLICY": json.dumps(policy), "SOURCE_READ_TOKEN": "SOURCE_SYNTHETIC",
                   "BUILDER_READ_TOKEN": "BUILDER_SYNTHETIC", "RUNNER_TEMP": str(root), "GITHUB_OUTPUT": str(root / "output")}
            def reply(path, token, **kwargs):
                if path.startswith("repos/" + value["source"]):
                    self.assertEqual(token, "SOURCE_SYNTHETIC")
                    self.assertNotIn("/actions/", path)
                    if path.endswith(value["source"]):
                        return {"id": 1, "full_name": value["source"]}
                    if "/releases/tags/" in path:
                        return {"draft": False, "prerelease": False, "tag_name": "v0.4.0", "published_at": "2026-01-01"}
                    if "/git/ref/tags/" in path:
                        return {"object": {"type": "commit", "sha": value["baseline_sha"]}}
                    if "/pulls/" in path:
                        return {"head": {"sha": value["source_sha"], "repo": {"id": 1}},
                                "base": {"sha": value["base_sha"], "repo": {"id": 1}, "ref": "main"}, "state": "open"}
                self.assertTrue(path.startswith("repos/" + ci.BUILDER + "/git/"))
                self.assertEqual(token, "BUILDER_SYNTHETIC")
                if "/ref/" in path:
                    return {"ref": value["input_ref"], "object": {"type": "commit", "sha": value["input_commit"]}}
                if "/commits/" in path:
                    return {"sha": value["input_commit"], "parents": [], "tree": {"sha": "2" * 40}}
                if "/trees/" in path:
                    return {"sha": "2" * 40, "truncated": False, "tree": [{"path": "sources.enc", "mode": "100644", "type": "blob", "sha": value["input_blob"], "size": len(raw)}]}
                if "/blobs/" in path:
                    return {"sha": value["input_blob"], "encoding": "base64", "size": len(raw), "content": crypto.b64(raw)}
                raise AssertionError(path)
            from secure_release import project_dependency_review
            with patch.dict(os.environ, env), patch.object(ci, "pages", return_value=[run]), patch.object(ci, "api_json", side_effect=reply), patch.object(ci, "checked"), patch.object(ci, "recipes", return_value=[{"id": f"synthetic-{i}", "runner": ["ubuntu-24.04"]} for i in range(40)]), patch.object(project_dependency_review, "verify", return_value={"synthetic": True}) as osv:
                for invalid in ({"actor": {"id": 7}}, {"triggering_actor": {"id": 7}}, {"run_attempt": 2},
                                {"path": ".github/workflows/other.yml"}, {"head_sha": "0" * 40}):
                    with self.subTest(invalid=invalid), patch.object(ci, "pages", return_value=[dict(run, **invalid)]), self.assertRaises(ValueError):
                        ci.prepare()
                with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}), self.assertRaises(ValueError):
                    ci.prepare()
                # Builder-owned release pins must reject candidate recipes
                # before OSV traverses any candidate-controlled YAML.
                with patch.object(ci, "recipes", side_effect=ValueError("release recipe contract mismatch")):
                    with self.assertRaisesRegex(ValueError, "recipe contract"):
                        ci.prepare()
                    osv.assert_not_called()
                ci.remove_staging(root / "project-ci-prepare")
                ci.prepare()
                osv.assert_called_once()
            self.assertTrue((root / "cipher-input/sources.enc").exists())
            self.assertTrue((root / "cipher-dependency/dependency-review.enc").exists())
            self.assertFalse((root / "project-ci-prepare").exists())

    @unittest.skipUnless(os.name == "posix", "local client uses POSIX file ownership; protocol tests run on every host")
    def test_local_package_dispatch_and_signed_inventory_are_nonexecuting(self):
        signing, verification = crypto.generate("sign")
        _, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "fixture.git"
            subprocess.run(["git", "init", "--bare", str(repo)], check=True, capture_output=True)
            recipe = b"jobs:\n  synthetic:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: exit 0\n"
            blob = subprocess.check_output(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=recipe).decode().strip()
            tree = subprocess.check_output(["git", "-C", str(repo), "mktree"], input=f"100644 blob {blob}\tci.yml\n100644 blob {blob}\twasm-async.yml\n".encode()).decode().strip()
            tree = subprocess.check_output(["git", "-C", str(repo), "mktree"], input=f"040000 tree {tree}\tbuilder\n".encode()).decode().strip()
            tree = subprocess.check_output(["git", "-C", str(repo), "mktree"], input=f"040000 tree {tree}\tci\n".encode()).decode().strip()
            env = dict(os.environ, GIT_AUTHOR_NAME="Synthetic", GIT_AUTHOR_EMAIL="synthetic@example.invalid",
                       GIT_COMMITTER_NAME="Synthetic", GIT_COMMITTER_EMAIL="synthetic@example.invalid")
            commits = [subprocess.check_output(["git", "-C", str(repo), "commit-tree", tree], input=message, env=env).decode().strip()
                       for message in (b"candidate\n", b"baseline\n")]
            for name, text in (("signing.json", signing), ("input.json", public)):
                (root / name).write_text(text)
                (root / name).chmod(0o644 if name == "input.json" else 0o600)
            value = operator_payload()
            policy = {"repository": value["source"], "repository_id": value["source_id"],
                      "operator_id": 5323024, "operator_origin": "local-operator", "approval_boundaries": []}
            (root / "policy.json").write_bytes(crypto.canonical(policy))
            (root / "policy.json").chmod(0o600)
            args = argparse.Namespace(work=root / "private", policy=root / "policy.json", pr=0, suite="ci",
                                      baseline_tag="v0.4.0", builder_sha=value["builder_sha"], builder_ref="refs/tags/synthetic",
                                      source_sha=commits[0], base_sha=commits[0], signing_private=root / "signing.json", input_public=root / "input.json")
            def reply(path, credential, **kwargs):
                self.assertNotIn("/actions/", path)
                if path.endswith(value["source"]):
                    return {"id": 1, "full_name": value["source"]}
                if "/releases/tags/" in path:
                    return {"draft": False, "prerelease": False, "tag_name": "v0.4.0", "published_at": "2026-01-01"}
                if "/git/ref/tags/" in path:
                    return {"object": {"type": "commit", "sha": commits[1]}}
                if "/git/ref/heads/main" in path:
                    return {"object": {"type": "commit", "sha": commits[0]}}
                raise AssertionError(path)
            checked = ci.checked
            def local_git(command, cwd, environment, log):
                self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
                self.assertEqual(environment["GIT_CONFIG_VALUE_1"], "")
                self.assertNotIn("GH_TOKEN", environment)
                if "fetch" in command:
                    command = [str(repo) if item.startswith("https://github.com/") else item for item in command]
                checked(command, cwd, environment, log)
            native_run = subprocess.run
            def run(command, **kwargs):
                if command[0] == "gh":
                    return subprocess.CompletedProcess(command, 0, b"5323024\n", b"")
                return native_run(command, **kwargs)
            def publish(payload, path, credential):
                with path.open("rb") as stream:
                    header = crypto.read_header(stream)
                self.assertEqual(header["context"], ci.source_context(payload))
                self.assertNotIn(payload["source"], json.dumps(header))
                payload.update(input_blob=ci.git_blob_sha(path.read_bytes()), input_commit="f" * 40)
            with patch.object(ci, "api_json", side_effect=reply), patch.object(operator, "builder_ref"), patch.object(ci, "checked", side_effect=local_git), patch.object(subprocess, "run", side_effect=run), patch.object(operator, "publish_input", side_effect=publish):
                state = operator.package(args, "synthetic")
            self.assertFalse((args.work / "repository.bundle").exists())
            self.assertFalse((args.work / "repository.git").exists())
            operator.validate_state(state, verification)
            for change in ({"payload": dict(state["payload"], source_sha="0" * 40)}, {"lanes": []}, {"request_digest": "0" * 64}):
                with self.subTest(change=change), self.assertRaises(Exception):
                    operator.validate_state(dict(state, **change), verification)
            with patch.object(operator, "builder_ref"), patch.object(operator, "matching_runs", return_value=[]), patch.object(ci, "api_json") as api:
                operator.dispatch(state, args.work, "synthetic")
                self.assertEqual(api.call_args.kwargs["data"]["inputs"]["request_schema"], "2")
                self.assertEqual(api.call_args.kwargs["data"]["ref"], "synthetic")
                with self.assertRaises(ValueError):
                    operator.dispatch(state, args.work, "synthetic")

    def test_schema2_non_pr_runner_uses_credential_free_dispatch_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "workspace/private-source").mkdir(parents=True)
            (root / "runner/project-ci").mkdir(parents=True)
            (root / "runner/project-ci/request.json").write_bytes(crypto.canonical(operator_payload()))
            lane = {"id": "synthetic", "profile": "ci", "matrix": {}, "runner": ["ubuntu-24.04"],
                    "job": {"steps": [{"run": "exit 0"}]}}
            env = {"GITHUB_WORKSPACE": str(root / "workspace"), "RUNNER_TEMP": str(root / "runner"),
                   "CI_LANE": "synthetic", "GITHUB_RUN_ID": "1", "GITHUB_RUN_NUMBER": "1",
                   "GITHUB_RUN_ATTEMPT": "1", "RUNNER_OS": "Linux", "GH_TOKEN": "synthetic"}
            with patch.dict(os.environ, env), patch.object(ci, "recipes", return_value=[lane]), patch.object(ci, "quiet", return_value=0) as command:
                runner.run()
            self.assertEqual(command.call_args.args[2]["GITHUB_EVENT_NAME"], "workflow_dispatch")
            self.assertNotIn("GH_TOKEN", command.call_args.args[2])

    def test_missing_cancelled_or_incomplete_evidence_never_mirrors_status(self):
        value = operator_payload()
        run = {"id": 10, "repository": {"id": ci.BUILDER_ID}, "head_repository": {"id": ci.BUILDER_ID},
               "path": ".github/workflows/" + ci.WORKFLOW, "head_sha": value["builder_sha"],
               "event": "workflow_dispatch", "run_attempt": 1, "actor": {"id": value["operator_id"]},
               "triggering_actor": {"id": value["operator_id"]}, "status": "completed", "conclusion": "success",
               "display_title": "Encrypted qualification " + "a" * 64,
               "html_url": "https://github.com/dobord/builder/actions/runs/10"}
        jobs = [{"name": name, "status": "completed", "conclusion": "success", "run_id": 10,
                 "head_sha": value["builder_sha"]} for name in ("prepare", "Encrypted lane synthetic", "Encrypted qualification required")]
        state = {"payload": value, "request_digest": "a" * 64, "lanes": ["synthetic"]}
        for bad_run, bad_jobs in ((None, jobs), (dict(run, conclusion="cancelled"), jobs),
                                  (run, jobs[:-1]), (run, [dict(jobs[0], conclusion="skipped")] + jobs[1:]),
                                  (dict(run, run_attempt=2), jobs)):
            with self.subTest(run=bad_run), patch.object(ci, "api_json") as api, self.assertRaises(ValueError):
                operator.mirror_success(state, bad_run, bad_jobs, "synthetic")
            api.assert_not_called()
        with patch.object(ci, "api_json") as api:
            operator.mirror_success(state, run, jobs, "synthetic")
        self.assertEqual(api.call_args.kwargs["data"]["state"], "success")

    def test_strict_schema_and_opaque_context(self):
        value = operator_payload()
        ci.validate_payload(value)
        for changes in ({"origin": "workflow_dispatch"}, {"operator_id": True},
                        {"source_run": 1}, {"input_ref": "refs/heads/main"},
                        {"input_blob": "main"}, {"schema": 3}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ci.validate_payload(dict(value, **changes))
        context = ci.source_context(value)
        self.assertEqual(set(context), {"schema", "purpose", "request_id", "builder_id", "builder_sha"})
        self.assertEqual(context["schema"], 2)
        self.assertNotIn(value["source"], json.dumps(context))
        self.assertNotIn(value["source_sha"], json.dumps(context))

    def test_operator_signed_ci_does_not_require_manual_reviews(self):
        value = dict(operator_payload(), pr=151)
        policy = {"repository": value["source"], "repository_id": value["source_id"],
                  "authorizer_branch": "main", "approval_boundaries": ["^sensitive", "^ci/"],
                  "operator_id": 5323024, "operator_origin": "local-operator", "request_schemas": [2]}
        repository = {"id": value["source_id"], "full_name": value["source"]}
        release = {"draft": False, "prerelease": False, "tag_name": value["baseline_tag"], "published_at": "2026-01-01"}
        baseline = {"object": {"type": "commit", "sha": value["baseline_sha"]}}
        pr = {"head": {"sha": value["source_sha"], "repo": {"id": value["source_id"]}},
              "base": {"sha": value["base_sha"], "repo": {"id": value["source_id"]}, "ref": "main"},
              "state": "open", "user": {"login": "synthetic"}}
        def reply(path, token):
            self.assertNotIn("/actions/", path)
            if path.endswith(value["source"]):
                return repository
            if "/releases/tags/" in path:
                return release
            if "/git/ref/tags/" in path:
                return baseline
            if "/pulls/" in path:
                return pr
            if "/git/ref/heads/main" in path:
                return {"object": {"type": "commit", "sha": value["source_sha"]}}
            raise AssertionError(path)
        def list_reply(path, token):
            if path.endswith("/files"):
                return [{"filename": "sensitive.cpp"}, {"filename": "ci/recipe.yml"}]
            if path.endswith("/reviews"):
                return []
            raise AssertionError(path)
        with patch.dict(os.environ, {"CI_SOURCE_POLICY": json.dumps(policy), "GITHUB_ACTOR_ID": "5323024"}), patch.object(ci, "api_json", side_effect=reply), patch.object(ci, "pages", side_effect=list_reply) as pages:
            # An authenticated operator authorizes every profile, even across
            # multiple sensitive boundaries. No review API may gate admission.
            for suite in sorted(ci.SUITES):
                with self.subTest(suite=suite):
                    ci.verify_source_policy(dict(value, suite=suite), "synthetic")
            pages.assert_not_called()
            for change in ({"operator_id": 7}, {"source_id": 8}, {"source_sha": "0" * 40},
                           {"base_sha": "0" * 40}, {"source": "dobord/foreign"}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    ci.verify_source_policy(dict(value, **change), "synthetic")
            with patch.dict(os.environ, {"GITHUB_ACTOR_ID": "7"}), self.assertRaisesRegex(ValueError, "unauthorized operator"):
                ci.verify_source_policy(value, "synthetic")
            # Same-repository current-head/base constraints and stable baseline
            # qualification still fail closed without any review fallback.
            invalid_prs = []
            for side in ("head", "base"):
                foreign = copy.deepcopy(pr)
                foreign[side]["repo"]["id"] = 7
                invalid_prs.append(foreign)
                stale = copy.deepcopy(pr)
                stale[side]["sha"] = "0" * 40
                invalid_prs.append(stale)
            invalid_prs.extend([dict(pr, state="closed"), dict(pr, base=dict(pr["base"], ref="foreign"))])
            for invalid in invalid_prs:
                with self.subTest(pr=invalid), patch.object(ci, "api_json", side_effect=lambda path, token: invalid if "/pulls/" in path else reply(path, token)), self.assertRaisesRegex(ValueError, "stale or foreign PR"):
                    ci.verify_source_policy(value, "synthetic")
            for change in ({"draft": True}, {"prerelease": True}, {"published_at": None}, {"tag_name": "v0.0.0"}):
                invalid = dict(release, **change)
                with self.subTest(release=change), patch.object(ci, "api_json", side_effect=lambda path, token: invalid if "/releases/tags/" in path else reply(path, token)), self.assertRaisesRegex(ValueError, "baseline is not a published stable release"):
                    ci.verify_source_policy(value, "synthetic")
            with patch.object(ci, "api_json", side_effect=lambda path, token: {"object": {"type": "commit", "sha": "0" * 40}} if "/git/ref/tags/" in path else reply(path, token)), self.assertRaisesRegex(ValueError, "released baseline identity mismatch"):
                ci.verify_source_policy(value, "synthetic")
            ci.verify_source_policy(dict(value, pr=0, base_sha=value["source_sha"]), "synthetic")

    def test_git_transport_rejects_moved_ref_extra_tree_and_blob_substitution(self):
        value = operator_payload()
        raw = b"PUBLIC_SYNTHETIC_CIPHERTEXT"
        value["input_blob"] = ci.git_blob_sha(raw)
        value["source_cipher_digest"] = ci.digest_bytes(raw)
        replies = [{"ref": value["input_ref"], "object": {"type": "commit", "sha": value["input_commit"]}},
                   {"sha": value["input_commit"], "tree": {"sha": "2" * 40}, "parents": []},
                   {"sha": "2" * 40, "truncated": False, "tree": [{"path": "sources.enc", "mode": "100644", "type": "blob", "sha": value["input_blob"], "size": len(raw)}]},
                   {"sha": value["input_blob"], "encoding": "base64", "size": len(raw), "content": base64.b64encode(raw).decode()},
                   {"ref": value["input_ref"], "object": {"type": "commit", "sha": value["input_commit"]}}]
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sources.enc"
            with patch.object(ci, "api_json", side_effect=replies):
                ci.fetch_operator_input(value, "synthetic", target)
            self.assertEqual(target.read_bytes(), raw)
            target.unlink()
            for index, change in ((0, {"object": {"type": "commit", "sha": "0" * 40}}),
                                  (0, {"object": {"type": "tag", "sha": value["input_commit"]}}),
                                  (1, {"sha": "0" * 40}), (1, {"parents": [{"sha": "0" * 40}]}),
                                  (2, {"tree": replies[2]["tree"] * 2}), (2, {"truncated": True}),
                                  (2, {"tree": [dict(replies[2]["tree"][0], type="tree")]}),
                                  (2, {"tree": [dict(replies[2]["tree"][0], mode="120000")]}),
                                  (2, {"tree": [dict(replies[2]["tree"][0], size=ci.MAX_GIT_INPUT + 1)]}),
                                  (3, {"sha": "0" * 40}), (3, {"encoding": "utf-8"}),
                                  (3, {"size": len(raw) + 1}), (3, {"content": base64.b64encode(b"wrong").decode()}),
                                  (4, {"object": {"type": "commit", "sha": "0" * 40}})):
                changed = copy.deepcopy(replies)
                changed[index].update(change)
                with self.subTest(index=index, change=change), patch.object(ci, "api_json", side_effect=changed), self.assertRaises(ValueError):
                    ci.fetch_operator_input(value, "synthetic", target)
                self.assertFalse(target.exists())
            with patch.object(ci, "api_json", side_effect=replies), self.assertRaises(ValueError):
                ci.fetch_operator_input(dict(value, source_cipher_digest="0" * 64), "synthetic", target)

    def test_schema2_crypto_rejects_context_recipient_and_signature_substitution(self):
        value = operator_payload()
        private, public = crypto.generate("encrypt")
        other_private, _ = crypto.generate("encrypt")
        signing, verify = crypto.generate("sign")
        context = ci.message_context(value["request_id"], 2, value["builder_sha"])
        message = crypto.seal_message(crypto.canonical(crypto.sign(value, signing)), public, context)
        self.assertEqual(crypto.verify(crypto.parse(crypto.open_message(message, private, context)), verify), value)
        for wrong in (ci.message_context(value["request_id"]), dict(context, builder_sha="0" * 40)):
            with self.assertRaises(Exception):
                crypto.open_message(message, private, wrong)
        with self.assertRaises(Exception):
            crypto.open_message(message, other_private, context)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "plain").write_bytes(b"PUBLIC_SYNTHETIC_BUNDLE")
            stream_context = ci.source_context(value)
            crypto.encrypt_file(root / "plain", root / "sources.enc", public, stream_context)
            for key, expected in ((private, dict(stream_context, builder_sha="0" * 40)),
                                  (private, ci.source_context(payload())), (other_private, stream_context)):
                with self.subTest(expected=expected), self.assertRaises(ValueError):
                    crypto.decrypt_file(root / "sources.enc", root / "failed", key, expected)
                self.assertFalse((root / "failed").exists())
        signed = crypto.sign(value, signing)
        signed["payload"] = dict(value, input_commit="0" * 40)
        with self.assertRaises(Exception):
            crypto.verify(signed, verify)


if __name__ == "__main__":
    unittest.main()
