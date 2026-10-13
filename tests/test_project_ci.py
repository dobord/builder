"""Fail-closed encrypted project-CI transport and runner regressions."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from secure_release import project_ci as ci
from secure_release import crypto, project_ci_runner as runner
from secure_release import project_ci_bootstrap as bootstrap


def payload():
    now = int(time.time())
    return {"schema": 1, "request_id": str(uuid.uuid4()), "source": "dobord/synthetic",
            "source_id": 1, "source_sha": "a" * 40, "base_sha": "a" * 40,
            "source_run": 1, "source_attempt": 1, "source_event": "push", "pr": 0,
            "builder_sha": "b" * 40, "suite": "ci", "created": now, "expires": now + 3600,
            "artifact_id": 1, "artifact_digest": "c" * 64, "source_cipher_digest": "d" * 64,
            "baseline_run": 0, "baseline_tag": "v0.4.0", "baseline_sha": "e" * 40}


class ProjectCiTests(unittest.TestCase):
    def test_lane_expansion_preserves_matrix_and_aggregates_are_not_jobs(self):
        recipe = {"jobs": {"build": {"runs-on": "${{ matrix.os }}", "strategy": {
            "matrix": {"include": [{"os": "ubuntu-24.04"}, {"os": "macos-14"}]}},
            "steps": [{"run": "ctest --timeout 20"}]},
            "ci-required": {"if": "always()", "steps": []}}}
        lanes = ci.expand_recipe("ci", recipe)
        self.assertEqual(len(lanes), 2)
        self.assertEqual([lane["runner"] for lane in lanes], [["ubuntu-24.04"], ["macos-14"]])

    def test_unknown_expression_or_action_is_rejected(self):
        with self.assertRaises(ValueError):
            ci.expand("${{ secrets.READ_TOKEN }}", {})
        with self.assertRaises(ValueError):
            ci.validate_action("attacker/action@main")

    def test_api_allows_dependency_comparison_but_rejects_traversal(self):
        response = unittest.mock.MagicMock()
        response.read.return_value = b"[]"
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch("urllib.request.build_opener", return_value=opener):
            self.assertEqual(ci.api_json("repos/dobord/synthetic/dependency-graph/compare/" + "a" * 40 + "..." + "b" * 40, "SYNTHETIC"), [])
            for path in ("repos/../synthetic", "repos/dobord/%2e%2e/synthetic", "repos/dobord/synthetic\n"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    ci.api(path, "SYNTHETIC")

    def test_cancelled_missing_and_wrong_attempt_do_not_authorize_success(self):
        run = {"repository": {"id": ci.BUILDER_ID}, "head_repository": {"id": ci.BUILDER_ID},
               "path": ".github/workflows/encrypted-project-ci.yml", "head_sha": "a" * 40,
               "event": "workflow_dispatch", "run_attempt": 2,
               "display_title": "Encrypted qualification " + "b" * 64,
               "status": "completed", "conclusion": "success"}
        ci.validate_run(run, "a" * 40, "b" * 64, 2)
        for change in ({"run_attempt": 1}, {"conclusion": "cancelled"}, {"head_sha": "c" * 40}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                ci.validate_run(dict(run, **change), "a" * 40, "b" * 64, 2)

    def test_private_command_output_never_reaches_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "command.log"
            console = io.StringIO()
            with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                result = ci.quiet([os.sys.executable, "-c", "print('PRIVATE_SENTINEL'); raise SystemExit(7)"],
                                  Path(tmp), {}, log, timeout=5)
            self.assertEqual(result, 7)
            self.assertNotIn("PRIVATE_SENTINEL", console.getvalue())
            self.assertIn("PRIVATE_SENTINEL", log.read_text())

    def test_bundle_archive_rejects_extra_members_and_traversal(self):
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "input.zip"
            with zipfile.ZipFile(archive, "w") as out:
                out.writestr("../sources.enc", b"bad")
            with self.assertRaises(ValueError):
                ci.unwrap_artifact(archive, Path(tmp) / "input.enc")

    def test_filtered_environment_removes_credentials_and_actions_channels(self):
        env = ci.build_environment({"PATH": "/bin", "SOURCE_READ_TOKEN": "secret",
                                    "BUILDER_INPUT_PRIVATE_KEY": "secret", "GH_TOKEN": "secret",
                                    "ACTIONS_RUNTIME_TOKEN": "secret", "HOME": "/home/user"})
        self.assertEqual(env, {"PATH": "/bin", "HOME": "/home/user"})

    def test_windows_environment_retains_case_normalized_host_tool_paths(self):
        environment = {"PATH": "synthetic", "RUNNER_OS": "Windows", "PROGRAMFILES": "PUBLIC_TOOLS",
                       "PROGRAMFILES(X86)": "PUBLIC_X86_TOOLS", "CHOCOLATEYINSTALL": "PUBLIC_CHOCO",
                       "VCTOOLSINSTALLDIR": "PUBLIC_MSVC", "SOURCE_READ_TOKEN": "SYNTHETIC_SECRET"}
        actual = ci.build_environment(environment)
        for name in ("PROGRAMFILES", "PROGRAMFILES(X86)", "CHOCOLATEYINSTALL", "VCTOOLSINSTALLDIR"):
            self.assertEqual(actual[name], environment[name])
        self.assertNotIn("SOURCE_READ_TOKEN", actual)

    def test_linux_recipes_use_host_python_not_the_builder_crypto_runtime(self):
        toolchain = "/opt/hostedtoolcache/Python/3.12.15/x64/bin"
        with patch.object(ci.sys, "executable", toolchain + "/python"):
            environment = ci.build_environment({"RUNNER_OS": "Linux", "PATH": toolchain + ":/usr/bin:/bin"})
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        with patch.object(ci.sys, "executable", "/usr/bin/python3"):
            environment = ci.build_environment({"RUNNER_OS": "Linux", "PATH": "/usr/bin:/bin"})
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")

    def test_cleanup_removes_read_only_git_staging_without_following_links(self):
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "staging"
            root.mkdir()
            pack = root / "public-synthetic.pack"
            pack.write_bytes(b"PUBLIC_SYNTHETIC_GIT_OBJECT")
            pack.chmod(stat.S_IRUSR)
            ci.remove_staging(root)
            self.assertFalse(root.exists())
            if os.name != "nt":
                link = Path(tmp) / "linked-staging"
                link.symlink_to(Path(tmp), target_is_directory=True)
                with self.assertRaises(ValueError):
                    ci.remove_staging(link)
                self.assertTrue(Path(tmp).is_dir())

    def test_payload_requires_fresh_exact_complete_identity(self):
        valid = payload()
        ci.validate_payload(valid)
        for changes in ({"source_sha": "main"}, {"source_attempt": True}, {"suite": "unknown"},
                        {"expires": int(time.time()) - 1}, {"artifact_digest": "bad"}, {"pr": -1},
                        {"baseline_tag": "main"}, {"baseline_run": 1},
                        {"suite": "release", "baseline_sha": valid["source_sha"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                ci.validate_payload(dict(valid, **changes))
        with self.assertRaises(ValueError):
            ci.validate_payload(dict(valid, extra="unsafe"))

    def test_conditions_cannot_execute_code_and_preserve_original_branches(self):
        context = {"runner.os": "Linux", "matrix.name": "Linux gcc14"}
        self.assertTrue(runner.condition("runner.os == 'Linux' && matrix.name == 'Linux gcc14'", context, True))
        self.assertFalse(runner.condition("runner.os == 'Windows'", context, True))
        self.assertTrue(runner.condition("always()", context, False))
        self.assertTrue(runner.condition("failure()", context, False))
        with self.assertRaises(ValueError):
            runner.condition("__import__('os').system('unsafe')", context, True)

    def test_explicit_matrix_conditions_keep_implicit_success_guard(self):
        context = {"matrix.name": "Windows native"}
        self.assertFalse(runner.condition("matrix.name == 'Windows native'", context, False))
        self.assertTrue(runner.condition("always() && matrix.name == 'Windows native'", context, False))

    def test_windows_bash_uses_git_bash_instead_of_the_wsl_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bash = root / "Git/bin/bash.exe"
            bash.parent.mkdir(parents=True)
            bash.write_bytes(b"PUBLIC_SYNTHETIC_TOOL")
            command = runner.shell_command("bash", root / "script.sh", {"PROGRAMFILES": str(root)}, "Windows")
            self.assertEqual(command[0], str(bash))
            self.assertNotEqual(command[0], "bash")

    def test_report_archive_rejects_linked_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "outside").write_text("PRIVATE_SYNTHETIC")
            (root / "report").symlink_to(root / "outside")
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}):
                (root / "project-ci").mkdir()
                with self.assertRaises(ValueError):
                    runner.artifact_archive(root, [root / "report"], root / "reports.enc", payload(),
                                            {"id": "synthetic", "runner": ["ubuntu-24.04"]})

    def test_timeout_does_not_publish_command_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaises(ValueError):
                    ci.quiet([os.sys.executable, "-c", "import threading; print('PRIVATE',flush=True); threading.Event().wait()"],
                             root, {}, root / "command.log", timeout=0.1)
            self.assertEqual(output.getvalue(), "")

    def test_replayed_request_is_rejected_before_private_key_access(self):
        request = "OPAQUE_SYNTHETIC_CIPHERTEXT"
        digest = ci.digest_bytes(request.encode())
        env = {"GITHUB_REPOSITORY": ci.BUILDER, "GITHUB_REPOSITORY_ID": str(ci.BUILDER_ID),
               "GITHUB_SHA": "a" * 40, "CI_BUILDER_SHA": "a" * 40,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "2",
               "CI_REQUEST": request, "CI_REQUEST_DIGEST": digest, "BUILDER_READ_TOKEN": "SYNTHETIC",
               "CI_SOURCE_POLICY": json.dumps({"repository": "dobord/synthetic", "repository_id": 1})}
        runs = [{"id": 1, "display_title": "Encrypted qualification " + digest},
                {"id": 2, "display_title": "Encrypted qualification " + digest}]
        with patch.dict(os.environ, env), patch.object(ci, "pages", return_value=runs), patch.object(crypto, "open_message") as decrypt:
            with self.assertRaises(ValueError):
                ci.prepare()
            decrypt.assert_not_called()

    def test_release_requires_ci_evidence_but_not_manual_pr_approval(self):
        policy = {"repository": "dobord/synthetic", "repository_id": 1,
                  "authorizer_branch": "main", "approval_boundaries": ["^sensitive"]}
        request = dict(payload(), pr=1, suite="release")
        def api_reply(path, token):
            if "/releases/tags/" in path:
                return {"draft": False, "prerelease": False, "tag_name": "v0.4.0", "published_at": "2026-09-22"}
            if "/git/ref/tags/" in path:
                return {"object": {"type": "commit", "sha": request["baseline_sha"]}}
            if "/actions/runs/" in path:
                return {"repository": {"id": 1}, "head_repository": {"id": 1},
                        "path": ".github/workflows/builder-ci.yml", "run_attempt": 1,
                        "event": "push", "head_branch": "main"}
            if "/pulls/" in path:
                return {"head": {"sha": request["source_sha"], "repo": {"id": 1}},
                        "base": {"sha": request["base_sha"]}, "state": "open", "user": {"login": "author"}}
            raise AssertionError("unexpected admission API")
        def list_reply(path, token, field=None):
            if path.endswith("/files"):
                return [{"filename": "sensitive.cpp"}]
            if path.endswith("/reviews"):
                return []
            if "/dependency-graph/compare/" in path:
                return []
            raise AssertionError("unexpected policy API")
        with patch.dict(os.environ, {"CI_SOURCE_POLICY": json.dumps(policy)}), patch.object(ci, "api_json", side_effect=api_reply), patch.object(ci, "pages", side_effect=list_reply) as calls:
            ci.verify_source_policy(request, "SYNTHETIC")
            self.assertFalse(any(call.args[0].endswith("/reviews") for call in calls.call_args_list))
            with self.assertRaisesRegex(ValueError, "independent approval"):
                ci.verify_source_policy(dict(request, suite="ci"), "SYNTHETIC")

    def test_unprotected_environment_cannot_receive_signing_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = {"repository": "dobord/synthetic", "repository_id": 1,
                      "authorizer_branch": "main", "approval_boundaries": ["^ci/"]}
            (root / "policy.json").write_bytes(crypto.canonical(policy))
            replies = [crypto.canonical({"id": ci.BUILDER_ID}), crypto.canonical({"id": 1, "private": True}),
                       crypto.canonical({"commit": {"sha": "a" * 40}}),
                       crypto.canonical({"protection_rules": [], "deployment_branch_policy": None}),
                       crypto.canonical({"branch_policies": []})]
            with patch.object(bootstrap, "gh", side_effect=replies) as github:
                with self.assertRaises(ValueError):
                    bootstrap.configure(root, "a" * 40, root / "policy.json")
                self.assertTrue(all(call.args[0][0] == "api" for call in github.call_args_list))

    def test_actual_runner_preserves_failure_without_exposing_output_or_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "workspace/private-source").mkdir(parents=True)
            (root / "runner/project-ci").mkdir(parents=True)
            (root / "runner/project-ci/request.json").write_bytes(crypto.canonical(payload()))
            script = "import os; assert 'GH_TOKEN' not in os.environ; assert 'CI_INPUT_PRIVATE_KEY_B64' not in os.environ; print('PRIVATE_SENTINEL')"
            command = ("& " if os.name == "nt" else "") + f"'{os.sys.executable}' -c \"{script}\""
            lane = {"id": "synthetic", "profile": "ci", "matrix": {}, "runner": ["ubuntu-24.04"],
                    "job": {"steps": [{"run": command}, {"run": "exit 7"}]}}
            environment = {"GITHUB_WORKSPACE": str(root / "workspace"), "RUNNER_TEMP": str(root / "runner"),
                           "CI_LANE": "synthetic", "GITHUB_RUN_ID": "1", "GITHUB_RUN_NUMBER": "1",
                           "GITHUB_RUN_ATTEMPT": "1", "RUNNER_OS": "Windows" if os.name == "nt" else "Linux", "GH_TOKEN": "SYNTHETIC_SECRET",
                           "CI_INPUT_PRIVATE_KEY_B64": "SYNTHETIC_SECRET"}
            console = io.StringIO()
            with patch.dict(os.environ, environment), patch.object(ci, "recipes", return_value=[lane]), contextlib.redirect_stdout(console):
                with self.assertRaises(ValueError):
                    runner.run()
            self.assertEqual(console.getvalue(), "")
            self.assertIn("PRIVATE_SENTINEL", (root / "runner/project-ci/step-0.log").read_text())


class ProjectCiCryptoTests(unittest.TestCase):
    def test_explicit_sdk_key_reuse_preserves_backups_and_crypto_roles(self):
        signing_private, signing_public = crypto.generate("sign")
        input_private, input_public = crypto.generate("encrypt")
        texts = {"request-signing-private.json": signing_private, "request-signing-public.json": signing_public,
                 "builder-input-private.json": input_private, "builder-input-public.json": input_public}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in texts.items():
                (root / name).write_text(text)
                (root / name).chmod(0o600)
            actual = bootstrap.load_key_pairs(root, reuse_sdk_keys=True)
            self.assertEqual(crypto.verify(crypto.sign({"purpose": "pair-check"}, actual[0]), actual[1]), {"purpose": "pair-check"})
            self.assertEqual(crypto.fingerprint(actual[3]), crypto.fingerprint(input_public))
            self.assertTrue(all((root / name).read_text() == text for name, text in texts.items()))
            with self.assertRaises(FileNotFoundError):
                bootstrap.load_key_pairs(root)

    def test_shared_input_key_does_not_bypass_protocol_context(self):
        private, public = crypto.generate("encrypt")
        context = ci.message_context(str(uuid.uuid4()))
        ciphertext = crypto.seal_message(b"PUBLIC_SYNTHETIC_CI_REQUEST", public, context)
        self.assertEqual(crypto.open_message(ciphertext, private, context), b"PUBLIC_SYNTHETIC_CI_REQUEST")
        with self.assertRaises(Exception):
            crypto.open_message(ciphertext, private, dict(context, purpose="sdk-release-request"))

    def test_existing_tink_stream_authenticates_context_and_never_exposes_failed_output(self):
        private, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "plain.txt"
            source.write_bytes(b"PUBLIC_SYNTHETIC_SOURCE" * 100)
            context = ci.source_context(payload())
            crypto.encrypt_file(source, root / "sources.enc", public, context)
            crypto.decrypt_file(root / "sources.enc", root / "valid.txt", private, context)
            self.assertEqual((root / "valid.txt").read_bytes(), source.read_bytes())
            with self.assertRaises(ValueError):
                crypto.decrypt_file(root / "sources.enc", root / "failed.txt", private,
                                    dict(context, source_attempt=2))
            self.assertFalse((root / "failed.txt").exists())

    def test_signed_source_request_rejects_revision_and_ciphertext_substitution(self):
        private, public = crypto.generate("sign")
        request = payload()
        document = crypto.sign(request, private)
        self.assertEqual(crypto.verify(document, public), request)
        for changes in ({"source_sha": "e" * 40}, {"source_cipher_digest": "f" * 64}):
            with self.subTest(changes=changes), self.assertRaises(Exception):
                crypto.verify({"payload": dict(request, **changes), "signature": document["signature"]}, public)

    def test_distributed_bundle_reverifies_signature_before_source_checkout(self):
        import subprocess
        import tarfile
        input_private, input_public = crypto.generate("encrypt")
        signing_private, signing_public = crypto.generate("sign")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            subprocess.run(["git", "init", "--bare", str(repo)], check=True, capture_output=True)
            tree = subprocess.check_output(["git", "-C", str(repo), "mktree"], input=b"").decode().strip()
            env = dict(os.environ, GIT_AUTHOR_NAME="Synthetic", GIT_AUTHOR_EMAIL="synthetic@example.invalid",
                       GIT_COMMITTER_NAME="Synthetic", GIT_COMMITTER_EMAIL="synthetic@example.invalid")
            commit = subprocess.check_output(["git", "-C", str(repo), "commit-tree", tree], input=b"Synthetic fixture\n", env=env).decode().strip()
            subprocess.run(["git", "-C", str(repo), "update-ref", "refs/heads/candidate", commit], check=True)
            subprocess.run(["git", "-C", str(repo), "bundle", "create", str(root / "repository.bundle"), "--all"], check=True, capture_output=True)
            request = dict(payload(), source_sha=commit, base_sha=commit)
            crypto.encrypt_file(root / "repository.bundle", root / "sources.enc", input_public, ci.source_context(request))
            request["source_cipher_digest"] = crypto.digest(root / "sources.enc")
            for tampered in (False, True):
                with self.subTest(tampered=tampered):
                    case = root / ("tampered" if tampered else "valid")
                    case.mkdir()
                    signed = crypto.sign(request, signing_private)
                    if tampered:
                        # Even a valid envelope may not substitute the signed tree.
                        signed["payload"] = dict(request, source_sha="f" * 40)
                    (case / "request.json").write_bytes(crypto.canonical(signed))
                    with tarfile.open(case / "prepared.tar", "w") as archive:
                        archive.add(root / "sources.enc", arcname="sources.enc")
                        archive.add(case / "request.json", arcname="request.json")
                    context_env = {"GITHUB_WORKSPACE": str(case / "workspace"), "RUNNER_TEMP": str(case / "runner"),
                                   "GITHUB_SHA": request["builder_sha"], "GITHUB_RUN_ID": "2", "GITHUB_RUN_ATTEMPT": "1",
                                   "CI_REQUEST_ID": request["request_id"], "CI_REQUEST_DIGEST": "d" * 64,
                                   "CI_INPUT_PRIVATE_KEY_B64": crypto.b64(input_private.encode()),
                                   "CI_VERIFY_PUBLIC_KEY_B64": crypto.b64(signing_public.encode()),
                                   "GITHUB_OUTPUT": str(case / "output.txt")}
                    (case / "workspace").mkdir()
                    (case / "runner").mkdir()
                    with patch.dict(os.environ, context_env):
                        crypto.encrypt_file(case / "prepared.tar", case / "runner/cipher-input/sources.enc", input_public, ci.builder_context("sources"))
                        if tampered:
                            with self.assertRaises(Exception):
                                ci.materialize()
                            self.assertFalse((case / "workspace/private-source").exists())
                        else:
                            ci.materialize()
                            actual = subprocess.check_output(["git", "-C", str(case / "workspace/private-source"), "rev-parse", "HEAD"]).decode().strip()
                            self.assertEqual(actual, commit)


if __name__ == "__main__":
    unittest.main()
