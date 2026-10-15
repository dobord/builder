"""Bounded private preparation diagnostics never authorize a failed request."""
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import yaml
from secure_release import crypto, project_ci as ci


class PrepareDiagnosticsTests(unittest.TestCase):
    def error(self, error):
        private_local = "PUBLIC_SYNTHETIC_SECRET_IN_LOCALS"
        try:
            raise error
        except Exception as caught:
            self.assertTrue(private_local)
            return caught

    def test_fixed_reason_and_trace_are_bounded_and_contain_no_locals(self):
        report = ci.prepare_failure_record(self.error(ValueError("request identity mismatch")))
        self.assertEqual(report["schema"], 1)
        self.assertEqual(report["stage"], "prepare")
        self.assertEqual(report["exception"], "ValueError")
        self.assertEqual(report["code"], "request identity mismatch")
        self.assertTrue(report["frames"])
        self.assertLessEqual(len(report["frames"]), 16)
        self.assertEqual(set(report["frames"][0]), {"module", "function", "line"})
        self.assertNotIn("PUBLIC_SYNTHETIC_SECRET_IN_LOCALS", json.dumps(report))
        self.assertLessEqual(len(crypto.canonical(report)), ci.PREPARE_DIAGNOSTIC_MAX_BYTES)

    def test_arbitrary_error_messages_attributes_and_str_are_never_read(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError("arbitrary exception string must not execute")
        marker = "PUBLIC_SYNTHETIC_NOT_A_REAL_KEY_OR_TOKEN"
        errors = [PrivateError(marker), ValueError(marker), ValueError({"private": marker}),
                  ValueError([marker]), RuntimeError("https://example.invalid/" + marker)]
        for error in errors:
            error.private_material = marker
            with self.subTest(kind=type(error).__name__):
                report = ci.prepare_failure_record(self.error(error))
                self.assertEqual(report["code"], "unclassified prepare failure")
                self.assertNotIn(marker, json.dumps(report))

    def test_http_status_only_is_recorded_with_no_url_headers_or_body(self):
        marker = "PUBLIC_SYNTHETIC_HTTP_SECRET"
        for status in (401, 403, 429, 500, 599, True, "403", 399, 600):
            with self.subTest(status=status):
                error = urllib.error.HTTPError("https://example.invalid/" + marker, status, marker,
                    {"Authorization": marker}, io.BytesIO(marker.encode()))
                report = ci.prepare_failure_record(self.error(error))
                if type(status) is int and 400 <= status <= 599:
                    self.assertEqual(report["http_status"], status)
                else:
                    self.assertNotIn("http_status", report)
                self.assertNotIn(marker, json.dumps(report))

    def test_invalid_code_identifiers_and_urls_use_placeholders(self):
        marker = "PUBLIC_SYNTHETIC_CODE_SECRET"
        namespace = {}
        function = "function_" + "x" * 200
        exec(compile(f"def {function}():\n    raise ValueError('arbitrary message')\n",
                     "https://example.invalid/" + marker + ".py", "exec"), namespace)
        try:
            namespace[function]()
        except ValueError as error:
            report = ci.prepare_failure_record(error)
        self.assertNotIn(marker, json.dumps(report))
        self.assertNotIn(function, json.dumps(report))
        self.assertEqual(report["frames"][-1]["module"], "<invalid>")
        self.assertEqual(report["frames"][-1]["function"], "<invalid>")
        error = type("invalid/type/" + marker, (Exception,), {})(marker)
        self.assertEqual(ci.prepare_failure_record(error)["exception"], "<invalid>")

    def test_deep_trace_has_bounded_walk_and_sixteen_frames(self):
        def recurse(count):
            if count:
                return recurse(count - 1)
            raise ValueError("arbitrary")
        try:
            recurse(100)
        except ValueError as error:
            report = ci.prepare_failure_record(error)
        self.assertEqual(len(report["frames"]), 16)
        self.assertTrue(report["frames_truncated"])
        self.assertLessEqual(len(crypto.canonical(report)), ci.PREPARE_DIAGNOSTIC_MAX_BYTES)

    def test_record_is_owner_private_exclusive_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            ci.record_prepare_failure(ValueError("request identity mismatch"))
            directory = Path(tmp) / "project-ci-prepare-diagnostics"
            record = directory / "prepare-error.json"
            before = record.read_bytes()
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
            with self.assertRaises((FileExistsError, ValueError)):
                ci.record_prepare_failure(ValueError("different reason"))
            self.assertEqual(record.read_bytes(), before)

    def symlink(self, path, target, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except NotImplementedError:
            self.skipTest("Host cannot create the required symlink fixture")
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES) or getattr(error, "winerror", None) in (5, 1314):
                self.skipTest("Host denies creation of the required symlink fixture")
            raise

    def test_linked_diagnostic_directory_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            outside = Path(tmp) / "outside"
            outside.mkdir()
            self.symlink(Path(tmp) / "project-ci-prepare-diagnostics", outside, directory=True)
            with self.assertRaises((OSError, ValueError)):
                ci.record_prepare_failure(ValueError("arbitrary"))
            with self.assertRaises((OSError, ValueError)):
                ci.ensure_prepare_diagnostics()
            self.assertEqual(list(outside.iterdir()), [])

    def test_linked_error_record_is_rejected_not_used_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            directory = Path(tmp) / "project-ci-prepare-diagnostics"
            directory.mkdir(mode=0o700)
            outside = Path(tmp) / "outside.json"
            outside.write_text("PUBLIC_SYNTHETIC_OUTSIDE", encoding="utf-8")
            self.symlink(directory / "prepare-error.json", outside)
            with self.assertRaises((OSError, ValueError)):
                ci.ensure_prepare_diagnostics()
            self.assertEqual(outside.read_text(encoding="utf-8"), "PUBLIC_SYNTHETIC_OUTSIDE")

    def test_missing_prepare_record_has_fixed_non_authorizing_header(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            ci.ensure_prepare_diagnostics()
            directory = Path(tmp) / "project-ci-prepare-diagnostics"
            self.assertEqual(json.loads((directory / "prepare-status.json").read_text(encoding="utf-8")),
                {"schema": 1, "stage": "prepare", "state": "no-prepare-error-record"})
            ci.ensure_prepare_diagnostics()  # Existing evidence is not replaced.

    def test_main_preserves_public_marker_and_failure_when_recording_fails(self):
        for recording_error in (OSError("PUBLIC_SYNTHETIC_ERROR"), KeyboardInterrupt()):
            with self.subTest(kind=type(recording_error).__name__), patch.object(sys, "argv", ["project_ci", "prepare"]), patch.object(ci, "prepare", side_effect=ValueError("PUBLIC_SYNTHETIC_SECRET")), patch.object(ci, "record_prepare_failure", side_effect=recording_error) as record:
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as exit:
                    ci.main()
                self.assertEqual(exit.exception.code, 1)
                self.assertEqual(output.getvalue(), "::error::PROJECT_CI_STAGE_FAILED stage=prepare; diagnostics remain private\n")
                record.assert_called_once()

    def test_prepare_main_failure_leaves_only_private_record_and_no_matrix(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}), patch.object(sys, "argv", ["project_ci", "prepare"]), patch.object(ci, "prepare", side_effect=ValueError("request identity mismatch")), patch.object(ci, "output") as matrix:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit:
                ci.main()
            self.assertEqual(exit.exception.code, 1)
            matrix.assert_not_called()
            record = Path(tmp) / "project-ci-prepare-diagnostics/prepare-error.json"
            self.assertEqual(json.loads(record.read_text(encoding="utf-8"))["code"], "request identity mismatch")

    def test_diagnostics_reuses_log_context_and_public_recipient_then_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            environment = {"RUNNER_TEMP": tmp, "GITHUB_WORKSPACE": str(workspace), "GITHUB_JOB": "prepare"}
            expected = {"schema": 1, "kind": "builder-encrypted-ci-logs", "repository": ci.BUILDER,
                "workflow": "Encrypted project qualification", "job": "prepare", "run_id": 1,
                "run_attempt": 1, "sha": "a" * 40}
            with patch.dict(os.environ, environment), patch.object(sys, "argv", ["project_ci", "diagnostics"]), patch.object(ci.crypto, "unb64", return_value=b"PUBLIC_SYNTHETIC_LOG_RECIPIENT"), patch.object(ci.encrypted_logs, "github_context", return_value=expected), patch.object(ci.encrypted_logs, "collect") as collect:
                ci.main()
                roots, target, key, context = collect.call_args.args
                self.assertIn(root / "project-ci-prepare-diagnostics", roots)
                self.assertEqual(target, root / "cipher-logs/diagnostics.enc")
                self.assertEqual(key, "PUBLIC_SYNTHETIC_LOG_RECIPIENT")
                self.assertEqual(context, expected)
            with patch.dict(os.environ, environment), patch.object(sys, "argv", ["project_ci", "cleanup"]):
                ci.main()
            self.assertFalse((root / "project-ci-prepare-diagnostics").exists())

    def test_missing_crypto_runtime_cannot_publish_plaintext_or_authorize_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            environment = {"RUNNER_TEMP": tmp, "GITHUB_WORKSPACE": str(workspace), "GITHUB_JOB": "prepare"}
            with patch.dict(os.environ, environment), patch.object(sys, "argv", ["project_ci", "diagnostics"]), patch.object(ci.crypto, "unb64", return_value=b"PUBLIC_RECIPIENT"), patch.object(ci.encrypted_logs, "github_context", return_value={}), patch.object(ci.encrypted_logs, "collect", side_effect=ImportError("PUBLIC_SYNTHETIC_RUNTIME_ERROR")), contextlib.redirect_stderr(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as exit:
                    ci.main()
            self.assertEqual(exit.exception.code, 1)
            self.assertEqual(output.getvalue(), "::error::PROJECT_CI_STAGE_FAILED stage=diagnostics; diagnostics remain private\n")
            self.assertTrue((root / "project-ci-prepare-diagnostics/prepare-status.json").exists())
            self.assertFalse((root / "cipher-logs/diagnostics.enc").exists())

    def test_posix_record_permissions_must_not_be_broadened(self):
        if os.name != "posix":
            self.skipTest("POSIX mode bits; Windows uses trusted runner-directory ACLs")
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            ci.record_prepare_failure(ValueError("arbitrary"))
            record = Path(tmp) / "project-ci-prepare-diagnostics/prepare-error.json"
            record.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "ownership"):
                ci.ensure_prepare_diagnostics()

    def test_hardlinked_error_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"RUNNER_TEMP": tmp}):
            ci.record_prepare_failure(ValueError("arbitrary"))
            record = Path(tmp) / "project-ci-prepare-diagnostics/prepare-error.json"
            try:
                os.link(record, Path(tmp) / "second-name.json")
            except NotImplementedError:
                self.skipTest("Host cannot create the required hardlink fixture")
            except OSError as error:
                if error.errno in (errno.EPERM, errno.EACCES, errno.ENOTSUP) or getattr(error, "winerror", None) in (1, 5, 1314):
                    self.skipTest("Host denies creation of the required hardlink fixture")
                raise
            with self.assertRaisesRegex(ValueError, "unsafe prepare diagnostic record"):
                ci.ensure_prepare_diagnostics()

    def test_workflow_always_encrypts_uploads_before_cleanup_without_secrets(self):
        workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/encrypted-project-ci.yml").read_text(encoding="utf-8"))
        self.assertEqual(set(workflow["jobs"]), {"prepare", "qualify", "required"})
        steps = workflow["jobs"]["prepare"]["steps"]
        prepare = next(index for index, step in enumerate(steps) if step.get("id") == "prepare")
        diagnostic = next(index for index, step in enumerate(steps) if step.get("run") == "python -m secure_release.project_ci diagnostics")
        upload = next(index for index, step in enumerate(steps) if step.get("with", {}).get("name", "").startswith("ШИФРОВАНЫЕ ЛОГИ-prepare-"))
        cleanup = next(index for index, step in enumerate(steps) if step.get("run") == "python -m secure_release.project_ci cleanup")
        self.assertLess(prepare, diagnostic)
        self.assertLess(diagnostic, upload)
        self.assertLess(upload, cleanup)
        for index in (diagnostic, upload, cleanup):
            self.assertEqual(steps[index]["if"], "always()")
            self.assertNotIn("continue-on-error", steps[index])
        self.assertNotIn("env", steps[diagnostic])
        self.assertEqual(steps[upload]["with"]["path"], "${{ runner.temp }}/cipher-logs/*.enc")
        self.assertEqual(steps[upload]["with"]["if-no-files-found"], "error")
        for step in steps:
            name = step.get("with", {}).get("name", "")
            if name.startswith(("sources-", "dependency-review-")):
                self.assertNotIn("if", step)  # Original implicit success guard.
        self.assertEqual(workflow["jobs"]["qualify"]["needs"], "prepare")


if __name__ == "__main__":
    unittest.main()
