"""Synthetic diagnostics regressions; no production logs or private keys."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from secure_release import cef_windows_diagnostics as diagnostics


def status(**changes):
    value = dict(status="failed", exit_code=1, slice_seconds=9000,
                 elapsed_seconds=123.5, timed_out=False, unsafe_stop=False,
                 engine_runtime_verified=False)
    value.update(changes)
    return json.dumps(value).encode()


class WindowsDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()

    def write(self, name, data):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        return target

    def test_semantic_clang_error_is_bounded_but_raw_evidence_is_retained(self):
        line = "PRIVATE_PATH/source.cc:17:3: error: no member named 'PRIVATE_MEMBER' in 'PRIVATE_TYPE'\n"
        self.write("cef-windows-engine-logs/ninja-slice.log", "FAILED: PRIVATE_OUTPUT\n" + line)
        self.write("cef-windows-engine-logs/ninja-slice.json", status())
        self.write("cef-windows-engine-slice.log", "PRIVATE_COMMAND\n" + line)
        report = diagnostics.collect(self.root)
        self.assertEqual(report["failure_reason"], "missing-member")
        self.assertTrue(report["ninja_status_valid"])
        self.assertEqual(report["ninja"]["exit_code"], 1)
        self.assertFalse(report["qualification_evidence"])
        public = (self.root / diagnostics.PUBLIC_REPORT).read_text()
        self.assertNotIn("PRIVATE_", public)
        self.assertIn(line, (self.root / diagnostics.STAGING / "ninja-slice.log").read_text())

    def test_original_summary_and_checkpoint_are_never_modified(self):
        original = b'{"schema":1,"status":"failed","checkpoint_ready":false,"ready":false,"runtime_verified":false}\n'
        summary = self.write("cef-windows-engine-summary.json", original)
        checkpoint = self.write("cef-windows-engine-checkpoint-encrypted/index.enc", b"ciphertext")
        self.write("cef-windows-engine-logs/ninja-slice.json", status(status="complete", exit_code=0))
        report = diagnostics.collect(self.root)
        self.assertEqual(summary.read_bytes(), original)
        self.assertEqual(checkpoint.read_bytes(), b"ciphertext")
        self.assertNotIn("ready", report)
        self.assertNotIn("checkpoint_ready", report)
        self.assertNotIn("runtime_verified", report)
        self.assertNotIn("engine_runtime_verified", report["ninja"])
        self.assertFalse(report["qualification_evidence"])

    def test_unknown_status_fields_do_not_leak(self):
        value = diagnostics.ninja_status(status(command="PRIVATE_COMMAND", path="PRIVATE_PATH", secret="PRIVATE_SECRET"))
        self.assertEqual(set(value), {"status", "exit_code", "slice_seconds", "elapsed_seconds", "timed_out", "unsafe_stop"})
        self.assertNotIn("PRIVATE_", json.dumps(value))

    def test_invalid_status_types_and_ranges_are_rejected(self):
        for changes in (
            {"exit_code": True}, {"exit_code": "1"}, {"exit_code": 2**32},
            {"exit_code": -(2**31)-1}, {"slice_seconds": True},
            {"slice_seconds": 0}, {"slice_seconds": 10801},
            {"timed_out": 1}, {"unsafe_stop": "false"},
            {"elapsed_seconds": float("nan")}, {"elapsed_seconds": float("inf")},
            {"elapsed_seconds": -1}, {"elapsed_seconds": True},
            {"status": "PRIVATE_TEXT"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                diagnostics.ninja_status(status(**changes))

    def test_duplicate_status_fields_are_rejected(self):
        payload = status().decode().replace('"exit_code": 1', '"exit_code": 0, "exit_code": 1')
        with self.assertRaises(ValueError):
            diagnostics.ninja_status(payload.encode())

    def test_oversized_status_is_rejected(self):
        with self.assertRaises(ValueError):
            diagnostics.ninja_status(b" " * (diagnostics.STATUS_BYTES + 1))

    def test_missing_diagnostics_do_not_fabricate_a_failure(self):
        report = diagnostics.collect(self.root)
        self.assertEqual(report["captured_files"], 0)
        self.assertEqual(report["failure_reason"], "unclassified")
        self.assertFalse(report["ninja_status_available"])
        self.assertNotIn("ninja", report)

    def test_malformed_status_is_preserved_only_privately(self):
        self.write("cef-windows-engine-logs/ninja-slice.json", b"PRIVATE_INVALID_JSON")
        report = diagnostics.collect(self.root)
        self.assertTrue(report["ninja_status_available"])
        self.assertFalse(report["ninja_status_valid"])
        self.assertNotIn("PRIVATE_", (self.root / diagnostics.PUBLIC_REPORT).read_text())
        self.assertEqual((self.root / diagnostics.STAGING / "ninja-slice.json").read_bytes(), b"PRIVATE_INVALID_JSON")

    def test_ninja_log_takes_precedence_over_wrapper(self):
        self.write("cef-windows-engine-slice.log", "old text: error: use of undeclared identifier")
        self.write("cef-windows-engine-logs/ninja-slice.log", "FAILED: obj/x\nninja: build stopped")
        self.assertEqual(diagnostics.collect(self.root)["failure_reason"], "ninja-failed")

    def test_wrapper_is_used_when_ninja_has_not_started(self):
        self.write("cef-windows-engine-slice.log", "CreateProcess failed")
        self.assertEqual(diagnostics.collect(self.root)["failure_reason"], "missing-tool")

    def test_reason_labels_are_fixed_for_representative_failures(self):
        for text, expected in (
            ("error: use of undeclared identifier 'private'", "undeclared-identifier"),
            ("error: no matching function for call to private", "no-matching-function"),
            ("error: static assertion failed: private", "static-assertion"),
            ("error C2440: private", "type-conversion"),
            ("fatal error: 'private.h' file not found", "missing-header"),
            ("lld-link: error: undefined symbol private", "linker-error"),
            ("error LNK2019: private", "linker-error"),
            ("[-Werror,-Wprivate]", "warning-as-error"),
            ("FAILED: output\nNo space left on device", "disk-full"),
            ("LLVM ERROR: out of memory", "out-of-memory"),
            ("PLEASE submit a bug report", "compiler-crash"),
            ("error: unknown private diagnostic", "compiler-error"),
            ("normal completion", "unclassified"),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(diagnostics.classify(text), expected)

    def test_large_log_retains_bounded_head_and_tail(self):
        self.write("cef-windows-engine-logs/ninja-slice.log", b"HEAD" + b"x"*1000 + b"\nerror: no member named 'private'\nTAIL")
        with mock.patch.object(diagnostics, "CAPTURE_BYTES", 128):
            report = diagnostics.collect(self.root)
        payload = (self.root / diagnostics.STAGING / "ninja-slice.log").read_bytes()
        self.assertLess(len(payload), 256)
        self.assertTrue(payload.startswith(b"HEAD"))
        self.assertTrue(payload.endswith(b"TAIL"))
        self.assertIn(b"middle omitted", payload)
        self.assertEqual(report["truncated_files"], 1)
        self.assertEqual(report["failure_reason"], "missing-member")

    def test_source_files_are_not_collected(self):
        self.write("credentials.txt", "PRIVATE_KEY")
        self.write("cef-windows-engine-work/download/source.cc", "PRIVATE_SOURCE")
        self.write("unrelated.log", "PRIVATE_UNRELATED")
        report = diagnostics.collect(self.root)
        self.assertEqual(report["captured_files"], 0)
        self.assertEqual(list((self.root / diagnostics.STAGING).iterdir()), [])

    def test_existing_outputs_are_not_overwritten(self):
        self.write(diagnostics.PUBLIC_REPORT, "sentinel")
        with self.assertRaises(ValueError):
            diagnostics.collect(self.root)
        self.assertEqual((self.root / diagnostics.PUBLIC_REPORT).read_text(), "sentinel")

    def test_directory_in_place_of_log_is_rejected(self):
        (self.root / "cef-windows-engine-slice.log").mkdir()
        with self.assertRaises(ValueError):
            diagnostics.collect(self.root)
        self.assertFalse((self.root / diagnostics.STAGING).exists())

    def test_hard_linked_input_is_rejected(self):
        source = self.write("other", "private")
        os.link(source, self.root / "cef-windows-engine-slice.log")
        with self.assertRaises(ValueError):
            diagnostics.collect(self.root)

    def test_symlinked_parent_is_rejected(self):
        (self.root / "other").mkdir()
        try:
            (self.root / "cef-windows-engine-logs").symlink_to(self.root / "other", target_is_directory=True)
        except OSError:
            self.skipTest("Host does not allow unprivileged symlinks")
        with self.assertRaises(ValueError):
            diagnostics.collect(self.root)

    def test_windows_reparse_parent_is_rejected_without_following_it(self):
        fake = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
        with mock.patch.object(Path, "lstat", return_value=fake), self.assertRaises(ValueError):
            diagnostics._checked_path(self.root, "cef-windows-engine-logs/ninja-slice.log")

    def test_cli_error_never_prints_private_exception(self):
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}):
            with mock.patch.object(diagnostics, "collect", side_effect=OSError("PRIVATE_PATH PRIVATE_KEY")):
                with self.assertRaises(SystemExit) as error:
                    diagnostics.main()
        self.assertEqual(str(error.exception), "CEF_WINDOWS_DIAGNOSTICS_FAILED")

    def test_cli_output_is_bounded_and_no_secret_environment_is_read(self):
        self.write("cef-windows-engine-slice.log", "error: PRIVATE_TEXT")
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "BUILDER_INPUT_PRIVATE_KEY": "PRIVATE_KEY"}):
            with contextlib.redirect_stdout(output):
                diagnostics.main()
        self.assertEqual(output.getvalue(), "CEF_WINDOWS_DIAGNOSTICS_CAPTURED files=1\n")
        self.assertNotIn("PRIVATE_", (self.root / diagnostics.PUBLIC_REPORT).read_text())

    def test_workflow_keeps_diagnostics_separate_from_qualified_summary(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/cef-windows-engine-iteration.yml").read_text()
        self.assertIn("python -m secure_release.cef_windows_diagnostics", workflow)
        self.assertIn("python -m unittest discover -s tests -p test_cef_windows_diagnostics.py -v", workflow)
        self.assertIn("python -m unittest discover -s tests -p test_encrypted_logs.py -v", workflow)
        self.assertIn("uses: ./.github/actions/encrypted-logs", workflow)
        self.assertIn("${{ runner.temp }}/cef-windows-iteration-diagnostics", workflow)
        self.assertIn("${{ runner.temp }}/cef-windows-engine-logs", workflow)
        self.assertIn("path: ${{ runner.temp }}/cef-windows-engine-diagnostics.json\n", workflow)
        self.assertIn("path: ${{ runner.temp }}/cef-windows-engine-summary.json\n", workflow)
        self.assertIn("steps.iteration.outcome == 'failure'", workflow)
        self.assertNotIn("continue-on-error", workflow)
        self.assertNotIn("path: ${{ runner.temp }}\n", workflow)
        self.assertNotIn("path: ${{ runner.temp }}/*.log", workflow)
        self.assertIn("checkpoint_ready == 'true'", workflow)
        self.assertIn("retention-days: 90", workflow)


if __name__ == "__main__":
    unittest.main()
