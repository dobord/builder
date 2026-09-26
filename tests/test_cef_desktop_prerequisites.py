"""Replay the real CEF prerequisite before testing strict desktop composition.

These are complete pinned public source fixtures, not private build logs or
engine runtime qualification. No network or large checkpoint is required.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib

from secure_release import cef_x11_static as desktop
from test_cef_x11_static import fake_platform, fixture_files

ROOT = Path(__file__).parent / "fixtures/desktop"
FIXTURE_SHA256 = "6b2da9357292c05bc036b8fc57fd86485454223279a12a025361be54516a4d94"
PATCH_SHA256 = "f1ae2665eec112445ade881252bbf48313f0e90dab22d3db72964278cb380492"
OLD_STOCK_PATCHED_SHA256 = "72c8e8c4b65e3b2aac4a0078ab1f1fd2e18aba34b45b0156877f2d237070ac40"


def public_sources():
    data = (ROOT / "source-prerequisites.json.zlib").read_bytes()
    if hashlib.sha256(data).hexdigest() != FIXTURE_SHA256:
        raise ValueError("Public desktop prerequisite fixture changed")
    decoder = zlib.decompressobj()
    decoded = decoder.decompress(data, 256 * 1024)
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("Invalid or oversized public desktop prerequisite fixture")
    value = json.loads(decoded)
    expected = {desktop.GTK_FILE, desktop.DESKTOP_FILE, "linux_gtk_theme_3610.gtk.patch"}
    if set(value) != expected or not all(isinstance(v, str) for v in value.values()):
        raise ValueError("Invalid public desktop prerequisite inventory")
    result = {name: text.encode("utf-8") for name, text in value.items()}
    for name in (desktop.GTK_FILE, desktop.DESKTOP_FILE):
        if hashlib.sha256(result[name]).hexdigest() != desktop.FILES[name]:
            raise ValueError("Public desktop source is not the pinned complete file")
    if hashlib.sha256(result["linux_gtk_theme_3610.gtk.patch"]).hexdigest() != PATCH_SHA256:
        raise ValueError("Public CEF GTK prerequisite patch changed")
    return result


def replay_vendor_patch(original: bytes, vendor_patch: bytes) -> bytes:
    """Use git apply as an independent oracle, not the repair's own transform."""
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        source = root / desktop.GTK_FILE
        source.parent.mkdir(parents=True)
        source.write_bytes(original)
        # Git for Windows defaults can convert a successful patch result to
        # CRLF. Pin the public oracle's output policy, not the production hashes.
        # Do not normalize bytes after replay: unknown content must still fail.
        command = ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
                   "apply", "-p0", "--include=" + desktop.GTK_FILE, "-"]
        result = subprocess.run(command, cwd=root, input=vendor_patch,
                                capture_output=True, timeout=30)
        if result.returncode:
            raise AssertionError("Exact public CEF prerequisite patch did not apply")
        return source.read_bytes()


class DesktopPrerequisiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = public_sources()
        cls.original = cls.inputs[desktop.GTK_FILE]
        cls.baseline = replay_vendor_patch(
            cls.original, cls.inputs["linux_gtk_theme_3610.gtk.patch"])

    def test_vendor_replay_is_independent_of_global_crlf_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "gitconfig"
            data = b"[core]\n    autocrlf = true\n    eol = crlf\n"
            config.write_bytes(data)
            # Exercise the actual Git subprocess under the setting that caused
            # the Windows-only failure. Never change a user's Git configuration.
            with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config),
                                         "GIT_CONFIG_NOSYSTEM": "1"}):
                actual = replay_vendor_patch(
                    self.original, self.inputs["linux_gtk_theme_3610.gtk.patch"])
            self.assertEqual(config.read_bytes(), data)
            self.assertNotIn(b"\r\n", actual)
            self.assertEqual(hashlib.sha256(actual).hexdigest(),
                             desktop.CEF_GTK_THEME_SHA256)
            self.assertEqual(desktop.transform(desktop.GTK_FILE, actual, self.original),
                             desktop.transform(desktop.GTK_FILE, self.baseline, self.original))

    def test_real_cef_patch_explains_old_complete_source_rejection(self):
        data = self.baseline
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        self.assertEqual(blob, "4e7f63878bfa1558167db2e91ad08394b3bd57bb")
        # #73 checked stock and stock+GDK only. Neither is the CEF workspace.
        old_known = {desktop.FILES[desktop.GTK_FILE], OLD_STOCK_PATCHED_SHA256}
        self.assertNotIn(hashlib.sha256(data).hexdigest(), old_known)
        self.assertEqual(data, desktop.cef_gtk_baseline(self.original))

    def test_composition_retains_all_vendor_bytes_and_is_idempotent(self):
        result = desktop.transform(desktop.GTK_FILE, self.baseline, self.original)
        self.assertEqual(result, desktop.patch_gtk_software(self.baseline.decode()).encode())
        self.assertEqual(hashlib.sha256(result).hexdigest(), desktop.PATCHED[desktop.GTK_FILE])
        self.assertEqual(desktop.transform(desktop.GTK_FILE, result, self.original), result)
        self.assertIn(b'#include "cef/libcef/features/features.h"', result)
        self.assertIn(b'#if !BUILDFLAG(ENABLE_CEF)', result)
        self.assertLess(result.index(b'"GDK_GL", "disable"'), result.index(b'GtkInitFromCommandLine'))

    def test_stock_only_wrong_old_result_and_partial_vendor_states_rejected(self):
        candidates = [
            self.original,
            desktop.patch_gtk_software(self.original.decode()).encode(),
            self.baseline.replace(b'#include "cef/libcef/features/features.h"\n', b''),
            self.baseline.replace(b'#if !BUILDFLAG(ENABLE_CEF)', b'#if 1'),
            self.baseline + b'\n',
        ]
        for data in candidates:
            with self.subTest(sha=hashlib.sha256(data).hexdigest()):
                with self.assertRaisesRegex(ValueError, "ui/gtk/gtk_ui.cc"):
                    desktop.transform(desktop.GTK_FILE, data, self.original)

    def test_partial_own_patch_and_changed_original_rejected(self):
        result = desktop.transform(desktop.GTK_FILE, self.baseline, self.original)
        with self.assertRaises(ValueError):
            desktop.transform(desktop.GTK_FILE, result.replace(b'"GDK_GL", "disable"', b'"GDK_GL", "always"'), self.original)
        with self.assertRaises(ValueError):
            desktop.transform(desktop.GTK_FILE, self.baseline, self.original + b'\n')
        with self.assertRaises(ValueError):
            desktop.cef_gtk_baseline(self.original + b'\n')

    def test_complete_webrtc_source_not_only_a_copied_anchor(self):
        original = self.inputs[desktop.DESKTOP_FILE]
        result = desktop.transform(desktop.DESKTOP_FILE, original, original)
        self.assertEqual(hashlib.sha256(result).hexdigest(), desktop.PATCHED[desktop.DESKTOP_FILE])
        self.assertEqual(desktop.transform(desktop.DESKTOP_FILE, result, original), result)

    def test_install_composes_all_five_files_and_keeps_resumed_mtimes(self):
        originals = fixture_files()
        originals.update({n: self.inputs[n] for n in (desktop.GTK_FILE, desktop.DESKTOP_FILE)})
        self.assertEqual(set(desktop.PATCHERS), {n for n in originals if n in desktop.PATCHERS})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, prefix, sha = fake_platform(root)
            source = root / "src"
            for relative in desktop.PATCHERS:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(self.baseline if relative == desktop.GTK_FILE else originals[relative])
            def git(args, **kwargs):
                if "rev-parse" in args:
                    return desktop.WEBRTC if Path(args[2]).name == "webrtc" else desktop.CHROMIUM
                name = args[-1].split(":", 1)[1]
                if Path(args[2]).name == "webrtc":
                    name = "third_party/webrtc/" + name
                return originals[name]
            with patch.object(desktop.subprocess, "check_output", side_effect=git):
                # All five files are validated before any write, including GTK
                # last in the patch order: a failed prerequisite is not a reset.
                gtk = source / desktop.GTK_FILE
                before = {n: (source / n).read_bytes() for n in desktop.PATCHERS}
                gtk.write_bytes(self.original)
                with self.assertRaises(ValueError):
                    desktop.install(source, manifest, prefix, sha)
                for name in desktop.PATCHERS:
                    if name != desktop.GTK_FILE:
                        self.assertEqual((source / name).read_bytes(), before[name])
                gtk.write_bytes(self.baseline)
                receipt = desktop.install(source, manifest, prefix, sha)
                self.assertEqual(receipt["changed_files"], 5)
                self.assertEqual(receipt["verified_files"], 5)
                self.assertFalse(receipt["runtime_verified"])
                mtimes = {n: (source / n).stat().st_mtime_ns for n in desktop.PATCHERS}
                self.assertEqual(desktop.install(source, manifest, prefix, sha)["changed_files"], 0)
                self.assertEqual(mtimes, {n: (source / n).stat().st_mtime_ns for n in desktop.PATCHERS})

    def test_fixture_preflight_runs_before_expensive_engine_restore(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/cef-strict-engine-iteration.yml").read_text()
        command = "python -m unittest discover -s tests -p test_cef_desktop_prerequisites.py -v"
        self.assertIn(command, workflow)
        self.assertLess(workflow.index(command), workflow.index("python -m secure_release.cef_strict_iteration_runtime"))


if __name__ == "__main__":
    unittest.main()
