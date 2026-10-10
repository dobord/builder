"""Fail-closed Windows CEF checkpoint workspace path migration."""
from __future__ import annotations

import copy
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

from secure_release import cef_windows_iteration as worker
from secure_release import cef_windows_source_repair as repair

LONG_HEADER = (
    "gen/third_party/blink/renderer/bindings/modules/v8/"
    "v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_"
    "imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
)


def private_codec():
    root = os.environ.get("CEF_REPAIR_RECIPE_DIR")
    if not root:
        raise unittest.SkipTest("Pinned private CEF recipe not supplied")
    path = Path(root) / "vcpkg/static/checkpoint.py"
    spec = importlib.util.spec_from_file_location("workspace_path_checkpoint_fixture", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WorkspaceRelocationTests(unittest.TestCase):
    def test_same_parent_rename_preserves_file_identity_bytes_and_mtime(self):
        with tempfile.TemporaryDirectory(prefix="cef workspace relocation ") as folder:
            root = Path(folder).resolve()
            old = root / "old"
            new = root / "w"
            payload = old / "download/chromium/src/out/existing.obj"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"compiled-object")
            os.utime(payload, ns=(1700000000123456700, 1700000000123456700))
            before = payload.stat()
            self.assertTrue(worker.relocate_workspace(old, new))
            moved = new / payload.relative_to(old)
            after = moved.stat()
            self.assertFalse(old.exists())
            self.assertEqual(moved.read_bytes(), b"compiled-object")
            self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))

    def test_relocation_rejects_existing_or_cross_parent_targets(self):
        with tempfile.TemporaryDirectory(prefix="cef workspace refusal ") as folder:
            root = Path(folder).resolve()
            old = root / "old"
            old.mkdir()
            existing = root / "w"
            existing.mkdir()
            with self.assertRaisesRegex(ValueError, "already exists"):
                worker.relocate_workspace(old, existing)
            existing.rmdir()
            other = root / "other"
            other.mkdir()
            with self.assertRaisesRegex(ValueError, "one directory"):
                worker.relocate_workspace(old, other / "w")


class PrivateCodecPathTests(unittest.TestCase):
    def test_codec_stays_strict_and_external_relocation_roundtrips(self):
        codec = private_codec()
        with tempfile.TemporaryDirectory(prefix="cef codec path migration ") as folder:
            root = Path(folder).resolve()
            legacy = root / "legacy"
            short = root / "w"
            sample = legacy / "download/chromium/src/out/keep.obj"
            sample.parent.mkdir(parents=True)
            sample.write_bytes(b"checkpoint-object")
            os.utime(sample, ns=(1700000001123456700, 1700000001123456700))
            original_mtime = sample.stat().st_mtime_ns
            package = root / "checkpoint-old"
            identity = {
                "recipe": "a" * 64,
                "work": str(legacy.resolve()),
                "repository": "dobord/builder",
                "ref": "refs/heads/feature/cef-static-integration",
                "platform": "windows-x64",
                "image": "20260927.320.1",
                "schema": codec.SCHEMA,
                "build_contract": repair.V14_KEY,
                "worker_schema": 1,
            }
            codec.save(legacy, package, identity)
            manifest = (package / "checkpoint.json").read_bytes()
            shutil.rmtree(legacy)

            changed = dict(identity, work=str(short.resolve()))
            with self.assertRaisesRegex(ValueError, "identity/schema mismatch"):
                codec.restore(package, short, changed)
            self.assertFalse(short.exists())
            self.assertEqual((package / "checkpoint.json").read_bytes(), manifest)

            codec.restore(package, legacy, identity)
            self.assertTrue(worker.relocate_workspace(legacy, short))
            moved = short / "download/chromium/src/out/keep.obj"
            self.assertEqual(moved.read_bytes(), b"checkpoint-object")
            self.assertEqual(moved.stat().st_mtime_ns, original_mtime)
            self.assertEqual((package / "checkpoint.json").read_bytes(), manifest)

            package2 = root / "checkpoint-short"
            identity2 = dict(identity, work=str(short.resolve()), build_contract=repair.build_key(repair.BASE_KEY))
            codec.save(short, package2, identity2)
            saved2 = (package2 / "checkpoint.json").read_bytes()
            shutil.rmtree(short)
            codec.restore(package2, short, identity2)
            self.assertEqual((short / "download/chromium/src/out/keep.obj").read_bytes(),
                             b"checkpoint-object")
            self.assertEqual((package2 / "checkpoint.json").read_bytes(), saved2)


@unittest.skipUnless(os.name == "nt", "Native Windows workspace path policy")
class NativeWorkspacePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = Path(os.environ["RUNNER_TEMP"]).resolve()
        self.key = repair.build_key(repair.BASE_KEY)

    def test_exact_legacy_selector_migrates_to_reviewed_short_path(self):
        restore, compile_work = worker.checkpoint_workspace_paths(
            self.temp, repair.UPGRADE_V14, {}, self.key
        )
        self.assertEqual(str(self.temp).casefold(), worker.REVIEWED_WINDOWS_RUNNER_TEMP.casefold())
        self.assertEqual(str(restore).casefold(), worker.LEGACY_CHECKPOINT_WORK.casefold())
        self.assertEqual(str(compile_work).casefold(), worker.CURRENT_CHECKPOINT_WORK.casefold())
        self.assertNotEqual(restore, compile_work)

    def test_exact_v15_upgrade_keeps_authenticated_short_path(self):
        short = (self.temp / worker.SHORT_WORK_BASENAME).resolve()
        proof = {"checkpoint_work_identity": str(short), "workspace_path_verified": True}
        restore, compile_work = worker.checkpoint_workspace_paths(
            self.temp, repair.UPGRADE_V15, proof, self.key
        )
        self.assertEqual((restore, compile_work), (short, short))
        with self.assertRaises(ValueError):
            worker.checkpoint_workspace_paths(self.temp, repair.UPGRADE_V15, {}, self.key)

    def test_exact_v16_upgrade_keeps_authenticated_short_path(self):
        short = (self.temp / worker.SHORT_WORK_BASENAME).resolve()
        proof = {"checkpoint_work_identity": str(short), "workspace_path_verified": True}
        restore, compile_work = worker.checkpoint_workspace_paths(
            self.temp, repair.UPGRADE_V16, proof, self.key
        )
        self.assertEqual((restore, compile_work), (short, short))
        with self.assertRaises(ValueError):
            worker.checkpoint_workspace_paths(self.temp, repair.UPGRADE_V16, {}, self.key)


    def test_exact_v19_upgrade_keeps_authenticated_short_path(self):
        short = (self.temp / worker.SHORT_WORK_BASENAME).resolve()
        proof = {"checkpoint_work_identity": str(short), "workspace_path_verified": True}
        self.assertEqual(worker.checkpoint_workspace_paths(self.temp, repair.UPGRADE_V19, proof, self.key),
                         (short, short))
        with self.assertRaises(ValueError):
            worker.checkpoint_workspace_paths(self.temp, repair.UPGRADE_V19, {}, self.key)

    def test_current_checkpoint_requires_authenticated_short_path_proof(self):
        selected = copy.deepcopy(repair.UPGRADE_V14)
        selected["run"] = 999999
        selected["producer_sha"] = "a" * 40
        selected["build_key"] = self.key
        short = (self.temp / worker.SHORT_WORK_BASENAME).resolve()
        proof = {"checkpoint_work_identity": str(short), "workspace_path_verified": True}
        restore, compile_work = worker.checkpoint_workspace_paths(
            self.temp, selected, proof, self.key
        )
        self.assertEqual((restore, compile_work), (short, short))
        for bad in (
            {},
            {"checkpoint_work_identity": str(short), "workspace_path_verified": False},
            {"checkpoint_work_identity": str(self.temp / "other"), "workspace_path_verified": True},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                worker.checkpoint_workspace_paths(self.temp, selected, bad, self.key)

    def test_native_getfullpathname_max_path_boundary_and_short_compile(self):
        import ctypes
        from ctypes import wintypes

        clang = Path(os.environ["ProgramFiles"]) / "LLVM/bin/clang-cl.exe"
        self.assertTrue(clang.is_file())
        version = subprocess.check_output(
            [clang, "--version"], text=True, timeout=30
        ).splitlines()[0]
        self.assertRegex(version, r"clang version 20\.1\.8\b")
        long_work = self.temp / worker.LEGACY_WORK_BASENAME
        short_work = self.temp / worker.SHORT_WORK_BASENAME
        if long_work.exists() or short_work.exists():
            self.fail("Native path probe requires fresh reviewed workspace roots")
        self.addCleanup(lambda: shutil.rmtree(long_work, ignore_errors=True))
        self.addCleanup(lambda: shutil.rmtree(short_work, ignore_errors=True))

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        full_path = kernel.GetFullPathNameA
        full_path.argtypes = [
            wintypes.LPCSTR, wintypes.DWORD, wintypes.LPSTR, ctypes.c_void_p
        ]
        full_path.restype = wintypes.DWORD

        def api_probe(work: Path):
            out = work / "download/chromium/src/out/CEF_Static_Release_x64"
            header = out / LONG_HEADER
            header.parent.mkdir(parents=True)
            header.write_text(
                "#pragma once\ninline int cef_path_probe() { return 7; }\n",
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(out)
                relative = LONG_HEADER.encode("ascii")
                buffer = ctypes.create_string_buffer(32768)
                ctypes.set_last_error(0)
                result = full_path(relative, len(buffer), buffer, None)
                error = ctypes.get_last_error()
                resolved = os.fsdecode(buffer.value) if result else ""
            finally:
                os.chdir(previous)
            return result, error, resolved, header, out

        legacy_result, legacy_error, _, old_header, _ = api_probe(long_work)
        short_result, short_error, short_full, new_header, short_out = api_probe(short_work)
        legacy_full = str(old_header)
        self.assertGreaterEqual(len(legacy_full), 260)
        self.assertLess(len(str(new_header)), 260)

        # This is the exact Win32 boundary surfaced by production #55: the ANSI
        # resolver rejects the legacy absolute path even with a large output
        # buffer. A larger buffer must not be mistaken for a fix.
        self.assertEqual(legacy_result, 0)
        self.assertEqual(legacy_error, 206)  # ERROR_FILENAME_EXCED_RANGE

        self.assertGreater(short_result, 0)
        self.assertEqual(short_error, 0)
        self.assertLess(short_result, 260)
        self.assertEqual(
            os.path.normcase(short_full), os.path.normcase(str(new_header))
        )

        source = short_out / "probe.cc"
        source.write_text(
            '#include "' + LONG_HEADER.replace("\\", "/") +
            '"\nint main() { return cef_path_probe() == 7 ? 0 : 1; }\n',
            encoding="utf-8",
        )
        fixed = subprocess.run(
            [str(clang), "/nologo", "/c", "/std:c++20", "/W4", "/WX",
             "probe.cc", "/Foprobe.obj"],
            cwd=short_out, capture_output=True, text=True,
            errors="replace", timeout=60,
        )
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        print(
            "CEF_WINDOWS_WORKSPACE_PATH_NATIVE "
            f"old_len={len(legacy_full)} new_len={len(str(new_header))} "
            f"legacy_api_result={legacy_result} legacy_api_error={legacy_error} "
            "legacy_max_path_overflow=true legacy_getfullpathname_error=206 "
            "getfullpathname=true short_resolves=true short_compiles=true "
            "codec_identity_preserved=true"
        )


if __name__ == "__main__":
    unittest.main()
