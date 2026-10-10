"""Pinned API-key header <string> self-containment and v14->v15 transition.

The native probe includes the exact public Chromium header before any helper
standard-library include. Windows must reproduce the production missing
std::string diagnostic; Linux is a portability control. This is not CEF runtime
qualification.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from secure_release.crypto import canonical, parse
from tests.cef_windows_layout_inputs import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/cef-windows"
SOURCE = "google_apis/common/api_key_request_util.h"
PUBLIC_BLOB = "49b79dd5f5c1192d32a0f21491e02098ae8b8141"


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_bytes():
    fixture = (FIXTURES / "api_key_request_util.h").read_bytes()
    root = os.environ.get("CEF_WINDOWS_API_KEY_SOURCE_ROOT")
    if root and (Path(root) / SOURCE).read_bytes() != fixture:
        raise ValueError("Pinned public API-key header mismatch")
    if git_blob(fixture) != PUBLIC_BLOB:
        raise ValueError("Unreviewed API-key fixture")
    return fixture


def populate_v14(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 14 else raw)
    marker = {"schema": 1, "kind": "cef-windows-source-repair",
              "build_key": repair.V14_KEY, "source_repair": repair.prior_profile()}
    (work / repair.MARKER).write_bytes(canonical(marker) + b"\n")


PROBE = r'''
#include "google_apis/common/api_key_request_util.h"
#include <type_traits>
static_assert(std::is_same_v<
    decltype(google_apis::internal::GetAPIKey(std::declval<const GURL&>())),
    std::optional<std::string>>);
static_assert(std::is_same_v<
    decltype(google_apis::internal::GetAPIKey(
        std::declval<const net::HttpRequestHeaders&>())),
    std::optional<std::string>>);
int main() { return 0; }
'''


class ApiKeyStringRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="api key string repair ")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.old = source_bytes()
        self.fixed = repair.transform(self.old, repair.API_KEY_HEADER)

    def test_exact_public_header_and_single_include(self):
        self.assertEqual(hashlib.sha256(self.old).hexdigest(), repair.API_KEY_BEFORE)
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), repair.API_KEY_AFTER)
        self.assertEqual(self.fixed.replace(b"#include <string>\n", b"", 1), self.old)
        self.assertEqual(self.fixed.count(b"#include <string>\n"), 1)
        self.assertIn(b"std::optional<std::string> GetAPIKey", self.fixed)
        self.assertEqual(repair.CORRECTIONS[14][0], repair.API_KEY_HEADER)
        self.assertEqual(repair.v15_profile()["id"], "windows-api-key-string-include-v15")
        self.assertEqual(repair.profile()["id"], "windows-watermark-string-include-v22")
        self.assertEqual(len(repair.CORRECTIONS), 23)

    def test_newlines_idempotence_and_unreviewed_inputs(self):
        for nl in (b"\n", b"\r\n"):
            raw = self.old.replace(b"\n", nl)
            changed = repair.transform(raw, repair.API_KEY_HEADER)
            self.assertEqual(repair.transform(changed, repair.API_KEY_HEADER), changed)
            self.assertEqual(changed.replace(b"\r\n", b"\n"), self.fixed)
        for raw in (b"", self.old + b"\n",
                    self.old.replace(b"std::optional<std::string>", b"std::optional<int>"),
                    self.old.replace(b"\n", b"\r\n", 1),
                    self.fixed + b"\n"):
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.API_KEY_HEADER)

    def command(self, include, source, output):
        if os.name == "nt":
            where = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            clang = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/clang-cl.exe"
            self.assertTrue(where.is_file() and clang.is_file(), "Native Windows toolchain required")
            vs = Path(subprocess.check_output([str(where), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                text=True).strip())
            version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
            self.assertTrue(version.startswith("14.44."), version)
            batch = self.root / "compile.cmd"
            batch.write_text(
                '@echo off\ncall "' + str(vs) + '/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\necho VCToolsVersion=%VCToolsVersion%\n'
                '"' + str(clang) + '" /nologo /std:c++20 /EHsc /W4 /WX -Werror '
                '/I"' + str(include) + '" "' + str(source) + '" /Fe:"' + str(output) + '"\n',
                encoding="utf-8")
            return ["cmd.exe", "/d", "/c", str(batch)]
        clang = shutil.which("clang++")
        self.assertTrue(clang, "Native API-key regression requires Clang")
        return [clang, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-I", str(include), str(source), "-o", str(output)]

    def test_native_header_self_containment_original_and_fixed(self):
        include = self.root / "include"
        header = include / SOURCE
        header.parent.mkdir(parents=True, exist_ok=True)
        source = self.root / "probe.cc"
        output = self.root / ("probe.exe" if os.name == "nt" else "probe")
        source.write_text(PROBE, encoding="utf-8")

        header.write_bytes(self.old)
        command = self.command(include, source, output)
        old = subprocess.run(command, cwd=self.root, capture_output=True, text=True,
                             errors="replace", timeout=90)
        if os.name == "nt":
            self.assertNotEqual(old.returncode, 0, "Original Windows header must fail")
            self.assertNotEqual(old.returncode, 90)
            self.assertIn("string", old.stdout + old.stderr)
            self.assertIn("api_key_request_util.h", old.stdout + old.stderr)
        elif old.returncode == 0:
            subprocess.run([str(output)], cwd=self.root, check=True,
                           capture_output=True, timeout=15)
        else:
            self.assertIn("string", old.stdout + old.stderr)

        header.write_bytes(self.fixed)
        fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True,
                               errors="replace", timeout=90)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True,
                       capture_output=True, timeout=15)
        print("CEF_API_KEY_STRING_NATIVE original_failed="
              + str(old.returncode != 0).lower()
              + " fixed_compiles=true signatures=2 direct_string_include=true")


class V14TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="v14 to v15 transition ")
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / "work"
        populate_v14(self.work)
        self.path = self.work / repair.API_KEY_HEADER
        self.credit_card = self.work / repair.CREDIT_CARD_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, "upgrade-v14")

    def test_only_exact_v14_selector_is_current_upgrade(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V14, repair.BASE_KEY),
                         (repair.V14_KEY, "upgrade-v14"))
        for field, value in repair.UPGRADE_V14.items():
            wrong = dict(repair.UPGRADE_V14)
            wrong[field] = value + 1 if type(value) is int else "0" * len(value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                repair.restore_contract(wrong, repair.BASE_KEY)
        for stale in (repair.UPGRADE_V13, repair.UPGRADE_V11,
                      dict(repair.UPGRADE_V14, run=37476650876),
                      {"build_key": repair.V14_KEY}):
            with self.assertRaises(ValueError):
                repair.restore_contract(stale, repair.BASE_KEY)

    def test_prior_profile_is_independently_bound_to_v14(self):
        old = repair.prior_profile()
        digest = hashlib.sha256(canonical({
            "schema": 2, "base_build_key": repair.BASE_KEY, "source_repair": old
        })).hexdigest()
        self.assertEqual(digest, repair.V14_KEY)
        self.assertEqual(len(old["corrections"]), 14)
        self.assertEqual(repair.profile()["corrections"][:14], old["corrections"])
        self.assertNotEqual(self.key, repair.V14_KEY)

    def test_producer_summary_requires_complete_v14_proof(self):
        value = {"base_build_key": repair.BASE_KEY,
                 "source_repair_verified": True,
                 "source_repair": repair.prior_profile()}
        repair.verify_summary(value, repair.UPGRADE_V14)
        for field in value:
            bad = copy.deepcopy(value)
            bad.pop(field)
            with self.assertRaises(ValueError):
                repair.verify_summary(bad, repair.UPGRADE_V14)
        bad = copy.deepcopy(value)
        bad["source_repair"]["corrections"].pop()
        with self.assertRaises(ValueError):
            repair.verify_summary(bad, repair.UPGRADE_V14)

    def test_upgrade_preserves_prior_sources_objects_and_repeat_resume(self):
        obj = self.work / "out/keep.obj"
        obj.parent.mkdir()
        obj.write_bytes(b"compiled-v14")
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.work.rglob("*") if p.is_file()}
        self.assertEqual(self.apply(), "upgraded-v14")
        for path, snapshot in before.items():
            if path in {self.path, self.credit_card, self.work / repair.FRAME_TREE_HEADER,
                        self.work / repair.LOCK_MANAGER_HEADER,
                        self.work / repair.AFFILIATED_MATCH_SOURCE,
                        self.work / repair.BACKEND_ERROR_HEADER,
                        self.work / repair.BACKEND_ERROR_SOURCE,
                        self.work / repair.PERMISSION_MANAGER_HEADER,
                        self.work / repair.WATERMARK_HEADER}:
                relative = path.relative_to(self.work).as_posix()
                self.assertEqual(path.read_bytes(), repair.transform(snapshot[0], relative))
                self.assertGreater(path.stat().st_mtime_ns, snapshot[1])
            elif path != self.marker:
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), snapshot)
        self.assertEqual(parse(self.marker.read_bytes())["source_repair"], repair.profile())
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual(after, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})
        with self.assertRaises(ValueError):
            self.apply()

    def test_all_prior_sources_checked_before_write(self):
        old_marker = self.marker.read_bytes()
        for relative, _, _, _ in repair.CORRECTIONS[:14]:
            path = self.work / relative
            fixed = path.read_bytes()
            path.write_bytes(fixture_bytes(path.name))
            with mock.patch.object(repair.os, "replace") as replace:
                with self.assertRaises(ValueError):
                    self.apply()
                replace.assert_not_called()
            self.assertEqual(self.marker.read_bytes(), old_marker)
            path.write_bytes(fixed)

    def test_partial_hardlink_and_race_fail_closed(self):
        raw = self.path.read_bytes()
        old_marker = self.marker.read_bytes()
        self.path.write_bytes(repair.transform(raw, repair.API_KEY_HEADER))
        with self.assertRaises(ValueError):
            self.apply()
        self.path.write_bytes(raw)

        alias = self.work / "api-key-alias.h"
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            self.apply()
        alias.unlink()

        original = repair.os.replace
        prior = self.work / repair.INLINE_ITEMS_SOURCE
        def source_race(source, target):
            original(source, target)
            if Path(target) == self.path:
                prior.write_bytes(b"concurrent prior source")
        with mock.patch.object(repair.os, "replace", side_effect=source_race):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_native_checkpoint_v14_to_v15_and_current_roundtrip(self):
        location = os.environ.get("CEF_REPAIR_RECIPE_DIR")
        if not location:
            self.skipTest("Pinned native checkpoint recipe not supplied")
        path = Path(location) / "vcpkg/static/checkpoint.py"
        spec = importlib.util.spec_from_file_location("api_key_checkpoint_fixture", path)
        codec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(codec)
        identity = {"schema": 3, "platform": "windows-x64",
                    "recipe": "unchanged-recipe",
                    "build_contract": repair.V14_KEY, "work": str(self.work)}
        old = self.work.parent / "old-checkpoint"
        new = self.work.parent / "new-checkpoint"
        codec.save(self.work, old, identity)
        saved = (old / "checkpoint.json").read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), "upgraded-v14")
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual((old / "checkpoint.json").read_bytes(), saved)
        self.assertFalse(__import__("json").loads(
            (new / "checkpoint.json").read_text())["engine_runtime_verified"])


if __name__ == "__main__":
    unittest.main()
