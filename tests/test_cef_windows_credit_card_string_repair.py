"""Pinned credit-card header <string> self-containment and V15->V16 transition."""
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
FIXTURE = ROOT / "tests/fixtures/cef-windows/credit_card_number_validation.h"
SOURCE = "components/autofill/core/common/credit_card_number_validation.h"
PUBLIC_BLOB = "5262b8ddc4af7dcf15f732d3c5da0bbb1a0854d4"

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def source_bytes():
    fixture = FIXTURE.read_bytes()
    root = os.environ.get("CEF_WINDOWS_CREDIT_CARD_SOURCE_ROOT")
    if root and (Path(root) / SOURCE).read_bytes() != fixture:
        raise ValueError("Pinned public credit-card header mismatch")
    if git_blob(fixture) != PUBLIC_BLOB:
        raise ValueError("Unreviewed credit-card fixture")
    return fixture

def populate_v15(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 15 else raw)
    marker = {"schema": 1, "kind": "cef-windows-source-repair",
              "build_key": repair.V15_KEY, "source_repair": repair.v15_profile()}
    (work / repair.MARKER).write_bytes(canonical(marker) + b"\n")

PROBE = r'''
#include "components/autofill/core/common/credit_card_number_validation.h"
#include <type_traits>
#include <utility>
static_assert(std::is_same_v<
    decltype(autofill::StripCardNumberSeparators(std::declval<std::u16string_view>())),
    std::u16string>);
static_assert(std::is_same_v<
    decltype(autofill::GetFormattedCardNumberForDisplay(std::declval<std::u16string_view>())),
    std::u16string>);
int main() { return 0; }
'''

class CreditCardStringRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="credit card string repair ")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.old = source_bytes()
        self.fixed = repair.transform(self.old, repair.CREDIT_CARD_HEADER)

    def test_exact_public_header_and_single_include(self):
        self.assertEqual(hashlib.sha256(self.old).hexdigest(), repair.CREDIT_CARD_BEFORE)
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), repair.CREDIT_CARD_AFTER)
        self.assertEqual(self.fixed.replace(b"#include <string>\n", b"", 1), self.old)
        self.assertEqual(self.fixed.count(b"#include <string>\n"), 1)
        self.assertEqual(repair.CORRECTIONS[15][0], repair.CREDIT_CARD_HEADER)
        self.assertEqual(repair.profile()["id"], "windows-watermark-string-include-v22")
        self.assertEqual(len(repair.CORRECTIONS), 23)

    def test_newlines_idempotence_and_unreviewed_inputs(self):
        for nl in (b"\n", b"\r\n"):
            raw = self.old.replace(b"\n", nl)
            changed = repair.transform(raw, repair.CREDIT_CARD_HEADER)
            self.assertEqual(repair.transform(changed, repair.CREDIT_CARD_HEADER), changed)
            self.assertEqual(changed.replace(b"\r\n", b"\n"), self.fixed)
        for raw in (b"", self.old + b"\n",
                    self.old.replace(b"std::u16string Strip", b"int Strip"),
                    self.old.replace(b"\n", b"\r\n", 1), self.fixed + b"\n"):
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.CREDIT_CARD_HEADER)

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
                'if errorlevel 1 exit /b 90\n'
                '"' + str(clang) + '" /nologo /std:c++20 /EHsc /W4 /WX -Werror '
                '/I"' + str(include) + '" "' + str(source) + '" /Fe:"' + str(output) + '"\n',
                encoding="utf-8")
            return ["cmd.exe", "/d", "/c", str(batch)]
        clang = shutil.which("clang++")
        self.assertTrue(clang, "Native credit-card regression requires Clang")
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
            evidence = old.stdout + old.stderr
            self.assertIn("u16string", evidence)
            self.assertIn("credit_card_number_validation.h", evidence)
        header.write_bytes(self.fixed)
        fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True,
                               errors="replace", timeout=90)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=15)
        print("CEF_CREDIT_CARD_STRING_NATIVE original_failed="
              + str(old.returncode != 0).lower()
              + " fixed_compiles=true signatures=2 direct_string_include=true")

class V15TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="v15 to v16 transition ")
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / "work"
        populate_v15(self.work)
        self.path = self.work / repair.CREDIT_CARD_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, "upgrade-v15")

    def test_only_exact_v15_selector_is_current_upgrade(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V15, repair.BASE_KEY),
                         (repair.V15_KEY, "upgrade-v15"))
        for field, value in repair.UPGRADE_V15.items():
            wrong = dict(repair.UPGRADE_V15)
            wrong[field] = value + 1 if type(value) is int else "0" * len(value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                repair.restore_contract(wrong, repair.BASE_KEY)

    def test_prior_profile_is_independently_bound_to_v15(self):
        old = repair.v15_profile()
        digest = hashlib.sha256(canonical({
            "schema": 2, "base_build_key": repair.BASE_KEY, "source_repair": old
        })).hexdigest()
        self.assertEqual(digest, repair.V15_KEY)
        self.assertEqual(len(old["corrections"]), 15)
        self.assertEqual(repair.profile()["corrections"][:15], old["corrections"])
        self.assertNotEqual(self.key, repair.V15_KEY)

    def test_producer_summary_requires_complete_v15_proof(self):
        value = {"base_build_key": repair.BASE_KEY,
                 "source_repair_verified": True,
                 "source_repair": repair.v15_profile()}
        repair.verify_summary(value, repair.UPGRADE_V15)
        for field in value:
            bad = copy.deepcopy(value); bad.pop(field)
            with self.assertRaises(ValueError):
                repair.verify_summary(bad, repair.UPGRADE_V15)

    def test_upgrade_preserves_prior_sources_objects_and_repeat_resume(self):
        obj = self.work / "out/keep.obj"
        obj.parent.mkdir()
        obj.write_bytes(b"compiled-v15")
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in self.work.rglob("*") if p.is_file()}
        self.assertEqual(self.apply(), "upgraded-v15")
        for path, snapshot in before.items():
            if path in (self.path, self.work / repair.FRAME_TREE_HEADER,
                        self.work / repair.LOCK_MANAGER_HEADER,
                        self.work / repair.AFFILIATED_MATCH_SOURCE,
                        self.work / repair.BACKEND_ERROR_HEADER,
                        self.work / repair.BACKEND_ERROR_SOURCE,
                        self.work / repair.PERMISSION_MANAGER_HEADER,
                        self.work / repair.WATERMARK_HEADER):
                self.assertEqual(path.read_bytes(),
                                 repair.transform(snapshot[0], path.relative_to(self.work).as_posix()))
                self.assertGreater(path.stat().st_mtime_ns, snapshot[1])
            elif path != self.marker:
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), snapshot)
        self.assertEqual(parse(self.marker.read_bytes())["source_repair"], repair.profile())
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual(after, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})

    def test_partial_hardlink_and_race_fail_closed(self):
        raw = self.path.read_bytes()
        old_marker = self.marker.read_bytes()
        self.path.write_bytes(repair.transform(raw, repair.CREDIT_CARD_HEADER))
        with self.assertRaises(ValueError):
            self.apply()
        self.path.write_bytes(raw)
        alias = self.work / "credit-card-alias.h"
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            self.apply()
        alias.unlink()
        original = repair.os.replace
        prior = self.work / repair.API_KEY_HEADER
        def source_race(source, target):
            original(source, target)
            if Path(target) == self.path:
                prior.write_bytes(b"concurrent prior source")
        with mock.patch.object(repair.os, "replace", side_effect=source_race):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_native_checkpoint_v15_to_v16_and_current_roundtrip(self):
        location = os.environ.get("CEF_REPAIR_RECIPE_DIR")
        if not location:
            self.skipTest("Pinned native checkpoint recipe not supplied")
        path = Path(location) / "vcpkg/static/checkpoint.py"
        spec = importlib.util.spec_from_file_location("credit_card_checkpoint_fixture", path)
        codec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(codec)
        identity = {"schema": 3, "platform": "windows-x64",
                    "recipe": "unchanged-recipe",
                    "build_contract": repair.V15_KEY, "work": str(self.work)}
        old = self.work.parent / "old-checkpoint"
        new = self.work.parent / "new-checkpoint"
        codec.save(self.work, old, identity)
        saved = (old / "checkpoint.json").read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), "upgraded-v15")
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual((old / "checkpoint.json").read_bytes(), saved)

if __name__ == "__main__":
    unittest.main()
