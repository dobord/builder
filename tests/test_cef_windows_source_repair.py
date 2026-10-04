"""Public Chromium header regression and explicit old/new checkpoint contracts."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from secure_release import cef_contract, cef_windows_iteration as worker
from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_layout_inputs import fixture_bytes, public_input

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cef-windows/websocket_handshake_challenge.h"
PAINT_FIXTURE = ROOT / "tests/fixtures/cef-windows/paint_vector_icon.h"
AUTOFILL_FIXTURE = ROOT / "tests/fixtures/cef-windows/form_field_data.cc"
ATOMIC_FIXTURE = ROOT / "tests/fixtures/cef-windows/atomic_string.cc"
HEAP_FIXTURE = ROOT / "tests/fixtures/cef-windows/heap-object-header.h"


def populate(work):
    for relative, fixture in ((repair.HEADER, FIXTURE), (repair.PAINT_HEADER, PAINT_FIXTURE),
                              (repair.AUTOFILL_SOURCE, AUTOFILL_FIXTURE),
                              (repair.ATOMIC_SOURCE, ATOMIC_FIXTURE),
                              (repair.HEAP_HEADER, HEAP_FIXTURE),
                              (repair.TORQUE_SOURCE, Path("implementation-visitor.cc")),
                              (repair.TEMPLATE_HEADER, Path("v8-template.h")),
                              (repair.BIND_HEADER, Path("bind-internal.h")),
                              (repair.ACCESSIBILITY_HEADER, Path("browser_accessibility.h")),
                              (repair.ACCESSIBILITY_SOURCE, Path("browser_accessibility.cc"))):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(public_input("include/v8-template.h")
                         if relative == repair.TEMPLATE_HEADER
                         else fixture_bytes(fixture.name))


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="cef header test ")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.work = self.root / "work"
        self.path = self.work / repair.HEADER
        populate(self.work)
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self, origin="legacy"):
        return repair.apply(self.work, self.key, origin)

    def test_fixture_is_exact_pinned_public_chromium_blob(self):
        data = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
                         "b2d53e31a1b602641676654f1fce5eee6a8cb4e5")
        self.assertEqual(hashlib.sha256(data).hexdigest(), repair.BEFORE)
        changed = repair.transform(data)
        self.assertEqual(hashlib.sha256(changed).hexdigest(), repair.AFTER)
        self.assertEqual(changed.replace(b"#include <string>\n", b"", 1), data)

    def test_lf_and_crlf_preserved_without_repeat_edit(self):
        for newline in (b"\n", b"\r\n"):
            raw = FIXTURE.read_bytes().replace(b"\n", newline)
            changed = repair.transform(raw)
            self.assertEqual(repair.transform(changed), changed)
            self.assertEqual(changed.count(b"\r\n"), changed.count(b"\n") if newline == b"\r\n" else 0)

    def test_unreviewed_or_partially_patched_header_rejected(self):
        old = FIXTURE.read_bytes()
        for data in (old + b"// changed\n", old.replace(b"std::string ", b"std::wstring "),
                     old.replace(b"#include <string_view>", b"#include <string>"),
                     old.replace(b"\n", b"\r\n", 1), old.replace(b"\n", b"\r"), b""):
            with self.subTest(data_hash=hashlib.sha256(data).hexdigest()):
                with self.assertRaises(ValueError):
                    repair.transform(data)

    def test_only_header_and_new_marker_change(self):
        other = self.work / "download/chromium/src/out/obj/untouched.obj"
        other.parent.mkdir(parents=True)
        other.write_bytes(b"unchanged-object")
        clock = (time.time_ns() - 5_000_000_000) // 100 * 100
        os.utime(self.path, ns=(clock, clock))
        before = (other.read_bytes(), other.stat().st_mtime_ns)
        self.assertEqual(self.apply(), "applied")
        self.assertEqual((other.read_bytes(), other.stat().st_mtime_ns), before)
        self.assertGreater(self.path.stat().st_mtime_ns, clock)
        snapshot = {p.relative_to(self.work): (p.read_bytes(), p.stat().st_mtime_ns)
                    for p in self.work.rglob("*") if p.is_file()}
        self.assertEqual(self.apply("resume"), "already-applied")
        self.assertEqual(snapshot, {p.relative_to(self.work): (p.read_bytes(), p.stat().st_mtime_ns)
                                   for p in self.work.rglob("*") if p.is_file()})

    def test_fresh_source_applies_same_exact_correction(self):
        self.assertEqual(self.apply("fresh"), "applied")
        self.assertEqual(self.apply("resume"), "already-applied")

    def test_old_and_new_contracts_are_distinct(self):
        self.assertNotEqual(self.key, repair.BASE_KEY)
        self.assertEqual(repair.restore_contract(copy.deepcopy(repair.LEGACY), repair.BASE_KEY),
                         (repair.BASE_KEY, "legacy"))
        self.assertEqual(repair.restore_contract({"build_key": self.key}, repair.BASE_KEY),
                         (self.key, "resume"))
        self.assertEqual(repair.restore_contract(None, repair.BASE_KEY), (self.key, "fresh"))
        with self.assertRaises(ValueError):
            repair.build_key("0" * 64)

    def test_every_legacy_selector_field_is_bound(self):
        for field, value in repair.LEGACY.items():
            selected = copy.deepcopy(repair.LEGACY)
            selected[field] = value + 1 if type(value) is int else "0" * len(value)
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    repair.restore_contract(selected, repair.BASE_KEY)
        for selected in (dict(repair.LEGACY, attempt=True), dict(repair.LEGACY, extra=1), [],
                         {"build_key": repair.BASE_KEY}):
            with self.assertRaises(ValueError):
                repair.restore_contract(selected, repair.BASE_KEY)

    def test_implementation_and_header_changes_invalidate_key(self):
        original = repair.profile
        for field in ("implementation_sha256", "chromium_commit"):
            value = dict(original(), **{field: "0" * len(original()[field])})
            with mock.patch.object(repair, "profile", return_value=value):
                self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_repaired_producer_requires_exact_proof(self):
        selected = {"build_key": self.key}
        value = {"base_build_key": repair.BASE_KEY, "source_repair": repair.profile(),
                 "source_repair_verified": True}
        repair.verify_summary(value, selected)
        for field in value:
            invalid = dict(value); invalid.pop(field)
            with self.assertRaises(ValueError):
                repair.verify_summary(invalid, selected)
        repair.verify_summary({}, repair.LEGACY)
        with self.assertRaises(ValueError):
            repair.verify_summary(value, repair.LEGACY)

    def test_new_contract_cannot_accept_old_unrepaired_source(self):
        with self.assertRaises((ValueError, OSError)):
            self.apply("resume")
        self.assertEqual(self.path.read_bytes(), FIXTURE.read_bytes())

    def test_legacy_cannot_accept_already_patched_source(self):
        self.path.write_bytes(repair.transform(self.path.read_bytes()))
        with self.assertRaises(ValueError):
            self.apply()

    def test_repaired_header_cannot_be_reverted_under_new_marker(self):
        self.apply(); self.path.write_bytes(FIXTURE.read_bytes())
        with self.assertRaises(ValueError):
            self.apply("resume")

    def test_marker_tampering_and_duplicate_keys_rejected(self):
        self.apply(); marker = self.work / repair.MARKER
        good = marker.read_bytes()
        for raw in (good.replace(self.key.encode(), b"0" * 64), b'{"schema":1,"schema":1}',
                    b"x" * 8193, b"[]"):
            marker.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.apply("resume")
        marker.write_bytes(good)
        self.assertEqual(self.apply("resume"), "already-applied")

    def test_hardlinked_input_rejected(self):
        alias = self.root / "alias.h"
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(alias.read_bytes(), FIXTURE.read_bytes())

    @unittest.skipIf(os.name == "nt", "Windows junction test covers redirected directories")
    def test_symlink_input_and_parent_rejected(self):
        self.path.rename(self.root / "outside.h")
        self.path.symlink_to(self.root / "outside.h")
        with self.assertRaises(ValueError):
            self.apply()
        self.path.unlink()
        parent = self.path.parent; parent.rmdir(); parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.apply()

    @unittest.skipUnless(os.name == "nt", "Native Windows junction regression")
    def test_windows_junction_rejected(self):
        self.path.unlink(); parent = self.path.parent; parent.rmdir()
        subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(parent), str(self.root)],
                       check=True, capture_output=True)
        try:
            with self.assertRaises(ValueError):
                self.apply()
        finally:
            parent.rmdir()

    def test_wrong_origin_contract_or_preexisting_marker_rejected(self):
        for key, origin in ((repair.BASE_KEY, "legacy"), (self.key, "other")):
            with self.assertRaises(ValueError):
                repair.apply(self.work, key, origin)
        (self.work / repair.MARKER).write_text("{}")
        with self.assertRaises(ValueError):
            self.apply()

    def test_path_and_handle_ctime_are_not_cross_api_identity(self):
        # Emulate CPython Windows path=CreationTime, handle=ChangeTime.
        real_fstat = os.fstat
        def by_handle(fd):
            info = real_fstat(fd)
            values = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
            values["st_birthtime_ns"] = getattr(info, "st_birthtime_ns", info.st_ctime_ns)
            values["st_ctime_ns"] += 1_000_000
            return SimpleNamespace(**values)
        with mock.patch.object(repair.os, "fstat", side_effect=by_handle):
            _, raw, _ = repair._read(self.work, repair.HEADER)
        self.assertEqual(raw, FIXTURE.read_bytes())

    def test_handle_ctime_change_during_read_is_still_rejected(self):
        real_fstat = os.fstat
        calls = 0
        def changed_handle(fd):
            nonlocal calls
            calls += 1
            info = real_fstat(fd)
            values = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
            values["st_birthtime_ns"] = getattr(info, "st_birthtime_ns", info.st_ctime_ns)
            if calls == 2:
                values["st_ctime_ns"] += 1_000_000
            return SimpleNamespace(**values)
        with mock.patch.object(repair.os, "fstat", side_effect=changed_handle):
            with self.assertRaises(ValueError):
                repair._read(self.work, repair.HEADER)

    def test_opened_file_identity_mismatch_is_rejected(self):
        real_fstat = os.fstat
        def replaced_handle(fd):
            info = real_fstat(fd)
            values = {name: getattr(info, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
            values["st_birthtime_ns"] = getattr(info, "st_birthtime_ns", info.st_ctime_ns)
            values["st_ino"] += 1
            return SimpleNamespace(**values)
        with mock.patch.object(repair.os, "fstat", side_effect=replaced_handle):
            with self.assertRaises(ValueError):
                repair._read(self.work, repair.HEADER)

    def test_changed_input_is_not_overwritten(self):
        original = repair._path
        calls = 0
        def raced(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.path.write_bytes(b"concurrent source edit")
            return original(*args)
        with mock.patch.object(repair, "_path", side_effect=raced):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), b"concurrent source edit")
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_lock_is_explicit_versioned_and_does_not_relabel_old_checkpoint(self):
        # Check the actual repository lock, not a reconstructed passing profile.
        value = worker.qualification_lock(ROOT)
        self.assertEqual(value["schema"], 2)
        self.assertEqual(value["source_repair"], repair.profile())
        # Future valid checkpoints can replace this exact initial legacy input.
        repair.restore_contract(value["checkpoint"], repair.BASE_KEY)
        (self.root / "ci").mkdir()
        path = self.root / "ci/cef-windows-engine-lock.json"
        for changes in ({"schema": 1}, {"schema": True}, {"source_repair": {}},
                        {"vcpkg_commit": "0" * 40}):
            path.write_text(json.dumps(dict(value, **changes)))
            with self.assertRaises(ValueError):
                worker.qualification_lock(self.root)

    def test_hash_bound_inputs_have_lf_checkout_policy(self):
        attrs = (ROOT / ".gitattributes").read_text()
        self.assertIn("/secure_release/cef_windows_source_repair.py text eol=lf", attrs)
        self.assertIn("/tests/fixtures/cef-windows/*.h text eol=lf", attrs)

    def test_actual_native_checkpoint_codec_retains_contract_boundary(self):
        location = os.environ.get("CEF_REPAIR_RECIPE_DIR")
        if not location:
            self.skipTest("Pinned native checkpoint recipe not supplied")
        path = Path(location) / "vcpkg/static/checkpoint.py"
        spec = importlib.util.spec_from_file_location("repair_checkpoint_fixture", path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        identity = {"schema": 3, "platform": "windows-x64", "recipe": "unchanged-recipe",
                    "build_contract": repair.BASE_KEY, "work": str(self.work)}
        old = self.root / "old-checkpoint"
        module.save(self.work, old, identity)
        saved = (old / "checkpoint.json").read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            module.restore(old, self.work, dict(identity, build_contract=self.key))
        module.restore(old, self.work, identity)
        self.apply()
        new = self.root / "new-checkpoint"
        module.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        module.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(self.apply("resume"), "already-applied")
        self.assertEqual((old / "checkpoint.json").read_bytes(), saved)
        self.assertFalse(json.loads((new / "checkpoint.json").read_text())["engine_runtime_verified"])

    @unittest.skipIf(os.name == "nt", "Separate native MSVC regression runs on Windows")
    def test_real_ninja_rebuilds_only_header_dependents(self):
        cxx, ninja = shutil.which("g++"), shutil.which("ninja")
        if not cxx or not ninja:
            self.skipTest("Native GCC and Ninja required")
        source = self.work / "download/chromium/src"
        stub = source / "net/base/net_export.h"; stub.parent.mkdir(parents=True)
        stub.write_text("#define NET_EXPORT\n")
        (source / "dependent.cc").write_text('#include <string>\n#include "net/websockets/websocket_handshake_challenge.h"\nint dependent(){return 1;}\n')
        (source / "other.cc").write_text("int independent(){return 2;}\n")
        (source / "build.ninja").write_text(
            f'rule cxx\n  command = "{cxx}" -std=c++20 -I. -MMD -MF $out.d -c $in -o $out\n'
            '  depfile = $out.d\n  deps = gcc\n'
            'build dependent.o: cxx dependent.cc\nbuild other.o: cxx other.cc\n')
        subprocess.run([ninja], cwd=source, capture_output=True, check=True)
        before = {name: (source / name).stat().st_mtime_ns for name in ("dependent.o", "other.o")}
        time.sleep(0.02)
        self.apply()
        subprocess.run([ninja], cwd=source, capture_output=True, check=True)
        self.assertGreater((source / "dependent.o").stat().st_mtime_ns, before["dependent.o"])
        self.assertEqual((source / "other.o").stat().st_mtime_ns, before["other.o"])
        self.apply("resume")
        result = subprocess.run([ninja], cwd=source, capture_output=True, text=True, check=True)
        self.assertIn("no work to do", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Native MSVC header self-containment regression")
    def test_real_msvc_old_header_fails_fixed_header_compiles(self):
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        vs = Path(subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip())
        version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
        self.assertTrue(version.startswith("14.44."), version)
        source = self.work / "download/chromium/src"
        stub = source / "net/base/net_export.h"; stub.parent.mkdir(parents=True)
        stub.write_text("#define NET_EXPORT\n")
        (source / "probe.cpp").write_text(
            '#include "net/websockets/websocket_handshake_challenge.h"\n'
            '#include <type_traits>\n'
            'static_assert(std::is_same_v<decltype(net::ComputeSecWebSocketAccept), std::string(std::string_view)>);\n'
            'static_assert(sizeof(std::string)>0);\n')
        batch = self.root / "compile.cmd"
        batch.write_text(f'@echo off\ncall "{vs}/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                         'if errorlevel 1 exit /b 90\ncl.exe /nologo /std:c++20 /Zs /W4 /WX /I. probe.cpp\n', encoding="utf-8")
        def compile_header():
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=source,
                                  capture_output=True, text=True, errors="replace", timeout=60)
        before = compile_header()
        self.assertNotEqual(before.returncode, 0)
        self.assertNotEqual(before.returncode, 90)
        self.assertIn("string", before.stdout + before.stderr)
        self.apply()
        after = compile_header()
        self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
        print("CEF_WEBSOCKET_MSVC_HEADER_REPAIR_VERIFIED toolset=" + version)


class OrchestrationTests(unittest.TestCase):
    def test_legacy_restore_and_new_save_use_different_real_contracts(self):
        self.exercise(False)

    def test_new_checkpoint_resumes_without_reapplying_header(self):
        self.exercise(True)

    def exercise(self, migrated):
        cfg = {"schema": 1, "recipe_commit": worker.CEF, "profile": "static-third-party",
               "release_lock": None, "slice_seconds": 9000, "jobs": 4,
               "platforms": {p: {"mode": "source-fresh", "checkpoint": None, "binary_cache": None}
                             for p in ("linux", "windows")}}
        base = cef_contract.build_key(cfg, "windows")
        self.assertEqual(base, repair.BASE_KEY)
        key = repair.build_key(base)
        selected = dict(repair.LEGACY)
        if migrated:
            selected.update(run=101, producer_sha="a" * 40, build_key=key)
        input_key = key if migrated else base
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); temp = root / "temp"; temp.mkdir()
            registry = root / "private-vcpkg/ci"; registry.mkdir(parents=True)
            (registry / "release-plan.json").write_text(json.dumps({"cef": cfg}))
            (root / "ci").mkdir()
            (root / "ci/cef-windows-engine-lock.json").write_text(json.dumps({
                "schema": 2, "platform": "windows", "vcpkg_commit": worker.VCPKG,
                "cef_recipe_commit": worker.CEF, "checkpoint": selected, "source_repair": repair.profile()}))
            work = temp / "cef-windows-engine-work"
            calls = []
            def restore(sel, dest, contract, private):
                self.assertEqual(contract, input_key); dest.mkdir()
            def run(command, **kwargs):
                args = list(map(str, command)); calls.append(args)
                if "restore" in args:
                    self.assertEqual(args[args.index("--contract") + 1], input_key)
                    populate(work)
                    if migrated:
                        repair.apply(work, key, "legacy")
                elif "slice" in args:
                    self.assertEqual(args[args.index("--contract") + 1], key)
                    self.assertEqual(repair.apply(work, key, "resume"), "already-applied")
                    Path(args[args.index("--checkpoint") + 1]).mkdir()
                    Path(args[args.index("--state") + 1]).write_text(json.dumps({
                        "ready": False, "checkpoint_ready": True,
                        "progress": {"status": "progress", "changed_outputs": 1}}))
                return subprocess.CompletedProcess(args, 0)
            env = {"GITHUB_WORKSPACE": str(root), "RUNNER_TEMP": str(temp), "GITHUB_RUN_ID": "102",
                   "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40,
                   "BUILDER_INPUT_PRIVATE_KEY": "synthetic-not-a-key"}
            def head(path):
                return worker.VCPKG if path.name == "private-vcpkg" else worker.CEF if path.name == "private-cef" else repair.CHROMIUM
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(worker.sys, "platform", "win32"), \
                    mock.patch.object(worker, "git_head", side_effect=head), \
                    mock.patch.object(worker, "restore_checkpoint", side_effect=restore), \
                    mock.patch.object(worker, "run", side_effect=run), \
                    mock.patch.object(worker.crypto, "public_text", return_value="synthetic-public"), \
                    mock.patch.object(worker.cef_cache, "seal") as seal:
                worker.main()
            summary = json.loads((temp / "cef-windows-engine-summary.json").read_text())
            self.assertEqual(summary["status"], "success")
            self.assertEqual(summary["build_key"], key)
            self.assertEqual(summary["input_build_key"], input_key)
            self.assertTrue(summary["source_repair_verified"])
            self.assertFalse(summary["ready"])
            self.assertFalse(summary["runtime_verified"])
            self.assertIn(key, json.dumps(seal.call_args.args[-1]))
            self.assertEqual([a[2] for a in calls], ["restore", "prepare", "slice"])

class PaintHeaderTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="paint header test ")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.work = self.root / "work"
        populate(self.work)
        self.path = self.work / repair.PAINT_HEADER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self, origin="legacy"):
        return repair.apply(self.work, self.key, origin)

    def stubs(self):
        # Only unrelated dependencies are stubbed. The header under test is
        # the complete pinned public blob, not a copied declaration.
        source = self.work / "download/chromium/src"
        headers = {
            "base/component_export.h": "#define COMPONENT_EXPORT(component)\n",
            "base/memory/raw_ref.h": "template<class T> struct raw_ref { T* ptr; };\n",
            "third_party/skia/include/core/SkColor.h": "using SkColor = unsigned int;\n",
            "ui/gfx/color_palette.h": "namespace gfx { inline constexpr unsigned int kPlaceholderColor = 0; }\n",
            "net/base/net_export.h": "#define NET_EXPORT\n",
        }
        for relative, text in headers.items():
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return source

    def probe(self, macro, prelude=""):
        return (prelude + f'#define {macro} 1\n#include "ui/gfx/paint_vector_icon.h"\n'
                '#include <type_traits>\n'
                'static_assert(std::is_same_v<decltype(gfx::CreateVectorIconFromSource),\n'
                '    gfx::ImageSkia(const std::string&, int, SkColor)>);\n')

    def test_exact_pinned_paint_blob_and_one_include_only(self):
        old = PAINT_FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha1(b"blob " + str(len(old)).encode() + b"\0" + old).hexdigest(),
                         "8eb7ac9c2a7cc8c25fd963aaa128bca34b1568ee")
        self.assertEqual(hashlib.sha256(old).hexdigest(), repair.PAINT_BEFORE)
        changed = repair.transform(old, repair.PAINT_HEADER)
        self.assertEqual(hashlib.sha256(changed).hexdigest(), repair.PAINT_AFTER)
        self.assertEqual(changed.replace(b"#include <string>\n\n", b"", 1), old)
        for newline in (b"\n", b"\r\n"):
            raw = old.replace(b"\n", newline)
            fixed = repair.transform(raw, repair.PAINT_HEADER)
            self.assertEqual(repair.transform(fixed, repair.PAINT_HEADER), fixed)
            self.assertEqual(fixed.count(b"\r\n"), fixed.count(b"\n") if newline == b"\r\n" else 0)

    def test_paint_unreviewed_contents_and_newlines_rejected(self):
        old = PAINT_FIXTURE.read_bytes()
        for raw in (b"", old + b"// unreviewed", old.replace(b"std::string", b"std::wstring"),
                    old.replace(b"\n", b"\r\n", 1), old.replace(b"\n", b"\r")):
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.PAINT_HEADER)
        with self.assertRaises(ValueError):
            repair.transform(old, "download/chromium/src/other.h")
        with self.assertRaises(ValueError):
            repair.transform(old, repair.HEADER)

    def test_profile_binds_both_headers_and_each_digest(self):
        expected_paths = [repair.HEADER, repair.PAINT_HEADER, repair.AUTOFILL_SOURCE, repair.ATOMIC_SOURCE,
                          repair.HEAP_HEADER, repair.TORQUE_SOURCE, repair.TEMPLATE_HEADER, repair.BIND_HEADER,
                          repair.ACCESSIBILITY_HEADER, repair.ACCESSIBILITY_SOURCE]
        profile = repair.profile()
        self.assertEqual(profile["schema"], 2)
        self.assertEqual(profile["id"], "windows-accessibility-default-iterator-v10")
        self.assertEqual([c["path"] for c in profile["corrections"]],
                         [p.removeprefix("download/chromium/src/") for p in expected_paths])
        for index in range(len(expected_paths)):
            for field in ("path", "before_sha256", "after_sha256"):
                altered = copy.deepcopy(profile)
                altered["corrections"][index][field] = "0" * len(altered["corrections"][index][field])
                with mock.patch.object(repair, "profile", return_value=altered):
                    self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)
        for corrections in (profile["corrections"][:1], list(reversed(profile["corrections"]))):
            with mock.patch.object(repair, "profile", return_value=dict(profile, corrections=corrections)):
                self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_bad_second_header_leaves_first_unmodified(self):
        first = self.work / repair.HEADER
        snapshot = (first.read_bytes(), first.stat().st_mtime_ns)
        self.path.write_bytes(b"unreviewed paint header")
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((first.read_bytes(), first.stat().st_mtime_ns), snapshot)
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_partial_baseline_patch_cannot_cross_contract(self):
        for relative in (repair.HEADER, repair.PAINT_HEADER):
            populate(self.work)
            path = self.work / relative
            path.write_bytes(repair.transform(path.read_bytes(), relative))
            snapshots = {p: p.read_bytes() for p in (self.work / repair.HEADER, self.path)}
            with self.assertRaises(ValueError):
                self.apply()
            self.assertEqual({p: p.read_bytes() for p in snapshots}, snapshots)
            self.assertFalse((self.work / repair.MARKER).exists())

    def test_resume_verifies_both_headers_not_just_marker(self):
        self.apply()
        for relative, fixture in ((repair.HEADER, FIXTURE), (repair.PAINT_HEADER, PAINT_FIXTURE),
                              (repair.AUTOFILL_SOURCE, AUTOFILL_FIXTURE),
                              (repair.ATOMIC_SOURCE, ATOMIC_FIXTURE),
                              (repair.HEAP_HEADER, HEAP_FIXTURE),
                              (repair.TORQUE_SOURCE, Path("implementation-visitor.cc")),
                              (repair.TEMPLATE_HEADER, Path("v8-template.h")),
                              (repair.BIND_HEADER, Path("bind-internal.h")),
                              (repair.ACCESSIBILITY_HEADER, Path("browser_accessibility.h")),
                              (repair.ACCESSIBILITY_SOURCE, Path("browser_accessibility.cc"))):
            path = self.work / relative
            fixed = path.read_bytes()
            path.write_bytes(public_input("include/v8-template.h")
                             if relative == repair.TEMPLATE_HEADER
                             else fixture_bytes(fixture.name))
            with self.assertRaises(ValueError):
                self.apply("resume")
            path.write_bytes(fixed)
        self.assertEqual(self.apply("resume"), "already-applied")

    def test_second_input_hardlink_rejected_before_any_write(self):
        first = self.work / repair.HEADER
        snapshot = (first.read_bytes(), first.stat().st_mtime_ns)
        os.link(self.path, self.root / "paint-alias.h")
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((first.read_bytes(), first.stat().st_mtime_ns), snapshot)

    def test_second_input_race_never_publishes_marker(self):
        original = repair._path
        calls = 0
        def raced(work, relative):
            nonlocal calls
            if relative == repair.PAINT_HEADER:
                calls += 1
                if calls == 2:
                    self.path.write_bytes(b"concurrent paint edit")
            return original(work, relative)
        with mock.patch.object(repair, "_path", side_effect=raced):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), b"concurrent paint edit")
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_first_header_is_rechecked_after_second_replacement(self):
        original = os.replace
        def raced(source, target):
            original(source, target)
            if Path(target) == self.path:
                (self.work / repair.HEADER).write_bytes(FIXTURE.read_bytes())
        with mock.patch.object(repair.os, "replace", side_effect=raced):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_old_v1_contract_and_failed_producers_are_not_migration_inputs(self):
        v1_key = "8e498e97d133633398724e333b064f5a1df749aa5b6323f7d3cfc9ae184e4a6e"
        self.assertNotEqual(self.key, v1_key)
        for selector in ({"build_key": v1_key}, dict(repair.LEGACY, run=37079399043),
                         dict(repair.LEGACY, build_key=v1_key)):
            with self.assertRaises(ValueError):
                repair.restore_contract(selector, repair.BASE_KEY)

    @unittest.skipIf(os.name == "nt", "Native MSVC regression below covers Windows")
    def test_real_compiler_old_paint_header_fails_both_guards_fixed_compiles(self):
        cxx = shutil.which("g++")
        if not cxx:
            self.skipTest("Native GCC required")
        source = self.stubs()
        for macro in ("IS_GFX_IMPL", "GFX_VECTOR_ICONS_UNSAFE"):
            (source / "probe.cpp").write_text(self.probe(macro))
            result = subprocess.run([cxx, "-std=c++20", "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-I.", "probe.cpp"],
                                    cwd=source, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("paint_vector_icon.h", result.stderr)
            self.assertIn("string", result.stderr)
        self.apply()
        for macro in ("IS_GFX_IMPL", "GFX_VECTOR_ICONS_UNSAFE"):
            (source / "probe.cpp").write_text(self.probe(macro))
            result = subprocess.run([cxx, "-std=c++20", "-fsyntax-only", "-Wall", "-Wextra", "-Werror", "-I.", "probe.cpp"],
                                    cwd=source, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipIf(os.name == "nt", "Native Ninja/GCC dependency regression")
    def test_real_ninja_invalidates_both_header_dependents_only(self):
        cxx, ninja = shutil.which("g++"), shutil.which("ninja")
        if not cxx or not ninja:
            self.skipTest("Native GCC and Ninja required")
        source = self.stubs()
        (source / "paint.cc").write_text('#include <string>\n#define IS_GFX_IMPL 1\n#include "ui/gfx/paint_vector_icon.h"\nint paint(){return 1;}\n')
        (source / "websocket.cc").write_text('#include <string>\n#include "net/websockets/websocket_handshake_challenge.h"\nint websocket(){return 2;}\n')
        (source / "other.cc").write_text("int other(){return 3;}\n")
        (source / "build.ninja").write_text(
            f'rule cxx\n  command = "{cxx}" -std=c++20 -I. -MMD -MF $out.d -c $in -o $out\n'
            '  depfile = $out.d\n  deps = gcc\n'
            'build paint.o: cxx paint.cc\nbuild websocket.o: cxx websocket.cc\nbuild other.o: cxx other.cc\n')
        def build():
            return subprocess.run([ninja], cwd=source, capture_output=True, text=True, check=True, timeout=60)
        build()
        before = {name: ((source / name).read_bytes(), (source / name).stat().st_mtime_ns)
                  for name in ("paint.o", "websocket.o", "other.o")}
        time.sleep(0.02)
        self.apply(); build()
        for name in ("paint.o", "websocket.o"):
            self.assertGreater((source / name).stat().st_mtime_ns, before[name][1])
        self.assertEqual(((source / "other.o").read_bytes(), (source / "other.o").stat().st_mtime_ns), before["other.o"])
        self.assertEqual(self.apply("resume"), "already-applied")
        self.assertIn("no work to do", build().stdout)
        print("CEF_BOTH_HEADERS_NINJA_INVALIDATION_VERIFIED")

    @unittest.skipUnless(os.name == "nt", "Native MSVC paint header self-containment regression")
    def test_real_msvc_paint_header_both_guards_and_signature(self):
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        vs = Path(subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip())
        version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
        self.assertTrue(version.startswith("14.44."), version)
        source = self.stubs()
        batch = self.root / "compile.cmd"
        batch.write_text(f'@echo off\ncall "{vs}/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                         'if errorlevel 1 exit /b 90\ncl.exe /nologo /std:c++20 /Zs /W4 /WX /I. probe.cpp\n', encoding="utf-8")
        def compile_header(macro):
            (source / "probe.cpp").write_text(self.probe(macro, '#include <string_view>\n'))
            return subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=source,
                                  capture_output=True, text=True, errors="replace", timeout=60)
        for macro in ("IS_GFX_IMPL", "GFX_VECTOR_ICONS_UNSAFE"):
            before = compile_header(macro)
            self.assertNotEqual(before.returncode, 0)
            self.assertNotEqual(before.returncode, 90)
            self.assertIn("paint_vector_icon.h", before.stdout + before.stderr)
            self.assertIn("string", before.stdout + before.stderr)
        self.apply()
        for macro in ("IS_GFX_IMPL", "GFX_VECTOR_ICONS_UNSAFE"):
            after = compile_header(macro)
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
        print("CEF_PAINT_MSVC_HEADER_REPAIR_VERIFIED guards=2 toolset=" + version)



def load_tests(loader, standard_tests, pattern):
    from tests import test_cef_windows_autofill_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_autofill_repair))
    from tests import test_cef_windows_iterator_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_iterator_repair))
    from tests import test_cef_windows_atomic_ref_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_atomic_ref_repair))
    from tests import test_cef_windows_layout_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_layout_repair))
    from tests import test_cef_windows_tail_size_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_tail_size_repair))
    from tests import test_cef_windows_callable_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_callable_repair))
    from tests import test_cef_windows_accessibility_iterator_repair
    standard_tests.addTests(loader.loadTestsFromModule(test_cef_windows_accessibility_iterator_repair))
    return standard_tests


if __name__ == "__main__":
    unittest.main()
