"""Actual public XML/CXX headers and the exact five-source v11-to-v16 upgrade.

No std/rust/Node definitions are stubbed. The native test checks header
self-containment and all six FFI declarations, not XML parsing or CEF runtime.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import urllib.request
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from secure_release.crypto import canonical, parse
from tests.test_cef_windows_inline_empty_repair import populate_v11

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/cef-windows"
PUBLIC = {
    "dom_builder.h": ("services/data_decoder/xml/dom_builder.h", 937,
        "6271857b1ef617fce72a93a5ec18947aec67590d"),
    "rust_cxx_forward.h": ("third_party/rust/cxx/v1/cxx.h", 435,
        "844e505182de6dedfa7e1a1f48e0696ef036006c"),
    "rust_cxx.h": ("third_party/rust/chromium_crates_io/vendor/cxx-v1/include/cxx.h", 29568,
        "4e261a35536c5d96f22008cff6a095171af2f89c"),
}
HEADER = PUBLIC["dom_builder.h"][0]
PROBE = r'''
#include "services/data_decoder/xml/dom_builder.h"
#include "services/data_decoder/xml/dom_builder.h"
#include <type_traits>
using data_decoder::xml::Node;
namespace ffi = data_decoder::xml::ffi;
static_assert(std::is_same_v<decltype(&ffi::create_element),
    std::unique_ptr<Node> (*)(rust::Str, rust::Str)>);
static_assert(std::is_same_v<decltype(&ffi::create_text_node),
    std::unique_ptr<Node> (*)(rust::Str)>);
static_assert(std::is_same_v<decltype(&ffi::create_cdata_node),
    std::unique_ptr<Node> (*)(rust::Str)>);
static_assert(std::is_same_v<decltype(&ffi::set_attribute),
    void (*)(Node&, rust::Str, rust::Str, rust::Str)>);
static_assert(std::is_same_v<decltype(&ffi::set_namespace),
    void (*)(Node&, rust::Str, rust::Str)>);
static_assert(std::is_same_v<decltype(&ffi::add_child),
    void (*)(Node&, std::unique_ptr<Node>)>);
int main() { return 0; }
'''


@lru_cache(maxsize=3)
def public_bytes(name):
    relative, size, blob = PUBLIC[name]
    if name == "dom_builder.h":
        data = (FIXTURES / name).read_bytes()
    elif os.environ.get("CEF_WINDOWS_DOM_SOURCE_ROOT"):
        with (Path(os.environ["CEF_WINDOWS_DOM_SOURCE_ROOT"]) / relative).open("rb") as stream:
            data = stream.read(size + 1)
    else:
        url = "https://raw.githubusercontent.com/chromium/chromium/" + repair.CHROMIUM + "/" + relative
        with urllib.request.urlopen(url, timeout=30) as stream:
            if stream.geturl() != url:
                raise ValueError("Unexpected public XML fixture redirect")
            data = stream.read(size + 1)
    actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if len(data) != size or actual != blob:
        raise ValueError("Unreviewed public XML header fixture")
    return data


class DomMemoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="DOM memory regression ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.old = public_bytes("dom_builder.h")
        self.fixed = repair.transform(self.old, repair.DOM_HEADER)

    def test_exact_public_headers_and_only_one_standard_include(self):
        for name in PUBLIC:
            public_bytes(name)
        self.assertEqual(hashlib.sha256(self.old).hexdigest(), repair.DOM_BEFORE)
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), repair.DOM_AFTER)
        self.assertEqual(self.fixed.replace(b"#include <memory>\n\n", b"", 1), self.old)
        self.assertEqual(self.fixed.count(b"#include <memory>"), 1)
        self.assertIn(b"class Node;", self.fixed)
        self.assertNotIn(b"#include <memory>", public_bytes("rust_cxx.h"))
        self.assertEqual(repair.profile()["id"], "windows-password-backend-error-nothrow-v20")
        self.assertEqual(len(repair.CORRECTIONS), 21)
        self.assertEqual(tuple(row[0] for row in repair.CORRECTIONS[11:13]),
                         (repair.INLINE_HEADER, repair.DOM_HEADER))

    def test_newlines_idempotence_and_modified_inputs(self):
        for nl in (b"\n", b"\r\n"):
            raw = self.old.replace(b"\n", nl)
            fixed = repair.transform(raw, repair.DOM_HEADER)
            self.assertEqual(fixed, self.fixed.replace(b"\n", nl))
            self.assertEqual(repair.transform(fixed, repair.DOM_HEADER), fixed)
        for raw in (b"", self.old + b"\n", self.old.replace(b"class Node;", b"class NodeX;"),
                    self.old.replace(b"\n", b"\r\n", 1), self.fixed + b"\n"):
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.DOM_HEADER)

    def native_command(self, include, source, executable, standard):
        if os.name != "nt":
            clang = shutil.which("clang++")
            self.assertTrue(clang, "Native XML regression requires Clang")
            return [clang, "-std=" + standard, "-Wall", "-Wextra", "-Werror",
                    "-fno-exceptions", "-fno-rtti", "-I", str(include),
                    str(source), "-o", str(executable)]
        where = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
        clang = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/clang-cl.exe"
        self.assertTrue(where.is_file() and clang.is_file(), "Native Windows toolchain required")
        vs = Path(subprocess.check_output([str(where), "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip())
        version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
        self.assertTrue(version.startswith("14.44."), version)
        batch = self.root / (standard + ".cmd")
        batch.write_text('@echo off\ncall "' + str(vs) + '/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
            'if errorlevel 1 exit /b 90\necho VCToolsVersion=%VCToolsVersion%\n'
            '"' + str(clang) + '" /nologo /std:' + standard + ' /W4 /WX /MT /GR- /D_HAS_EXCEPTIONS=0 -Werror '
            '/I"' + str(include) + '" "' + str(source) + '" /Fe:"' + str(executable) + '"\n', encoding="utf-8")
        return ["cmd.exe", "/d", "/c", str(batch)]

    def test_native_real_cxx_headers_original_failure_and_six_signatures(self):
        include = self.root / "include"
        for name, (relative, _, _) in PUBLIC.items():
            path = include / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(public_bytes(name))
        source = self.root / "probe.cc"
        executable = self.root / ("probe.exe" if os.name == "nt" else "probe")
        standards = ("c++20", "c++latest" if os.name == "nt" else "c++23")
        old_failed = []
        for standard in standards:
            command = self.native_command(include, source, executable, standard)
            def compile_probe():
                return subprocess.run(command, cwd=self.root, capture_output=True, text=True,
                                      errors="replace", timeout=90)
            source.write_text(PROBE, encoding="utf-8")
            (include / HEADER).write_bytes(self.old)
            old = compile_probe()
            old_failed.append(old.returncode != 0)
            if os.name == "nt":
                self.assertNotEqual(old.returncode, 0, "Original Windows header must fail")
            if old.returncode:
                self.assertNotEqual(old.returncode, 90)
                self.assertIn("unique_ptr", old.stdout + old.stderr)
                self.assertIn("dom_builder.h", old.stdout + old.stderr)
            (include / HEADER).write_bytes(self.fixed)
            for prelude in ("", '#include "third_party/rust/cxx/v1/cxx.h"\n#include <memory>\n'):
                source.write_text(prelude + PROBE, encoding="utf-8")
                fixed = compile_probe()
                self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
                subprocess.run([str(executable)], cwd=self.root, check=True, capture_output=True, timeout=15)
        print("CEF_DOM_MEMORY_NATIVE original_failed=" + str(old_failed)
              + " actual_public_cxx=true signatures=6 standards=2 flags_strict=true")


class DomUpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="DOM v11 upgrade ")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve() / "work"
        populate_v11(self.work)
        self.dom = self.work / repair.DOM_HEADER
        self.inline = self.work / repair.INLINE_HEADER
        self.inline_items = self.work / repair.INLINE_ITEMS_SOURCE
        self.api_key = self.work / repair.API_KEY_HEADER
        self.credit_card = self.work / repair.CREDIT_CARD_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, "upgrade-v11")

    def test_five_source_upgrade_preserves_all_other_bytes_and_clocks(self):
        obj = self.work / "out/keep.obj"; obj.parent.mkdir(); obj.write_bytes(b"v11 object")
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.work.rglob("*") if p.is_file()}
        self.assertEqual(self.apply(), "upgraded-v11")
        changed = {
            self.inline: repair.INLINE_HEADER,
            self.dom: repair.DOM_HEADER,
            self.inline_items: repair.INLINE_ITEMS_SOURCE,
            self.api_key: repair.API_KEY_HEADER,
            self.credit_card: repair.CREDIT_CARD_HEADER,
            self.work / repair.FRAME_TREE_HEADER: repair.FRAME_TREE_HEADER,
            self.work / repair.LOCK_MANAGER_HEADER: repair.LOCK_MANAGER_HEADER,
            self.work / repair.AFFILIATED_MATCH_SOURCE: repair.AFFILIATED_MATCH_SOURCE,
            self.work / repair.BACKEND_ERROR_HEADER: repair.BACKEND_ERROR_HEADER,
            self.work / repair.BACKEND_ERROR_SOURCE: repair.BACKEND_ERROR_SOURCE,
        }
        for path, snapshot in before.items():
            if path in changed:
                self.assertEqual(path.read_bytes(), repair.transform(snapshot[0], changed[path]))
                self.assertGreater(path.stat().st_mtime_ns, snapshot[1])
            elif path != self.marker:
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), snapshot)
        self.assertEqual(parse(self.marker.read_bytes())["source_repair"], repair.profile())
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual(after, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})

    def test_bad_dom_is_checked_before_inline_write(self):
        before = self.inline.read_bytes(), self.marker.read_bytes()
        self.dom.write_bytes(b"unreviewed DOM header")
        with mock.patch.object(repair.os, "replace") as replace:
            with self.assertRaises(ValueError): self.apply()
            replace.assert_not_called()
        self.assertEqual((self.inline.read_bytes(), self.marker.read_bytes()), before)

    def test_dom_hardlink_is_checked_before_any_write(self):
        os.link(self.dom, self.work / "alias.h")
        with mock.patch.object(repair.os, "replace") as replace:
            with self.assertRaises(ValueError): self.apply()
            replace.assert_not_called()

    def test_each_partially_applied_new_source_fails_closed(self):
        old_marker = self.marker.read_bytes()
        changed = {
            self.inline: repair.INLINE_HEADER,
            self.dom: repair.DOM_HEADER,
            self.inline_items: repair.INLINE_ITEMS_SOURCE,
            self.api_key: repair.API_KEY_HEADER,
            self.credit_card: repair.CREDIT_CARD_HEADER,
            self.work / repair.FRAME_TREE_HEADER: repair.FRAME_TREE_HEADER,
            self.work / repair.LOCK_MANAGER_HEADER: repair.LOCK_MANAGER_HEADER,
            self.work / repair.AFFILIATED_MATCH_SOURCE: repair.AFFILIATED_MATCH_SOURCE,
            self.work / repair.BACKEND_ERROR_HEADER: repair.BACKEND_ERROR_HEADER,
            self.work / repair.BACKEND_ERROR_SOURCE: repair.BACKEND_ERROR_SOURCE,
        }
        for path, relative in changed.items():
            raw = path.read_bytes()
            path.write_bytes(repair.transform(raw, relative))
            with mock.patch.object(repair.os, "replace") as replace:
                with self.assertRaises(ValueError): self.apply()
                replace.assert_not_called()
            with self.assertRaises(ValueError): repair.apply(self.work, self.key, "resume")
            self.assertEqual(self.marker.read_bytes(), old_marker)
            path.write_bytes(raw)

    def test_failure_on_second_replace_never_publishes_marker(self):
        original = repair.os.replace
        old_marker = self.marker.read_bytes()
        def fail(source, target):
            if Path(target) == self.dom: raise OSError("injected second write failure")
            return original(source, target)
        with mock.patch.object(repair.os, "replace", side_effect=fail):
            with self.assertRaises(OSError): self.apply()
        self.assertEqual(self.marker.read_bytes(), old_marker)
        with self.assertRaises(ValueError): self.apply()
        with self.assertRaises(ValueError): repair.apply(self.work, self.key, "resume")
        self.assertFalse(list(self.work.rglob(".cef-header-*")))

    def test_dom_race_after_first_replace_is_not_overwritten(self):
        original = repair.os.replace
        old_marker = self.marker.read_bytes()
        def race(source, target):
            original(source, target)
            if Path(target) == self.inline: self.dom.write_bytes(b"concurrent DOM")
        with mock.patch.object(repair.os, "replace", side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.dom.read_bytes(), b"concurrent DOM")
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_first_header_race_after_second_replace_prevents_marker(self):
        original = repair.os.replace
        old_marker = self.marker.read_bytes()
        def race(source, target):
            original(source, target)
            if Path(target) == self.dom: self.inline.write_bytes(b"concurrent InlineNode")
        with mock.patch.object(repair.os, "replace", side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.inline.read_bytes(), b"concurrent InlineNode")
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_failed_v12_producer_and_incomplete_v13_summary_are_not_accepted(self):
        old_key = "556e9187d8165ea910115c9e304a16e2d148e19df0102c348e6c53a86768c48d"
        for selected in ({"build_key": old_key}, dict(repair.UPGRADE_V11, run=37286971696),
                         dict(repair.UPGRADE_V11, build_key=old_key)):
            with self.assertRaises(ValueError): repair.restore_contract(selected, repair.BASE_KEY)
        value = {"base_build_key": repair.BASE_KEY, "source_repair_verified": True,
                 "source_repair": repair.profile()}
        repair.verify_summary(value, {"build_key": self.key})
        value["source_repair"]["corrections"].pop()
        with self.assertRaises(ValueError): repair.verify_summary(value, {"build_key": self.key})

    @unittest.skipIf(os.name == "nt", "Unix Ninja dependency proof; native Windows header test is mandatory")
    def test_ninja_rebuilds_dom_dependent_only_and_resume_is_no_work(self):
        ninja, clang = shutil.which("ninja"), shutil.which("clang++")
        self.assertTrue(ninja and clang, "Native dependency tools required")
        include = self.work / "download/chromium/src"
        for name in ("rust_cxx_forward.h", "rust_cxx.h"):
            path = include / PUBLIC[name][0]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(public_bytes(name))
        build = self.work.parent / "build"; build.mkdir()
        # An explicit caller include permits the OLD header to build only for
        # this dependency-clock test. The separate native probe includes the
        # header first and must reproduce the Windows error without this include.
        (build / "probe.cc").write_text('#include <memory>\n' + PROBE, encoding="utf-8")
        (build / "other.cc").write_text('int untouched() { return 48; }\n')
        (build / "build.ninja").write_text(
            'rule cxx\n  command = "' + clang + '" -std=c++20 -I"' + str(include)
            + '" -MMD -MF $out.d -c $in -o $out\n  depfile = $out.d\n  deps = gcc\n'
            'build probe.o: cxx probe.cc\nbuild other.o: cxx other.cc\n')
        def run():
            result = subprocess.run([ninja], cwd=build, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        run()
        old_clock = (build / "probe.o").stat().st_mtime_ns
        other = (build / "other.o").read_bytes(), (build / "other.o").stat().st_mtime_ns
        self.apply(); run()
        self.assertGreater((build / "probe.o").stat().st_mtime_ns, old_clock)
        self.assertEqual(((build / "other.o").read_bytes(), (build / "other.o").stat().st_mtime_ns), other)
        repair.apply(self.work, self.key, "resume")
        self.assertIn("no work to do", run().stdout)
