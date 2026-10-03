"""Pinned public Autofill sentinel: strict warnings, reference lifetime and v3 identity.

Only generated Mojom enums are stubbed in the native probe. The actual pinned
AutocompleteParsingResult and NoDestructor headers are compiled; the declaration
and tuple expression are extracted from the full hash-verified source fixture.
This probe is not a full-engine or browser/renderer qualification receipt.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_layout_inputs import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/cef-windows"
OLD_V2 = "2b080bbfc3a1aa242e5e107a07841175378504e0b24de2955808ef4c4e86cfc0"
PUBLIC_BLOBS = {
    "form_field_data.cc": "51101bed0bf95e5f024069323e12081ddcac791a",
    "no_destructor.h": "9c035c1b651f68f7da90bcc30b1ff81b56bcfee0",
    "autocomplete_parsing_util.h": "3f63cfab708bc85f0dc6068d7b7c88e99039ffe7",
    "html_field_types.h": "9b5aa61ebcc8f884ac192c25146cae4af47d2b80",
}


def populate(work):
    for relative, _, _, _ in repair.CORRECTIONS:
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture_bytes(path.name))


def probe_source(source: bytes) -> str:
    text = source.decode("utf-8")
    declarations = re.findall(
        r"    static const (?:base::NoDestructor<)?std::optional<AutocompleteParsingResult>[^;]+;",
        text,
    )
    expressions = re.findall(
        r"!e\.contains\(kNotRefillRelated\) \? f\.parsed_autocomplete_ : \*?kNoParsingResult,",
        text,
    )
    if len(declarations) != 1 or len(expressions) != 1:
        raise ValueError("Autofill probe requires one exact declaration and expression")
    declaration = declarations[0]
    expression = expressions[0][:-1]
    return r'''
#include "components/autofill/core/common/autocomplete_parsing_util.h"
#include "base/no_destructor.h"
#include <cassert>
#include <memory>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>
namespace autofill {
bool AutocompleteParsingResult::operator==(const AutocompleteParsingResult&) const = default;
using Optional = std::optional<AutocompleteParsingResult>;
struct FormFieldData { Optional parsed_autocomplete_; };
inline constexpr int kNotRefillRelated = 1;
struct Exclusions {
  bool excluded;
  bool contains(int) const { return excluded; }
};
auto MakeTuple(const FormFieldData& field, Exclusions exclusions) {
  auto equality_tuple = [e = exclusions](const FormFieldData& f) {
''' + declaration + r'''
    return std::tie(''' + expression + r''');
  };
  return equality_tuple(field);
}
static_assert(std::is_same_v<decltype(MakeTuple(std::declval<const FormFieldData&>(), {false})),
                             std::tuple<const Optional&>>);
static_assert(std::is_trivially_destructible_v<base::NoDestructor<Optional>>);
}
int main() {
  using namespace autofill;
  FormFieldData a, b;
  a.parsed_autocomplete_.emplace();
  a.parsed_autocomplete_->section.assign(128, 'a');
  b.parsed_autocomplete_.emplace();
  b.parsed_autocomplete_->section.assign(128, 'b');
  const auto left = MakeTuple(a, {true});
  const auto right = MakeTuple(b, {true});
  assert(!std::get<0>(left).has_value());
  assert(left == right);
  assert(MakeTuple(a, {false}) != MakeTuple(b, {false}));
  const auto* sentinel = std::addressof(std::get<0>(left));
  assert(sentinel == std::addressof(std::get<0>(right)));
  auto live = MakeTuple(a, {false});
  assert(std::addressof(std::get<0>(live)) == std::addressof(a.parsed_autocomplete_));
  a.parsed_autocomplete_.reset();
  assert(!std::get<0>(live));
  a.parsed_autocomplete_ = b.parsed_autocomplete_;
  assert(std::get<0>(live)->section == b.parsed_autocomplete_->section);
  assert(MakeTuple(a, {false}) == MakeTuple(b, {false}));
  std::vector<std::thread> threads;
  for (int i = 0; i < 8; ++i) {
    threads.emplace_back([sentinel] {
      FormFieldData temporary;
      for (int j = 0; j < 1000; ++j) {
        auto tuple = MakeTuple(temporary, {true});
        assert(std::addressof(std::get<0>(tuple)) == sentinel);
        assert(!std::get<0>(tuple));
      }
    });
  }
  for (auto& thread : threads) thread.join();
  assert(!*sentinel);
}
'''


class AutofillRepairTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="autofill lifetime ")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.work = self.root / "work"
        populate(self.work)
        self.path = self.work / repair.AUTOFILL_SOURCE
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self, origin="legacy"):
        return repair.apply(self.work, self.key, origin)

    def test_all_native_inputs_are_exact_pinned_public_blobs(self):
        for name, expected in PUBLIC_BLOBS.items():
            data = (FIXTURES / name).read_bytes()
            actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            self.assertEqual(actual, expected, name)
        attrs = (ROOT / ".gitattributes").read_text()
        self.assertIn("/tests/fixtures/cef-windows/*.cc text eol=lf", attrs)

    def test_exact_three_edits_keep_tuple_reference_expression(self):
        old = self.path.read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(), repair.AUTOFILL_BEFORE)
        fixed = repair.transform(old, repair.AUTOFILL_SOURCE)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.AUTOFILL_AFTER)
        restored = fixed
        for anchor, replacement in reversed(repair.CORRECTIONS[2][3]):
            self.assertEqual(restored.count(replacement), 1)
            restored = restored.replace(replacement, anchor, 1)
        self.assertEqual(restored, old)
        self.assertIn(" : *kNoParsingResult)", probe_source(fixed))
        self.assertNotIn(b"#pragma", fixed)
        self.assertNotIn(b"Wno-", fixed)

    def test_autofill_newlines_and_idempotence(self):
        old = self.path.read_bytes()
        for ending in (b"\n", b"\r\n"):
            original = old.replace(b"\n", ending)
            fixed = repair.transform(original, repair.AUTOFILL_SOURCE)
            self.assertEqual(repair.transform(fixed, repair.AUTOFILL_SOURCE), fixed)
            self.assertEqual(fixed.count(b"\r\n"), fixed.count(b"\n") if ending == b"\r\n" else 0)
        for invalid in (old + b"// drift\n", old.replace(b"\n", b"\r\n", 1), b"", b"x" * 65537):
            with self.assertRaises(ValueError):
                repair.transform(invalid, repair.AUTOFILL_SOURCE)

    def test_bad_third_input_does_not_modify_either_header(self):
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in (self.work / repair.HEADER, self.work / repair.PAINT_HEADER)}
        self.path.write_bytes(b"unreviewed source")
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_third_input_hardlink_is_rejected_before_writes(self):
        os.link(self.path, self.root / "alias.cc")
        before = (self.work / repair.HEADER).read_bytes()
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.work / repair.HEADER).read_bytes(), before)
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_partial_autofill_edits_are_not_a_migration(self):
        old = self.path.read_bytes()
        for anchor, replacement in repair.CORRECTIONS[2][3]:
            self.path.write_bytes(old.replace(anchor, replacement, 1))
            with self.assertRaises(ValueError):
                self.apply()
            self.assertFalse((self.work / repair.MARKER).exists())

    def test_v2_and_failed37_are_not_checkpoint_inputs(self):
        for selected in (dict(repair.LEGACY, build_key=OLD_V2),
                         dict(repair.LEGACY, run=37094488607),
                         dict(repair.LEGACY, run=37094488607, build_key=OLD_V2)):
            with self.assertRaises(ValueError):
                repair.restore_contract(selected, repair.BASE_KEY)
        self.assertNotEqual(self.key, OLD_V2)
        self.assertEqual(repair.restore_contract(repair.LEGACY, repair.BASE_KEY),
                         (repair.BASE_KEY, "legacy"))

    def test_resume_checks_autofill_contents_and_complete_profile(self):
        self.apply()
        fixed = self.path.read_bytes()
        self.path.write_bytes((FIXTURES / "form_field_data.cc").read_bytes())
        with self.assertRaises(ValueError):
            self.apply("resume")
        self.path.write_bytes(fixed)
        value = {"base_build_key": repair.BASE_KEY, "source_repair_verified": True,
                 "source_repair": repair.profile()}
        repair.verify_summary(value, {"build_key": self.key})
        value["source_repair"]["corrections"].pop()
        with self.assertRaises(ValueError):
            repair.verify_summary(value, {"build_key": self.key})
        self.assertEqual(self.apply("resume"), "already-applied")

    def test_third_file_replacement_race_cannot_publish_marker(self):
        original = repair._path
        seen = 0
        def race(work, relative):
            nonlocal seen
            if relative == repair.AUTOFILL_SOURCE:
                seen += 1
                if seen == 2:
                    self.path.write_bytes(b"concurrent change")
            return original(work, relative)
        with mock.patch.object(repair, "_path", side_effect=race):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), b"concurrent change")
        self.assertFalse((self.work / repair.MARKER).exists())

    def test_autofill_cpp_edit_rebuilds_its_object_only(self):
        ninja, cxx = shutil.which("ninja"), shutil.which("clang++")
        if os.name == "nt" or not ninja or not cxx:
            self.skipTest("Native Unix Ninja/Clang dependency test")
        self.native_headers()
        build = self.root / "build"; build.mkdir()
        def materialize():
            (build / "autofill.cc").write_text(probe_source(self.path.read_bytes()))
        materialize()
        (build / "other.cc").write_text("int untouched(){return 0;}\n")
        include = str(self.root / "include").replace("$", "$$")
        (build / "build.ninja").write_text(
            f'rule cxx\n  command = "{cxx}" -std=c++20 -I"{include}" -c $in -o $out\n'
            'build autofill.o: cxx autofill.cc\nbuild other.o: cxx other.cc\n')
        subprocess.run([ninja], cwd=build, check=True, capture_output=True, timeout=60)
        before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in build.glob("*.o")}
        self.apply(); materialize()
        subprocess.run([ninja], cwd=build, check=True, capture_output=True, timeout=60)
        self.assertGreater((build / "autofill.o").stat().st_mtime_ns, before[build / "autofill.o"][0])
        self.assertEqual(((build / "other.o").stat().st_mtime_ns, (build / "other.o").read_bytes()),
                         before[build / "other.o"])
        self.apply("resume")
        result = subprocess.run([ninja], cwd=build, check=True, capture_output=True, text=True, timeout=60)
        self.assertIn("no work to do", result.stdout)

    def native_headers(self):
        include = self.root / "include"
        for name, relative in (
            ("no_destructor.h", "base/no_destructor.h"),
            ("autocomplete_parsing_util.h", "components/autofill/core/common/autocomplete_parsing_util.h"),
            ("html_field_types.h", "components/autofill/core/common/html_field_types.h"),
        ):
            target = include / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((FIXTURES / name).read_bytes())
        generated = include / "components/autofill/core/common/mojom/autofill_types.mojom-shared.h"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_text(
            "namespace autofill::mojom { enum class HtmlFieldMode { kNone, kBilling, kShipping };"
            " enum class HtmlFieldType { kUnspecified, kUnrecognized }; }\n")
        return include

    def test_native_clang_werror_and_reference_lifetime(self):
        include = self.native_headers()
        source = self.root / "probe.cc"
        output = self.root / ("probe.exe" if os.name == "nt" else "probe")
        if os.name == "nt":
            vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            if not vswhere.is_file():
                self.fail("Native Windows regression requires MSVC toolchain")
            vs = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
            clang = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/clang-cl.exe"
            if not clang.is_file():
                self.fail("Native Windows regression requires installed clang-cl")
            batch = self.root / "compile.cmd"
            batch.write_text(
                '@echo off\ncall "' + vs + '/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\n"' + str(clang) + '" /nologo /std:c++20 /EHsc /W4 /WX '
                '-Wexit-time-destructors -Werror /I"' + str(include) + '" "' + str(source) + '" /Fe:"' + str(output) + '"\n')
            command = ["cmd.exe", "/d", "/c", str(batch)]
        else:
            clang = shutil.which("clang++")
            if not clang:
                self.fail("Native regression requires Clang")
            command = [str(clang), "-std=c++20", "-Wall", "-Wextra", "-Werror",
                       "-Wexit-time-destructors", "-pthread", "-I", str(include), str(source), "-o", str(output)]
        source.write_text(probe_source(self.path.read_bytes()))
        old = subprocess.run(command, cwd=self.root, capture_output=True, text=True, errors="replace", timeout=60)
        if os.name == "nt":
            self.assertNotEqual(old.returncode, 0, "Original MSVC-STL sentinel must reproduce the diagnostic")
            self.assertIn("declaration requires an exit-time destructor", old.stdout + old.stderr)
            self.assertIn("kNoParsingResult", old.stdout + old.stderr)
            self.assertIn("-Wexit-time-destructors", old.stdout + old.stderr)
            self.assertNotEqual(old.returncode, 90)
        elif old.returncode:
            self.assertIn("-Wexit-time-destructors", old.stdout + old.stderr)
        self.apply()
        source.write_text(probe_source(self.path.read_bytes()))
        fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True, errors="replace", timeout=60)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        print("CEF_AUTOFILL_LIFETIME_VERIFIED old_warning=" + str(old.returncode != 0)
              + " strict_warning=true tuple_const_reference=true threads=8")
        if os.name != "nt":
            sanitized = command + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            result = subprocess.run(sanitized, cwd=self.root, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
