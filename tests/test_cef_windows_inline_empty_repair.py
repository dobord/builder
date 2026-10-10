"""Public InlineNode empty sentinel and exact v11-to-current transition regressions.

The native probe extracts FirstLineOffsetMap verbatim from the pinned public
header and compiles the actual TextOffsetMap/NoDestructor headers. The surrounding
layout data, ICU declaration and Vector backing are small adapters; this is not
full Blink, ICU, Oilpan, or CEF runtime qualification.
"""
from __future__ import annotations

import copy
import hashlib
import json
import importlib.util
import sys
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
PUBLIC_BLOBS = {
    "inline_node.h": "1028a02140df492646f9f828fe2e724ca51ee459",
    "text_offset_map.h": "32760ad735c3fa50d5b383146c55fad91d011af9",
    "no_destructor.h": "9c035c1b651f68f7da90bcc30b1ff81b56bcfee0",
}


def populate_v11(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 11 else raw)
    marker = {"schema": 1, "kind": "cef-windows-source-repair",
              "build_key": repair.V11_KEY, "source_repair": repair.v11_profile()}
    (work / repair.MARKER).write_bytes(canonical(marker) + b"\n")


def method(source):
    text = source.decode("utf-8")
    anchor = "  const std::optional<TextOffsetMap>& FirstLineOffsetMap() const {"
    if text.count(anchor) != 1:
        raise ValueError("Expected one exact FirstLineOffsetMap method")
    start = text.index(anchor)
    cursor = text.index("{", start)
    depth = 0
    for end in range(cursor, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0:
                return text[start:end + 1]
    raise ValueError("Unterminated public method")


def probe(source):
    return r'''
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
#include "base/no_destructor.h"
#include <optional>
#include <array>
#include <cassert>
#include <memory>
#include <thread>
#include <type_traits>
namespace blink {
using Optional = std::optional<TextOffsetMap>;
struct Items {
  Optional offsets;
  const Optional& OffsetMap() const { return offsets; }
};
struct ItemRef {
  const Items* pointer;
  const Items* Get() const { return pointer; }
};
struct DataAdapter { ItemRef first_line_items_; };
class InlineNode {
 public:
  explicit InlineNode(const Items* first_line = nullptr) : data_{{first_line}} {}
  const DataAdapter& Data() const { return data_; }
''' + method(source) + r'''
 private:
  DataAdapter data_;
};
static_assert(std::is_same_v<decltype(std::declval<const InlineNode&>().FirstLineOffsetMap()),
                             const Optional&>);
static_assert(!std::is_trivially_destructible_v<TextOffsetMap>);
static_assert(std::is_trivially_destructible_v<base::NoDestructor<Optional>>);
}
int main() {
  using namespace blink;
  std::array<const Optional*, 8> observed{};
  std::array<std::thread, 8> threads;
  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i] = std::thread([i, &observed] {
      InlineNode absent;
      for (int j = 0; j < 1000; ++j) {
        const Optional& value = absent.FirstLineOffsetMap();
        assert(!value.has_value());
        if (j == 0) observed[i] = std::addressof(value);
        assert(observed[i] == std::addressof(value));
      }
    });
  }
  for (auto& t : threads) t.join();
  for (auto* p : observed) assert(p == observed[0]);
  const Optional* empty = observed[0];
  InlineNode a, b;
  assert(std::addressof(a.FirstLineOffsetMap()) == empty);
  assert(std::addressof(b.FirstLineOffsetMap()) == empty);
  Items first;
  InlineNode live(&first);
  const Optional& forwarded = live.FirstLineOffsetMap();
  assert(std::addressof(forwarded) == std::addressof(first.offsets));
  assert(std::addressof(forwarded) != empty);
  assert(!forwarded);
  first.offsets.emplace();
  assert(forwarded.has_value() && forwarded->IsEmpty());
  assert(std::addressof(live.FirstLineOffsetMap()) == std::addressof(first.offsets));
  first.offsets.reset();
  assert(!forwarded && !*empty);
}
'''


class InlineEmptyRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="inline empty test ")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.old = (FIXTURES / "inline_node.h").read_bytes()
        self.fixed = repair.transform(self.old, repair.INLINE_HEADER)

    def test_exact_public_blobs_and_three_narrow_edits(self):
        for name, expected in PUBLIC_BLOBS.items():
            data = (FIXTURES / name).read_bytes()
            self.assertEqual(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(), expected)
        self.assertEqual(hashlib.sha256(self.old).hexdigest(), repair.INLINE_BEFORE)
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), repair.INLINE_AFTER)
        reversed_source = self.fixed
        for before, after in reversed(repair.CORRECTIONS[11][3]):
            self.assertEqual(reversed_source.count(after), 1)
            reversed_source = reversed_source.replace(after, before, 1)
        self.assertEqual(reversed_source, self.old)
        self.assertEqual(method(self.old).splitlines()[0], method(self.fixed).splitlines()[0])
        self.assertIn("return first_line->OffsetMap();", method(self.fixed))
        self.assertIn("return *kEmpty;", method(self.fixed))
        self.assertNotIn(b"Wno-", self.fixed)
        self.assertNotIn(b"#pragma", self.fixed)

    def test_idempotence_newlines_and_unreviewed_sources(self):
        for nl in (b"\n", b"\r\n"):
            raw = self.old.replace(b"\n", nl)
            changed = repair.transform(raw, repair.INLINE_HEADER)
            self.assertEqual(repair.transform(changed, repair.INLINE_HEADER), changed)
            self.assertEqual(changed.replace(b"\r\n", b"\n"), self.fixed)
        for raw in (b"", self.old + b"\n", self.old.replace(b"kEmpty", b"kOther"),
                    self.old.replace(b"\n", b"\r\n", 1)):
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.INLINE_HEADER)

    def headers(self):
        include = self.root / "include"
        for name, relative in (("no_destructor.h", "base/no_destructor.h"),
                ("text_offset_map.h", "third_party/blink/renderer/platform/wtf/text/text_offset_map.h")):
            path = include / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((FIXTURES / name).read_bytes())
        stubs = {
            "unicode/edits.h": "namespace icu { class Edits; }\n",
            "third_party/blink/renderer/platform/wtf/forward.h":
                "#include <cstdint>\n#include <cstddef>\n#include <iosfwd>\nnamespace blink { using wtf_size_t = uint32_t; }\n",
            "third_party/blink/renderer/platform/wtf/wtf_export.h": "#define WTF_EXPORT\n",
            "third_party/blink/renderer/platform/wtf/vector.h":
                "#include <vector>\nnamespace blink { template<class T> class Vector : public std::vector<T> { public: void Shrink(size_t n) { this->erase(this->begin() + n, this->end()); } }; }\n",
        }
        for relative, text in stubs.items():
            path = include / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return include

    def command(self, include, source, output):
        if os.name == "nt":
            where = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            self.assertTrue(where.is_file(), "Native regression requires MSVC")
            vs = subprocess.check_output([str(where), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
            clang = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/clang-cl.exe"
            self.assertTrue(clang.is_file(), "Native regression requires Clang")
            batch = self.root / "compile.cmd"
            batch.write_text('@echo off\ncall "' + vs + '/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\n"' + str(clang) + '" /nologo /std:c++20 /EHsc /W4 /WX '
                '-Werror -Wexit-time-destructors /I"' + str(include) + '" "' + str(source) + '" /Fe:"' + str(output) + '"\n')
            return ["cmd.exe", "/d", "/c", str(batch)]
        clang = shutil.which("clang++")
        self.assertTrue(clang, "Native regression requires Clang")
        return [clang, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-Wexit-time-destructors",
                "-pthread", "-I", str(include), str(source), "-o", str(output)]

    def test_native_strict_warning_reference_identity_and_threads(self):
        include = self.headers()
        source = self.root / "probe.cc"
        output = self.root / ("probe.exe" if os.name == "nt" else "probe")
        command = self.command(include, source, output)
        source.write_text(probe(self.old))
        old = subprocess.run(command, cwd=self.root, capture_output=True, text=True, errors="replace", timeout=90)
        if os.name == "nt":
            self.assertNotEqual(old.returncode, 0, "Original Windows sentinel must fail")
            self.assertNotEqual(old.returncode, 90)
            self.assertIn("declaration requires an exit-time destructor", old.stdout + old.stderr)
            self.assertIn("kEmpty", old.stdout + old.stderr)
        elif old.returncode:
            self.assertIn("-Wexit-time-destructors", old.stdout + old.stderr)
        source.write_text(probe(self.fixed))
        fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True, errors="replace", timeout=90)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        if os.name != "nt":
            checked = subprocess.run(command + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
                                     cwd=self.root, capture_output=True, text=True, timeout=90)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        print("CEF_INLINE_EMPTY_VERIFIED old_warning=" + str(old.returncode != 0)
              + " strict_warning=true first_line_passthrough=true const_reference=true threads=8")


class V11TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="v11 upgrade test ")
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / "work"
        populate_v11(self.work)
        self.path = self.work / repair.INLINE_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, "upgrade-v11")

    def test_v11_selector_is_historical_not_current_migration(self):
        for selected in (repair.UPGRADE_V11, {"build_key": repair.V11_KEY},
                         dict(repair.UPGRADE_V11, attempt=True),
                         dict(repair.UPGRADE_V11, extra=1)):
            with self.assertRaises(ValueError):
                repair.restore_contract(selected, repair.BASE_KEY)

    def test_previous_profile_key_is_independently_bound(self):
        old = repair.v11_profile()
        digest = hashlib.sha256(canonical({"schema": 2, "base_build_key": repair.BASE_KEY, "source_repair": old})).hexdigest()
        self.assertEqual(digest, repair.V11_KEY)
        self.assertNotEqual(self.key, repair.V11_KEY)
        self.assertEqual(len(old["corrections"]), 11)
        self.assertEqual(repair.profile()["corrections"][:11], old["corrections"])

    def test_v11_summary_cannot_authorize_current_transition(self):
        value = {"base_build_key": repair.BASE_KEY, "source_repair_verified": True,
                 "source_repair": repair.v11_profile()}
        with self.assertRaises(ValueError):
            repair.verify_summary(value, repair.UPGRADE_V11)
        with self.assertRaises(ValueError):
            repair.verify_summary(value, {"build_key": self.key})

    def test_upgrade_preserves_all_previous_sources_objects_and_repeat_resume(self):
        obj = self.work / "out/keep.obj"; obj.parent.mkdir(); obj.write_bytes(b"compiled-v11")
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.work.rglob("*") if p.is_file()}
        self.assertEqual(self.apply(), "upgraded-v11")
        for path, snap in before.items():
            if path not in (self.path, self.work / repair.DOM_HEADER,
                            self.work / repair.INLINE_ITEMS_SOURCE,
                            self.work / repair.API_KEY_HEADER,
                            self.work / repair.CREDIT_CARD_HEADER,
                            self.work / repair.FRAME_TREE_HEADER,
                            self.work / repair.LOCK_MANAGER_HEADER,
                            self.work / repair.AFFILIATED_MATCH_SOURCE,
                            self.work / repair.BACKEND_ERROR_HEADER,
                            self.work / repair.BACKEND_ERROR_SOURCE, self.marker):
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), snap)
        self.assertGreater(self.path.stat().st_mtime_ns, before[self.path][1])
        self.assertEqual(parse(self.marker.read_bytes())["build_key"], self.key)
        snapshot = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual(snapshot, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before})
        with self.assertRaises(ValueError): self.apply()

    def test_all_previous_sources_checked_before_upgrade(self):
        before = self.path.read_bytes(), self.marker.read_bytes()
        for relative, _, _, _ in repair.CORRECTIONS[:11]:
            p = self.work / relative; fixed = p.read_bytes()
            p.write_bytes(fixture_bytes(p.name))
            with self.assertRaises(ValueError): self.apply()
            self.assertEqual((self.path.read_bytes(), self.marker.read_bytes()), before)
            p.write_bytes(fixed)

    def test_wrong_old_marker_is_rejected_without_source_write(self):
        original = self.marker.read_bytes(); source = self.path.read_bytes()
        for field in ("build_key", "source_repair"):
            value = parse(original); value[field] = None; self.marker.write_bytes(canonical(value))
            with self.assertRaises(ValueError): self.apply()
            self.assertEqual(self.path.read_bytes(), source)
        self.marker.write_bytes(original)

    def test_interrupted_upgrade_fails_closed(self):
        old_marker = self.marker.read_bytes()
        self.path.write_bytes(repair.transform(self.path.read_bytes(), repair.INLINE_HEADER))
        with self.assertRaises(ValueError): self.apply()
        with self.assertRaises(ValueError): repair.apply(self.work, self.key, "resume")
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_marker_hardlink_is_rejected(self):
        os.link(self.marker, self.work / "alias-marker.json")
        with self.assertRaises(ValueError): self.apply()

    def test_old_source_race_does_not_publish_new_marker(self):
        original = repair.os.replace
        old_marker = self.marker.read_bytes()
        previous = self.work / repair.HEADER
        def raced(source, target):
            original(source, target)
            if Path(target) == self.path: previous.write_bytes(b"concurrent edit")
        with mock.patch.object(repair.os, "replace", side_effect=raced):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), old_marker)
        self.assertEqual(previous.read_bytes(), b"concurrent edit")

    def test_marker_race_is_not_overwritten(self):
        original = repair.os.replace
        def raced(source, target):
            original(source, target)
            if Path(target) == self.path: self.marker.write_bytes(b"concurrent marker")
        with mock.patch.object(repair.os, "replace", side_effect=raced):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), b"concurrent marker")

    def test_native_v11_restore_upgrade_and_current_roundtrip(self):
        location = os.environ.get("CEF_REPAIR_RECIPE_DIR")
        if not location:
            self.skipTest("Pinned native checkpoint recipe not supplied")
        path = Path(location) / "vcpkg/static/checkpoint.py"
        spec = importlib.util.spec_from_file_location("inline_checkpoint_fixture", path)
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {"schema": 3, "platform": "windows-x64", "recipe": "unchanged-recipe",
                    "build_contract": repair.V11_KEY, "work": str(self.work)}
        old = self.work.parent / "old-checkpoint"
        new = self.work.parent / "new-checkpoint"
        codec.save(self.work, old, identity)
        saved = (old / "checkpoint.json").read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), "upgraded-v11")
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual((old / "checkpoint.json").read_bytes(), saved)
        self.assertFalse(json.loads((new / "checkpoint.json").read_text())["engine_runtime_verified"])

    @unittest.skipIf(os.name == "nt", "Unix Ninja dependency proof; Windows native probe is required separately")
    def test_ninja_rebuilds_changed_header_dependents_not_other_objects(self):
        ninja, clang = shutil.which("ninja"), shutil.which("clang++")
        if not ninja or not clang: self.skipTest("Native Ninja and Clang required")
        self.root = self.work.parent / "native"
        include = InlineEmptyRepairTests.headers(self)
        build = self.root / "build"; build.mkdir()
        generator = build / "generate.py"
        generator.write_text("import sys\nfrom pathlib import Path\nsys.path.insert(0, " + repr(str(ROOT)) + ")\n"
            "from tests.test_cef_windows_inline_empty_repair import probe\n"
            "Path('probe.cc').write_text(probe(Path(sys.argv[1]).read_bytes()))\n")
        (build / "other.cc").write_text("int untouched() { return 47; }\n")
        def esc(path): return str(path).replace("$", "$$").replace(" ", "$ ").replace(":", "$:")
        (build / "build.ninja").write_text(
            'rule gen\n  command = "' + sys.executable + '" generate.py $in\n'
            'rule cxx\n  command = "' + clang + '" -std=c++20 -pthread -I"' + str(include) + '" -c $in -o $out\n'
            'build probe.cc: gen ' + esc(self.path) + '\n'
            'build probe.o: cxx probe.cc\nbuild other.o: cxx other.cc\n')
        def run():
            result = subprocess.run([ninja], cwd=build, capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        run()
        before = {name: ((build/name).read_bytes(), (build/name).stat().st_mtime_ns) for name in ("probe.o", "other.o")}
        self.apply(); run()
        self.assertGreater((build/"probe.o").stat().st_mtime_ns, before["probe.o"][1])
        self.assertEqual(((build/"other.o").read_bytes(), (build/"other.o").stat().st_mtime_ns), before["other.o"])
        repair.apply(self.work, self.key, "resume")
        self.assertIn("no work to do", run().stdout)
