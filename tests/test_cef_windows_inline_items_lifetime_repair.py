"""Pinned InlineItemsData empty OffsetMap lifetime regression and v13->v16 transition.

The native probe extracts InlineItemsData::OffsetMap verbatim from the pinned
public Chromium source and uses actual TextOffsetMap/NoDestructor headers.
Small adapters provide only DynamicTo routing and surrounding object storage;
this is not full Blink/Oilpan/CEF runtime qualification.
"""
from __future__ import annotations
import copy, hashlib, importlib.util, os, shutil, subprocess, tempfile, unittest
from pathlib import Path
from unittest import mock
from secure_release import cef_windows_source_repair as repair
from secure_release.crypto import canonical, parse
from tests.cef_windows_layout_inputs import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/cef-windows"
SOURCE = "third_party/blink/renderer/core/layout/inline/inline_items_data.cc"
PUBLIC_BLOB = "2431074856574bec84878e10c2bc2a5827da04bd"
NO_DESTRUCTOR_BLOB = "9c035c1b651f68f7da90bcc30b1ff81b56bcfee0"
TEXT_MAP_BLOB = "32760ad735c3fa50d5b383146c55fad91d011af9"

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def source_bytes():
    fixture = (FIXTURES / "inline_items_data.cc").read_bytes()
    root = os.environ.get("CEF_WINDOWS_INLINE_ITEMS_SOURCE_ROOT")
    if root and (Path(root) / SOURCE).read_bytes() != fixture:
        raise ValueError("Pinned public InlineItemsData source mismatch")
    if git_blob(fixture) != PUBLIC_BLOB:
        raise ValueError("Unreviewed InlineItemsData fixture")
    return fixture

def method(source):
    text = source.decode("utf-8")
    anchor = "const std::optional<TextOffsetMap>& InlineItemsData::OffsetMap() const {"
    if text.count(anchor) != 1:
        raise ValueError("Expected one exact InlineItemsData::OffsetMap method")
    start = text.index(anchor); cursor = text.index("{", start); depth = 0
    for end in range(cursor, len(text)):
        if text[end] == "{": depth += 1
        elif text[end] == "}":
            depth -= 1
            if depth == 0: return text[start:end + 1]
    raise ValueError("Unterminated public OffsetMap method")

def probe(source):
    text = source.decode("utf-8")
    count = text.count('#include "base/no_destructor.h"')
    if count not in (0, 1): raise ValueError("Unexpected NoDestructor include count")
    include = '#include "base/no_destructor.h"\n' if count else ""
    return r'''
#include "third_party/blink/renderer/platform/wtf/text/text_offset_map.h"
''' + include + r'''
#include <array>
#include <cassert>
#include <memory>
#include <optional>
#include <thread>
#include <type_traits>
namespace blink {
using Optional = std::optional<TextOffsetMap>;
struct InlineItemsDataWithOffsetMap;
struct InlineItemsData {
  const InlineItemsDataWithOffsetMap* with_offset_ = nullptr;
  const Optional& OffsetMap() const;
};
struct InlineItemsDataWithOffsetMap { Optional offset_map; };
template <class T> const T* DynamicTo(const InlineItemsData* value) {
  static_assert(std::is_same_v<T, InlineItemsDataWithOffsetMap>);
  return value->with_offset_;
}
''' + method(source) + r'''
static_assert(std::is_same_v<decltype(std::declval<const InlineItemsData&>().OffsetMap()), const Optional&>);
static_assert(!std::is_trivially_destructible_v<TextOffsetMap>);
}
int main() {
  using namespace blink;
  std::array<const Optional*, 8> observed{};
  std::array<std::thread, 8> threads;
  for (size_t i = 0; i < threads.size(); ++i) {
    threads[i] = std::thread([i, &observed] {
      InlineItemsData absent;
      for (int j = 0; j < 1000; ++j) {
        const Optional& value = absent.OffsetMap();
        assert(!value.has_value());
        if (j == 0) observed[i] = std::addressof(value);
        assert(observed[i] == std::addressof(value));
      }
    });
  }
  for (auto& thread : threads) thread.join();
  for (auto* p : observed) assert(p == observed[0]);
  InlineItemsData a, b;
  assert(std::addressof(a.OffsetMap()) == observed[0]);
  assert(std::addressof(b.OffsetMap()) == observed[0]);
  InlineItemsDataWithOffsetMap payload;
  InlineItemsData live; live.with_offset_ = &payload;
  const Optional& forwarded = live.OffsetMap();
  assert(std::addressof(forwarded) == std::addressof(payload.offset_map));
  assert(!forwarded);
  payload.offset_map.emplace();
  assert(forwarded.has_value() && forwarded->IsEmpty());
  assert(std::addressof(live.OffsetMap()) == std::addressof(payload.offset_map));
  payload.offset_map.reset();
  assert(!forwarded && !*observed[0]);
}
'''

def populate_v13(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative; path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 13 else raw)
    marker = {"schema": 1, "kind": "cef-windows-source-repair",
              "build_key": repair.V13_KEY, "source_repair": repair.v13_profile()}
    (work / repair.MARKER).write_bytes(canonical(marker) + b"\n")

class InlineItemsLifetimeTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="inline items lifetime "); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve(); self.old = source_bytes()
        self.fixed = repair.transform(self.old, repair.INLINE_ITEMS_SOURCE)

    def test_exact_public_source_and_three_narrow_edits(self):
        self.assertEqual(hashlib.sha256(self.old).hexdigest(), repair.INLINE_ITEMS_BEFORE)
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), repair.INLINE_ITEMS_AFTER)
        self.assertEqual(git_blob((FIXTURES / "no_destructor.h").read_bytes()), NO_DESTRUCTOR_BLOB)
        self.assertEqual(git_blob((FIXTURES / "text_offset_map.h").read_bytes()), TEXT_MAP_BLOB)
        reversed_source = self.fixed
        for before, after in reversed(repair.CORRECTIONS[13][3]):
            self.assertEqual(reversed_source.count(after), 1)
            reversed_source = reversed_source.replace(after, before, 1)
        self.assertEqual(reversed_source, self.old)
        self.assertIn("return with_offset->offset_map;", method(self.fixed))
        self.assertIn("return *kEmpty;", method(self.fixed))
        self.assertNotIn(b"Wno-", self.fixed); self.assertNotIn(b"#pragma", self.fixed)
        self.assertEqual(repair.profile()["id"], "windows-password-backend-error-nothrow-v20")
        self.assertEqual(len(repair.CORRECTIONS), 21)

    def test_idempotence_newlines_and_unreviewed_sources(self):
        for nl in (b"\n", b"\r\n"):
            raw = self.old.replace(b"\n", nl); changed = repair.transform(raw, repair.INLINE_ITEMS_SOURCE)
            self.assertEqual(repair.transform(changed, repair.INLINE_ITEMS_SOURCE), changed)
            self.assertEqual(changed.replace(b"\r\n", b"\n"), self.fixed)
        for raw in (b"", self.old + b"\n", self.old.replace(b"kEmpty", b"kOther"), self.old.replace(b"\n", b"\r\n", 1)):
            with self.assertRaises(ValueError): repair.transform(raw, repair.INLINE_ITEMS_SOURCE)

    def headers(self):
        include = self.root / "include"
        for name, relative in (("no_destructor.h", "base/no_destructor.h"),
                               ("text_offset_map.h", "third_party/blink/renderer/platform/wtf/text/text_offset_map.h")):
            path = include / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((FIXTURES / name).read_bytes())
        stubs = {
            "unicode/edits.h": "namespace icu { class Edits; }\n",
            "third_party/blink/renderer/platform/wtf/forward.h":
                "#include <cstdint>\n#include <cstddef>\n#include <iosfwd>\nnamespace blink { using wtf_size_t = uint32_t; }\n",
            "third_party/blink/renderer/platform/wtf/wtf_export.h": "#define WTF_EXPORT\n",
            "third_party/blink/renderer/platform/wtf/vector.h":
                "#include <vector>\nnamespace blink { template<class T> class Vector : public std::vector<T> { public: void Shrink(size_t n) { this->erase(this->begin() + n, this->end()); } }; }\n",
        }
        for relative, data in stubs.items():
            path = include / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(data)
        return include

    def command(self, include, source, output):
        if os.name == "nt":
            where = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
            clang = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/clang-cl.exe"
            self.assertTrue(where.is_file() and clang.is_file(), "Native Windows toolchain required")
            vs = Path(subprocess.check_output([str(where), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip())
            version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
            self.assertTrue(version.startswith("14.44."), version)
            batch = self.root / "compile.cmd"
            batch.write_text('@echo off\ncall "' + str(vs) + '/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\necho VCToolsVersion=%VCToolsVersion%\n'
                '"' + str(clang) + '" /nologo /std:c++20 /EHsc /W4 /WX -Werror -Wexit-time-destructors '
                '/I"' + str(include) + '" "' + str(source) + '" /Fe:"' + str(output) + '"\n', encoding="utf-8")
            return ["cmd.exe", "/d", "/c", str(batch)]
        clang = shutil.which("clang++"); self.assertTrue(clang, "Native regression requires Clang")
        return [clang, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-Wexit-time-destructors",
                "-pthread", "-I", str(include), str(source), "-o", str(output)]

    def test_native_strict_warning_reference_identity_and_threads(self):
        include = self.headers(); source = self.root / "probe.cc"; output = self.root / ("probe.exe" if os.name == "nt" else "probe")
        command = self.command(include, source, output)
        source.write_text(probe(self.old), encoding="utf-8")
        old = subprocess.run(command, cwd=self.root, capture_output=True, text=True, errors="replace", timeout=90)
        if os.name == "nt":
            self.assertNotEqual(old.returncode, 0, "Original Windows lifetime sentinel must fail strict warning")
            self.assertNotEqual(old.returncode, 90)
            self.assertIn("exit-time destructor", old.stdout + old.stderr)
            self.assertIn("kEmpty", old.stdout + old.stderr)
        else:
            # The production failure is a Windows/MSVC-ABI Clang warning. Linux
            # Clang is a portability control: the unchanged source must remain
            # valid rather than being forced to reproduce a platform warning.
            self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
            subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        source.write_text(probe(self.fixed), encoding="utf-8")
        fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True, errors="replace", timeout=90)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        print("CEF_INLINE_ITEMS_OFFSET_NATIVE original_failed="
              + str(old.returncode != 0).lower()
              + " strict_warning=true offset_passthrough=true const_reference=true threads=8")

class V13TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="v13 to v16 transition "); self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / "work"; populate_v13(self.work)
        self.path = self.work / repair.INLINE_ITEMS_SOURCE
        self.api_key = self.work / repair.API_KEY_HEADER
        self.credit_card = self.work / repair.CREDIT_CARD_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)
    def apply(self): return repair.apply(self.work, self.key, "upgrade-v13")

    def test_v13_selector_is_historical_not_current_migration(self):
        for stale in (repair.UPGRADE_V13, repair.UPGRADE_V11,
                      dict(repair.UPGRADE_V13, run=37405866769),
                      {"build_key": repair.V13_KEY}):
            with self.assertRaises(ValueError):
                repair.restore_contract(stale, repair.BASE_KEY)

    def test_prior_profile_is_independently_bound_to_v13(self):
        old = repair.v13_profile()
        digest = hashlib.sha256(canonical({"schema": 2, "base_build_key": repair.BASE_KEY, "source_repair": old})).hexdigest()
        self.assertEqual(digest, repair.V13_KEY); self.assertEqual(len(old["corrections"]), 13)
        self.assertEqual(repair.profile()["corrections"][:13], old["corrections"]); self.assertNotEqual(self.key, repair.V13_KEY)

    def test_v13_summary_cannot_authorize_current_transition(self):
        value = {"base_build_key": repair.BASE_KEY, "source_repair_verified": True,
                 "source_repair": repair.v13_profile()}
        with self.assertRaises(ValueError):
            repair.verify_summary(value, repair.UPGRADE_V13)

    def test_upgrade_preserves_previous_sources_objects_and_repeat_resume(self):
        obj = self.work / "out/keep.obj"; obj.parent.mkdir(); obj.write_bytes(b"compiled-v13")
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.work.rglob("*") if p.is_file()}
        self.assertEqual(self.apply(), "upgraded-v13")
        changed = {
            self.path: repair.INLINE_ITEMS_SOURCE,
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
        with self.assertRaises(ValueError): self.apply()

    def test_all_prior_sources_are_checked_before_write(self):
        old_marker = self.marker.read_bytes()
        for relative, _, _, _ in repair.CORRECTIONS[:13]:
            path = self.work / relative; fixed = path.read_bytes(); path.write_bytes(fixture_bytes(path.name))
            with mock.patch.object(repair.os, "replace") as replace:
                with self.assertRaises(ValueError): self.apply()
                replace.assert_not_called()
            self.assertEqual(self.marker.read_bytes(), old_marker); path.write_bytes(fixed)

    def test_partial_hardlink_and_races_fail_closed(self):
        raw = self.path.read_bytes(); old_marker = self.marker.read_bytes()
        self.path.write_bytes(repair.transform(raw, repair.INLINE_ITEMS_SOURCE))
        with self.assertRaises(ValueError): self.apply()
        self.path.write_bytes(raw)
        alias = self.work / "inline-items-alias.cc"; os.link(self.path, alias)
        with self.assertRaises(ValueError): self.apply()
        alias.unlink()
        original = repair.os.replace; prior = self.work / repair.DOM_HEADER
        def source_race(source, target):
            original(source, target)
            if Path(target) == self.path: prior.write_bytes(b"concurrent prior source")
        with mock.patch.object(repair.os, "replace", side_effect=source_race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_native_checkpoint_v13_to_v16_and_current_roundtrip(self):
        location = os.environ.get("CEF_REPAIR_RECIPE_DIR")
        if not location: self.skipTest("Pinned native checkpoint recipe not supplied")
        path = Path(location) / "vcpkg/static/checkpoint.py"
        spec = importlib.util.spec_from_file_location("inline_items_checkpoint_fixture", path)
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {"schema": 3, "platform": "windows-x64", "recipe": "unchanged-recipe",
                    "build_contract": repair.V13_KEY, "work": str(self.work)}
        old = self.work.parent / "old-checkpoint"; new = self.work.parent / "new-checkpoint"
        codec.save(self.work, old, identity); saved = (old / "checkpoint.json").read_bytes(); shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity); self.assertEqual(self.apply(), "upgraded-v13")
        codec.save(self.work, new, dict(identity, build_contract=self.key)); shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, "resume"), "already-applied")
        self.assertEqual((old / "checkpoint.json").read_bytes(), saved)
        self.assertFalse(__import__("json").loads((new / "checkpoint.json").read_text())["engine_runtime_verified"])

if __name__ == "__main__": unittest.main()
