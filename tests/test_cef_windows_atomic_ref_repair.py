"""Pinned V8 atomic-ref type: strict native warning and unchanged load semantics.

The full public header is hash-bound. The native probe extracts LoadEncoded
verbatim and uses real std::atomic_ref with a small HeapObjectHeader declaration,
not the rest of V8. This focused test is not full V8 or engine qualification.
"""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/cef-windows'
V8_COMMIT = '4323497a6a73839e6d5260f6acd7ec0212cb3321'
HEADER_BLOB = '0155cd6b559bb973df84fda22a7179960586c5b5'
OLD_V4 = '326368685e857c582ef20e47f09a420acaf698e37449a589345ae33907c6e761'
OLD = b'std::atomic_ref(const_cast<uint16_t&>(half)).load(memory_order)'
NEW = b'std::atomic_ref<uint16_t>(const_cast<uint16_t&>(half)).load(memory_order)'


def populate(work):
    for relative, _, _, _ in repair.CORRECTIONS:
        target = work / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((FIXTURES / target.name).read_bytes())


def probe_source(raw: bytes) -> str:
    text = raw.decode('utf-8')
    prefix = ('template <AccessMode mode, HeapObjectHeader::EncodedHalf part,\n'
              '          std::memory_order memory_order>\n')
    start = prefix + 'uint16_t HeapObjectHeader::LoadEncoded() const {'
    stop = prefix + 'void HeapObjectHeader::StoreEncoded('
    if text.count(start) != 1 or text.count(stop) != 1:
        raise ValueError('Expected the exact V8 LoadEncoded definition')
    method = text[text.index(start):text.index(stop)]
    return r'''
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>
namespace cppgc::internal {
enum class AccessMode { kNonAtomic, kAtomic };
// A focused declaration with the same two 16-bit fields and x64 padding.
struct HeapObjectHeader {
  enum class EncodedHalf : uint8_t { kLow, kHigh };
  template <AccessMode mode, EncodedHalf part,
            std::memory_order memory_order = std::memory_order_seq_cst>
  uint16_t LoadEncoded() const;
  uint32_t padding_ = 0;
  uint16_t encoded_high_ = 0;
  uint16_t encoded_low_ = 0;
};
''' + method + r'''
static_assert(sizeof(HeapObjectHeader) == 8);
static_assert(alignof(HeapObjectHeader) >= std::atomic_ref<uint16_t>::required_alignment);
static_assert(offsetof(HeapObjectHeader, encoded_high_) % std::atomic_ref<uint16_t>::required_alignment == 0);
static_assert(offsetof(HeapObjectHeader, encoded_low_) % std::atomic_ref<uint16_t>::required_alignment == 0);
static_assert(std::is_same_v<std::atomic_ref<uint16_t>::value_type, uint16_t>);
using Mode = AccessMode;
using Half = HeapObjectHeader::EncodedHalf;
static_assert(std::is_same_v<decltype(std::declval<const HeapObjectHeader&>().LoadEncoded<Mode::kAtomic, Half::kLow>()), uint16_t>);
static_assert(std::is_same_v<decltype(std::declval<const HeapObjectHeader&>().LoadEncoded<Mode::kNonAtomic, Half::kHigh>()), uint16_t>);
template <Mode mode, Half half, std::memory_order order>
void Check(const HeapObjectHeader& header, uint16_t expected) {
  assert((header.LoadEncoded<mode, half, order>() == expected));
}
template <Mode mode, Half half>
void CheckOrders(const HeapObjectHeader& header, uint16_t expected) {
  Check<mode, half, std::memory_order_relaxed>(header, expected);
  Check<mode, half, std::memory_order_acquire>(header, expected);
  Check<mode, half, std::memory_order_seq_cst>(header, expected);
}
}
int main() {
  using namespace cppgc::internal;
  HeapObjectHeader header;
  const HeapObjectHeader& view = header;
  const uint16_t cases[] = {0, 1, 0x7fff, 0x8000, 0xffff};
  for (const uint16_t value : cases) {
    header.encoded_low_ = value;
    header.encoded_high_ = static_cast<uint16_t>(value ^ 0xffffu);
    CheckOrders<Mode::kNonAtomic, Half::kLow>(view, value);
    CheckOrders<Mode::kNonAtomic, Half::kHigh>(view, header.encoded_high_);
    CheckOrders<Mode::kAtomic, Half::kLow>(view, value);
    CheckOrders<Mode::kAtomic, Half::kHigh>(view, header.encoded_high_);
  }
  header.encoded_high_ = 0;
  header.encoded_low_ = 0;
  int published = 0;
  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i) {
    readers.emplace_back([&] {
      while (view.LoadEncoded<Mode::kAtomic, Half::kHigh, std::memory_order_acquire>() == 0)
        std::this_thread::yield();
      // This non-atomic payload must be visible after the release/acquire pair.
      assert(published == 42);
      for (int j = 0; j < 2000; ++j) {
        assert((view.LoadEncoded<Mode::kAtomic, Half::kLow, std::memory_order_relaxed>() <= 4095));
        assert((view.LoadEncoded<Mode::kAtomic, Half::kLow, std::memory_order_acquire>() <= 4095));
        assert((view.LoadEncoded<Mode::kAtomic, Half::kLow, std::memory_order_seq_cst>() <= 4095));
      }
    });
  }
  std::thread writer([&] {
    published = 42;
    std::atomic_ref<uint16_t>(header.encoded_high_).store(1, std::memory_order_release);
    for (uint16_t i = 1; i <= 4095; ++i)
      std::atomic_ref<uint16_t>(header.encoded_low_).store(i, std::memory_order_relaxed);
  });
  writer.join();
  for (auto& reader : readers) reader.join();
  CheckOrders<Mode::kAtomic, Half::kLow>(view, 4095);
  CheckOrders<Mode::kNonAtomic, Half::kLow>(view, 4095);
}
'''


class AtomicRefRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='V8 atomic ref ')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.work = self.root / 'work'
        populate(self.work)
        self.path = self.work / repair.HEAP_HEADER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self, origin='legacy'):
        return repair.apply(self.work, self.key, origin)

    def test_exact_public_v8_blob_and_explicit_submodule_identity(self):
        raw = self.path.read_bytes()
        self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(), HEADER_BLOB)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), repair.HEAP_BEFORE)
        self.assertEqual(repair.profile()['v8_commit'], V8_COMMIT)
        self.assertEqual(repair.profile()['chromium_commit'], '79460ebecaa5625e57a5fb679a735659e73dc687')
        self.assertIn('/tests/fixtures/cef-windows/*.h text eol=lf', (ROOT/'.gitattributes').read_text())

    def test_only_template_argument_changes_not_constness_or_memory_order(self):
        raw = self.path.read_bytes()
        fixed = repair.transform(raw, repair.HEAP_HEADER)
        self.assertEqual(raw.count(OLD), 1)
        self.assertEqual(fixed, raw.replace(OLD, NEW, 1))
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.HEAP_AFTER)
        self.assertEqual(fixed.replace(NEW, OLD, 1), raw)
        for token in (b'const_cast<uint16_t&>(half)', b'.load(memory_order)', b'if constexpr (mode == AccessMode::kNonAtomic)'):
            self.assertEqual(fixed.count(token), raw.count(token))

    def test_newlines_idempotence_and_unreviewed_source_rejection(self):
        raw = self.path.read_bytes()
        for newline in (b'\n', b'\r\n'):
            old = raw.replace(b'\n', newline)
            fixed = repair.transform(old, repair.HEAP_HEADER)
            self.assertEqual(repair.transform(fixed, repair.HEAP_HEADER), fixed)
            self.assertEqual(fixed.count(b'\r\n'), fixed.count(b'\n') if newline == b'\r\n' else 0)
        for bad in (b'', raw+b'// drift', raw.replace(b'uint16_t', b'uint32_t'),
                    raw.replace(b'.load(memory_order)', b'.load(std::memory_order_relaxed)'),
                    raw.replace(b'\n', b'\r\n', 1), raw.replace(b'\n', b'\r')):
            with self.assertRaises(ValueError):
                repair.transform(bad, repair.HEAP_HEADER)

    def test_bad_fifth_file_leaves_prior_four_unchanged(self):
        paths = [self.work/c[0] for c in repair.CORRECTIONS[:4]]
        snapshot = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        self.path.write_bytes(b'unreviewed')
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(snapshot, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths})
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_fifth_hardlink_rejected_before_writes(self):
        os.link(self.path, self.root/'alias.h')
        raw = (self.work/repair.HEADER).read_bytes()
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.work/repair.HEADER).read_bytes(), raw)
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_fifth_replacement_race_cannot_publish_marker(self):
        original, seen = repair._path, 0
        def race(work, relative):
            nonlocal seen
            if relative == repair.HEAP_HEADER:
                seen += 1
                if seen == 2:
                    self.path.write_bytes(b'concurrent change')
            return original(work, relative)
        with mock.patch.object(repair, '_path', side_effect=race):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), b'concurrent change')
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_v4_and_failed39_are_not_migration_inputs(self):
        for selected in (dict(repair.LEGACY, build_key=OLD_V4),
                         dict(repair.LEGACY, run=37124575284),
                         dict(repair.LEGACY, run=37124575284, build_key=OLD_V4)):
            with self.assertRaises(ValueError):
                repair.restore_contract(selected, repair.BASE_KEY)
        self.assertEqual(repair.restore_contract(repair.LEGACY, repair.BASE_KEY), (repair.BASE_KEY, 'legacy'))
        self.assertNotEqual(self.key, OLD_V4)
        for relative, _, _, _ in repair.CORRECTIONS[:4]:
            p = self.work/relative
            p.write_bytes(repair.transform(p.read_bytes(), relative))
        with self.assertRaises(ValueError):
            self.apply()
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_resume_verifies_fifth_file_and_full_profile(self):
        self.apply()
        fixed = self.path.read_bytes()
        self.path.write_bytes((FIXTURES/'heap-object-header.h').read_bytes())
        with self.assertRaises(ValueError):
            self.apply('resume')
        self.path.write_bytes(fixed)
        self.assertEqual(self.apply('resume'), 'already-applied')
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True, 'source_repair': repair.profile()}
        repair.verify_summary(value, {'build_key': self.key})
        for field in ('v8_commit', 'corrections'):
            bad = copy.deepcopy(value)
            if field == 'corrections':
                bad['source_repair'][field].pop()
            else:
                bad['source_repair'][field] = '0'*40
            with self.assertRaises(ValueError):
                repair.verify_summary(bad, {'build_key': self.key})
        with mock.patch.object(repair, 'V8', '0'*40):
            self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_native_strict_ctad_and_atomic_load_semantics(self):
        source = self.root/'probe.cc'
        output = self.root/('probe.exe' if os.name == 'nt' else 'probe')
        if os.name == 'nt':
            vswhere = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
            self.assertTrue(vswhere.is_file(), 'Native MSVC toolchain required')
            vs = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
            clang = Path(os.environ.get('ProgramFiles', 'C:/Program Files'))/'LLVM/bin/clang-cl.exe'
            self.assertTrue(clang.is_file(), 'Native clang-cl required')
            batch = self.root/'compile.cmd'
            batch.write_text('@echo off\ncall "'+vs+'/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\n"'+str(clang)+'" /nologo /std:c++20 /EHsc /W4 /WX '
                '-Werror -Wctad-maybe-unsupported "'+str(source)+'" /Fe:"'+str(output)+'"\n')
            command = ['cmd.exe', '/d', '/c', str(batch)]
        else:
            clang = shutil.which('clang++')
            self.assertIsNotNone(clang, 'Native Clang required')
            command = [clang, '-std=c++20', '-Wall', '-Wextra', '-Werror', '-Wctad-maybe-unsupported',
                       '-pthread', str(source), '-o', str(output)]
        source.write_text(probe_source(self.path.read_bytes()))
        old = subprocess.run(command, cwd=self.root, text=True, capture_output=True, errors='replace', timeout=60)
        if os.name == 'nt':
            self.assertNotEqual(old.returncode, 0, 'MSVC STL must reproduce the CTAD diagnostic')
            self.assertNotEqual(old.returncode, 90)
            self.assertIn('-Wctad-maybe-unsupported', old.stdout+old.stderr)
            self.assertIn('atomic_ref', old.stdout+old.stderr)
        elif old.returncode:
            self.assertIn('-Wctad-maybe-unsupported', old.stdout+old.stderr)
        self.apply()
        source.write_text(probe_source(self.path.read_bytes()))
        fixed = subprocess.run(command, cwd=self.root, text=True, capture_output=True, errors='replace', timeout=60)
        self.assertEqual(fixed.returncode, 0, fixed.stdout+fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        print('CEF_ATOMIC_REF_VERIFIED old_warning='+str(old.returncode != 0)
              +' strict_ctad=true modes=2 halves=2 load_orders=3 release_acquire=true readers=4')
        if os.name != 'nt':
            sanitized = subprocess.run(command+['-fsanitize=address,undefined', '-fno-omit-frame-pointer'],
                cwd=self.root, text=True, capture_output=True, timeout=60)
            self.assertEqual(sanitized.returncode, 0, sanitized.stdout+sanitized.stderr)
            subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)

    @unittest.skipIf(os.name == 'nt', 'Native Unix Ninja header dependency regression')
    def test_header_edit_rebuilds_dependent_object_only(self):
        ninja, clang = shutil.which('ninja'), shutil.which('clang++')
        self.assertTrue(ninja and clang, 'Ninja and Clang required')
        build = self.root/'build'; build.mkdir()
        header = build/'heap_probe.h'
        header.write_text(probe_source(self.path.read_bytes()))
        (build/'dependent.cc').write_text('#include "heap_probe.h"\n')
        (build/'other.cc').write_text('int other(){return 0;}\n')
        (build/'build.ninja').write_text(
            f'rule cxx\n  command = "{clang}" -std=c++20 -MMD -MF $out.d -c $in -o $out\n'
            '  depfile = $out.d\n  deps = gcc\n'
            'build dependent.o: cxx dependent.cc\nbuild other.o: cxx other.cc\n')
        subprocess.run([ninja], cwd=build, capture_output=True, check=True, timeout=60)
        old = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in build.glob('*.o')}
        self.apply(); header.write_text(probe_source(self.path.read_bytes()))
        subprocess.run([ninja], cwd=build, capture_output=True, check=True, timeout=60)
        self.assertGreater((build/'dependent.o').stat().st_mtime_ns, old[build/'dependent.o'][1])
        self.assertEqual(((build/'other.o').read_bytes(), (build/'other.o').stat().st_mtime_ns), old[build/'other.o'])
        self.apply('resume')
        result = subprocess.run([ninja], cwd=build, capture_output=True, text=True, check=True, timeout=60)
        self.assertIn('no work to do', result.stdout)
