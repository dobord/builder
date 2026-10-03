"""Blink iterator completeness at Perfetto overload resolution, not engine proof.

Compile the exact pinned CodePointIterator header with narrow support shims.
The String begin/end declarations match pinned wtf_string.h (blob 4d799673...),
and the two unchanged Perfetto overloads are a licensed public excerpt. The
surrounding String/trace sink is a fixture, not full Blink/Perfetto. No ICU code
is executed: its declarations suffice because string tracing must win over
range iteration. Native Windows must reproduce the actual incomplete-return
error with its real std::begin; no replacement of namespace std is permitted.
"""
from __future__ import annotations

import copy
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

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/cef-windows'
OLD_V3 = 'ba9677c4828284049abb396ed382f5149a66298753b417b02f48463da7b45050'
INCLUDE = '#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"'
BLOBS = {
    'atomic_string.cc': '3a7563baa0b28ba2eb460eba254f3f42446272c2',
    'code_point_iterator.h': '685f494e6eb95508627b99fa8fa2b3fa91eaadb5',
    'perfetto_iterator_overloads.inc': 'e2dce53186d09969698b9b7fce11dd91275cce18',
}


def populate(work):
    for relative, _, _, _ in repair.CORRECTIONS:
        target = work / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((FIXTURES / target.name).read_bytes())


def probe_source(atomic: bytes) -> str:
    """Drive the include and the unchanged call from the actual source fixture."""
    text = atomic.decode('utf-8')
    body = re.findall(r'void AtomicString::WriteIntoTrace\(perfetto::TracedValue context\) const \{\n([^}]+)\}', text)
    if len(body) != 1 or text.count(INCLUDE) not in (0, 1):
        raise ValueError('Expected one unchanged AtomicString trace definition')
    return r'''
#include <cassert>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>
''' + (INCLUDE + '\n' if INCLUDE in text else '') + r'''
namespace perfetto {
struct TraceState { int strings = 0; int arrays = 0; int elements = 0; };
struct TracedValue {
  TraceState* state;
  struct Array {
    TraceState* state;
    template <class T> void Append(const T&) { ++state->elements; }
  };
  Array WriteArray() && { ++state->arrays; return {state}; }
};
namespace base {
template <int N> struct priority_tag : priority_tag<N-1> {};
template <> struct priority_tag<0> {};
}
template <class T> struct check_traced_value_support { using type = void; };
namespace internal {
#include "perfetto_iterator_overloads.inc"
}
template <class T> void WriteIntoTracedValue(TracedValue context, T&& value) {
  internal::WriteImpl(base::priority_tag<4>{}, context, std::forward<T>(value));
}
}
namespace blink {
class CodePointIterator;
class String {
 public:
  CodePointIterator begin() const;
  CodePointIterator end() const;
  void WriteIntoTrace(perfetto::TracedValue context) const {
    ++context.state->strings;
  }
};
class AtomicString {
 public:
  const String& GetString() const { return value_; }
  void WriteIntoTrace(perfetto::TracedValue context) const;
 private:
  String value_;
};
void AtomicString::WriteIntoTrace(perfetto::TracedValue context) const {
''' + body[0] + r'''
}
}
int main() {
  perfetto::TraceState state;
  const blink::AtomicString atom;
  atom.WriteIntoTrace({&state});
  assert(state.strings == 1 && state.arrays == 0);
  const blink::String string;
  perfetto::WriteIntoTracedValue({&state}, string);
  blink::String mutable_string;
  perfetto::WriteIntoTracedValue({&state}, mutable_string);
  assert(state.strings == 3 && state.arrays == 0);
  std::vector<int> controls{1, 2, 3};
  perfetto::WriteIntoTracedValue({&state}, controls);
  assert(state.strings == 3 && state.arrays == 1 && state.elements == 3);
}
'''


class IteratorRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='blink iterator ')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.work = self.root / 'work'
        populate(self.work)
        self.path = self.work / repair.ATOMIC_SOURCE
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self, origin='legacy'):
        return repair.apply(self.work, self.key, origin)

    def test_public_fixtures_are_exact_reviewed_blobs(self):
        for name, expected in BLOBS.items():
            raw = (FIXTURES / name).read_bytes()
            self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(), expected, name)
        self.assertIn('/tests/fixtures/cef-windows/*.inc text eol=lf', (ROOT/'.gitattributes').read_text())

    def test_only_one_include_and_no_tracing_or_flag_changes(self):
        original = self.path.read_bytes()
        fixed = repair.transform(original, repair.ATOMIC_SOURCE)
        self.assertEqual(hashlib.sha256(original).hexdigest(), repair.ATOMIC_BEFORE)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.ATOMIC_AFTER)
        self.assertEqual(fixed.replace((INCLUDE+'\n').encode(), b'', 1), original)
        self.assertEqual(fixed.count(INCLUDE.encode()), 1)
        self.assertNotIn(b'Wno-', fixed)
        self.assertNotIn(b'#pragma', fixed)
        self.assertIn('perfetto::WriteIntoTracedValue(std::move(context), GetString());', probe_source(fixed))

    def test_lf_crlf_idempotence_and_unreviewed_inputs(self):
        old = self.path.read_bytes()
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(old.replace(b'\n', newline), repair.ATOMIC_SOURCE)
            self.assertEqual(repair.transform(fixed, repair.ATOMIC_SOURCE), fixed)
            self.assertEqual(fixed.count(b'\r\n'), fixed.count(b'\n') if newline == b'\r\n' else 0)
        for invalid in (b'', old+b'// drift\n', old.replace(b'\n', b'\r\n', 1)):
            with self.assertRaises(ValueError):
                repair.transform(invalid, repair.ATOMIC_SOURCE)

    def test_bad_fourth_input_leaves_all_three_sources_unchanged(self):
        previous = [self.work / item[0] for item in repair.CORRECTIONS[:3]]
        snapshot = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in previous}
        self.path.write_bytes(b'unreviewed')
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(snapshot, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in previous})
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_fourth_hardlink_rejected_before_any_write(self):
        os.link(self.path, self.root/'alias.cc')
        before = (self.work/repair.HEADER).read_bytes()
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.work/repair.HEADER).read_bytes(), before)
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_partial_v3_and_failed38_cannot_be_migration_inputs(self):
        for selected in (dict(repair.LEGACY, build_key=OLD_V3),
                         dict(repair.LEGACY, run=37109359138),
                         dict(repair.LEGACY, run=37109359138, build_key=OLD_V3)):
            with self.assertRaises(ValueError):
                repair.restore_contract(selected, repair.BASE_KEY)
        self.assertNotEqual(self.key, OLD_V3)
        for relative, _, _, _ in repair.CORRECTIONS[:3]:
            p = self.work/relative
            p.write_bytes(repair.transform(p.read_bytes(), relative))
        with self.assertRaises(ValueError):
            self.apply()
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_resume_requires_fourth_source_and_complete_profile(self):
        self.apply()
        fixed = self.path.read_bytes()
        self.path.write_bytes((FIXTURES/'atomic_string.cc').read_bytes())
        with self.assertRaises(ValueError):
            self.apply('resume')
        self.path.write_bytes(fixed)
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True,
                 'source_repair': repair.profile()}
        repair.verify_summary(value, {'build_key': self.key})
        value['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError):
            repair.verify_summary(value, {'build_key': self.key})
        snapshot = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(self.apply('resume'), 'already-applied')
        self.assertEqual(snapshot, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in snapshot})

    def test_fourth_replacement_race_cannot_publish_marker(self):
        original = repair._path
        seen = 0
        def race(work, relative):
            nonlocal seen
            if relative == repair.ATOMIC_SOURCE:
                seen += 1
                if seen == 2:
                    self.path.write_bytes(b'concurrent source edit')
            return original(work, relative)
        with mock.patch.object(repair, '_path', side_effect=race):
            with self.assertRaises(ValueError):
                self.apply()
        self.assertEqual(self.path.read_bytes(), b'concurrent source edit')
        self.assertFalse((self.work/repair.MARKER).exists())

    def native_headers(self):
        include = self.root/'include'
        # Compile the actual iterator. Only its support dependencies are shimmed;
        # ICU functions are declarations and never execute in this trace test.
        files = {
            'unicode/utf16.h': '#pragma once\n#include <cstdint>\nvoid ProbeNext(const char16_t*,uint32_t&,uint32_t,int32_t&);\nvoid ProbeForward(const char16_t*,uint32_t&,uint32_t);\n#define U16_NEXT(s,i,n,c) ProbeNext(s,i,n,c)\n#define U16_FWD_1(s,i,n) ProbeForward(s,i,n)\n',
            'base/check_op.h': '#pragma once\n#include <cassert>\n#define CHECK_GE(a,b) assert((a)>=(b))\n#define CHECK_LE(a,b) assert((a)<=(b))\n#define DCHECK_EQ(a,b) assert((a)==(b))\n',
            'base/compiler_specific.h': '#pragma once\n#define UNSAFE_BUFFERS(...) __VA_ARGS__\n',
            'base/containers/span.h': '#pragma once\n#include <span>\nnamespace base { template<class T> using span=std::span<T>; }\n',
            'base/memory/stack_allocated.h': '#pragma once\n#define STACK_ALLOCATED() static_assert(true)\n',
            'base/numerics/safe_conversions.h': '#pragma once\nnamespace base { template<class D,class S> constexpr D checked_cast(S v){return static_cast<D>(v);} }\n',
            'base/types/to_address.h': '#pragma once\n#include <memory>\nnamespace base { using std::to_address; }\n',
            'third_party/blink/renderer/platform/wtf/forward.h': '#pragma once\n#include <cstdint>\nnamespace blink { using UChar=char16_t; using UChar32=int32_t; using wtf_size_t=uint32_t; }\n',
        }
        for name, text in files.items():
            p = include/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
        target = include/INCLUDE.split('"')[1]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((FIXTURES/'code_point_iterator.h').read_bytes())
        (include/'perfetto_iterator_overloads.inc').write_bytes((FIXTURES/'perfetto_iterator_overloads.inc').read_bytes())
        return include

    def test_native_std_begin_completeness_and_string_trace_priority(self):
        include = self.native_headers()
        source = self.root/'probe.cc'
        output = self.root/('probe.exe' if os.name == 'nt' else 'probe')
        if os.name == 'nt':
            vswhere = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
            self.assertTrue(vswhere.is_file(), 'Native MSVC toolchain required')
            vs = subprocess.check_output([str(vswhere), '-latest','-products','*','-requires',
                'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'], text=True).strip()
            clang = Path(os.environ.get('ProgramFiles','C:/Program Files'))/'LLVM/bin/clang-cl.exe'
            self.assertTrue(clang.is_file(), 'Native clang-cl required')
            batch = self.root/'compile.cmd'
            batch.write_text('@echo off\ncall "'+vs+'/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\n"'+str(clang)+'" /nologo /std:c++20 /EHsc /W4 /WX '
                '-Werror /I"'+str(include)+'" "'+str(source)+'" /Fe:"'+str(output)+'"\n')
            command = ['cmd.exe','/d','/c',str(batch)]
        else:
            clang = shutil.which('clang++')
            self.assertIsNotNone(clang, 'Native Clang required')
            command = [clang,'-std=c++20','-Wall','-Wextra','-Werror','-I',str(include),str(source),'-o',str(output)]
        source.write_text(probe_source(self.path.read_bytes()))
        old = subprocess.run(command, cwd=self.root, text=True, capture_output=True, errors='replace', timeout=60)
        if os.name == 'nt':
            self.assertNotEqual(old.returncode, 0, 'MSVC std::begin must reproduce missing complete type')
            self.assertNotEqual(old.returncode, 90)
            self.assertIn('incomplete return type', old.stdout+old.stderr)
            self.assertIn('CodePointIterator', old.stdout+old.stderr)
        elif old.returncode:
            self.assertIn('CodePointIterator', old.stdout+old.stderr)
        self.apply()
        source.write_text(probe_source(self.path.read_bytes()))
        fixed = subprocess.run(command, cwd=self.root, text=True, capture_output=True, errors='replace', timeout=60)
        self.assertEqual(fixed.returncode, 0, fixed.stdout+fixed.stderr)
        subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)
        print('CEF_ITERATOR_TRACE_VERIFIED old_error='+str(old.returncode != 0)+' actual_iterator_header=true string_priority=true container_control=true')
        if os.name != 'nt':
            sanitized = subprocess.run(command+['-fsanitize=address,undefined','-fno-omit-frame-pointer'],
                cwd=self.root, text=True, capture_output=True, timeout=60)
            self.assertEqual(sanitized.returncode, 0, sanitized.stdout+sanitized.stderr)
            subprocess.run([str(output)], cwd=self.root, check=True, capture_output=True, timeout=30)

    @unittest.skipIf(os.name == 'nt', 'Native Unix Ninja selective invalidation')
    def test_atomic_cpp_rebuilds_only_its_object(self):
        ninja, clang = shutil.which('ninja'), shutil.which('clang++')
        self.assertTrue(ninja and clang, 'Ninja and Clang required')
        include = self.native_headers()
        build = self.root/'build'; build.mkdir()
        source = build/'atomic.cc'
        source.write_text(probe_source(self.path.read_bytes()))
        (build/'other.cc').write_text('int other(){return 0;}\n')
        (build/'build.ninja').write_text(
            f'rule cxx\n  command = "{clang}" -std=c++20 -I"{include}" -c $in -o $out\n'
            'build atomic.o: cxx atomic.cc\nbuild other.o: cxx other.cc\n')
        subprocess.run([ninja],cwd=build,capture_output=True,check=True,timeout=60)
        previous = {p: (p.read_bytes(),p.stat().st_mtime_ns) for p in build.glob('*.o')}
        self.apply(); source.write_text(probe_source(self.path.read_bytes()))
        subprocess.run([ninja],cwd=build,capture_output=True,check=True,timeout=60)
        self.assertGreater((build/'atomic.o').stat().st_mtime_ns, previous[build/'atomic.o'][1])
        self.assertEqual(((build/'other.o').read_bytes(),(build/'other.o').stat().st_mtime_ns), previous[build/'other.o'])
        self.apply('resume')
        result = subprocess.run([ninja],cwd=build,capture_output=True,text=True,check=True,timeout=60)
        self.assertIn('no work to do', result.stdout)
