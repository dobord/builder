"""Verbatim public raw_ref comparator and const permission-source lookup regression."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_permission_inputs import HEADER, SOURCE_PATH, RAW_REF_PATH, public_input
from tests.test_cef_windows_backend_error_repair import populate_v19


def native_probe(header):
    declarations = re.findall(rb'  std::map<base::raw_ref<(?:const )?PermissionRequest>, PermissionRequestSource>\n'
                              rb'      request_sources_map_;\n', header)
    if len(declarations) != 1:
        raise ValueError('Unexpected public permission map declaration')
    raw = public_input(RAW_REF_PATH)
    first = b'template <typename T, base::RawPtrTraits Traits>\nstruct less<raw_ref<T, Traits>> {\n'
    last = b'\n// Specialize std::pointer_traits.'
    if raw.count(first) != 1 or raw.count(last) != 1:
        raise ValueError('Unexpected public raw_ref comparator boundaries')
    comparator = raw[raw.index(first):raw.index(last)].decode()
    source = public_input(SOURCE_PATH)
    start = b'  const auto iter = request_sources_map_.find(request);\n'
    if source.count(start) != 1:
        raise ValueError('Unexpected public const lookup expression')
    offset = source.index(start)
    end = source.index(b'  return false;\n}', offset) + len(b'  return false;\n}')
    body = source[offset:end].decode()
    prefix = r'''
#include <cassert>
#include <concepts>
#include <functional>
#include <map>
#include <memory>
#include <type_traits>
#include <vector>
namespace base {
enum class RawPtrTraits { kEmpty };
template<class T,RawPtrTraits Traits=RawPtrTraits::kEmpty> class raw_ref {
  T* ptr_;
 public:
  struct Impl { static void IncrementLessCountForTest() {} };
  explicit raw_ref(T& value) : ptr_(std::addressof(value)) {}
  template<class U,RawPtrTraits Other> requires std::convertible_to<U*,T*>
  raw_ref(const raw_ref<U,Other>& other) : ptr_(std::addressof(other.get())) {}
  T& get() const { return *ptr_; }
  friend bool operator<(const raw_ref& lhs,const raw_ref& rhs) {
    return std::less<const void*>{}(lhs.ptr_,rhs.ptr_);
  }
  friend bool operator<(T& lhs,const raw_ref& rhs) {
    return std::less<const void*>{}(std::addressof(lhs),rhs.ptr_);
  }
  friend bool operator<(const raw_ref& lhs,T& rhs) {
    return std::less<const void*>{}(lhs.ptr_,std::addressof(rhs));
  }
};
template<class T> raw_ref(T&)->raw_ref<T>;
}
using base::raw_ref;
namespace std {
'''
    prefix += comparator + '}\n'
    prefix += r'''
struct PermissionRequest { int value; };
struct PermissionRequestSource {
  bool inactive;
  bool IsSourceFrameInactiveAndDisallowActivation() const { return inactive; }
};
struct Manager {
'''
    prefix += declarations[0].decode()
    prefix += '  bool Query(const PermissionRequest& request) const {\n' + body + '\n};\n'
    return prefix + r'''
int main() {
  PermissionRequest first{1}, second{1}, missing{1};
  Manager manager;
  assert(!manager.Query(missing));
  manager.request_sources_map_.emplace(first,PermissionRequestSource{false});
  manager.request_sources_map_.emplace(second,PermissionRequestSource{true});
  const PermissionRequest& const_first=first;
  const PermissionRequest& const_second=second;
  assert(manager.Query(const_first));
  assert(!manager.Query(const_second));
  assert(!manager.Query(missing)); // Address identity, not equal object values.
  assert(manager.request_sources_map_.size()==2);
  manager.request_sources_map_.emplace(first,PermissionRequestSource{true});
  assert(manager.request_sources_map_.size()==2 && manager.Query(first));
  using Key=typename decltype(manager.request_sources_map_)::key_type;
  Key retained(first);
  assert(std::addressof(retained.get())==std::addressof(first));
  assert(manager.request_sources_map_.erase(base::raw_ref(first))==1);
  assert(!manager.Query(first));
  manager.request_sources_map_.emplace(first,PermissionRequestSource{false});
  assert(manager.Query(first));
  std::vector<base::raw_ref<PermissionRequest>> validated;
  validated.emplace_back(first);
  validated[0].get().value=42; // Mutable request-management references are unchanged.
  assert(first.value==42);
  assert(manager.request_sources_map_.erase(base::raw_ref(second))==1);
  assert(manager.request_sources_map_.erase(retained)==1);
  assert(manager.request_sources_map_.empty());
}
'''


class PermissionSourceRepairTests(unittest.TestCase):
    def test_exact_header_and_only_source_map_key_becomes_const(self):
        fixed = repair.transform(HEADER, repair.PERMISSION_MANAGER_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.PERMISSION_MANAGER_AFTER)
        old, new = repair.CORRECTIONS[21][3][0]
        self.assertEqual(fixed.replace(new, old, 1), HEADER)
        self.assertIn(b'std::vector<base::raw_ref<PermissionRequest>> validated_requests_;', fixed)
        self.assertEqual(len(repair.CORRECTIONS), 22)
        self.assertEqual(repair.profile()['corrections'][:19], repair.v19_profile()['corrections'])

    def test_native_original_const_lookup_failure_and_fixed_identity_erasure(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(HEADER, repair.PERMISSION_MANAGER_HEADER)
        with tempfile.TemporaryDirectory(prefix='permission-source-v21-') as folder:
            root = Path(folder).resolve()
            for label, raw in (('original', HEADER), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(raw), encoding='utf-8')
                result = subprocess.run(helper.command(source, exe), cwd=root,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original':
                    self.assertNotIn(result.returncode, (0, 90))
                    self.assertIn('PermissionRequest', result.stdout + result.stderr)
                    self.assertIn('const', result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_PERMISSION_SOURCE_V21_NATIVE original_failed=true fixed_runs=true const_lookup=true'
              ' address_identity=true mutable_erasure=true mutable_request_refs=true comparator_verbatim=true edits=1 public_blob=true'
              ' before_sha256=' + repair.PERMISSION_MANAGER_BEFORE + ' after_sha256=' + repair.PERMISSION_MANAGER_AFTER)

    def test_newlines_idempotence_and_unreviewed_inputs_rejected(self):
        for newline in (b'\n', b'\r\n'):
            raw = HEADER.replace(b'\n', newline)
            fixed = repair.transform(raw, repair.PERMISSION_MANAGER_HEADER)
            self.assertEqual(repair.transform(fixed, repair.PERMISSION_MANAGER_HEADER), fixed)
        for raw in (b'', HEADER + b'\n', HEADER.replace(b'\n', b'\r\n', 1)):
            with self.assertRaises(ValueError): repair.transform(raw, repair.PERMISSION_MANAGER_HEADER)

    def test_invalid_last_source_precedes_all_writes(self):
        with tempfile.TemporaryDirectory(prefix='permission-transition-v21-') as folder:
            work = Path(folder).resolve() / 'work'
            populate_v19(work)
            path = work / repair.PERMISSION_MANAGER_HEADER
            marker = work / repair.MARKER
            previous = marker.read_bytes()
            path.write_bytes(HEADER + b'\n')
            with mock.patch.object(repair.os, 'replace') as replace:
                with self.assertRaises(ValueError): repair.apply(work, repair.build_key(repair.BASE_KEY), 'upgrade-v19')
                replace.assert_not_called()
            self.assertEqual(marker.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
