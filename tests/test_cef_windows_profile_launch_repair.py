"""Pinned raw_ptr comparison and profile-set const lookup/activation regression."""
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
from tests.cef_windows_profile_launch_inputs import HEADER, RAW_PTR_PATH, SOURCE_PATH, public_input
from tests.test_cef_windows_vertical_tab_math_repair import populate_v23


def native_probe(header):
    declarations = re.findall(rb'  std::set<raw_ptr<Profile, SetExperimental>(?:, std::less<>)?> '
                              rb'(?:launched_profiles_|opened_profiles_);\n', header)
    if len(declarations) != 2:
        raise ValueError('Unexpected public profile-set declarations')
    raw = public_input(RAW_PTR_PATH)
    start = b'template <typename T, base::RawPtrTraits Traits>\nstruct less<raw_ptr<T, Traits>> {\n'
    end = b'\n// Override so flat_hash_set/flat_hash_map lookups'
    if raw.count(start) != 1 or raw.count(end) != 1:
        raise ValueError('Unexpected public raw_ptr comparator boundaries')
    comparator = raw[raw.index(start):raw.index(end)].decode()
    first = b'  // Comparisons with U*. These operators also handle the case where the RHS is\n'
    last = b'  // Comparisons with `std::nullptr_t`.\n'
    if raw.count(first) != 1 or raw.count(last) != 1:
        raise ValueError('Unexpected public pointer comparison operator boundaries')
    operators = raw[raw.index(first):raw.index(last)].decode()
    source = public_input(SOURCE_PATH)
    expression = b'  return opened_profiles_.contains(profile) &&\n         launched_profiles_.contains(profile);\n'
    if source.count(expression) != 1:
        raise ValueError('Unexpected public const profile lookup')
    prefix = r'''
#include <cassert>
#include <compare>
#include <functional>
#include <set>
#include <type_traits>
#define PA_ALWAYS_INLINE inline
#define PA_HAVE_SPACESHIP_OPERATOR 1
namespace base { enum class RawPtrTraits { kEmpty, kMayDangle }; }
inline constexpr auto SetExperimental=base::RawPtrTraits::kMayDangle;
template<class T,base::RawPtrTraits Traits=base::RawPtrTraits::kEmpty> class raw_ptr {
  T* ptr_;
 public:
  struct Impl { static void IncrementLessCountForTest() {} };
  constexpr raw_ptr(T* ptr) : ptr_(ptr) {}
  constexpr operator T*() const { return ptr_; }
  constexpr T* GetForComparison() const { return ptr_; }
  friend constexpr auto operator<=>(const raw_ptr& lhs,const raw_ptr& rhs) {
    return lhs.GetForComparison()<=>rhs.GetForComparison();
  }
'''
    prefix += operators + '};\nnamespace std {\n' + comparator + '}\n'
    prefix += 'struct Profile { int activated=0; };\nstruct Observer {\n'
    prefix += b''.join(declarations).decode()
    prefix += '  bool Query(const Profile* profile) const {\n' + expression.decode() + '  }\n};\n'
    return prefix + r'''
void Activate(Profile* profile) { ++profile->activated; }
int main() {
  Profile first, second, missing;
  Observer observer;
  using Key=typename decltype(observer.launched_profiles_)::key_type;
  static_assert(std::is_same_v<Key,raw_ptr<Profile,SetExperimental>>);
  assert(!observer.Query(&missing));
  observer.launched_profiles_.insert(&first);
  assert(!observer.Query(&first));
  observer.opened_profiles_.insert(&first);
  const Profile* const_first=&first;
  assert(observer.Query(const_first));
  observer.opened_profiles_.insert(&second);
  assert(!observer.Query(&second));
  observer.launched_profiles_.insert(&second);
  assert(observer.Query(&second));
  assert(!observer.Query(&missing));
  observer.launched_profiles_.insert(&first);
  assert(observer.launched_profiles_.size()==2);
  for(const auto& profile : observer.launched_profiles_) {
    assert(observer.opened_profiles_.find(profile)!=observer.opened_profiles_.end());
    Activate(profile); // Activation still receives a mutable Profile*.
  }
  assert(first.activated==1 && second.activated==1);
  observer.launched_profiles_.erase(&first);
  observer.opened_profiles_.erase(&first);
  assert(!observer.Query(const_first));
  observer.launched_profiles_.clear();observer.opened_profiles_.clear();
  assert(observer.launched_profiles_.empty() && observer.opened_profiles_.empty());
}
'''


class ProfileLaunchRepairTests(unittest.TestCase):
    def test_exact_public_header_and_only_comparators_and_direct_include_change(self):
        fixed = repair.transform(HEADER, repair.PROFILE_LAUNCH_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.PROFILE_LAUNCH_AFTER)
        for old, new in reversed(repair.CORRECTIONS[25][3]):
            fixed = fixed.replace(new, old, 1)
        self.assertEqual(fixed, HEADER)
        self.assertEqual(len(repair.CORRECTIONS), 27)
        self.assertEqual(repair.profile()['corrections'][:24], repair.v23_profile()['corrections'])

    def test_native_original_const_lookup_failure_fixed_traits_and_mutable_activation(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(HEADER, repair.PROFILE_LAUNCH_HEADER)
        with tempfile.TemporaryDirectory(prefix='profile-launch-v25-') as folder:
            root = Path(folder).resolve()
            for label, raw in (('original', HEADER), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(raw), encoding='utf-8')
                result = subprocess.run(helper.command(source, exe), cwd=root,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original':
                    self.assertNotIn(result.returncode, (0, 90))
                    self.assertIn('Profile', result.stdout + result.stderr)
                    self.assertIn('const', result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_PROFILE_LAUNCH_V25_NATIVE original_failed=true fixed_runs=true const_lookup=true key_type_unchanged=true'
              ' dangling_traits_preserved=true mutable_activation=true mutable_insert_erase=true both_sets=true public_comparisons=true edits=3 public_blob=true'
              ' before_sha256=' + repair.PROFILE_LAUNCH_BEFORE + ' after_sha256=' + repair.PROFILE_LAUNCH_AFTER)

    def test_newlines_idempotence_and_partial_inputs_rejected(self):
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(HEADER.replace(b'\n', newline), repair.PROFILE_LAUNCH_HEADER)
            self.assertEqual(repair.transform(fixed, repair.PROFILE_LAUNCH_HEADER), fixed)
        for invalid in (b'', HEADER + b'\n', HEADER.replace(b'\n', b'\r\n', 1),
                        HEADER.replace(*repair.CORRECTIONS[25][3][1], 1)):
            with self.assertRaises(ValueError): repair.transform(invalid, repair.PROFILE_LAUNCH_HEADER)

    def test_invalid_last_source_precedes_all_writes(self):
        with tempfile.TemporaryDirectory(prefix='profile-transition-v25-') as folder:
            work = Path(folder).resolve() / 'work'
            populate_v23(work)
            marker = work / repair.MARKER
            previous = marker.read_bytes()
            (work / repair.PROFILE_LAUNCH_HEADER).write_bytes(HEADER + b'\n')
            with mock.patch.object(repair.os, 'replace') as replace:
                with self.assertRaises(ValueError): repair.apply(work, repair.build_key(repair.BASE_KEY), 'upgrade-v23')
                replace.assert_not_called()
            self.assertEqual(marker.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
