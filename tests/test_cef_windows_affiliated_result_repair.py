"""Pinned in-place variant binding for move-only credential results.

An isolated native STL/binding-trait probe runs the exact public closure
expression. Small callback/credential adapters are not CEF runtime proof.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_affiliated_inputs import AFFILIATED_MATCH, BIND_INTERNAL, CREDENTIAL, public_input
from tests.test_cef_windows_frame_tree_iterator_repair import populate_v16


def native_probe(raw):
    begin = b'  base::OnceClosure on_get_all_realms(\n'
    end = b'  base::RepeatingClosure barrier_closure = base::BarrierClosure(\n'
    if raw.count(begin) != 1 or raw.count(end) != 1:
        raise ValueError('Unexpected exact public closure boundaries')
    closure = raw[raw.index(begin):raw.index(end)].decode()
    credential = public_input(CREDENTIAL)
    first = b'  StoredCredential();\n'
    last = b'  ~StoredCredential();\n'
    if credential.count(first) != 1 or credential.count(last) != 1:
        raise ValueError('Unexpected exact public credential constructors')
    declarations = credential[credential.index(first):credential.index(last) + len(last)].decode()
    bind = public_input(BIND_INTERNAL)
    begin_trait = b'template <int i>\nstruct BindArgument {\n'
    end_trait = b'\n// Helper to assert that parameter `i` of type `Arg` can be bound'
    if bind.count(begin_trait) != 1 or bind.count(end_trait) != 1:
        raise ValueError('Unexpected pinned BindArgument trait boundaries')
    traits = bind[bind.index(begin_trait):bind.index(end_trait)].decode()
    prefix = r'''
#include <cassert>
#include <concepts>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>
struct StoredCredential {
'''
    prefix += declarations
    prefix += r'''
  std::unique_ptr<int> value;
  static inline int live=0, moves=0;
};
StoredCredential::StoredCredential() : value(std::make_unique<int>(0)) { ++live; }
StoredCredential::StoredCredential(StoredCredential&& other) : value(std::move(other.value)) { ++moves; }
StoredCredential& StoredCredential::operator=(StoredCredential&& other) {
  if(value) --live;
  value=std::move(other.value);++moves;return *this;
}
StoredCredential::~StoredCredential() { if(value) --live; }
static_assert(!std::is_copy_constructible_v<StoredCredential>);
using LoginsResult = std::vector<StoredCredential>;
struct PasswordStoreBackendError { int code; };
using LoginsResultOrError = std::variant<LoginsResult,PasswordStoreBackendError>;
namespace base {
template<class T> inline constexpr bool IsRawPtr=false;
template<class T> inline constexpr bool IsRawPtrMayDangle=false;
template<class T> inline constexpr bool IsUnretainedMayDangle=false;
template<class T,class U> inline constexpr bool UnretainedAndRawPtrHaveCompatibleTraits=false;
'''
    prefix += traits
    prefix += r'''
template<class Signature> using OnceCallback = std::function<Signature>;
struct OnceClosure {
  struct State {
    OnceCallback<void(LoginsResultOrError)> callback;
    LoginsResultOrError result;
    State(OnceCallback<void(LoginsResultOrError)> cb,LoginsResultOrError value)
        : callback(std::move(cb)),result(std::move(value)) {}
  };
  std::unique_ptr<State> state;
  OnceClosure(OnceCallback<void(LoginsResultOrError)> cb,LoginsResultOrError value)
      : state(std::make_unique<State>(std::move(cb),std::move(value))) {}
  void Run() && {
    assert(state);
    auto taken=std::move(state);
    taken->callback(std::move(taken->result));
  }
};
template<class Arg> OnceClosure BindOnce(OnceCallback<void(LoginsResultOrError)> callback,Arg value) {
  // Instantiate the verbatim pinned Chromium forwarding diagnostics, including
  // the lvalue convertibility control that triggers MSVC's variant resolver.
  using Forwarded=typename BindArgument<0>::template ForwardedAs<Arg&&>::template ToParamWithType<LoginsResultOrError>;
  static_assert(Forwarded::kCanBeForwardedToBoundFunctor);
  static_assert(!Forwarded::kIsUnwrappedForwardableNonConstReference);
  static_assert(Forwarded::kWouldBeForwardableWithPassed);
  return OnceClosure(std::move(callback),LoginsResultOrError(std::move(value)));
}
}
int main() {
  int calls=0;
  {
    LoginsResult forms;
    forms.reserve(3);
    for(int i=0;i<3;++i) { forms.emplace_back();*forms.back().value=i; }
    StoredCredential* original=forms.data();
    base::OnceCallback<void(LoginsResultOrError)> result_callback=[&](LoginsResultOrError result) {
      ++calls;
      assert(std::holds_alternative<LoginsResult>(result));
      const auto& received=std::get<LoginsResult>(result);
      assert(received.size()==3 && received.data()==original);
      assert(*received[0].value==17 && *received[1].value==29 && *received[2].value==2);
      assert(StoredCredential::moves==0 && StoredCredential::live==3);
    };
'''
    suffix = r'''
    // Match the public method's Android-form pointers retained across binding
    // until affiliation injection completes and the barrier runs the callback.
    *original[0].value=17;
    *original[1].value=29;
    assert(calls==0 && StoredCredential::live==3);
    std::move(on_get_all_realms).Run();
    assert(calls==1 && StoredCredential::live==0);
  }
  assert(StoredCredential::live==0 && StoredCredential::moves==0);
}
'''
    return prefix + closure + suffix


class AffiliatedResultRepairTests(unittest.TestCase):
    def test_exact_public_source_and_only_typed_in_place_binding_changes(self):
        fixed = repair.transform(AFFILIATED_MATCH, repair.AFFILIATED_MATCH_SOURCE)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.AFFILIATED_MATCH_AFTER)
        old, new = repair.CORRECTIONS[18][3][0]
        self.assertEqual(fixed.replace(new, old, 1), AFFILIATED_MATCH)
        self.assertEqual(len(repair.CORRECTIONS), 23)
        self.assertIn(b'#include <variant>\n', AFFILIATED_MATCH)
        self.assertIn(b'StoredCredential(const StoredCredential&) = delete;', public_input(CREDENTIAL))
        self.assertEqual(repair.profile()['corrections'][:16], repair.v16_profile()['corrections'])

    def test_newline_idempotence_unreviewed_and_partial_inputs_rejected(self):
        for newline in (b'\n', b'\r\n'):
            raw = AFFILIATED_MATCH.replace(b'\n', newline)
            fixed = repair.transform(raw, repair.AFFILIATED_MATCH_SOURCE)
            self.assertEqual(repair.transform(fixed, repair.AFFILIATED_MATCH_SOURCE), fixed)
        for raw in (b'', AFFILIATED_MATCH + b'\n', AFFILIATED_MATCH.replace(b'\n', b'\r\n', 1),
                    AFFILIATED_MATCH.replace(b'std::move(forms)', b'forms')):
            with self.assertRaises(ValueError): repair.transform(raw, repair.AFFILIATED_MATCH_SOURCE)

    def test_native_windows_original_variant_failure_and_fixed_once_ownership(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(AFFILIATED_MATCH, repair.AFFILIATED_MATCH_SOURCE)
        with tempfile.TemporaryDirectory(prefix='affiliated-result-v19-') as folder:
            root = Path(folder).resolve()
            for label, raw in (('original', AFFILIATED_MATCH), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(raw), encoding='utf-8')
                result = subprocess.run(helper.command(source, exe), cwd=root,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original':
                    self.assertNotIn(result.returncode, (0, 90))
                    self.assertIn('construct_at', result.stdout + result.stderr)
                    self.assertIn('StoredCredential', result.stdout + result.stderr)
                    self.assertIn('deleted', result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_AFFILIATED_RESULT_V19_NATIVE windows_variant_failed=' + str(os.name == 'nt').lower()
              + ' original_variant_failed=true fixed_runs=true in_place=true move_only=true stable_form_pointers=true once=true'
                ' no_element_moves=true no_leaks=true public_blob=true edits=1'
                ' before_sha256=' + repair.AFFILIATED_MATCH_BEFORE + ' after_sha256=' + repair.AFFILIATED_MATCH_AFTER)


class V19TransitionTests(unittest.TestCase):
    def test_bad_final_source_precedes_any_write_and_final_race_blocks_marker(self):
        with tempfile.TemporaryDirectory(prefix='affiliated-transition-v19-') as folder:
            work = Path(folder).resolve() / 'work'
            populate_v16(work)
            path = work / repair.AFFILIATED_MATCH_SOURCE
            marker = work / repair.MARKER
            previous = marker.read_bytes()
            key = repair.build_key(repair.BASE_KEY)
            path.write_bytes(AFFILIATED_MATCH + b'\n')
            with mock.patch.object(repair.os, 'replace') as replace:
                with self.assertRaises(ValueError): repair.apply(work, key, 'upgrade-v16')
                replace.assert_not_called()
            path.write_bytes(AFFILIATED_MATCH)
            original = repair.os.replace
            def race(source, target):
                original(source, target)
                if Path(target) == path:
                    (work / repair.LOCK_MANAGER_HEADER).write_bytes(b'synthetic concurrent edit')
            with mock.patch.object(repair.os, 'replace', side_effect=race):
                with self.assertRaises(ValueError): repair.apply(work, key, 'upgrade-v16')
            self.assertEqual(marker.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
