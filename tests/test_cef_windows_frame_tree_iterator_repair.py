"""Exact public NodeIterator declaration and authenticated V16-to-V17 transition.

The native probe compiles the verbatim public NodeIterator declaration with small
raw_ptr/deque/node adapters. It is an iterator regression, NOT full CEF runtime
qualification. Production compiler flags and the private codec are unchanged.
"""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from secure_release.crypto import canonical, parse
from tests.cef_windows_layout_inputs import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cef-windows/frame_tree.h'
PUBLIC_SOURCE = 'content/browser/renderer_host/frame_tree.h'
PUBLIC_BLOB = '2259ef06982e610888fcf35a5dd293bdfa38f5fe'
BEFORE = '6dff457016eb06cc710a53012c80884d089665bbf1346cf8933b4535c060b17f'
AFTER = '968192391f2275c7732e37b1547261e01a424df9633db7e1993d1ff899ecbd77'


def source_bytes():
    data = FIXTURE.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if blob != PUBLIC_BLOB or hashlib.sha256(data).hexdigest() != BEFORE:
        raise ValueError('Exact pinned frame-tree fixture mismatch')
    location = os.environ.get('CEF_WINDOWS_FRAME_TREE_SOURCE_ROOT')
    if location and (Path(location) / PUBLIC_SOURCE).read_bytes() != data:
        raise ValueError('Pinned public checkout differs from frame-tree fixture')
    return data


def class_block(data, name, next_name):
    start = ('  class CONTENT_EXPORT ' + name + ' {\n').encode()
    end = ('\n  class CONTENT_EXPORT ' + next_name + ' {').encode()
    if data.count(start) != 1 or data.count(end) != 1:
        raise ValueError('Unexpected public class boundaries')
    return data[data.index(start):data.index(end, data.index(start))]


def native_probe(data, fixed, mode):
    """Use the exact declaration, not a separately rewritten iterator type."""
    block = class_block(data, 'NodeIterator', 'NodeRange').decode()
    # These two macros have no bearing on copy assignment. Their original
    # occurrences, field types, queue member and declaration order remain exact.
    prefix = r'''
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <deque>
#include <iterator>
#include <memory>
#include <type_traits>
#include <vector>
#define CONTENT_EXPORT
#define RAW_PTR_EXCLUSION
inline constexpr int DanglingUntriaged = 0;
template<class T, int = 0> using raw_ptr = T*;
namespace base { template<class T> using circular_deque = std::deque<T>; }
struct FrameTreeNode { int value; };
class FrameTree {
 public:
  class NodeRange;
'''
    body = r'''
  class NodeRange {
   public:
    static NodeIterator Make(const std::vector<FrameTreeNode*>& nodes,
        const FrameTreeNode* root, bool descend, bool include) {
      return NodeIterator(nodes, root, descend, include);
    }
    static bool Policy(const NodeIterator& it, const FrameTreeNode* root,
                       bool descend, bool include) {
      return it.root_of_subtree_to_skip_ == root &&
             it.should_descend_into_inner_trees_ == descend &&
             it.include_delegate_nodes_for_inner_frame_trees_ == include;
    }
  };
};
using Iterator = FrameTree::NodeIterator;
using Range = FrameTree::NodeRange;
FrameTree::NodeIterator::NodeIterator(const NodeIterator&) = default;
FrameTree::NodeIterator::~NodeIterator() = default;
FrameTree::NodeIterator::NodeIterator(
    const std::vector<raw_ptr<FrameTreeNode, DanglingUntriaged>>& nodes,
    const FrameTreeNode* root, bool descend, bool include)
    : current_node_(nullptr), root_of_subtree_to_skip_(root),
      should_descend_into_inner_trees_(descend),
      include_delegate_nodes_for_inner_frame_trees_(include),
      queue_(nodes.begin(), nodes.end()) { AdvanceNode(); }
void FrameTree::NodeIterator::AdvanceNode() {
  if (queue_.empty()) { current_node_ = nullptr; }
  else { current_node_ = queue_.front(); queue_.pop_front(); }
}
Iterator& FrameTree::NodeIterator::operator++() { AdvanceNode(); return *this; }
Iterator& FrameTree::NodeIterator::AdvanceSkippingChildren() {
  AdvanceNode(); return *this;
}
bool FrameTree::NodeIterator::operator==(const NodeIterator& rhs) const {
  return current_node_ == rhs.current_node_;
}
static_assert(std::is_copy_constructible_v<Iterator>);
static_assert(std::is_same_v<typename std::iterator_traits<Iterator>::iterator_category,
                           std::forward_iterator_tag>);
'''
    body += 'static_assert(std::is_copy_assignable_v<Iterator> == ' + str(fixed).lower() + ');\n'
    if mode == 'traits':
        return prefix + block + body + 'int main() { return 0; }\n'
    main = r'''
int main() {
  FrameTreeNode a{1}, b{2}, c{3};
  auto begin = Range::Make({&a, &b, &c}, &a, true, false);
  auto end = Range::Make({}, &a, true, false);
  assert(Range::Policy(begin, &a, true, false));
  auto found = std::find_if(begin, end, [](FrameTreeNode* n) { return n->value == 2; });
  assert(found != end && *found == &b);
  assert(*begin == &a);  // Searching a copied iterator must not advance begin.
  assert(std::find_if(begin, end, [](FrameTreeNode* n) { return n->value == 9; }) == end);
'''
    if fixed:
        main += r'''
  auto assigned = Range::Make({}, &c, false, true);
  assigned = found;
  assert(Range::Policy(assigned, &a, true, false));
  assert(*assigned == &b);
  ++assigned;
  assert(*assigned == &c && *found == &b);  // Independent copied queue.
  auto const* alias = std::addressof(assigned);
  assigned = *alias;  // Self-assignment through an alias, without a warning suppression.
  assert(*assigned == &c);
  ++assigned;
  assert(assigned == end);
'''
    return prefix + block + body + main + '  return 0;\n}\n'


class FrameTreeRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='frame-tree-native-')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.old = source_bytes()
        self.fixed = repair.transform(self.old, repair.FRAME_TREE_HEADER)

    def test_exact_blob_digests_and_only_four_source_edits(self):
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), AFTER)
        self.assertEqual((repair.FRAME_TREE_BEFORE, repair.FRAME_TREE_AFTER), (BEFORE, AFTER))
        self.assertEqual(len(repair.CORRECTIONS), 21)
        self.assertEqual(repair.CORRECTIONS[16][0], repair.FRAME_TREE_HEADER)
        self.assertEqual(repair.profile()['id'], 'windows-password-backend-error-nothrow-v20')
        reverted = self.fixed
        for before, after in reversed(repair.CORRECTIONS[16][3]):
            self.assertEqual(reverted.count(after), 1)
            reverted = reverted.replace(after, before, 1)
        self.assertEqual(reverted, self.old)
        self.assertEqual(class_block(self.old, 'NodeRange', 'Delegate'),
                         class_block(self.fixed, 'NodeRange', 'Delegate'))
        block = class_block(self.fixed, 'NodeIterator', 'NodeRange')
        self.assertIn(b'const FrameTreeNode* root_of_subtree_to_skip_;', block)
        self.assertNotIn(b'const FrameTreeNode* const root_of_subtree_to_skip_;', block)
        self.assertEqual(re.findall(rb'^    bool ([a-z_]+);$', block, re.MULTILINE),
                         [b'should_descend_into_inner_trees_',
                          b'include_delegate_nodes_for_inner_frame_trees_'])

    def test_newlines_idempotence_and_unreviewed_partial_inputs(self):
        for newline in (b'\n', b'\r\n'):
            old = self.old.replace(b'\n', newline)
            changed = repair.transform(old, repair.FRAME_TREE_HEADER)
            self.assertEqual(changed, self.fixed.replace(b'\n', newline))
            self.assertEqual(repair.transform(changed, repair.FRAME_TREE_HEADER), changed)
        invalid = [b'', self.old + b'\n', self.fixed + b'\n',
                   self.old.replace(b'\n', b'\r\n', 1)]
        for anchor, replacement in repair.CORRECTIONS[16][3]:
            invalid.append(self.old.replace(anchor, replacement, 1))
        for raw in invalid:
            with self.assertRaises(ValueError):
                repair.transform(raw, repair.FRAME_TREE_HEADER)

    def command(self, source, output):
        if os.name != 'nt':
            clang = shutil.which('clang++')
            self.assertTrue(clang, 'Native Clang required')
            return [clang, '-std=c++23', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(output)]
        where = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        clang = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'LLVM/bin/clang-cl.exe'
        self.assertTrue(where.is_file() and clang.is_file(), 'Native reviewed toolchain required')
        vs = Path(subprocess.check_output([str(where), '-latest', '-products', '*', '-requires',
            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
            text=True, timeout=30).strip())
        version = (vs / 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt').read_text().strip()
        self.assertTrue(version.startswith('14.44.'), version)
        clang_version = subprocess.check_output([str(clang), '--version'], text=True, timeout=30).splitlines()[0]
        self.assertRegex(clang_version, r'clang version 20\.1\.8\b')
        batch = source.with_suffix('.cmd')
        batch.write_bytes(('@echo off\r\ncall "' + str(vs) + '/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\r\n'
            'if errorlevel 1 exit /b 90\r\n"' + str(clang) + '" /nologo /std:c++23preview /EHsc /W4 /WX "'
            + str(source) + '" /Fe:"' + str(output) + '"\r\n').encode())
        return ['cmd.exe', '/d', '/c', str(batch)]

    def build(self, data, fixed, mode, name):
        source = self.root / (name + '.cc')
        output = self.root / (name + ('.exe' if os.name == 'nt' else ''))
        source.write_text(native_probe(data, fixed, mode), encoding='utf-8')
        result = subprocess.run(self.command(source, output), cwd=self.root,
            capture_output=True, text=True, errors='replace', timeout=90)
        return result, output

    def test_native_original_deleted_assignment_and_fixed_memberwise_semantics(self):
        traits, exe = self.build(self.old, False, 'traits', 'old_traits')
        self.assertEqual(traits.returncode, 0, traits.stdout + traits.stderr)
        subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
        old, exe = self.build(self.old, False, 'find', 'old_find')
        if os.name == 'nt':
            self.assertNotEqual(old.returncode, 0)
            self.assertNotEqual(old.returncode, 90)
            self.assertIn('copy assignment operator is implicitly deleted', old.stdout + old.stderr)
            self.assertIn('root_of_subtree_to_skip_', old.stdout + old.stderr)
        else:
            self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
            subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
        fixed, exe = self.build(self.fixed, True, 'find', 'fixed_find')
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        subprocess.run([str(exe)], check=True, capture_output=True, timeout=15)
        print('CEF_FRAME_TREE_V17_NATIVE original_nonassignable=true windows_find_if_failed='
              + str(os.name == 'nt').lower() + ' fixed_assignable=true fixed_find_if_runs=true'
              ' policy_copied=true independent_queue=true node_range_unchanged=true public_blob=true edits=4'
              ' before_sha256=' + BEFORE + ' after_sha256=' + AFTER)


def populate_v16(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 16 else raw)
    (work / repair.MARKER).write_bytes(canonical({
        'schema': 1, 'kind': 'cef-windows-source-repair',
        'build_key': repair.V16_KEY, 'source_repair': repair.v16_profile(),
    }) + b'\n')


class V16TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='v16-to-v17-')
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / 'work'
        populate_v16(self.work)
        self.path = self.work / repair.FRAME_TREE_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, 'upgrade-v16')

    def test_exact_selector_and_immutable_profile(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V16, repair.BASE_KEY),
                         (repair.V16_KEY, 'upgrade-v16'))
        for field, value in repair.UPGRADE_V16.items():
            wrong = dict(repair.UPGRADE_V16)
            wrong[field] = value + 1 if type(value) is int else '0' * len(value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                repair.restore_contract(wrong, repair.BASE_KEY)
        for wrong in (dict(repair.UPGRADE_V16, attempt=True), dict(repair.UPGRADE_V16, extra=1),
                      {'build_key': repair.V16_KEY}):
            with self.assertRaises(ValueError):
                repair.restore_contract(wrong, repair.BASE_KEY)
        profile = repair.v16_profile()
        self.assertEqual(hashlib.sha256(canonical({'schema': 2, 'base_build_key': repair.BASE_KEY,
            'source_repair': profile})).hexdigest(), repair.V16_KEY)
        self.assertEqual(repair.profile()['corrections'][:16], profile['corrections'])
        self.assertEqual(profile['implementation_sha256'],
                         '3f9edeb27f84f38437c690d3fb23f283650f2e295b2aba63fc13ac36fe80d176')
        self.assertNotEqual(self.key, repair.V16_KEY)

    def test_summary_requires_complete_prior_proof(self):
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True,
                 'source_repair': repair.v16_profile()}
        repair.verify_summary(value, repair.UPGRADE_V16)
        for field in value:
            wrong = copy.deepcopy(value); wrong.pop(field)
            with self.assertRaises(ValueError):
                repair.verify_summary(wrong, repair.UPGRADE_V16)
        value['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError):
            repair.verify_summary(value, repair.UPGRADE_V16)

    def test_only_later_sources_and_marker_change_objects_and_resume_preserved(self):
        obj = self.work / 'out/keep.obj'; obj.parent.mkdir(); obj.write_bytes(b'v16-object')
        def snapshot(p):
            st = p.stat()
            return p.read_bytes(), st.st_mtime_ns, st.st_dev, st.st_ino
        before = {p: snapshot(p) for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(self.apply(), 'upgraded-v16')
        for p, saved in before.items():
            if p in (self.path, self.work / repair.LOCK_MANAGER_HEADER,
                     self.work / repair.AFFILIATED_MATCH_SOURCE,
                     self.work / repair.BACKEND_ERROR_HEADER,
                     self.work / repair.BACKEND_ERROR_SOURCE):
                self.assertEqual(p.read_bytes(), repair.transform(saved[0], p.relative_to(self.work).as_posix()))
                self.assertGreater(p.stat().st_mtime_ns, saved[1])
            elif p != self.marker:
                self.assertEqual(snapshot(p), saved)
        self.assertEqual(parse(self.marker.read_bytes())['source_repair'], repair.profile())
        after = {p: snapshot(p) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual(after, {p: snapshot(p) for p in before})
        with self.assertRaises(ValueError):
            self.apply()

    def test_all_prior_sources_checked_before_any_write(self):
        marker = self.marker.read_bytes()
        for relative, _, _, _ in repair.CORRECTIONS[:16]:
            path = self.work / relative
            old = path.read_bytes()
            path.write_bytes(fixture_bytes(path.name))
            with mock.patch.object(repair.os, 'replace') as operation:
                with self.assertRaises(ValueError): self.apply()
                operation.assert_not_called()
            self.assertEqual(self.marker.read_bytes(), marker)
            path.write_bytes(old)

    def test_partial_hardlink_and_race_rejected_without_marker_publication(self):
        raw, old_marker = self.path.read_bytes(), self.marker.read_bytes()
        self.path.write_bytes(repair.transform(raw, repair.FRAME_TREE_HEADER))
        with self.assertRaises(ValueError): self.apply()
        self.path.write_bytes(raw)
        alias = self.work / 'frame-alias.h'; os.link(self.path, alias)
        with self.assertRaises(ValueError): self.apply()
        alias.unlink()
        replace = repair.os.replace
        prior = self.work / repair.CREDIT_CARD_HEADER
        def race(source, target):
            replace(source, target)
            if Path(target) == self.path: prior.write_bytes(b'concurrent-prior-edit')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), old_marker)

    def test_marker_race_does_not_publish_current_marker(self):
        replace = repair.os.replace
        marker = self.marker.read_bytes()
        def race(source, target):
            replace(source, target)
            if Path(target) == self.path: self.marker.write_bytes(marker + b' ')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertNotEqual(parse(self.marker.read_bytes())['build_key'], self.key)

    def test_native_private_codec_v16_to_v17_and_current_roundtrip(self):
        location = os.environ.get('CEF_REPAIR_RECIPE_DIR')
        if not location:
            self.skipTest('Pinned private checkpoint recipe not supplied')
        spec = importlib.util.spec_from_file_location('frame_tree_checkpoint_fixture',
            Path(location) / 'vcpkg/static/checkpoint.py')
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {'schema': 3, 'platform': 'windows-x64', 'recipe': 'unchanged-recipe',
                    'build_contract': repair.V16_KEY, 'work': str(self.work)}
        old = self.work.parent / 'v16-checkpoint'; new = self.work.parent / 'v17-checkpoint'
        codec.save(self.work, old, identity)
        manifest = (old / 'checkpoint.json').read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError):
            codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), 'upgraded-v16')
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual((old / 'checkpoint.json').read_bytes(), manifest)
        self.assertFalse(parse((new / 'checkpoint.json').read_bytes())['engine_runtime_verified'])


if __name__ == '__main__':
    unittest.main()
