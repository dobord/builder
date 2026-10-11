"""Exact public rounding expression and qualified V23-to-current transition."""
from __future__ import annotations
import hashlib
import importlib.util
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
from tests.cef_windows_vertical_tab_inputs import SOURCE


def native_probe(raw):
    start = b'  size.set_width(kCollapsedWidth +\n'
    if raw.count(start) != 1:
        raise ValueError('Unexpected public vertical-tab rounding boundary')
    offset = raw.index(start)
    end = raw.index(b'  return size;\n', offset)
    expression = raw[offset:end].decode()
    return r'''
#include <algorithm>
#include <cassert>
#include <cmath>
enum class TabStripAnimations { kExpand, kCollapse };
inline constexpr int kCollapsedWidth=48;
struct Size {
  int width=0;
  void set_width(double value) { width=static_cast<int>(value); }
};
int Width(TabStripAnimations motion,int expanded_width,double expand_percent) {
  const int expand_amount=std::max(0,expanded_width-kCollapsedWidth);
  Size size;
''' + expression + r'''
  return size.width;
}
int main() {
  for(int width : {0,48,49,99,128,250}) {
    for(double fraction : {-0.5,0.0,0.125,0.25,0.5,0.75,0.999,1.0,1.5}) {
      const double amount=std::max(0,width-kCollapsedWidth)*fraction;
      assert(Width(TabStripAnimations::kExpand,width,fraction)==kCollapsedWidth+static_cast<int>(std::floor(amount)));
      assert(Width(TabStripAnimations::kCollapse,width,fraction)==kCollapsedWidth+static_cast<int>(std::ceil(amount)));
    }
  }
  assert(Width(TabStripAnimations::kExpand,99,0.5)==73);
  assert(Width(TabStripAnimations::kCollapse,99,0.5)==74);
}
'''


class VerticalTabMathRepairTests(unittest.TestCase):
    def test_exact_public_source_and_only_two_overload_selections_change(self):
        fixed = repair.transform(SOURCE, repair.VERTICAL_TAB_SOURCE)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.VERTICAL_TAB_AFTER)
        for old, new in reversed(repair.CORRECTIONS[24][3]):
            self.assertEqual(fixed.count(new), 1)
            fixed = fixed.replace(new, old, 1)
        self.assertEqual(fixed, SOURCE)
        self.assertEqual(len(repair.CORRECTIONS), 25)
        self.assertEqual(repair.profile()['corrections'][:24], repair.v23_profile()['corrections'])

    def test_native_original_overload_failure_and_fixed_expand_collapse_rounding(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        fixed = repair.transform(SOURCE, repair.VERTICAL_TAB_SOURCE)
        original_failed = None
        with tempfile.TemporaryDirectory(prefix='vertical-tab-math-v24-') as folder:
            root = Path(folder).resolve()
            for label, raw in (('original', SOURCE), ('fixed', fixed)):
                source = root / (label + '.cc')
                exe = root / (label + ('.exe' if os.name == 'nt' else ''))
                source.write_text(native_probe(raw), encoding='utf-8')
                result = subprocess.run(helper.command(source, exe), cwd=root,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if label == 'original':
                    original_failed = result.returncode != 0
                    if os.name == 'nt': self.assertNotIn(result.returncode, (0, 90))
                    if original_failed:
                        self.assertIn('floor', result.stdout + result.stderr)
                    else:
                        subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_VERTICAL_TAB_MATH_V24_NATIVE original_failed=' + str(original_failed).lower()
              + ' windows_overload_failed=' + str(os.name == 'nt').lower()
              + ' fixed_runs=true expand_floor=true collapse_ceil=true clamped_extent=true fractional_cases=54 edits=2 public_blob=true'
                ' before_sha256=' + repair.VERTICAL_TAB_BEFORE + ' after_sha256=' + repair.VERTICAL_TAB_AFTER)

    def test_newlines_idempotence_and_partial_inputs_rejected(self):
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(SOURCE.replace(b'\n', newline), repair.VERTICAL_TAB_SOURCE)
            self.assertEqual(repair.transform(fixed, repair.VERTICAL_TAB_SOURCE), fixed)
        for invalid in (b'', SOURCE + b'\n', SOURCE.replace(b'\n', b'\r\n', 1),
                        SOURCE.replace(*repair.CORRECTIONS[24][3][0], 1)):
            with self.assertRaises(ValueError): repair.transform(invalid, repair.VERTICAL_TAB_SOURCE)


def populate_v23(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 24 else raw)
    (work / repair.MARKER).write_bytes(canonical({
        'schema': 1, 'kind': 'cef-windows-source-repair',
        'build_key': repair.V23_KEY, 'source_repair': repair.v23_profile()}) + b'\n')


class V23TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='v23-to-v24-')
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / 'work'
        populate_v23(self.work)
        self.path = self.work / repair.VERTICAL_TAB_SOURCE
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, 'upgrade-v23')

    def test_exact_selector_profile_and_summary_binding(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V23, repair.BASE_KEY), (repair.V23_KEY, 'upgrade-v23'))
        for field, value in repair.UPGRADE_V23.items():
            invalid = dict(repair.UPGRADE_V23)
            invalid[field] = value + 1 if type(value) is int else '0' * len(value)
            with self.assertRaises(ValueError): repair.restore_contract(invalid, repair.BASE_KEY)
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True, 'source_repair': repair.v23_profile()}
        repair.verify_summary(value, repair.UPGRADE_V23)
        value['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError): repair.verify_summary(value, repair.UPGRADE_V23)

    def test_only_source_and_marker_change_preserving_objects_and_resume(self):
        obj = self.work / 'out/keep.obj'; obj.parent.mkdir(); obj.write_bytes(b'qualified-v23-object')
        def snapshot(path):
            st = path.stat()
            return path.read_bytes(), st.st_mtime_ns, st.st_dev, st.st_ino
        before = {p: snapshot(p) for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(self.apply(), 'upgraded-v23')
        for path, saved in before.items():
            if path == self.path:
                self.assertEqual(path.read_bytes(), repair.transform(saved[0], repair.VERTICAL_TAB_SOURCE))
                self.assertGreater(path.stat().st_mtime_ns, saved[1])
            elif path != self.marker:
                self.assertEqual(snapshot(path), saved)
        self.assertEqual(parse(self.marker.read_bytes())['source_repair'], repair.profile())
        after = {p: snapshot(p) for p in before}
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual(after, {p: snapshot(p) for p in before})

    def test_partial_hardlink_and_prior_source_race_cannot_publish_marker(self):
        previous = self.marker.read_bytes()
        raw = self.path.read_bytes()
        self.path.write_bytes(repair.transform(raw, repair.VERTICAL_TAB_SOURCE))
        with self.assertRaises(ValueError): self.apply()
        self.path.write_bytes(raw)
        alias = self.work / 'alias'; os.link(self.path, alias)
        with self.assertRaises(ValueError): self.apply()
        alias.unlink()
        original = repair.os.replace
        def race(source, target):
            original(source, target)
            if Path(target) == self.path:
                (self.work / repair.PDFIUM_SPAN_HEADER).write_bytes(b'synthetic concurrent edit')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), previous)

    def test_private_codec_retains_v23_to_current_contract_boundary(self):
        location = os.environ.get('CEF_REPAIR_RECIPE_DIR')
        if not location:
            self.skipTest('Pinned private checkpoint recipe not supplied')
        spec = importlib.util.spec_from_file_location('vertical_tab_checkpoint_fixture',
            Path(location) / 'vcpkg/static/checkpoint.py')
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {'schema': 3, 'platform': 'windows-x64', 'recipe': 'unchanged-recipe',
                    'build_contract': repair.V23_KEY, 'work': str(self.work)}
        old = self.work.parent / 'v23-checkpoint'; new = self.work.parent / 'current-checkpoint'
        codec.save(self.work, old, identity)
        original_manifest = (old / 'checkpoint.json').read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), 'upgraded-v23')
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual((old / 'checkpoint.json').read_bytes(), original_manifest)
        self.assertFalse(parse((new / 'checkpoint.json').read_bytes())['engine_runtime_verified'])


if __name__ == '__main__':
    unittest.main()
