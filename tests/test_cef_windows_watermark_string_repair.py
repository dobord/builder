"""Exact public watermark header self-containment and qualified V21 transition."""
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

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cef-windows/watermark_settings.h'
PUBLIC_PATH = 'chrome/browser/enterprise/watermark/settings.h'


def source_bytes():
    raw = FIXTURE.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob != 'f8ed6cad076bcfb02d40ea66c5cb213c59419e34' or hashlib.sha256(raw).hexdigest() != repair.WATERMARK_BEFORE:
        raise ValueError('Pinned public watermark fixture mismatch')
    location = os.environ.get('CEF_WINDOWS_WATERMARK_SOURCE_ROOT')
    if location and (Path(location) / PUBLIC_PATH).read_bytes() != raw:
        raise ValueError('Pinned public checkout differs from watermark fixture')
    return raw


class WatermarkStringRepairTests(unittest.TestCase):
    def test_exact_public_header_and_only_one_direct_include(self):
        raw = source_bytes()
        fixed = repair.transform(raw, repair.WATERMARK_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.WATERMARK_AFTER)
        self.assertEqual(fixed.replace(b'#include <string>\n\n', b'', 1), raw)
        self.assertEqual(fixed.count(b'#include <string>'), 1)
        self.assertEqual(len(repair.CORRECTIONS), 23)

    def test_newlines_idempotence_and_unreviewed_inputs_rejected(self):
        raw = source_bytes()
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(raw.replace(b'\n', newline), repair.WATERMARK_HEADER)
            self.assertEqual(repair.transform(fixed, repair.WATERMARK_HEADER), fixed)
        for invalid in (b'', raw + b'\n', raw.replace(b'\n', b'\r\n', 1)):
            with self.assertRaises(ValueError): repair.transform(invalid, repair.WATERMARK_HEADER)

    def test_native_original_failure_fixed_self_containment_and_both_signatures(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        raw = source_bytes()
        with tempfile.TemporaryDirectory(prefix='watermark-string-v22-') as folder:
            root = Path(folder).resolve()
            stub = root / 'third_party/skia/include/core/SkColor.h'
            stub.parent.mkdir(parents=True)
            stub.write_text('using SkColor=unsigned int; using SkAlpha=unsigned char;\n'
                'constexpr SkColor SkColorSetRGB(unsigned int r,unsigned int g,unsigned int b) { return (r<<16)|(g<<8)|b; }\n')
            source = root / 'probe.cc'
            source.write_text('#include "settings.h"\n#include <type_traits>\n'
                'static_assert(std::is_same_v<decltype(&enterprise_watermark::GetDefaultTimestampTimezone),std::string(*)()>);\n'
                'static_assert(std::is_same_v<decltype(&enterprise_watermark::GetTimestampTimezone),std::string(*)(const PrefService*)>);\n'
                'static_assert(sizeof(std::string)>0);\n'
                'int main() { std::string timezone="UTC"; return timezone.size()!=3; }\n')
            for fixed in (False, True):
                (root / 'settings.h').write_bytes(repair.transform(raw, repair.WATERMARK_HEADER) if fixed else raw)
                exe = root / ('fixed' + ('.exe' if os.name == 'nt' else ''))
                command = helper.command(source, exe)
                if os.name == 'nt':
                    env = dict(os.environ, CL='/I"' + str(root) + '"')
                else:
                    command.insert(1, '-I' + str(root)); env = None
                result = subprocess.run(command, cwd=root, env=env,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if not fixed:
                    self.assertNotIn(result.returncode, (0, 90))
                    self.assertIn('string', result.stdout + result.stderr)
                    self.assertIn('settings.h', result.stdout + result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_WATERMARK_STRING_V22_NATIVE original_failed=true fixed_runs=true signatures=2 direct_string_include=true public_blob=true'
              ' before_sha256=' + repair.WATERMARK_BEFORE + ' after_sha256=' + repair.WATERMARK_AFTER)


def populate_v21(work):
    for index, (relative, _, _, _) in enumerate(repair.CORRECTIONS):
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = fixture_bytes(path.name)
        path.write_bytes(repair.transform(raw, relative) if index < 22 else raw)
    (work / repair.MARKER).write_bytes(canonical({
        'schema': 1, 'kind': 'cef-windows-source-repair',
        'build_key': repair.V21_KEY, 'source_repair': repair.v21_profile()}) + b'\n')


class V21TransitionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='v21-to-v22-')
        self.addCleanup(folder.cleanup)
        self.work = Path(folder.name).resolve() / 'work'
        populate_v21(self.work)
        self.path = self.work / repair.WATERMARK_HEADER
        self.marker = self.work / repair.MARKER
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self):
        return repair.apply(self.work, self.key, 'upgrade-v21')

    def test_exact_selector_profile_and_summary_binding(self):
        self.assertEqual(repair.restore_contract(repair.UPGRADE_V21, repair.BASE_KEY), (repair.V21_KEY, 'upgrade-v21'))
        for field, value in repair.UPGRADE_V21.items():
            invalid = dict(repair.UPGRADE_V21)
            invalid[field] = value + 1 if type(value) is int else '0' * len(value)
            with self.assertRaises(ValueError): repair.restore_contract(invalid, repair.BASE_KEY)
        self.assertEqual(repair.profile()['corrections'][:22], repair.v21_profile()['corrections'])
        value = {'base_build_key': repair.BASE_KEY, 'source_repair_verified': True, 'source_repair': repair.v21_profile()}
        repair.verify_summary(value, repair.UPGRADE_V21)
        value['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError): repair.verify_summary(value, repair.UPGRADE_V21)

    def test_only_header_and_marker_change_preserving_objects_and_resume(self):
        obj = self.work / 'out/keep.obj'; obj.parent.mkdir(); obj.write_bytes(b'qualified-v21-object')
        def snapshot(path):
            st = path.stat()
            return path.read_bytes(), st.st_mtime_ns, st.st_dev, st.st_ino
        before = {p: snapshot(p) for p in self.work.rglob('*') if p.is_file()}
        self.assertEqual(self.apply(), 'upgraded-v21')
        for path, saved in before.items():
            if path == self.path:
                self.assertEqual(path.read_bytes(), repair.transform(saved[0], repair.WATERMARK_HEADER))
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
        self.path.write_bytes(repair.transform(raw, repair.WATERMARK_HEADER))
        with self.assertRaises(ValueError): self.apply()
        self.path.write_bytes(raw)
        alias = self.work / 'alias'; os.link(self.path, alias)
        with self.assertRaises(ValueError): self.apply()
        alias.unlink()
        original = repair.os.replace
        def race(source, target):
            original(source, target)
            if Path(target) == self.path:
                (self.work / repair.PERMISSION_MANAGER_HEADER).write_bytes(b'synthetic concurrent edit')
        with mock.patch.object(repair.os, 'replace', side_effect=race):
            with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.marker.read_bytes(), previous)

    def test_private_codec_retains_v21_to_current_contract_boundary(self):
        location = os.environ.get('CEF_REPAIR_RECIPE_DIR')
        if not location:
            self.skipTest('Pinned private checkpoint recipe not supplied')
        spec = importlib.util.spec_from_file_location('watermark_checkpoint_fixture',
            Path(location) / 'vcpkg/static/checkpoint.py')
        codec = importlib.util.module_from_spec(spec); spec.loader.exec_module(codec)
        identity = {'schema': 3, 'platform': 'windows-x64', 'recipe': 'unchanged-recipe',
                    'build_contract': repair.V21_KEY, 'work': str(self.work)}
        old = self.work.parent / 'v21-checkpoint'; new = self.work.parent / 'current-checkpoint'
        codec.save(self.work, old, identity)
        original_manifest = (old / 'checkpoint.json').read_bytes()
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(old, self.work, dict(identity, build_contract=self.key))
        codec.restore(old, self.work, identity)
        self.assertEqual(self.apply(), 'upgraded-v21')
        codec.save(self.work, new, dict(identity, build_contract=self.key))
        shutil.rmtree(self.work)
        with self.assertRaises(ValueError): codec.restore(new, self.work, identity)
        codec.restore(new, self.work, dict(identity, build_contract=self.key))
        self.assertEqual(repair.apply(self.work, self.key, 'resume'), 'already-applied')
        self.assertEqual((old / 'checkpoint.json').read_bytes(), original_manifest)
        self.assertFalse(parse((new / 'checkpoint.json').read_bytes())['engine_runtime_verified'])


if __name__ == '__main__':
    unittest.main()
