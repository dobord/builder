"""Exact public wallpaper string header and unchanged optional-string signatures."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.test_cef_windows_vertical_tab_math_repair import populate_v23

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cef-windows/wallpaper_search_string_map.h'
PUBLIC_PATH = 'chrome/browser/ui/webui/side_panel/customize_chrome/wallpaper_search/wallpaper_search_string_map.h'


def source_bytes():
    raw = FIXTURE.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob != 'bb470738acf0f876126d5905144f113513b23368' or hashlib.sha256(raw).hexdigest() != repair.WALLPAPER_BEFORE:
        raise ValueError('Pinned public wallpaper fixture mismatch')
    location = os.environ.get('CEF_WINDOWS_WALLPAPER_SOURCE_ROOT')
    if location and (Path(location) / PUBLIC_PATH).read_bytes() != raw:
        raise ValueError('Pinned public checkout differs from wallpaper fixture')
    return raw


class WallpaperStringRepairTests(unittest.TestCase):
    def test_exact_public_header_and_only_one_direct_include(self):
        raw = source_bytes()
        fixed = repair.transform(raw, repair.WALLPAPER_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.WALLPAPER_AFTER)
        self.assertEqual(fixed.replace(b'#include <string>\n', b'', 1), raw)
        self.assertEqual(fixed.count(b'#include <string>'), 1)
        self.assertEqual(len(repair.CORRECTIONS), 27)

    def test_native_original_failure_fixed_self_containment_and_five_signatures(self):
        from tests.test_cef_windows_frame_tree_iterator_repair import FrameTreeRepairTests
        helper = FrameTreeRepairTests()
        raw = source_bytes()
        original_failed = None
        with tempfile.TemporaryDirectory(prefix='wallpaper-string-v26-') as folder:
            root = Path(folder).resolve()
            stub = root / 'base/functional/callback_forward.h'
            stub.parent.mkdir(parents=True)
            stub.write_text('namespace base { template<class Signature> class RepeatingCallback; }\n')
            source = root / 'probe.cc'
            text = '#include "wallpaper_search_string_map.h"\n#include <type_traits>\n'
            text += 'using Signature=std::optional<std::string>(WallpaperSearchStringMap::*)(std::string_view) const;\n'
            for method in ('FindCategory', 'FindDescriptorA', 'FindDescriptorB', 'FindDescriptorC', 'FindInspirationDescription'):
                text += 'static_assert(std::is_same_v<decltype(&WallpaperSearchStringMap::' + method + '),Signature>);\n'
            text += 'int main() { std::optional<std::string> value{std::in_place,"wallpaper"}; return value->size()!=9; }\n'
            source.write_text(text)
            for fixed in (False, True):
                (root / 'wallpaper_search_string_map.h').write_bytes(repair.transform(raw, repair.WALLPAPER_HEADER) if fixed else raw)
                exe = root / ('fixed' + ('.exe' if os.name == 'nt' else ''))
                command = helper.command(source, exe)
                if os.name == 'nt':
                    env = dict(os.environ, CL='/I"' + str(root) + '"')
                else:
                    command.insert(1, '-I' + str(root)); env = None
                result = subprocess.run(command, cwd=root, env=env,
                    capture_output=True, text=True, errors='replace', timeout=90)
                if not fixed:
                    original_failed = result.returncode != 0
                    if os.name == 'nt': self.assertNotIn(result.returncode, (0, 90))
                    if original_failed:
                        self.assertIn('string', result.stdout + result.stderr)
                    else:
                        subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    subprocess.run([str(exe)], check=True, capture_output=True, timeout=20)
        print('CEF_WALLPAPER_STRING_V26_NATIVE original_failed=' + str(original_failed).lower()
              + ' windows_header_failed=' + str(os.name == 'nt').lower()
              + ' fixed_runs=true signatures=5 optional_string=true direct_string_include=true public_blob=true'
              ' before_sha256=' + repair.WALLPAPER_BEFORE + ' after_sha256=' + repair.WALLPAPER_AFTER)

    def test_newlines_idempotence_and_unreviewed_inputs_rejected(self):
        raw = source_bytes()
        for newline in (b'\n', b'\r\n'):
            fixed = repair.transform(raw.replace(b'\n', newline), repair.WALLPAPER_HEADER)
            self.assertEqual(repair.transform(fixed, repair.WALLPAPER_HEADER), fixed)
        for invalid in (b'', raw + b'\n', raw.replace(b'\n', b'\r\n', 1)):
            with self.assertRaises(ValueError): repair.transform(invalid, repair.WALLPAPER_HEADER)

    def test_invalid_last_source_precedes_all_writes(self):
        with tempfile.TemporaryDirectory(prefix='wallpaper-transition-v26-') as folder:
            work = Path(folder).resolve() / 'work'
            populate_v23(work)
            marker = work / repair.MARKER
            previous = marker.read_bytes()
            (work / repair.WALLPAPER_HEADER).write_bytes(source_bytes() + b'\n')
            with mock.patch.object(repair.os, 'replace') as replace:
                with self.assertRaises(ValueError): repair.apply(work, repair.build_key(repair.BASE_KEY), 'upgrade-v23')
                replace.assert_not_called()
            self.assertEqual(marker.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
