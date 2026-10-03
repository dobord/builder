"""Captured include layout, with real pinned HarfBuzz + FreeType consumers.

This is a disposable native source test, not the qualified engine archives.
Optional FreeType compression dependencies are disabled ONLY in this fixture.
Both production HarfBuzz proofs and their strict link/runtime checks are used.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_harfbuzz_boundary as hb

ROOT = Path(__file__).resolve().parents[1]
PORT_BLOB = 'cc039386bdce1adc245f547fcf9bd6c3b2d6a0bc'
FREETYPE_SHA512 = ('c3b6b0cc4b428c9c647ab2148386901dfd315273b68051940e8fea6010d46fdd291'
                   '3467c3ef58be0d499b8e2ef5a0f1a4cc5e739756155587f4f7dff08ef9695')


def snapshot(prefix: Path) -> dict:
    return {p.relative_to(prefix).as_posix(): {'size': p.stat().st_size,
                                              'sha256': hb.digest(p)}
            for p in prefix.rglob('*') if p.is_file()}


def command(args: list, cwd: Path, timeout: int = 180) -> str:
    env = dict(os.environ)
    for key in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH'):
        env.pop(key, None)
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(result.stdout[-2000:] + result.stderr[-4000:])
    return result.stdout


class IncludePolicyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.prefix = self.root / 'prefix'
        for name in ('include/harfbuzz/hb.h', 'include/ft2build.h',
                     'include/freetype/freetype.h', 'include/libpng16/png.h'):
            p = self.prefix / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('/* disposable public header */\n')
        self.inventory = {'modules': {'harfbuzz': {'includes': [
            'include/harfbuzz', 'include', 'include/libpng16']}},
            'files': snapshot(self.prefix)}

    def test_captured_order_and_root_layout_without_filesystem_writes(self):
        before = {p: p.stat().st_mtime_ns for p in self.prefix.rglob('*')}
        self.assertFalse((self.prefix / 'include/freetype2').exists())
        self.assertEqual(hb.include_flags(self.prefix, self.inventory), [
            '-I' + str(self.prefix / n) for n in
            ('include/harfbuzz', 'include', 'include/libpng16')])
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in before})

    def test_both_native_proofs_use_recorded_paths_not_distro_assumptions(self):
        for method in (hb.link_probe, hb.native_probe):
            source = inspect.getsource(method)
            self.assertIn('include_flags(prefix,', source)
            self.assertNotIn('include/freetype2', source)
        self.assertIn('reviewed_verify(', inspect.getsource(hb.verify))
        self.assertIn('"--whole-archive"', inspect.getsource(hb.native_probe))

    def test_missing_interface_or_unbound_root_never_falls_back_to_host(self):
        for data in ({}, {'modules': {}}, {'modules': {'harfbuzz': {'includes': []}}, 'files': {}},
                     {'modules': {'harfbuzz': {'includes': ['include/empty']}}, 'files': {}}):
            (self.prefix / 'include/empty').mkdir(exist_ok=True)
            with self.subTest(data=data), self.assertRaises(ValueError):
                hb.include_flags(self.prefix, data)

    def test_absolute_escape_injected_and_duplicate_paths_fail(self):
        for paths in (['/usr/include'], ['include/../elsewhere'], ['include//freetype'],
                      ['include/./freetype'], ['include;bad'], ['-I/usr/include'],
                      ['include', 'include'], [None]):
            data = copy.deepcopy(self.inventory)
            data['modules']['harfbuzz']['includes'] = paths
            with self.subTest(paths=paths), self.assertRaisesRegex(ValueError, 'include root'):
                hb.include_flags(self.prefix, data)

    def test_required_source_layout_preflight_precedes_large_restore(self):
        workflow = (ROOT / '.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn('- tests/test_cef_harfbuzz_includes.py', workflow)
        self.assertIn("REQUIRE_CEF_FREETYPE_INCLUDE_FIXTURE: '1'", workflow)
        self.assertIn(FREETYPE_SHA512, workflow)
        self.assertLess(workflow.index('-p test_cef_harfbuzz_includes.py'),
                        workflow.index('name: Run checkpoint-resumed final'))

    def test_changed_or_removed_recorded_header_is_fatal(self):
        p = self.prefix / 'include/ft2build.h'
        p.write_text('/* changed */\n')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            hb.include_flags(self.prefix, self.inventory)
        p.unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            hb.include_flags(self.prefix, self.inventory)

    @unittest.skipUnless(sys.platform == 'linux', 'Native symlink regression')
    def test_redirected_root_or_header_is_not_a_search_path(self):
        p = self.prefix / 'include/ft2build.h'
        outside = self.root / 'external.h'
        outside.write_bytes(p.read_bytes())
        p.unlink(); p.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'Redirected'):
            hb.include_flags(self.prefix, self.inventory)
        p.unlink(); p.write_bytes(outside.read_bytes())
        directory = self.prefix / 'include/libpng16'
        moved = self.root / 'external-include'
        directory.rename(moved); directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Redirected'):
            hb.include_flags(self.prefix, self.inventory)


@unittest.skipUnless(sys.platform == 'linux', 'Full static native source fixture requires Linux')
class PublicSourceTests(unittest.TestCase):
    def test_full_freetype_layout_and_both_real_harfbuzz_probes_after_relocation(self):
        raw = os.environ.get('CEF_FREETYPE_SOURCE_ARCHIVE')
        hb_source = os.environ.get('CEF_HARFBUZZ_SOURCE_FIXTURE')
        port = Path(os.environ.get('CEF_FREETYPE_PORT_FIXTURE',
                    str(ROOT / 'private-vcpkg/.full-upstream/ports/freetype/portfile.cmake')))
        if not raw or not hb_source or not port.is_file():
            if os.environ.get('REQUIRE_CEF_FREETYPE_INCLUDE_FIXTURE') == '1':
                self.fail('Pinned FreeType/HarfBuzz sources and port are required')
            self.skipTest('Pinned source include-layout fixture not supplied')
        archive = Path(raw)
        self.assertEqual(hashlib.sha512(archive.read_bytes()).hexdigest(), FREETYPE_SHA512)
        port_bytes = port.read_bytes()
        self.assertEqual(hashlib.sha1(b'blob ' + str(len(port_bytes)).encode() + b'\0' +
                                     port_bytes).hexdigest(), PORT_BLOB)
        port_text = port_bytes.decode()
        first = port_text.index('file(RENAME "${CURRENT_PACKAGES_DIR}/include/freetype2/freetype"')
        last = port_text.index('file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")', first)
        layout = port_text[first:last]
        policy = json.loads(hb.INTERFACE.read_bytes())
        source = Path(hb_source)
        for name, expected in policy['headers'].items():
            self.assertEqual(hb.digest(source / 'src' / name), expected)
        with tempfile.TemporaryDirectory(prefix='hb-freetype-layout-') as tmp:
            root = Path(tmp).resolve(); prefix = root / 'frozen'
            unpack = root / 'source'; unpack.mkdir()
            import tarfile
            with tarfile.open(archive) as t:
                for member in t.getmembers():
                    self.assertTrue((unpack / member.name).resolve().is_relative_to(unpack))
                    self.assertFalse(member.issym() or member.islnk() or member.isdev())
                t.extractall(unpack, filter='data')
            ft_source = unpack / 'freetype-VER-2-14-3'
            ft_build = root / 'ft-build'; hb_build = root / 'hb-build'
            command(['cmake', '-S', ft_source, '-B', ft_build, '-G', 'Ninja',
                     '-DBUILD_SHARED_LIBS=OFF', '-DCMAKE_INSTALL_PREFIX=' + str(prefix),
                     '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_BUILD_TYPE=Release',
                     '-DCMAKE_C_FLAGS_RELEASE=-O0 -g0', '-DFT_DISABLE_HARFBUZZ=ON',
                     '-DFT_DISABLE_BROTLI=ON', '-DFT_DISABLE_BZIP2=ON',
                     '-DFT_DISABLE_PNG=ON', '-DFT_DISABLE_ZLIB=ON'], root)
            command(['cmake', '--build', ft_build, '--target', 'install', '-j2'], root, 240)
            script = root / 'layout.cmake'; script.write_text(layout)
            command(['cmake', '-DCURRENT_PACKAGES_DIR=' + str(prefix), '-P', script], root)
            self.assertTrue((prefix / 'include/ft2build.h').is_file())
            self.assertFalse((prefix / 'include/freetype2').exists())
            command(['cmake', '-S', source, '-B', hb_build, '-G', 'Ninja',
                     '-DBUILD_SHARED_LIBS=OFF', '-DHB_HAVE_FREETYPE=ON',
                     '-DFREETYPE_INCLUDE_DIR_ft2build=' + str(prefix / 'include'),
                     '-DFREETYPE_INCLUDE_DIR_freetype2=' + str(prefix / 'include'),
                     '-DFREETYPE_LIBRARY_RELEASE=' + str(prefix / 'lib/libfreetype.a'),
                     '-DHB_BUILD_SUBSET=OFF', '-DHB_BUILD_RASTER=OFF', '-DHB_BUILD_VECTOR=OFF',
                     '-DHB_BUILD_GPU=OFF', '-DCMAKE_BUILD_TYPE=Release',
                     '-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0 -fno-exceptions -fno-rtti'], root)
            command(['cmake', '--build', hb_build, '--target', 'harfbuzz', '-j2'], root, 240)
            (prefix / 'include/harfbuzz').mkdir()
            for name in policy['headers']:
                shutil.copyfile(source / 'src' / name, prefix / 'include/harfbuzz' / name)
            shutil.copyfile(hb_build / 'src/hb-features.h', prefix / 'include/harfbuzz/hb-features.h')
            shutil.copyfile(hb_build / 'libharfbuzz.a', prefix / hb.ARCHIVE)
            defs, _ = hb.symbols(prefix / hb.ARCHIVE)
            declared = set(re.findall(r'^hb_\w+(?= \()', '\n'.join(
                (source / 'src' / n).read_text() for n in policy['core_headers'] if n.endswith('.h')), re.M))
            api = hb.public_c_api(defs, defs, declared)
            self.assertIn('hb_ft_font_create', api)
            inv = {'files': {n: r for n, r in snapshot(prefix).items() if n.startswith('include/') or n.endswith('.a')},
                   'archive_objects': {n: len(command(['ar', 't', prefix / n], root).splitlines())
                       for n in ('lib/libharfbuzz.a', 'lib/libfreetype.a')},
                   'modules': {'harfbuzz': {'includes': ['include/harfbuzz', 'include'],
                       'libraries': ['lib/libharfbuzz.a', 'm', 'lib/libfreetype.a'], 'link_options': ['-pthread']}}}
            before = snapshot(prefix)
            old_flags = ['-I' + str(prefix / 'include/harfbuzz'), '-I' + str(prefix / 'include/freetype2')]
            with mock.patch.object(hb, 'include_flags', return_value=old_flags), self.assertRaisesRegex(
                    ValueError, 'public C-link proof failed'):
                hb.link_probe(prefix, inv, api, root / 'old-proof')
            self.assertIn('ft2build.h', (root / 'old-proof/link.log').read_text())
            hb.link_probe(prefix, inv, api, root / 'new-proof')
            native = root / 'whole-core'; native.mkdir()
            self.assertEqual(hb.native_probe(native, prefix, prefix, inv, api, set(), prefix / hb.ARCHIVE), len(api))
            self.assertEqual(snapshot(prefix), before)
            relocated = root / 'relocated'; prefix.rename(relocated)
            ft_build.rename(root / 'hidden-ft-build'); hb_build.rename(root / 'hidden-hb-build')
            hb.link_probe(relocated, inv, api, root / 'relocated-c-proof')
            native = root / 'relocated-whole-core'; native.mkdir()
            hb.native_probe(native, relocated, relocated, inv, api, set(), relocated / hb.ARCHIVE)
            self.assertEqual(snapshot(relocated), before)


if __name__ == '__main__':
    unittest.main()
