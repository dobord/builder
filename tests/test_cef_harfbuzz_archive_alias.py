"""Source-defined archive alias tests, not real libpng/HarfBuzz qualification."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

from secure_release import cef_harfbuzz_boundary as hb
from secure_release import cef_frozen_dependencies as replay
import test_cef_harfbuzz_uploaded_proof as fixture
import test_cef_harfbuzz_boundary as primary_fixture

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tests/fixtures/cef-libpng-alias/upstream-install.cmake'
ALIAS, TARGET = 'lib/libpng.a', 'lib/libpng16.a'


@unittest.skipUnless(sys.platform == 'linux', 'Native archive aliases require Linux')
class ArchiveAliasTests(unittest.TestCase):
    def setUp(self):
        fixture.Boundary.setUp(self)
        src = self.root / 'png-source'; src.mkdir()
        (src / 'fixture.c').write_text('int png_alias_fixture(void){return 73;}\n')
        (src / 'CMakeLists.txt').write_text(
            'cmake_minimum_required(VERSION 3.20)\nproject(alias C)\n'
            'set(PNG_STATIC ON)\nset(CMAKE_INSTALL_LIBDIR lib)\n'
            'add_library(png_static STATIC fixture.c)\n'
            'set_target_properties(png_static PROPERTIES OUTPUT_NAME png16)\n'
            'install(TARGETS png_static ARCHIVE DESTINATION lib)\n'
            'include("'+SOURCE.as_posix()+'")\n')
        build = self.root / 'png-build'
        fixture.run(['cmake', '-S', src, '-B', build,
                     '-DCMAKE_INSTALL_PREFIX='+str(self.installed)], self.root)
        fixture.run(['cmake', '--build', build], self.root)
        fixture.run(['cmake', '--install', build], self.root)
        self.alias, self.canonical = self.installed / ALIAS, self.installed / TARGET
        shutil.copyfile(self.canonical, self.prefix / TARGET)
        self.record()

    def record(self):
        p = self.prefix / TARGET
        self.value['files'][TARGET] = {'size': p.stat().st_size, 'sha256': hb.digest(p)}
        self.value['archive_objects'][TARGET] = 1

    def resolve(self):
        return hb.verified_archive_alias(self.alias, self.installed, self.value)

    def test_source_defined_install_reproduces_73_and_resolves_to_audited_archive(self):
        self.assertTrue(self.alias.is_symlink())
        self.assertEqual(os.readlink(self.alias), 'libpng16.a')
        with self.assertRaisesRegex(ValueError, 'Redirected surviving'):
            for p in (self.installed / 'lib').rglob('*'):
                hb.require(not p.is_symlink(), 'Redirected surviving HarfBuzz consumer')
        self.assertEqual(self.resolve(), self.canonical)
        # Not an ignored alias: the real archive is present exactly once.
        self.assertEqual(hb.reference_inputs([self.installed], set(), self.value), [self.canonical])
        self.assertIn('png_alias_fixture', hb.symbols(self.canonical)[0])

    def test_entire_uploaded_cpp_proof_preserves_alias_bytes_and_timestamps(self):
        before = (self.canonical.read_bytes(), self.canonical.stat().st_mtime_ns,
                  self.alias.lstat().st_mtime_ns, self.target.read_bytes())
        proof = fixture.Boundary.verify(self)
        self.assertTrue(proof['static_link_and_api_verified'])
        self.assertEqual(before, (self.canonical.read_bytes(), self.canonical.stat().st_mtime_ns,
                         self.alias.lstat().st_mtime_ns, self.target.read_bytes()))

    def test_primary_scanner_passes_canonical_archive_to_both_mandatory_stages(self):
        api = {'hb_shape', 'hb_buffer_create', 'hb_ft_font_create',
               'hb_ft_face_create', 'hb_version_string'}
        with mock.patch.object(hb, 'interface', return_value=api), \
             mock.patch.object(hb, 'closed_difference', return_value=(api, {})) as closure, \
             mock.patch.object(hb, 'link_probe') as primary, \
             mock.patch.object(hb, 'reviewed_verify', side_effect=ValueError('whole proof required')) as whole:
            with self.assertRaisesRegex(ValueError, 'whole proof required'):
                hb.verify(package=self.package, prefix=self.prefix, inventory=self.value,
                    version='14.2.1', features='core;c-linker;freetype',
                    installed=self.installed, output=self.root/'proof')
            self.assertIn(self.canonical, closure.call_args.args[3])
            self.assertNotIn(self.alias, closure.call_args.args[3])
            primary.assert_called_once(); whole.assert_called_once()

    def test_alias_target_incoming_reference_is_not_skipped(self):
        api = 'extern "C" __attribute__((visibility("default"))) int hb_probe(void){return 73;}\n'
        built = primary_fixture.NativeTests.lib(self, 'scoped-built',
            'struct Internal{__attribute__((noinline)) int local(){return 73;}};\n'+api+
            '__attribute__((visibility("hidden"))) int internal_root(){return Internal().local();}')
        frozen = primary_fixture.NativeTests.lib(self, 'scoped-frozen', api+
            '__attribute__((visibility("hidden"))) int internal_root(){return 73;}')
        absent = set(hb.symbols(built)[0]) - set(hb.symbols(frozen)[0])
        self.assertEqual(len(absent), 1)
        missing = next(iter(absent))
        c = self.root/'client.c'
        c.write_text('extern int need(void) __asm__("'+missing+'"); int png_need(void){return need();}\n')
        o = c.with_suffix('.o'); fixture.run(['cc', '-c', c, '-o', o], self.root)
        fixture.run(['ar', 'r', self.canonical, o], self.root)
        shutil.copyfile(self.canonical, self.prefix/TARGET); self.record()
        self.assertEqual(self.resolve(), self.canonical)
        paths = hb.reference_inputs([self.installed], set(), self.value)
        with self.assertRaisesRegex(ValueError, 'another consumer'):
            hb.audit_incoming(paths, absent)
        with self.assertRaisesRegex(ValueError, 'Another archive'):
            hb.closed_difference(built, frozen, {'hb_probe'}, paths)

    def test_absolute_escape_chain_missing_and_directory_targets_are_rejected(self):
        for target in (str(self.canonical), './libpng16.a', '../lib/libpng16.a',
                       '../../outside.a', 'other.a'):
            with self.subTest(target=target):
                self.alias.unlink(); self.alias.symlink_to(target)
                with self.assertRaisesRegex(ValueError, 'Redirected'): self.resolve()
        self.alias.unlink(); self.alias.symlink_to('libpng16.a')
        self.canonical.unlink()
        with self.assertRaises(ValueError): self.resolve()
        self.canonical.symlink_to(self.alias.name)
        with self.assertRaises(ValueError): self.resolve()
        self.canonical.unlink(); self.canonical.mkdir()
        with self.assertRaises(ValueError): self.resolve()

    def test_tampered_unbound_or_nonregular_canonical_archive_is_rejected(self):
        good = self.canonical.read_bytes(); value = copy.deepcopy(self.value)
        self.canonical.write_bytes(good[:-1]+bytes([good[-1]^1]))
        with self.assertRaisesRegex(ValueError, 'qualified bytes'): self.resolve()
        self.canonical.write_bytes(good)
        for bad in (None, {'size': len(good), 'sha256': '0'*64},
                    {'size': True, 'sha256': hb.digest(self.canonical)}):
            self.value['files'][TARGET] = bad
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.resolve()
        self.value = copy.deepcopy(value)
        self.value['archive_objects'][TARGET] = True
        with self.assertRaisesRegex(ValueError, 'Unbound'): self.resolve()
        self.value = copy.deepcopy(value)
        self.value['files'][ALIAS] = {'size': 1, 'sha256': '0'*64}
        with self.assertRaisesRegex(ValueError, 'Unbound'): self.resolve()
        for data in (b'!<thin>\nnot-a-regular-archive', b'\x7fELFnot-an-archive'):
            self.value = copy.deepcopy(value); self.canonical.write_bytes(data)
            self.value['files'][TARGET] = {'size': len(data), 'sha256': hb.digest(self.canonical)}
            with self.assertRaisesRegex(ValueError, 'regular archive'): self.resolve()

    def test_unknown_aliases_and_redirected_parent_remain_fatal(self):
        for name in ('other.a', 'alias.so', 'alias.o', 'directory'):
            p = self.installed/'lib'/name; p.symlink_to('libpng16.a')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'redirected consumer'):
                hb.reference_inputs([self.installed], set(), self.value)
            p.unlink()
        original = self.installed/'lib'; moved = self.installed/'real-lib'; original.rename(moved)
        original.symlink_to('real-lib', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Redirected'): self.resolve()

    def test_real_c_consumer_links_via_alias_after_producer_roots_are_hidden(self):
        main = self.root/'consumer.c'
        main.write_text('extern int png_alias_fixture(void);int main(void){return png_alias_fixture()!=73;}\n')
        moved = self.root/'relocated'; shutil.copytree(self.installed, moved, symlinks=True)
        self.installed.rename(self.root/'hidden-installed'); self.prefix.rename(self.root/'hidden-frozen')
        self.assertEqual(hb.verified_archive_alias(moved/ALIAS, moved, self.value), moved/TARGET)
        app = self.root/'consumer'
        fixture.run(['cc', main, '-L'+str(moved/'lib'), '-lpng', '-o', app], self.root)
        fixture.run([app], self.root)
        elf = fixture.run(['readelf', '-d', app], self.root)
        self.assertNotIn('libpng', elf)

    def test_install_relocation_and_real_vcpkg_owner_lists_cover_alias_and_target(self):
        value = {'schema': 1, 'kind': 'linux-x64-static-platform-build-inputs',
                 'runtime_verified': False, 'files': {TARGET: self.value['files'][TARGET]},
                 'archive_objects': {TARGET: 1}}
        manifest = self.root/'png-manifest.json'; manifest.write_bytes(replay.canonical(value))
        packages = self.root/'owner-packages'; package = packages/('libpng_'+replay.TRIPLET)
        shutil.copytree(self.installed, package, symlinks=True)
        overlay = replay.materialize(self.root/'png-overlay', ROOT/'triplets'/f'{replay.TRIPLET}.cmake',
            manifest, self.prefix, replay.sha(manifest), packages,
            ROOT/'tests/fixtures/cef-frozen-dependencies/ports.cmake')
        spec = overlay/'frozen-dependencies.json'
        replay.replay(spec, replay.sha(spec), package, 'libpng', replay.TRIPLET)
        installed = self.root/'owned-sdk'; sdk = installed/replay.TRIPLET
        shutil.copytree(package, sdk, symlinks=True)
        info = installed/'vcpkg/info'; info.mkdir(parents=True)
        lines = ''.join(replay.TRIPLET+'/'+n+'\n' for n in (ALIAS, TARGET))
        (info/('libpng_1.6.58_'+replay.TRIPLET+'.list')).write_text(lines)
        report = replay.verify_installed(sdk, manifest, replay.sha(manifest))
        self.assertEqual(report['frozen_dependency_archive_aliases_verified'], 1)
        moved = self.root/'exported-sdk'; shutil.copytree(installed, moved, symlinks=True)
        self.assertEqual(replay.verify_installed(moved/replay.TRIPLET, manifest,
                         replay.sha(manifest))['frozen_dependency_archive_aliases_verified'], 1)
        # Some copy/export implementations materialize links as regular files.
        copied = self.root/'copied-sdk'; shutil.copytree(installed, copied, symlinks=False)
        self.assertFalse((copied/replay.TRIPLET/ALIAS).is_symlink())
        self.assertEqual(replay.verify_installed(copied/replay.TRIPLET, manifest,
                         replay.sha(manifest))['frozen_dependency_archive_aliases_verified'], 1)
        wrong = copied/replay.TRIPLET/ALIAS; data = wrong.read_bytes()
        wrong.write_bytes(data[:-1]+bytes([data[-1]^1]))
        with self.assertRaisesRegex(ValueError, 'Copied libpng alias'):
            replay.verify_installed(copied/replay.TRIPLET, manifest, replay.sha(manifest))
        listing = moved/'vcpkg/info'/('libpng_1.6.58_'+replay.TRIPLET+'.list')
        listing.write_text(replay.TRIPLET+'/'+TARGET+'\n')
        with self.assertRaisesRegex(ValueError, 'canonical package ownership'):
            replay.verify_installed(moved/replay.TRIPLET, manifest, replay.sha(manifest))
        (listing.parent/('other_1.0_'+replay.TRIPLET+'.list')).write_text(replay.TRIPLET+'/'+ALIAS+'\n')
        with self.assertRaisesRegex(ValueError, 'canonical package ownership'):
            replay.verify_installed(moved/replay.TRIPLET, manifest, replay.sha(manifest))

    def test_workflow_runs_source_alias_regression_before_large_restore(self):
        text = (ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn('- tests/fixtures/cef-libpng-alias/**', text)
        self.assertLess(text.index('python -m unittest discover -s tests -p test_cef_harfbuzz_archive_alias.py'),
                        text.index('name: Run checkpoint-resumed final'))
        self.assertEqual(hashlib.sha256(SOURCE.read_bytes()).hexdigest(), '14775fd9b010c281a22ec83174c5cacba90507c3d3f711c9857eb0ad3fe64713')


if __name__ == '__main__': unittest.main()
