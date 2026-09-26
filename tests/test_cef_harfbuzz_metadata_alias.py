"""Metadata-alias regressions; real C/C++ fixtures are not SDK qualification."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_harfbuzz_boundary as hb
from secure_release import cef_frozen_dependencies as replay
import test_cef_harfbuzz_uploaded_proof as fixture
import test_cef_frozen_dependencies as frozen

PC = ('prefix=/original/producer\nlibdir=${prefix}/lib\nName: libxcrypt\n'
      'Description: disposable pkg-config alias fixture\nVersion: 4.5.2\n'
      'Libs: -L${libdir} -lcrypt\n')
ALIAS = 'lib/pkgconfig/libcrypt.pc'
TARGET = 'lib/pkgconfig/libxcrypt.pc'


def add_alias(prefix, installed, inventory):
    (prefix / 'lib/pkgconfig').mkdir(exist_ok=True, parents=True)
    for name in (ALIAS, TARGET):
        p = prefix / name
        p.write_text(PC)
        inventory['files'][name] = {'size': p.stat().st_size, 'sha256': hb.digest(p)}
    (installed / 'lib/pkgconfig').mkdir(exist_ok=True, parents=True)
    # Exactly the relative same-directory install rule in pinned libxcrypt.
    target = installed / TARGET
    target.write_text(PC.replace('/original/producer', str(installed)))
    alias = installed / ALIAS
    alias.symlink_to('libxcrypt.pc')
    return alias, target


@unittest.skipUnless(sys.platform == 'linux', 'Native metadata-alias tests require Linux')
class AliasTests(unittest.TestCase):
    def setUp(self):
        fixture.Boundary.setUp(self)
        self.alias, self.pc = add_alias(self.prefix, self.installed, self.value)

    def checked(self):
        return hb.verified_metadata_alias(self.alias, self.installed, self.value)

    def test_72_blanket_symlink_rejection_reproduces_on_real_vendor_alias(self):
        with self.assertRaisesRegex(ValueError, 'Redirected surviving'):
            for path in (self.installed / 'lib').rglob('*'):
                hb.require(not path.is_symlink(), 'Redirected surviving HarfBuzz consumer')
        self.assertTrue(self.checked())
        paths = hb.reference_inputs([self.installed], set(), self.value)
        self.assertEqual(paths, [])  # Metadata never enters nm/readelf.

    def test_whole_core_and_cpp_proof_accept_metadata_without_mutation(self):
        before = (self.source.read_bytes(), self.target.read_bytes(),
                  self.pc.read_bytes(), self.pc.stat().st_mtime_ns,
                  os.readlink(self.alias), self.alias.lstat().st_mtime_ns)
        proof = fixture.Boundary.verify(self)
        self.assertTrue(proof['static_link_and_api_verified'])
        self.assertEqual(before, (self.source.read_bytes(), self.target.read_bytes(),
                  self.pc.read_bytes(), self.pc.stat().st_mtime_ns,
                  os.readlink(self.alias), self.alias.lstat().st_mtime_ns))

    def test_primary_gate_validates_alias_before_both_required_proofs(self):
        api = {'hb_shape', 'hb_buffer_create', 'hb_ft_font_create',
               'hb_ft_face_create', 'hb_version_string'}
        with mock.patch.object(hb, 'interface', return_value=api), \
             mock.patch.object(hb, 'closed_difference', return_value=(api, {})), \
             mock.patch.object(hb, 'link_probe') as primary, \
             mock.patch.object(hb, 'reviewed_verify', side_effect=ValueError('additional proof required')) as whole:
            with self.assertRaisesRegex(ValueError, 'additional proof required'):
                hb.verify(package=self.package, prefix=self.prefix, inventory=self.value,
                    version='14.2.1', features='core;c-linker;freetype',
                    installed=self.installed, output=self.root/'proof')
            primary.assert_called_once()
            whole.assert_called_once()

    def test_unbound_or_nonidentical_captured_metadata_is_not_approved(self):
        original = self.value['files'][ALIAS]
        for change in (None, {'size': 1, 'sha256': '0'*64}, {'size': 0}):
            with self.subTest(change=change):
                self.value['files'][ALIAS] = change
                with self.assertRaisesRegex(ValueError, 'Unbound'):
                    self.checked()
        self.value['files'][ALIAS] = original

    def test_absolute_escape_chain_missing_and_directory_targets_fail_closed(self):
        for link in (str(self.pc), '../pkgconfig/libxcrypt.pc', '../../outside.pc', 'other.pc'):
            with self.subTest(link=link):
                self.alias.unlink(); self.alias.symlink_to(link)
                with self.assertRaisesRegex(ValueError, 'Redirected'):
                    self.checked()
        self.alias.unlink(); self.alias.symlink_to('libxcrypt.pc')
        self.pc.unlink()
        with self.assertRaises(ValueError): self.checked()
        self.pc.symlink_to(self.alias.name)
        with self.assertRaises(ValueError): self.checked()
        self.pc.unlink(); self.pc.mkdir()
        with self.assertRaises(ValueError): self.checked()

    def test_redirected_parent_and_binary_metadata_targets_fail_closed(self):
        for data in (b'\x7fELF\nName: x\nLibs: y', b'!<arch>\nName: x\nLibs: y',
                     b'Name: x\0\nLibs: y', b'x'*65537, b'Name: x\n'):
            with self.subTest(data=data[:8]):
                self.pc.write_bytes(data)
                with self.assertRaises(ValueError): self.checked()
        self.pc.write_text(PC)
        parent = self.pc.parent
        moved = parent.with_name('real-pkgconfig'); parent.rename(moved)
        parent.symlink_to(moved.name, target_is_directory=True)
        with self.assertRaises(ValueError): self.checked()

    def test_other_metadata_and_every_symbolic_link_input_remain_forbidden(self):
        for name, target in [('other.pc', 'libxcrypt.pc'), ('alias.a', '../../lib/libharfbuzz.a'),
                             ('alias.o', 'libxcrypt.pc'), ('alias.so', 'libxcrypt.pc')]:
            p = self.alias.parent / name
            p.symlink_to(target)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'redirected consumer'):
                hb.reference_inputs([self.installed], set(), self.value)
            p.unlink()
        d = self.installed/'directory'; d.symlink_to('lib', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'redirected consumer'):
            hb.reference_inputs([self.installed], set(), self.value)

    def test_archive_incoming_reference_still_rejects_with_valid_metadata_alias(self):
        missing = next(iter(self.built - self.frozen))
        c = self.root/'client.c'
        c.write_text('extern int need(void) __asm__("'+missing+'"); int client(void){return need();}\n')
        o = c.with_suffix('.o')
        fixture.run(['cc','-c',c,'-o',o],self.root)
        fixture.run(['ar','rcsD',self.installed/'lib/libclient.a',o],self.root)
        with self.assertRaisesRegex(ValueError, 'another consumer'):
            fixture.Boundary.verify(self)

    def test_actual_pkgconfig_alias_links_before_and_after_relocation(self):
        c = self.root/'crypt.c'; c.write_text('int crypt_fixture(void){return 73;}\n')
        o = c.with_suffix('.o');fixture.run(['cc','-c',c,'-o',o],self.root)
        fixture.run(['ar','rcsD',self.installed/'lib/libcrypt.a',o],self.root)
        consumer=self.root/'consumer.c'
        consumer.write_text('extern int crypt_fixture(void);int main(void){return crypt_fixture()!=73;}')
        moved=self.root/'moved'
        shutil.copytree(self.installed,moved,symlinks=True)
        for prefix in (self.installed,moved):
            self.assertTrue(hb.verified_metadata_alias(prefix/ALIAS,prefix,self.value))
            env=dict(os.environ, PKG_CONFIG_PATH='',PKG_CONFIG_LIBDIR=str(prefix/'lib/pkgconfig'))
            flags=subprocess.check_output(['pkg-config','--define-variable=prefix='+str(prefix),
                '--static','--libs','libcrypt'],env=env,text=True)
            fixture.run(['cc',consumer,*shlex.split(flags),'-o',self.root/'consumer'],self.root)
            fixture.run([self.root/'consumer'],self.root)

    def test_install_and_relocation_verifier_retains_alias_and_owner_validation(self):
        # Build a separate minimal owned package using the real replay path.
        base=self.root/'owned';base.mkdir()
        prefix,packages,manifest,spec,overlay=frozen.setup(base)
        target=frozen.package(base,packages)
        replay.replay(spec,replay.sha(spec),target,'frozenlib',replay.TRIPLET)
        installed=base/'sdk/installed';sdk=installed/replay.TRIPLET
        shutil.copytree(target,sdk)
        value=json.loads(manifest.read_bytes())
        add_alias(prefix,sdk,value)
        manifest.write_bytes(replay.canonical(value))
        receipt=sdk/'share/frozenlib'/replay.RECEIPT
        r=json.loads(receipt.read_bytes());r['platform_sha256']=replay.sha(manifest)
        receipt.write_bytes(replay.canonical(r))
        info=installed/'vcpkg/info';info.mkdir(parents=True)
        (info/('frozenlib_1.0_'+replay.TRIPLET+'.list')).write_text(replay.TRIPLET+'/lib/libfrozen.a\n')
        self.assertEqual(replay.verify_installed(sdk,manifest,replay.sha(manifest))['frozen_dependency_archives_verified'],1)
        moved=base/'relocated';shutil.copytree(installed,moved,symlinks=True)
        self.assertEqual(replay.verify_installed(moved/replay.TRIPLET,manifest,replay.sha(manifest))['frozen_dependency_owners_verified'],1)
        bad=moved/replay.TRIPLET/ALIAS;bad.unlink();bad.symlink_to(str(sdk/TARGET))
        with self.assertRaisesRegex(ValueError,'Redirected'):
            replay.verify_installed(moved/replay.TRIPLET,manifest,replay.sha(manifest))


if __name__ == '__main__':
    unittest.main()
