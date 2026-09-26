"""Native archive and metadata ZIP alias regressions, not real SDK qualification."""
from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from secure_release import cef_sdk_aliases as aliases, safeio
from secure_release import cef_sdk_example as checked, cef_frozen_dependencies as frozen
from secure_release import encrypted_logs

ROOT = Path(__file__).resolve().parents[1]
TRIPLET = aliases.TRIPLET
PNG = 'lib/libpng.a'
CANONICAL = 'lib/libpng16.a'
PC = 'lib/pkgconfig/libcrypt.pc'
PCTARGET = 'lib/pkgconfig/libxcrypt.pc'
METADATA = b'prefix=${pcfiledir}/../..\nlibdir=${prefix}/lib\nName: libxcrypt\nDescription: disposable alias consumer\nVersion: 4.5.2\nLibs: -L${libdir} -lpng\n'
INSTALL = ROOT / 'tests/fixtures/cef-libpng-alias/upstream-install.cmake'


def run(args, cwd, env=None):
    p = subprocess.run(list(map(str, args)), cwd=cwd, env=env, capture_output=True, text=True, timeout=240)
    if p.returncode:
        raise AssertionError(p.stdout[-2000:] + p.stderr[-4000:])
    return p.stdout


def platform(root, prefix):
    records = {n: checked.record((prefix / n).read_bytes()) for n in (CANONICAL, PCTARGET)}
    records[PC] = dict(records[PCTARGET])
    m = root / 'platform.json'
    m.write_bytes(frozen.canonical({'schema': 1, 'kind': 'linux-x64-static-platform-build-inputs',
        'runtime_verified': False, 'files': records, 'archive_objects': {CANONICAL: 1}}))
    return m, frozen.sha(m)


def owners(sdk):
    info = sdk / 'installed/vcpkg/info'; info.mkdir(parents=True, exist_ok=True)
    for label, names in [('libpng_1.6.58', [PNG, CANONICAL]), ('libxcrypt_4.5.2', [PC, PCTARGET])]:
        (info / (label + '_' + TRIPLET + '.list')).write_text(''.join(TRIPLET + '/' + n + '\n' for n in names))
    return info


@unittest.skipUnless(sys.platform == 'linux', 'Native archive alias regression')
class AliasTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.root = Path(t.name).resolve(); self.sdk = self.root / 'sdk'
        self.prefix = self.sdk / 'installed' / TRIPLET
        self.prefix.mkdir(parents=True)
        # Execute the exact source-defined libpng alias/install helper with a
        # disposable C library; do not imitate it by changing archive contents.
        src = self.root / 'source'; src.mkdir()
        (src / 'fixture.c').write_text('int png_alias_value(void){return 79;}\n')
        (src / 'CMakeLists.txt').write_text(
            'cmake_minimum_required(VERSION 3.20)\nproject(alias C)\n'
            'set(PNG_STATIC ON)\nset(CMAKE_INSTALL_LIBDIR lib)\n'
            'add_library(png_static STATIC fixture.c)\n'
            'set_target_properties(png_static PROPERTIES OUTPUT_NAME png16)\n'
            'install(TARGETS png_static ARCHIVE DESTINATION lib)\n'
            'include("' + INSTALL.as_posix() + '")\n')
        run(['cmake', '-S', src, '-B', self.root / 'build', '-DCMAKE_INSTALL_PREFIX=' + str(self.prefix)], self.root)
        run(['cmake', '--build', self.root / 'build', '--target', 'install'], self.root)
        (self.prefix / 'lib/pkgconfig').mkdir()
        (self.prefix / PCTARGET).write_bytes(METADATA)
        (self.prefix / PC).symlink_to('libxcrypt.pc')
        self.info = owners(self.sdk)
        self.manifest, self.sha = platform(self.root, self.prefix)
        self.zip = self.root / 'sdk.zip'

    def review(self, **kw):
        return aliases.verify(self.sdk, self.manifest, self.sha, **kw)

    def pack(self, review=None):
        safeio.sdk_zip(self.sdk, self.zip, reviewed_aliases=review or self.review())

    def test_default_78_failure_then_materialized_roundtrip_and_source_preserved(self):
        before = {p: (p.lstat().st_mtime_ns, os.readlink(p) if p.is_symlink() else p.read_bytes())
                  for p in (self.prefix / n for n in (PNG, CANONICAL, PC, PCTARGET))}
        with self.assertRaisesRegex(ValueError, 'cannot package link'):
            safeio.sdk_zip(self.sdk, self.zip)
        self.assertFalse(self.zip.exists())
        plan = self.review(); self.assertEqual(len(plan), 2)
        self.pack(plan)
        with zipfile.ZipFile(self.zip) as z:
            self.assertTrue(all(stat.S_IFMT(i.external_attr >> 16) == stat.S_IFREG for i in z.infolist()))
        moved = self.root / 'moved'; safeio.extract_zip(self.zip, moved)
        self.assertEqual(aliases.verify(moved, self.manifest, self.sha, expected=plan), plan)
        for p, (stamp, data) in before.items():
            self.assertEqual(p.lstat().st_mtime_ns, stamp)
            self.assertEqual(os.readlink(p) if p.is_symlink() else p.read_bytes(), data)
        # Ordinary copied aliases are equally verified on a subsequent export.
        safeio.sdk_zip(moved, self.root / 'again.zip', reviewed_aliases=plan)

    def test_alias_and_canonical_ownership_and_versions_are_required(self):
        listing = self.info / ('libpng_1.6.58_' + TRIPLET + '.list'); original = listing.read_bytes()
        for data in (b'unrelated\n', original + original, (TRIPLET + '/' + CANONICAL + '\n').encode()):
            listing.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'owner|unowned'): self.review()
        listing.write_bytes(original)
        for name in ('other_1.6.58_', 'libpng_1.6.59_'):
            bad = listing.with_name(name + TRIPLET + '.list'); listing.rename(bad)
            with self.assertRaisesRegex(ValueError, 'owning'): self.review()
            bad.rename(listing)

    def test_canonical_archive_must_match_original_manifest_and_format(self):
        p = self.prefix / CANONICAL; data = p.read_bytes(); p.write_bytes(data + b'changed')
        with self.assertRaisesRegex(ValueError, 'qualified bytes'): self.review()
        p.write_bytes(b'!<thin>\n')
        self.manifest, self.sha = platform(self.root, self.prefix)
        with self.assertRaises(ValueError): self.review()

    def test_metadata_alias_is_not_rewritten_to_old_producer_prefix(self):
        value = json.loads(self.manifest.read_bytes())
        old = checked.record(METADATA.replace(b'${pcfiledir}/../..', b'/old/producer'))
        value['files'][PC] = old; value['files'][PCTARGET] = old
        self.manifest.write_bytes(frozen.canonical(value)); self.sha = frozen.sha(self.manifest)
        self.assertEqual(self.review()['installed/' + TRIPLET + '/' + PC]['sha256'], checked.record(METADATA)['sha256'])
        (self.prefix / PCTARGET).write_bytes(b'\x7fELF not metadata')
        with self.assertRaises(ValueError): self.review()

    def test_missing_and_changed_reviewed_payloads_or_tampered_manifest_fail(self):
        plan = self.review()
        with self.assertRaisesRegex(ValueError, 'manifest identity'):
            aliases.verify(self.sdk, self.manifest, '0' * 64)
        p = self.prefix / PCTARGET; data = p.read_bytes(); p.write_bytes(data.replace(b'fixture', b'changed'))
        # Keep size identical so this specifically exercises the digest guard.
        if p.read_bytes() == data: p.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        with self.assertRaisesRegex(ValueError, 'bytes changed'): self.pack(plan)
        self.assertFalse(self.zip.exists()); p.write_bytes(data)
        (self.prefix / PC).unlink()
        with self.assertRaisesRegex(ValueError, 'missing'): self.pack(plan)
        self.assertFalse(self.zip.exists())

    def test_unknown_links_all_recorded_privately_without_following(self):
        for name in ('extra.pc', 'second.a'):
            (self.prefix / 'lib' / name).symlink_to('outside')
        (self.prefix / 'lib/redirect').symlink_to(self.root, target_is_directory=True)
        report = self.root / 'diagnostics/sdk-link-inventory.json'
        with self.assertRaisesRegex(ValueError, 'unreviewed links'): self.review(diagnostics=report)
        data = json.loads(report.read_bytes()); self.assertEqual(len(data['entries']), 5)
        self.assertEqual(sum(not e['known_name'] for e in data['entries']), 3)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertIn(report, list(encrypted_logs.iter_logs(report.parent)))
        self.assertFalse(any(p.name == report.name for p in self.sdk.rglob('*')))
        with self.assertRaises(FileExistsError): self.review(diagnostics=report)

    def test_alias_absolute_escape_chained_broken_or_directory_never_approved(self):
        p = self.prefix / PNG
        for target in (str(self.prefix / CANONICAL), '../lib/libpng16.a', 'other.a', '.', 'missing.a'):
            p.unlink(); p.symlink_to(target)
            with self.subTest(target=target), self.assertRaises((ValueError, OSError)): self.review()
        p.unlink(); p.symlink_to('libpng16.a')
        target = self.prefix / CANONICAL; data = target.read_bytes(); target.unlink()
        outside = self.root / 'outside.a'; outside.write_bytes(data); target.symlink_to(outside)
        with self.assertRaises(ValueError): self.review()

    def test_special_files_and_redirected_dirs_still_fail_default_and_reviewed(self):
        plan = self.review()
        fifo = self.prefix / 'lib/fifo.a'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): self.review()
        with self.assertRaisesRegex(ValueError, 'special file'): self.pack(plan)
        self.assertFalse(self.zip.exists()); fifo.unlink()
        directory = self.prefix / 'lib'; moved = self.root / 'lib'; directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError): self.pack(plan)
        self.assertFalse(self.zip.exists())

    def test_source_policy_and_shared_payload_checks_still_mandatory(self):
        plan = self.review()
        for name in ('installed/x/lib/leak.so.1', 'installed/x/include/unknown.c', 'buildtrees/file.h'):
            p = self.sdk / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('bad')
            with self.assertRaises(ValueError): self.pack(plan)
            self.assertFalse(self.zip.exists()); p.unlink()
        self.zip.write_bytes(b'prior')
        with self.assertRaises(FileExistsError): self.pack(plan)
        self.assertEqual(self.zip.read_bytes(), b'prior')

    def test_alias_and_canonical_same_digest_cannot_race_to_inconsistent_zip(self):
        plan = self.review(); real_open = zipfile.ZipFile.open
        target = self.prefix / CANONICAL
        alias_name = 'installed/' + TRIPLET + '/' + PNG
        def mutate(z, item, mode='r', *a, **kw):
            if mode == 'w' and getattr(item, 'filename', '') == alias_name:
                target.write_bytes(b'tampered canonical')
            return real_open(z, item, mode, *a, **kw)
        with mock.patch.object(zipfile.ZipFile, 'open', new=mutate):
            with self.assertRaises(ValueError): self.pack(plan)
        self.assertFalse(self.zip.exists())

    def test_relocated_alias_or_canonical_tampering_is_fatal(self):
        plan = self.review(); self.pack(plan); moved = self.root / 'moved'; safeio.extract_zip(self.zip, moved)
        p = moved / 'installed' / TRIPLET / PC
        p.write_bytes(METADATA + b'\n')
        with self.assertRaises(ValueError): aliases.verify(moved, self.manifest, self.sha, expected=plan)

    def test_real_relocated_pkgconfig_and_lpng_link_without_producer(self):
        plan = self.review(); self.pack(plan); moved = self.root / 'moved'; safeio.extract_zip(self.zip, moved)
        for p in (self.sdk, self.root / 'source', self.root / 'build'): shutil.rmtree(p)
        aliases.verify(moved, self.manifest, self.sha, expected=plan)
        env = dict(os.environ, PKG_CONFIG_LIBDIR=str(moved / 'installed' / TRIPLET / 'lib/pkgconfig'), PKG_CONFIG_PATH='')
        flags = shlex.split(run(['pkg-config', '--static', '--libs', 'libcrypt'], self.root, env))
        main = self.root / 'client.c'; main.write_text('extern int png_alias_value(void);int main(void){return png_alias_value()!=79;}')
        run(['cc', main, *flags, '-o', self.root / 'client'], self.root, env)
        run([self.root / 'client'], self.root)


class PolicyTests(unittest.TestCase):
    def test_review_scope_paths_hashes_and_no_chains(self):
        good = {'installed/x/lib/liba.a': {'target': 'libb.a', 'size': 9, 'sha256': 'a' * 64}}
        self.assertEqual(safeio._alias_review(good), good)
        for name in ('installed/x/bin/a.a', 'installed/x/include/a.a', 'installed/x/lib/extra/a.a',
                     'installed/x/lib/a.so', 'installed/x/lib/a.cpp', 'lib/a.a', 'installed/x/lib/*.a'):
            with self.assertRaises(ValueError): safeio._alias_review({name: good['installed/x/lib/liba.a']})
        for field, value in (('target', '../libb.a'), ('target', '/libb.a'), ('target', 'libb.so'),
                             ('size', True), ('size', 17 * 1024**2), ('sha256', 'A' * 64)):
            bad = copy.deepcopy(good); bad[next(iter(bad))][field] = value
            with self.assertRaises(ValueError): safeio._alias_review(bad)
        bad = copy.deepcopy(good); bad['installed/x/lib/libb.a'] = dict(target='libc.a', size=9, sha256='b' * 64)
        with self.assertRaises(ValueError): safeio._alias_review(bad)
        with self.assertRaises(ValueError): safeio._alias_review({})

    def test_extract_zip_still_rejects_stored_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            z = Path(t) / 'link.zip'; i = zipfile.ZipInfo('installed/x/lib/liba.a')
            i.create_system = 3; i.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(z, 'w') as out: out.writestr(i, b'libb.a')
            with self.assertRaises(ValueError): safeio.extract_zip(z, Path(t) / 'out')

    def test_orchestration_requires_both_alias_reviews_and_native_preflight(self):
        from secure_release import cef_strict_combined as combined
        text = inspect.getsource(combined.main)
        self.assertLess(text.index('reviewed_aliases = cef_sdk_aliases.verify('), text.index('safeio.sdk_zip(sdk,'))
        self.assertLess(text.index('safeio.extract_zip(sdk_zip,'), text.index('cef_sdk_aliases.verify(consumer_sdk,'))
        self.assertLess(text.index('cef_sdk_aliases.verify(consumer_sdk,'), text.index('shutil.rmtree(installed)'))
        self.assertIn('cef_build.verify_consumer(', text)
        wf = (ROOT / '.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn("REQUIRE_CEF_SDK_ALIASES: '1'", wf)
        self.assertLess(wf.index('-p test_cef_sdk_aliases.py'), wf.index('name: Run checkpoint-resumed final'))


@unittest.skipUnless(sys.platform == 'linux', 'Real vcpkg native alias regression')
class NativeVcpkgTests(unittest.TestCase):
    def test_native_vcpkg_raw_export_zip_aliases_ownership_and_relocated_link(self):
        raw = os.environ.get('CEF_SDK_ALIASES_VCPKG_ROOT')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_ALIASES') == '1': self.fail('Pinned native vcpkg required')
            self.skipTest('Native vcpkg supplied by required CI')
        upstream = Path(raw).resolve(strict=True)
        with tempfile.TemporaryDirectory() as t:
            root = Path(t).resolve(); ports = root / 'ports'; ports.mkdir()
            if not (upstream / 'vcpkg').is_file(): run(['bash', upstream / 'bootstrap-vcpkg.sh', '-disableMetrics'], upstream)
            png = ports / 'libpng'; png.mkdir()
            (png / 'vcpkg.json').write_text('{"name":"libpng","version":"1.6.58"}')
            (png / 'png.c').write_text('int png_alias_value(void){return 79;}')
            (png / 'portfile.cmake').write_text('''file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/lib" "${CURRENT_PACKAGES_DIR}/include" "${CURRENT_BUILDTREES_DIR}")
execute_process(COMMAND cc -c "${CMAKE_CURRENT_LIST_DIR}/png.c" -o "${CURRENT_BUILDTREES_DIR}/png.o" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND ar rcs "${CURRENT_PACKAGES_DIR}/lib/libpng16.a" "${CURRENT_BUILDTREES_DIR}/png.o" COMMAND_ERROR_IS_FATAL ANY)
file(CREATE_LINK libpng16.a "${CURRENT_PACKAGES_DIR}/lib/libpng.a" SYMBOLIC)
file(WRITE "${CURRENT_PACKAGES_DIR}/include/png-fixture.h" "int png_alias_value(void);\\n")
file(WRITE "${CURRENT_PACKAGES_DIR}/share/libpng/copyright" "Disposable public domain test\\n")
''')
            crypt = ports / 'libxcrypt'; crypt.mkdir()
            (crypt / 'vcpkg.json').write_text('{"name":"libxcrypt","version":"4.5.2","dependencies":["libpng"]}')
            (crypt / 'libxcrypt.pc').write_bytes(METADATA)
            (crypt / 'portfile.cmake').write_text('''file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/libxcrypt.pc" DESTINATION "${CURRENT_PACKAGES_DIR}/lib/pkgconfig")
file(CREATE_LINK libxcrypt.pc "${CURRENT_PACKAGES_DIR}/lib/pkgconfig/libcrypt.pc" SYMBOLIC)
file(WRITE "${CURRENT_PACKAGES_DIR}/share/libxcrypt/copyright" "Disposable public domain test\\n")
set(VCPKG_POLICY_EMPTY_PACKAGE enabled)
''')
            args = ['--triplet=' + TRIPLET, '--host-triplet=' + TRIPLET, '--overlay-triplets=' + str(ROOT / 'triplets'),
                    '--overlay-ports=' + str(ports), '--x-install-root=' + str(root / 'installed')]
            env = dict(os.environ, VCPKG_ROOT=str(upstream), VCPKG_DISABLE_METRICS='1')
            run([upstream / 'vcpkg', 'install', 'libpng', 'libxcrypt', '--classic', '--binarysource=clear', *args,
                 '--x-packages-root=' + str(root / 'packages'), '--x-buildtrees-root=' + str(root / 'buildtrees')], root, env)
            exported = root / 'export'; exported.mkdir()
            run([upstream / 'vcpkg', 'export', 'libpng', 'libxcrypt', '--raw', '--output=sdk', '--output-dir=' + str(exported), *args], root, env)
            sdk = exported / 'sdk'; prefix = sdk / 'installed' / TRIPLET
            self.assertTrue((prefix / PNG).is_symlink()); self.assertTrue((prefix / PC).is_symlink())
            m, sha = platform(root, prefix); plan = aliases.verify(sdk, m, sha)
            with self.assertRaisesRegex(ValueError, 'cannot package link'): safeio.sdk_zip(sdk, root / 'old.zip')
            safeio.sdk_zip(sdk, root / 'sdk.zip', reviewed_aliases=plan)
            relocated = root / 'moved'; safeio.extract_zip(root / 'sdk.zip', relocated)
            for p in (exported, ports, root / 'packages', root / 'installed', root / 'buildtrees'): shutil.rmtree(p)
            aliases.verify(relocated, m, sha, expected=plan)
            env.update(PKG_CONFIG_LIBDIR=str(relocated / 'installed' / TRIPLET / 'lib/pkgconfig'), PKG_CONFIG_PATH='')
            flags = shlex.split(run(['pkg-config', '--static', '--libs', 'libcrypt'], root, env))
            main = root / 'client.c'; main.write_text('extern int png_alias_value(void);int main(void){return png_alias_value()!=79;}')
            run(['cc', main, *flags, '-o', root / 'client'], root, env); run([root / 'client'], root)


if __name__ == '__main__': unittest.main()
