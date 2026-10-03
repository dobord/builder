"""An upstream .c inclusion header is public; arbitrary SDK C sources are not.

Native/vcpkg consumers below use a disposable inclusion-header implementation,
not a substitute for the real qualified GLib/GObject or CEF runtime.
"""
from __future__ import annotations

import copy
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from secure_release import cef_sdk_headers as headers, cef_sdk_example as example
from secure_release import cef_frozen_dependencies as frozen, safeio

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/cef-sdk-headers'
PUBLIC_HEADER = (FIXTURES / 'gobjectnotifyqueue.c').read_bytes()
NATIVE_HEADER = b'#ifndef INCLUDED_FIXTURE\n#define INCLUDED_FIXTURE\nstatic inline int included_value(int x){return x+1;}\n#endif\n'


def run(args, cwd, env=None):
    p = subprocess.run(list(map(str, args)), cwd=cwd, env=env, capture_output=True,
                       text=True, timeout=300)
    if p.returncode:
        raise AssertionError(p.stdout[-2000:] + p.stderr[-4000:])
    return p.stdout


def manifest(root, record=None):
    # Archive payload is outside the selected source-header review; this fixture
    # is structurally valid for the real unchanged manifest identity validator.
    data = {'schema':1, 'kind':'linux-x64-static-platform-build-inputs', 'runtime_verified':False,
            'files':{headers.HEADER:record or dict(headers.HEADER_RECORD),
                     'lib/libfixture.a':{'size':8,'sha256':'a'*64}},
            'archive_objects':{'lib/libfixture.a':1},
            'modules':{n:{'version':'2.88.2'} for n in ('glib-2.0','gobject-2.0')}}
    p = root / 'platform.json'; p.write_bytes(frozen.canonical(data))
    return p, frozen.sha(p)


def populate(sdk, data=PUBLIC_HEADER):
    p = sdk / 'installed' / headers.TRIPLET / headers.HEADER
    p.parent.mkdir(parents=True); p.write_bytes(data)
    info = sdk / 'installed/vcpkg/info'; info.mkdir(parents=True)
    listing = info / ('glib_2.88.2_' + headers.TRIPLET + '.list')
    listing.write_text(headers.TRIPLET + '/' + headers.HEADER + '\n')
    return p, listing


class HeaderTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.root = Path(t.name).resolve(); self.sdk = self.root / 'sdk'
        self.header, self.listing = populate(self.sdk)
        self.manifest, self.sha = manifest(self.root)
        self.archive = self.root / 'sdk.zip'

    def review(self):
        return headers.verify(self.sdk, self.manifest, self.sha)

    def test_full_source_and_install_policy_are_independently_pinned(self):
        self.assertEqual(example.blob(PUBLIC_HEADER),headers.HEADER_BLOB)
        self.assertEqual(example.record(PUBLIC_HEADER),headers.HEADER_RECORD)
        meson = (FIXTURES / 'gobject-meson.build').read_bytes()
        self.assertEqual(example.blob(meson),headers.MESON_BLOB)
        text = meson.decode()
        installed = text.split('gobject_install_headers = files(',1)[1].split(')',1)[0]
        self.assertIn("'gobjectnotifyqueue.c', # sic",installed)
        self.assertIn('install_headers(gobject_install_headers, install_dir : gobject_includedir)',text)
        compiled = text.split('gobject_sources += files(',1)[1].split(')',1)[0]
        self.assertNotIn('gobjectnotifyqueue.c',compiled)
        self.assertIn(b'This file is INSTALLED',PUBLIC_HEADER)
        self.assertIn(b'#ifndef __G_OBJECT_NOTIFY_QUEUE_H__',PUBLIC_HEADER)

    def test_77_default_failure_then_exact_header_roundtrip_without_mutation(self):
        before = (self.header.read_bytes(),self.header.stat().st_mtime_ns)
        with self.assertRaisesRegex(ValueError,'implementation source'):
            safeio.sdk_zip(self.sdk,self.archive)
        self.assertFalse(self.archive.exists())
        approved = self.review()
        with self.assertRaisesRegex(ValueError,'source review'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_sources=approved)
        safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
        moved = self.root / 'relocated'; safeio.extract_zip(self.archive,moved)
        self.assertEqual(headers.verify(moved,self.manifest,self.sha),approved)
        self.assertEqual((self.header.read_bytes(),self.header.stat().st_mtime_ns),before)

    def test_header_identity_is_not_trusted_just_because_sdk_manifest_says_so(self):
        data = json.loads(self.manifest.read_bytes())
        self.header.write_bytes(PUBLIC_HEADER+b'changed')
        data['files'][headers.HEADER] = example.record(self.header.read_bytes())
        self.manifest.write_bytes(frozen.canonical(data)); self.sha = frozen.sha(self.manifest)
        with self.assertRaisesRegex(ValueError,'Unreviewed'):self.review()
        self.header.write_bytes(PUBLIC_HEADER)
        self.manifest,self.sha = manifest(self.root)
        data = json.loads(self.manifest.read_bytes()); data['modules']['gobject-2.0']['version']='other'
        self.manifest.write_bytes(frozen.canonical(data)); self.sha=frozen.sha(self.manifest)
        with self.assertRaisesRegex(ValueError,'version'):self.review()
        with self.assertRaisesRegex(ValueError,'manifest identity'):
            headers.verify(self.sdk,self.manifest,'0'*64)

    def test_owner_must_be_unique_glib_and_correct_version(self):
        data = self.listing.read_bytes()
        self.listing.write_bytes(data+data)
        with self.assertRaisesRegex(ValueError,'owning package'):self.review()
        self.listing.write_bytes(data)
        for label in ('other_2.88.2_','glib_2.88.4_'):
            wrong = self.listing.with_name(label+headers.TRIPLET+'.list')
            self.listing.rename(wrong)
            with self.assertRaisesRegex(ValueError,'owning package'):self.review()
            wrong.rename(self.listing)
        self.listing.write_text(headers.TRIPLET+'/include/other.h\n')
        with self.assertRaisesRegex(ValueError,'owning package'):self.review()

    def test_missing_modified_header_fails_before_and_during_packaging(self):
        approved=self.review()
        self.header.write_bytes(PUBLIC_HEADER+b'\n')
        with self.assertRaisesRegex(ValueError,'bytes changed'):self.review()
        with self.assertRaisesRegex(ValueError,'bytes changed'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
        self.assertFalse(self.archive.exists());self.header.unlink()
        with self.assertRaisesRegex(ValueError,'Missing'):self.review()
        with self.assertRaisesRegex(ValueError,'missing'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
        self.assertFalse(self.archive.exists())

    def test_no_general_include_suffix_or_self_supplied_sdk_approval(self):
        approved=self.review()
        unknown=self.header.parent/'other.c';unknown.write_text('int internal;')
        with self.assertRaisesRegex(ValueError,'implementation source'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
        self.assertFalse(self.archive.exists());unknown.unlink()
        (self.sdk/'policy.json').write_text(json.dumps(approved))
        with self.assertRaisesRegex(ValueError,'implementation source'):
            safeio.sdk_zip(self.sdk,self.archive)

    def test_separate_scopes_no_paths_globs_empty_or_oversize_records(self):
        record=headers.HEADER_RECORD
        for name in ('installed/x/include/*.c','installed/x/include/../a.c','installed/x/lib/a.c',
                     'installed/x/share/p/examples/a/a.cpp','installed/x/include/a.c/',
                     '/installed/x/include/a.c','installed/x/include/buildtrees/a.c'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources={name:record})
        name=next(iter(self.review()))
        for record in ({'size':True,'sha256':'a'*64},{'size':1024**2+1,'sha256':'a'*64},
                       {'size':1,'sha256':'A'*64},{'size':1,'sha256':'a'*64,'optional':True}):
            with self.subTest(record=record),self.assertRaises(ValueError):
                safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources={name:record})
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources={})
        self.assertFalse(self.archive.exists())

    def test_same_checked_buffer_written_even_when_source_changes_during_write(self):
        approved=self.review();real_open=zipfile.ZipFile.open
        def race(z,entry,mode='r',*args,**kwargs):
            if mode=='w' and getattr(entry,'filename',None) in approved:
                self.header.write_text('not the checked header')
            return real_open(z,entry,mode,*args,**kwargs)
        with mock.patch.object(zipfile.ZipFile,'open',new=race):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
        with zipfile.ZipFile(self.archive) as z:self.assertEqual(z.read(next(iter(approved))),PUBLIC_HEADER)

    def test_canonical_example_and_inclusion_header_both_required(self):
        name='installed/'+headers.TRIPLET+'/share/fixture/examples/client/main.cpp'
        cpp=self.sdk/name;cpp.parent.mkdir(parents=True);cpp.write_text('int main(){return 0;}')
        approved=self.review();example_review={name:example.record(cpp.read_bytes())}
        with self.assertRaisesRegex(ValueError,'implementation source'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_sources=example_review)
        safeio.sdk_zip(self.sdk,self.archive,reviewed_sources=example_review,reviewed_include_sources=approved)
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(z.read(name),cpp.read_bytes());self.assertEqual(z.read(next(iter(approved))),PUBLIC_HEADER)

    def test_review_does_not_relax_target_tree_or_output_protection(self):
        approved=self.review()
        for name in ('installed/x/lib/leak.so.1','buildtrees/leak.h'):
            p=self.sdk/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('bad')
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
            self.assertFalse(self.archive.exists());p.unlink()
        self.archive.write_bytes(b'previous')
        with self.assertRaises(FileExistsError):safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
        self.assertEqual(self.archive.read_bytes(),b'previous')

    @unittest.skipUnless(sys.platform=='linux','Native redirected paths')
    def test_source_and_ownership_links_cannot_authorize_source(self):
        approved=self.review()
        for path in (self.header,self.listing):
            data=path.read_bytes();outside=self.root/'outside';outside.write_bytes(data)
            path.unlink();path.symlink_to(outside)
            with self.assertRaisesRegex(ValueError,'Redirected'):self.review()
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.archive,reviewed_include_sources=approved)
            path.unlink();path.write_bytes(data)
        self.assertFalse(self.archive.exists())


class CompositionTests(unittest.TestCase):
    def test_both_boundary_checks_in_real_orchestration_and_required_preflight(self):
        from secure_release import cef_strict_combined
        text=inspect.getsource(cef_strict_combined.main)
        review=text.index('cef_sdk_headers.verify(')
        pack=text.index('safeio.sdk_zip(sdk,')
        extract=text.index('safeio.extract_zip(sdk_zip,')
        recheck=text.index('cef_sdk_headers.verify(consumer_sdk,')
        self.assertLess(review,pack);self.assertLess(pack,extract);self.assertLess(extract,recheck)
        self.assertLess(recheck,text.index('shutil.rmtree(installed)'))
        self.assertIn('reviewed_include_sources=reviewed_headers',text)
        self.assertIn('cef_build.verify_consumer(',text)
        wf=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        for path in ('secure_release/cef_sdk_headers.py','tests/test_cef_sdk_headers.py','tests/fixtures/cef-sdk-headers/**'):
            self.assertIn('- '+path,wf)
        self.assertIn("REQUIRE_CEF_SDK_HEADERS: '1'",wf)
        self.assertLess(wf.index('-p test_cef_sdk_headers.py'),wf.index('name: Run checkpoint-resumed final'))

    def test_pinned_glib_port_installs_the_meson_headers(self):
        raw=os.environ.get('CEF_SDK_HEADERS_GLIB_PORT')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_HEADERS')=='1':self.fail('Pinned GLib port required')
            self.skipTest('Pinned source port supplied in required CI')
        data=Path(raw).read_bytes()
        self.assertEqual(example.blob(data),headers.PORT_BLOB)
        self.assertIn('vcpkg_install_meson(ADD_BIN_TO_PATH)',data.decode())


@unittest.skipUnless(sys.platform=='linux','Native vcpkg and C inclusion test')
class NativeVcpkgTests(unittest.TestCase):
    def test_actual_vcpkg_install_export_package_and_recompile_include_source(self):
        raw=os.environ.get('CEF_SDK_HEADERS_VCPKG_ROOT')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_HEADERS')=='1':self.fail('Native vcpkg required')
            self.skipTest('Native vcpkg supplied in required CI')
        upstream=Path(raw).resolve(strict=True)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve()
            if not (upstream/'vcpkg').is_file():
                run(['bash',upstream/'bootstrap-vcpkg.sh','-disableMetrics'],upstream)
            ports=root/'ports';port=ports/'glib';port.mkdir(parents=True)
            (port/'vcpkg.json').write_text(json.dumps({'name':'glib','version':'2.88.2'}))
            (port/'gobjectnotifyqueue.c').write_bytes(NATIVE_HEADER)
            (port/'portfile.cmake').write_text('''file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/gobjectnotifyqueue.c" DESTINATION "${CURRENT_PACKAGES_DIR}/include/glib-2.0/gobject")
file(WRITE "${CURRENT_PACKAGES_DIR}/share/glib/copyright" "Public domain disposable fixture\\n")
set(VCPKG_POLICY_EMPTY_PACKAGE enabled)
''')
            args=['--triplet='+headers.TRIPLET,'--host-triplet='+headers.TRIPLET,
                  '--overlay-triplets='+str(ROOT/'triplets'),'--overlay-ports='+str(ports),
                  '--x-install-root='+str(root/'installed')]
            env=dict(os.environ,VCPKG_ROOT=str(upstream),VCPKG_DISABLE_METRICS='1')
            run([upstream/'vcpkg','install','glib','--classic','--binarysource=clear',*args,
                 '--x-packages-root='+str(root/'packages'),'--x-buildtrees-root='+str(root/'buildtrees')],root,env)
            export=root/'export';export.mkdir()
            run([upstream/'vcpkg','export','glib','--raw','--output=sdk','--output-dir='+str(export),*args],root,env)
            m,sha=manifest(root,example.record(NATIVE_HEADER));sdk=export/'sdk'
            with mock.patch.object(headers,'HEADER_RECORD',example.record(NATIVE_HEADER)),mock.patch.object(headers,'HEADER_BLOB',example.blob(NATIVE_HEADER)):
                approved=headers.verify(sdk,m,sha)
                with self.assertRaisesRegex(ValueError,'implementation source'):safeio.sdk_zip(sdk,root/'sdk.zip')
                safeio.sdk_zip(sdk,root/'sdk.zip',reviewed_include_sources=approved)
                moved=root/'relocated';safeio.extract_zip(root/'sdk.zip',moved)
                for p in (export,ports,root/'installed',root/'packages',root/'buildtrees'):shutil.rmtree(p)
                headers.verify(moved,m,sha)
                # The .c is INCLUDED by separate clients, not compiled as a
                # library translation unit. Static/inline header semantics remain.
                a=root/'a.c';b=root/'b.c'
                a.write_text('#include <gobject/gobjectnotifyqueue.c>\nint other(void){return included_value(6);}\n')
                b.write_text('#include <gobject/gobjectnotifyqueue.c>\nextern int other(void);int main(void){return other()!=7||included_value(2)!=3;}\n')
                run(['cc','-I'+str(moved/'installed'/headers.TRIPLET/'include/glib-2.0'),a,b,'-o',root/'consumer'],root)
                run([root/'consumer'],root)


if __name__=='__main__':unittest.main()
