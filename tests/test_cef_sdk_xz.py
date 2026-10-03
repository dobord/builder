"""Pinned XZ sources and real compression tests, not final CEF qualification.

Unit fixtures are disposable. Native tests build full, unchanged XZ 5.8.3, use
its actual installation and five documented C clients. A transport-only vcpkg
overlay imports those built bytes to exercise real owner lists/export.
"""
from __future__ import annotations
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
from secure_release import cef_sdk_xz as docs, cef_sdk_example as checked, safeio
ROOT = Path(__file__).resolve().parents[1]
T = docs.TRIPLET
REL = 'installed/' + T + '/' + docs.DIRECTORY


def records(payloads):
    return {n:(len(d),hashlib.sha256(d).hexdigest(),checked.blob(d)) for n,d in payloads.items()}


def owner(sdk):
    info=sdk/'installed/vcpkg/info';info.mkdir(parents=True,exist_ok=True)
    p=info/('liblzma_5.8.3_'+T+'.list')
    p.write_text(''.join(T+'/'+docs.DIRECTORY+'/'+n+'\n' for n in docs.FILES))
    return p


class PolicyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.sdk=self.root/'sdk'
        self.directory=self.sdk/REL;self.directory.mkdir(parents=True)
        self.payloads={n:('/* disposable '+n+' */\n').encode() for n in docs.FILES}
        for n,d in self.payloads.items():(self.directory/n).write_bytes(d)
        self.listing=owner(self.sdk);self.archive=self.root/'sdk.zip'
        patch=mock.patch.object(docs,'FILES',records(self.payloads));patch.start();self.addCleanup(patch.stop)

    def pack(self):safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources=docs.verify(self.sdk))

    def test_80_default_rejection_then_exact_roundtrip_without_mutation(self):
        with self.assertRaisesRegex(ValueError,'implementation source'):safeio.sdk_zip(self.sdk,self.archive)
        self.assertFalse(self.archive.exists())
        before={n:((self.directory/n).read_bytes(),(self.directory/n).stat().st_mtime_ns) for n in self.payloads}
        review=docs.verify(self.sdk);self.assertEqual(len(review),5)
        self.pack();moved=self.root/'moved';safeio.extract_zip(self.archive,moved)
        self.assertEqual(docs.verify(moved),review)
        self.assertEqual(before,{n:((self.directory/n).read_bytes(),(self.directory/n).stat().st_mtime_ns) for n in self.payloads})

    def test_all_seven_files_required_and_extra_unknown_source_fatal(self):
        for name in docs.FILES:
            p=self.directory/name;data=p.read_bytes();p.unlink()
            with self.assertRaisesRegex(ValueError,'inventory'):docs.verify(self.sdk)
            p.write_bytes(data+b'changed')
            with self.assertRaisesRegex(ValueError,'upstream bytes'):docs.verify(self.sdk)
            p.write_bytes(data)
        p=self.directory/'unknown.c';p.write_text('int private_code;')
        with self.assertRaisesRegex(ValueError,'inventory'):docs.verify(self.sdk)
        p.unlink();review=docs.verify(self.sdk)
        p=self.sdk/'other.c';p.write_text('int private_code;')
        with self.assertRaisesRegex(ValueError,'implementation source'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources=review)
        self.assertFalse(self.archive.exists())

    def test_unique_correct_owner_and_version_for_all_companions(self):
        data=self.listing.read_bytes();self.listing.write_bytes(data+data)
        with self.assertRaisesRegex(ValueError,'Duplicate'):docs.verify(self.sdk)
        self.listing.write_bytes(data)
        for label in ('liblzma_5.8.4_','other_5.8.3_'):
            other=self.listing.with_name(label+T+'.list');self.listing.rename(other)
            with self.assertRaisesRegex(ValueError,'owning package'):docs.verify(self.sdk)
            other.rename(self.listing)
        self.listing.write_text('unrelated\n')
        with self.assertRaisesRegex(ValueError,'Unowned'):docs.verify(self.sdk)

    def test_separate_scopes_no_globs_parent_paths_or_oversized_approvals(self):
        review=docs.verify(self.sdk)
        for kwargs in ({'reviewed_sources':review},{'reviewed_include_sources':review}):
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.archive,**kwargs)
        record=next(iter(review.values()))
        for path in ('installed/t/share/doc/xz/examples/*.c','installed/t/share/doc/xz/examples/../a.c',
                     'installed/t/share/doc/xz/private.c','installed/t/include/private.c','installed/t/lib/private.c',
                     'installed/t/share/xz/examples/a/client.c'):
            with self.subTest(path=path),self.assertRaises(ValueError):
                safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources={path:record})
        for record in ({'size':True,'sha256':'a'*64},{'size':1024**2+1,'sha256':'a'*64},
                       {'size':1,'sha256':'A'*64},{'size':1,'sha256':'a'*64,'allow':True}):
            with self.assertRaises(ValueError):
                safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources={next(iter(review)):record})
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources={})

    @unittest.skipUnless(sys.platform=='linux','Native links and FIFOs')
    def test_source_sidecar_owner_and_parent_redirects_never_approved(self):
        for p in (self.directory/'01_compress_easy.c',self.directory/'Makefile',self.listing):
            data=p.read_bytes();target=self.root/'redirect-target';target.write_bytes(data)
            p.unlink();p.symlink_to(target)
            with self.assertRaisesRegex(ValueError,'Redirected'):docs.verify(self.sdk)
            p.unlink();p.write_bytes(data)
        actual=self.directory.with_name('actual');self.directory.rename(actual)
        self.directory.symlink_to(actual,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'Redirected'):docs.verify(self.sdk)
        self.directory.unlink();actual.rename(self.directory)
        p=self.directory/'01_compress_easy.c';p.unlink();os.mkfifo(p)
        with self.assertRaises(ValueError):docs.verify(self.sdk)

    def test_same_buffer_written_and_missing_approved_file_fails(self):
        review=docs.verify(self.sdk);p=self.directory/'01_compress_easy.c';old=p.read_bytes()
        original=zipfile.ZipFile.open
        def race(z,entry,mode='r',*a,**kw):
            if mode=='w' and getattr(entry,'filename',None)==REL+'/'+p.name:p.write_text('changed after hashing')
            return original(z,entry,mode,*a,**kw)
        with mock.patch.object(zipfile.ZipFile,'open',new=race):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources=review)
        with zipfile.ZipFile(self.archive) as z:self.assertEqual(z.read(REL+'/'+p.name),old)
        self.archive.unlink();p.unlink()
        with self.assertRaisesRegex(ValueError,'missing'):
            safeio.sdk_zip(self.sdk,self.archive,reviewed_doc_sources=review)
        self.assertFalse(self.archive.exists())

    def test_default_shared_workspace_and_existing_output_guards_preserved(self):
        self.archive.write_bytes(b'keep existing')
        with self.assertRaises(FileExistsError):self.pack()
        self.assertEqual(self.archive.read_bytes(),b'keep existing');self.archive.unlink()
        for name in ('installed/'+T+'/lib/libbad.so','buildtrees/private.txt'):
            p=self.sdk/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'bad')
            with self.assertRaises(ValueError):self.pack()
            self.assertFalse(self.archive.exists());p.unlink()

    def test_complete_private_source_inventory_never_discovers_permission(self):
        review=docs.verify(self.sdk);log=self.root/'diagnostic/source.json'
        def inventory():return docs.inventory_sources(self.sdk,examples=None,headers=None,docs=review,aliases=None,diagnostics=log)
        self.assertEqual(inventory(),5);log.unlink()
        for n in ('other.c','other.cc','other.cpp'):(self.sdk/n).write_text('not reviewed')
        with self.assertRaisesRegex(ValueError,'unreviewed sources'):inventory()
        entries=json.loads(log.read_bytes())['entries'];self.assertEqual(len(entries),8)
        self.assertEqual({r['path'] for r in entries if not r['reviewed_name']},{'other.c','other.cc','other.cpp'})
        self.assertNotIn('not reviewed',log.read_text());self.assertFalse(list(self.sdk.rglob('source.json')))
        if sys.platform=='linux':self.assertEqual(stat.S_IMODE(log.stat().st_mode),0o600)
        with self.assertRaises(FileExistsError):inventory()

    def test_inventory_bounds_and_output_redirection_or_overlap(self):
        review=docs.verify(self.sdk)
        def inventory(p):return docs.inventory_sources(self.sdk,examples=None,headers=None,docs=review,aliases=None,diagnostics=p)
        with mock.patch.object(safeio,'MAX_FILES',2),self.assertRaises(ValueError):inventory(self.root/'diag.json')
        with self.assertRaisesRegex(ValueError,'overlap'):inventory(self.sdk/'diag.json')
        if sys.platform=='linux':
            target=self.root/'target';target.write_text('keep');link=self.root/'diag.json';link.symlink_to(target)
            with self.assertRaises(ValueError):inventory(link)
            self.assertEqual(target.read_text(),'keep')


class CompositionTests(unittest.TestCase):
    def test_real_main_order_and_required_workflow_preflight(self):
        from secure_release import cef_strict_combined as combined
        text=inspect.getsource(combined.main)
        self.assertLess(text.index('cef_sdk_xz.validate_sources('),text.index('restore_checkpoint('))
        self.assertLess(text.index('cef_sdk_xz.verify(sdk)'),text.index('safeio.sdk_zip('))
        self.assertLess(text.index('cef_sdk_xz.inventory_sources('),text.index('safeio.sdk_zip('))
        self.assertLess(text.index('safeio.extract_zip('),text.index('cef_sdk_xz.verify(consumer_sdk)'))
        self.assertLess(text.index('cef_sdk_xz.verify(consumer_sdk)'),text.index('shutil.rmtree(installed)'))
        self.assertIn('reviewed_doc_sources=reviewed_docs',text);self.assertIn('cef_build.verify_consumer(',text)
        wf=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        for s in ('- secure_release/cef_sdk_xz.py','- tests/test_cef_sdk_xz.py',"REQUIRE_CEF_SDK_XZ: '1'",docs.ARCHIVE_SHA512):self.assertIn(s,wf)
        self.assertLess(wf.index('-p test_cef_sdk_xz.py'),wf.index('name: Run checkpoint-resumed final'))

    def test_complete_exact_port_and_manifest_before_source_changes(self):
        raw=os.environ.get('CEF_SDK_XZ_UPSTREAM')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_XZ')=='1':self.fail('Pinned XZ port required')
            self.skipTest('Pinned port supplied in required CI')
        docs.validate_sources(Path(raw))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for n in docs.ORIGINS:
                p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((Path(raw)/n).read_bytes())
            docs.validate_sources(root);(root/'ports/liblzma/portfile.cmake').write_text('disable docs')
            with self.assertRaisesRegex(ValueError,'policy changed'):docs.validate_sources(root)


def run(args,cwd,*,data=None,env=None):
    p=subprocess.run(list(map(str,args)),cwd=cwd,env=env,input=data,capture_output=True,timeout=240)
    if p.returncode:raise AssertionError(p.stdout[-2000:].decode(errors='replace')+p.stderr[-4000:].decode(errors='replace'))
    return p.stdout


@unittest.skipUnless(sys.platform=='linux','Real XZ source and ELF tests')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=os.environ.get('CEF_SDK_XZ_ARCHIVE')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_XZ')=='1':raise AssertionError('Real XZ source required')
            raise unittest.SkipTest('Pinned complete XZ source supplied in CI')
        archive=Path(raw)
        if hashlib.sha512(archive.read_bytes()).hexdigest()!=docs.ARCHIVE_SHA512:raise AssertionError('XZ source changed')
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name).resolve();source_root=cls.root/'source';source_root.mkdir()
        with tarfile.open(archive,'r:gz') as tar:tar.extractall(source_root,filter='data')
        source=source_root/'xz-5.8.3'
        if checked.blob((source/'CMakeLists.txt').read_bytes())!=docs.CMAKE_BLOB:raise AssertionError('XZ install policy changed')
        if records({n:(source/'doc/examples'/n).read_bytes() for n in docs.FILES})!=docs.FILES:raise AssertionError('Source examples changed')
        cls.prefix=cls.root/'original-prefix';build=cls.root/'build'
        flags=['-DBUILD_SHARED_LIBS=OFF','-DBUILD_TESTING=OFF','-DXZ_NLS=OFF',
               '-DXZ_TOOL_XZ=OFF','-DXZ_TOOL_XZDEC=OFF','-DXZ_TOOL_LZMADEC=OFF','-DXZ_TOOL_LZMAINFO=OFF',
               '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_LIBDIR=lib','-DXZ_INSTALL_CMAKEDIR=share/liblzma',
               '-DCMAKE_INSTALL_PREFIX='+str(cls.prefix)]
        run(['cmake','-S',source,'-B',build,*flags],cls.root)
        run(['cmake','--build',build,'--target','install','-j2'],cls.root)
        shutil.rmtree(source_root);shutil.rmtree(build)

    def exercise(self,sdk,root):
        review=docs.verify(sdk);self.assertEqual(len(review),5);prefix=sdk/'installed'/T
        def fingerprint(p):return {f.relative_to(p).as_posix():checked.record(f.read_bytes()) for f in p.rglob('*') if f.is_file()}
        baseline=fingerprint(prefix);archive=root/'sdk.zip'
        with self.assertRaisesRegex(ValueError,'implementation source'):safeio.sdk_zip(sdk,archive)
        docs.inventory_sources(sdk,examples=None,headers=None,docs=review,aliases=None,diagnostics=root/'sources.json')
        safeio.sdk_zip(sdk,archive,reviewed_doc_sources=review);moved=root/'moved';safeio.extract_zip(archive,moved)
        self.assertEqual(docs.verify(moved),review);self.assertEqual(fingerprint(prefix),baseline)
        shutil.rmtree(sdk);prefix=moved/'installed'/T;self.assertEqual(fingerprint(prefix),baseline)
        # The reusable fixture is not a fallback installed prefix for clients.
        hidden=self.prefix.with_name('hidden-original-prefix');self.prefix.rename(hidden)
        self.addCleanup(lambda:hidden.rename(self.prefix) if hidden.exists() else None)
        self.assertFalse(self.prefix.exists())
        exe={}
        for name in docs.FILES:
            if not name.endswith('.c'):continue
            out=root/Path(name).stem
            run(['cc','-std=c99','-I'+str(prefix/'include'),prefix/docs.DIRECTORY/name,prefix/'lib/liblzma.a','-pthread','-o',out],root)
            needed=run(['readelf','-d',out],root).decode()
            self.assertLessEqual(set(re.findall(r'Shared library: \[([^\]]+)\]',needed)),{'libc.so.6','libm.so.6','ld-linux-x86-64.so.2','libpthread.so.0','librt.so.1'})
            exe[Path(name).stem]=out
        payload=b'Pinned SDK XZ compression and relocation round trip\n'*100
        for name in ('01_compress_easy','03_compress_custom','04_compress_easy_mt'):
            command=[exe[name]]+(['1'] if name=='01_compress_easy' else [])
            p=root/(name+'.xz');p.write_bytes(run(command,root,data=payload))
            self.assertEqual(run([exe['02_decompress'],p],root),payload)
            self.assertIn(str(len(payload)).encode(),run([exe['11_file_info'],p],root))

    def test_real_upstream_install_zip_and_all_five_documented_clients(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();sdk=root/'sdk';shutil.copytree(self.prefix,sdk/'installed'/T);owner(sdk)
            self.exercise(sdk,root)

    def test_real_vcpkg_owners_export_and_relocated_actual_xz_clients(self):
        raw=os.environ.get('CEF_SDK_XZ_UPSTREAM');up=Path(raw).resolve() if raw else None
        if up is None or not (up/'bootstrap-vcpkg.sh').is_file():
            if os.environ.get('REQUIRE_CEF_SDK_XZ')=='1':self.fail('Real vcpkg required')
            self.skipTest('Real vcpkg provided by required CI')
        if not (up/'vcpkg').is_file():run(['bash',up/'bootstrap-vcpkg.sh','-disableMetrics'],up)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();port=root/'ports/liblzma';port.mkdir(parents=True);shutil.copytree(self.prefix,port/'payload')
            (port/'vcpkg.json').write_text(json.dumps({'name':'liblzma','version':'5.8.3'}))
            # Use the same relocatable pkg-config normalization as the actual
            # upstream port. Only fixture metadata is staged; doc/library bytes
            # remain the output of the real XZ build and install above.
            (port/'portfile.cmake').write_text(
                'file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/payload/" DESTINATION "${CURRENT_PACKAGES_DIR}")\n'
                'file(READ "${CURRENT_PACKAGES_DIR}/lib/pkgconfig/liblzma.pc" pc)\n'
                'string(REPLACE "'+self.prefix.as_posix()+'" "${CURRENT_INSTALLED_DIR}" pc "${pc}")\n'
                'file(WRITE "${CURRENT_PACKAGES_DIR}/lib/pkgconfig/liblzma.pc" "${pc}")\n'
                'vcpkg_fixup_pkgconfig()\n'
                'file(WRITE "${CURRENT_PACKAGES_DIR}/share/liblzma/copyright" "See share/doc/xz/COPYING.0BSD\\n")\n')
            args=['--triplet='+T,'--host-triplet='+T,'--overlay-triplets='+str(ROOT/'triplets'),'--overlay-ports='+str(root/'ports'),'--x-install-root='+str(root/'installed')]
            env=dict(os.environ,VCPKG_ROOT=str(up),VCPKG_DISABLE_METRICS='1')
            run([up/'vcpkg','install','liblzma','--classic','--binarysource=clear',*args,'--x-packages-root='+str(root/'packages'),'--x-buildtrees-root='+str(root/'buildtrees')],root,env=env)
            export=root/'export';export.mkdir();run([up/'vcpkg','export','liblzma','--raw','--output=sdk','--output-dir='+str(export),*args],root,env=env)
            for n in ('ports','installed','packages','buildtrees'):shutil.rmtree(root/n)
            self.exercise(export/'sdk',root)


if __name__=='__main__':unittest.main()
