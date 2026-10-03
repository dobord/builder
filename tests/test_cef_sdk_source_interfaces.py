"""Installed source interfaces: real FFmpeg samples and patched Xtrans C inclusion.

Only transport/provenance changes are under test. Minimal native FFmpeg builds
exercise real scaling/resampling; hardware-specific documentation is preserved,
NOT advertised as enabled. Xtrans uses platform X11 declarations and real socket
transport code, with no dynamic X11 library. Real vcpkg transport runs in CI.
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
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
from secure_release import cef_sdk_source_interfaces as interfaces
from secure_release import cef_sdk_example as checked, cef_sdk_xz, safeio

ROOT=Path(__file__).resolve().parents[1]
T=interfaces.TRIPLET
POLICY=interfaces.policy()


def fingerprint(root):
    return {p.relative_to(root).as_posix(): (hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file()}


def owner(sdk, package):
    spec=POLICY['packages'][package];info=sdk/'installed/vcpkg/info';info.mkdir(parents=True,exist_ok=True)
    listing=info/(package+'_'+spec['version']+'_'+T+'.list')
    listing.write_text(''.join(T+'/'+spec['directory']+'/'+name+'\n' for name in spec['files']))
    return listing


def run(args,cwd,*,env=None):
    p=subprocess.run(list(map(str,args)),cwd=cwd,env=env,capture_output=True,timeout=240)
    if p.returncode:raise AssertionError(p.stdout[-2000:].decode(errors='replace')+p.stderr[-4000:].decode(errors='replace'))
    return p.stdout


class PolicyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name).resolve();self.sdk=self.root/'sdk';self.zip=self.root/'sdk.zip'
        self.policy=copy.deepcopy(POLICY)
        for pkg,spec in self.policy['packages'].items():
            for name,entry in spec['files'].items():
                p=self.sdk/'installed'/T/spec['directory']/name;p.parent.mkdir(parents=True,exist_ok=True)
                data=('/* disposable interface '+name+' */\n').encode();p.write_bytes(data)
                entry.update(checked.record(data),blob=checked.blob(data))
            owner(self.sdk,pkg)
        patch=mock.patch.object(interfaces,'policy',return_value=self.policy);patch.start();self.addCleanup(patch.stop)

    def test_81_inventory_refusal_then_all_29_exact_sources_roundtrip(self):
        with self.assertRaisesRegex(ValueError,'unreviewed sources'):
            cef_sdk_xz.inventory_sources(self.sdk,examples=None,headers=None,docs=None,aliases=None,diagnostics=self.root/'old.json')
        old=json.loads((self.root/'old.json').read_text())
        self.assertEqual(len(old['entries']),29);self.assertFalse(any(x['reviewed_name'] for x in old['entries']))
        review=interfaces.verify(self.sdk);before=fingerprint(self.sdk)
        self.assertEqual(cef_sdk_xz.inventory_sources(self.sdk,examples=None,headers=None,docs=None,aliases=None,
                         interfaces=review,diagnostics=self.root/'new.json'),29)
        safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
        moved=self.root/'moved';safeio.extract_zip(self.zip,moved)
        self.assertEqual(interfaces.verify(moved),review);self.assertEqual(fingerprint(self.sdk),before)

    def test_all_33_companions_are_required_and_immutable(self):
        for pkg,spec in self.policy['packages'].items():
            for name in spec['files']:
                p=self.sdk/'installed'/T/spec['directory']/name;data=p.read_bytes();p.unlink()
                with self.assertRaisesRegex(ValueError,'inventory'):interfaces.verify(self.sdk)
                p.write_bytes(data+b'changed')
                with self.assertRaisesRegex(ValueError,'bytes changed'):interfaces.verify(self.sdk)
                p.write_bytes(data)
        extra=self.sdk/'installed'/T/'share/ffmpeg/examples/unknown.c';extra.write_text('int unknown;')
        with self.assertRaisesRegex(ValueError,'inventory'):interfaces.verify(self.sdk)

    def test_unique_versioned_owner_including_headers_makefile_readme(self):
        for pkg in POLICY['packages']:
            listing=owner(self.sdk,pkg);data=listing.read_bytes();listing.write_bytes(data+data)
            with self.assertRaisesRegex(ValueError,'duplicated'):interfaces.verify(self.sdk)
            listing.write_bytes(data)
            for label in ('other_1.0_'+T+'.list',pkg+'_99.0_'+T+'.list'):
                other=listing.with_name(label);listing.rename(other)
                with self.assertRaisesRegex(ValueError,'owner changed'):interfaces.verify(self.sdk)
                other.rename(listing)
            listing.write_text('unrelated\n')
            with self.assertRaisesRegex(ValueError,'Unowned'):interfaces.verify(self.sdk)
            listing.write_bytes(data)

    def test_no_blanket_share_or_source_tree_or_other_scope(self):
        review=interfaces.verify(self.sdk)
        for kwargs in ({'reviewed_sources':review},{'reviewed_doc_sources':review},{'reviewed_include_sources':review}):
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.zip,**kwargs)
        for name in ('installed/'+T+'/share/other/examples/a.c', 'installed/'+T+'/share/xtrans/src/a.c',
                     'installed/'+T+'/share/xtrans/include/X11/Xtrans/nested/a.c', 'installed/'+T+'/share/ffmpeg/examples/../a.c'):
            with self.assertRaises(ValueError):safeio._source_review({name:next(iter(review.values()))},shared_interfaces=True)
        for flags in ({'include_headers':True},{'documentation':True}):
            with self.assertRaises(ValueError):safeio._source_review(review,shared_interfaces=True,**flags)
        record=next(iter(review.values()))
        excessive={'installed/'+T+'/share/ffmpeg/examples/f'+str(i)+'.c':record for i in range(30)}
        with self.assertRaises(ValueError):safeio._source_review(excessive,shared_interfaces=True)

    def test_unknown_source_still_fails_with_complete_private_inventory(self):
        review=interfaces.verify(self.sdk)
        for name in ('other.c','nested/other.cpp'):
            p=self.sdk/name;p.parent.mkdir(exist_ok=True);p.write_text('int private_implementation;')
        with self.assertRaisesRegex(ValueError,'unreviewed sources'):
            cef_sdk_xz.inventory_sources(self.sdk,examples=None,headers=None,docs=None,aliases=None,
                         interfaces=review,diagnostics=self.root/'sources.json')
        text=(self.root/'sources.json').read_text();value=json.loads(text)
        self.assertEqual(len(value['entries']),31);self.assertNotIn('private_implementation',text)
        with self.assertRaisesRegex(ValueError,'implementation source'):
            safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
        self.assertFalse(self.zip.exists())

    def test_review_does_not_bypass_shared_library_or_workspace_guards(self):
        review=interfaces.verify(self.sdk)
        for name in ('installed/'+T+'/lib/bad.so','buildtrees/config.h'):
            p=self.sdk/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('bad')
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
            self.assertFalse(self.zip.exists());p.unlink()
            if name.startswith('buildtrees'):p.parent.rmdir()
        self.zip.write_text('existing')
        with self.assertRaises(FileExistsError):safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
        self.assertEqual(self.zip.read_text(),'existing')

    def test_changed_file_at_transport_or_missing_record_is_fatal(self):
        review=interfaces.verify(self.sdk);name=next(iter(review));p=self.sdk/name;data=p.read_bytes()
        p.write_bytes(data+b'changed')
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
        self.assertFalse(self.zip.exists());p.write_bytes(data);p.unlink()
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
        self.assertFalse(self.zip.exists())

    def test_verified_buffer_is_written_without_rereading_source(self):
        review=interfaces.verify(self.sdk);name=next(iter(review));p=self.sdk/name;data=p.read_bytes();original=zipfile.ZipFile.open
        def writing(z,n,*args,**kwargs):
            if isinstance(n,zipfile.ZipInfo) and n.filename==name:p.write_bytes(b'changed after verification')
            return original(z,n,*args,**kwargs)
        with mock.patch.object(zipfile.ZipFile,'open',writing):safeio.sdk_zip(self.sdk,self.zip,reviewed_interface_sources=review)
        with zipfile.ZipFile(self.zip) as z:self.assertEqual(z.read(name),data)

    @unittest.skipUnless(sys.platform=='linux','POSIX redirects')
    def test_symbolic_sources_parent_and_owner_are_never_authorized(self):
        for path in (self.sdk/'installed'/T/'share/xtrans/include/X11/Xtrans/transport.c',
                     self.sdk/'installed'/T/'share/ffmpeg/examples',owner(self.sdk,'ffmpeg')):
            target=path.with_name(path.name+'-saved');path.rename(target);path.symlink_to(target.name,target_is_directory=target.is_dir())
            with self.assertRaises(ValueError):interfaces.verify(self.sdk)
            path.unlink();target.rename(path)


class CompositionTests(unittest.TestCase):
    def test_policy_hash_and_complete_pinned_ports_and_patches(self):
        self.assertEqual(hashlib.sha256(interfaces.POLICY.read_bytes()).hexdigest(),interfaces.POLICY_SHA256)
        upstream=os.environ.get('CEF_SDK_INTERFACES_UPSTREAM')
        if not upstream:
            if os.environ.get('REQUIRE_CEF_SDK_INTERFACES')=='1':self.fail('Exact source inputs required')
            self.skipTest('Exact upstream inputs supplied in CI')
        interfaces.validate_sources(Path(upstream))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for n in POLICY['origins']:
                p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((Path(upstream)/n).read_bytes())
            for n in POLICY['origins']:
                p=root/n;data=p.read_bytes();p.write_bytes(data+b'\n')
                with self.assertRaises(ValueError):interfaces.validate_sources(root)
                p.write_bytes(data)
        with mock.patch.object(interfaces,'POLICY_SHA256','0'*64),self.assertRaises(ValueError):interfaces.policy()

    def test_actual_main_keeps_inventory_packaging_relocated_review_and_final_proofs(self):
        from secure_release import cef_strict_combined as c
        s=inspect.getsource(c.main)
        self.assertLess(s.index('cef_sdk_source_interfaces.validate_sources('),s.index('restore_checkpoint('))
        self.assertLess(s.index('cef_sdk_source_interfaces.verify(sdk)'),s.index('cef_sdk_xz.inventory_sources('))
        self.assertLess(s.index('safeio.extract_zip('),s.index('cef_sdk_source_interfaces.verify(consumer_sdk)'))
        self.assertLess(s.index('cef_sdk_source_interfaces.verify(consumer_sdk)'),s.index('shutil.rmtree(installed)'))
        self.assertIn('reviewed_interface_sources=reviewed_interfaces',s);self.assertIn('cef_build.verify_consumer(',s)
        wf=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        for text in ('- secure_release/cef_sdk_source_interfaces.py','- ci/cef-sdk-source-interfaces.json',
                     '- tests/test_cef_sdk_source_interfaces.py',"REQUIRE_CEF_SDK_INTERFACES: '1'"):
            self.assertIn(text,wf)
        self.assertLess(wf.index('-p test_cef_sdk_source_interfaces.py'),wf.index('name: Run checkpoint-resumed final'))


XTRANS_CLIENT = r'''
#define TRANS_CLIENT
#define TRANS_SERVER
#define UNIXCONN
#define TCPCONN
#define X11_t
#include <X11/Xtrans/transport.c>
int main(void) {
    int fd[2]; char buf[4] = {0};
    struct _XtransConnInfo a = {0}, b = {0};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) return 1;
    a.fd=fd[0]; b.fd=fd[1]; a.transptr=b.transptr=&_X11TransSocketUNIXFuncs;
    if (_X11TransWrite(&a,"xyz",3)!=3) return 2;
    if (_X11TransRead(&b,buf,3)!=3 || memcmp(buf,"xyz",3)) return 3;
    close(fd[0]); close(fd[1]); return 0;
}
'''


@unittest.skipUnless(sys.platform=='linux','Native source interfaces and ELF')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        archives={p:os.environ.get('CEF_SDK_'+p.upper()+'_ARCHIVE') for p in ('ffmpeg','xtrans')}
        upstream=os.environ.get('CEF_SDK_INTERFACES_UPSTREAM')
        if not all(archives.values()) or not upstream:
            if os.environ.get('REQUIRE_CEF_SDK_INTERFACES')=='1':raise AssertionError('Pinned native fixtures required')
            raise unittest.SkipTest('Pinned FFmpeg/Xtrans sources provided in CI')
        cls.tmp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.tmp.cleanup);cls.root=Path(cls.tmp.name).resolve()
        cls.upstream=Path(upstream).resolve();interfaces.validate_sources(cls.upstream)
        for pkg,path in archives.items():
            if hashlib.sha512(Path(path).read_bytes()).hexdigest()!=POLICY['archive_sha512'][pkg]:raise AssertionError('Wrong source archive')
            dst=cls.root/pkg;dst.mkdir()
            with tarfile.open(path,'r:gz') as tar:tar.extractall(dst,filter='data')
        ff=cls.root/'ffmpeg/FFmpeg-n8.1.2';xt=cls.root/'xtrans/libxtrans-xtrans-1.6.0'
        for path,key in ((ff/'doc/examples/Makefile','ffmpeg_makefile'),(xt/'Makefile.am','xtrans_makefile')):
            if checked.blob(path.read_bytes())!=POLICY['source_inputs'][key]:raise AssertionError('Install recipe drift')
        for n,digest in POLICY['source_inputs']['xtrans_unpatched'].items():
            if checked.blob((xt/n).read_bytes())!=digest:raise AssertionError('Xtrans source drift')
        for patch in ('win32.patch','symbols.patch'):
            run(['git','apply','--ignore-space-change',cls.upstream/'ports/xtrans'/patch],xt)
        cls.prefix=cls.root/'built-prefix';cls.prefix.mkdir();build=cls.root/'ff-build';build.mkdir()
        flags=['--disable-everything','--disable-autodetect','--disable-x86asm','--disable-programs','--disable-doc',
               '--disable-avcodec','--disable-avformat','--disable-avdevice','--disable-avfilter',
               '--enable-swscale','--enable-swresample','--disable-shared','--enable-static']
        run([ff/'configure','--prefix='+str(cls.prefix),*flags],build);run(['make','-j2','install'],build)
        spec=POLICY['packages']['xtrans'];dest=cls.prefix/'include/X11/Xtrans';dest.mkdir(parents=True)
        # Exact upstream installed-header list and the actual vcpkg move command.
        make=(xt/'Makefile.am').read_text();names=re.search(r'Xtransinclude_HEADERS = (.*?)\n\n',make,re.S).group(1).replace('\\','').split()
        if set(names)!=set(spec['files']):raise AssertionError('Xtrans header inventory changed')
        for n in names:shutil.copyfile(xt/n,dest/n)
        port=(cls.upstream/'ports/xtrans/portfile.cmake').read_text()
        block=re.search(r'file\(RENAME "\$\{CURRENT_PACKAGES_DIR\}/include" .*?\)',port).group(0)
        (cls.prefix/'share/xtrans').mkdir(parents=True)
        script=cls.root/'move.cmake';script.write_text('set(PORT xtrans)\nset(CURRENT_PACKAGES_DIR "'+cls.prefix.as_posix()+'")\n'+block+'\n')
        # Move ONLY the actual Xtrans package staging include, not FFmpeg's headers.
        ff_headers=cls.prefix/'include';held=cls.root/'ff-headers';ff_headers.rename(held)
        (cls.prefix/'include/X11').mkdir(parents=True);shutil.move(str(held/'X11/Xtrans'),str(cls.prefix/'include/X11/Xtrans'))
        run(['cmake','-P',script],cls.root);shutil.move(str(held),str(cls.prefix/'include'))
        (cls.prefix/'include/X11').rmdir()
        for pkg,sp in POLICY['packages'].items():
            for n,e in sp['files'].items():
                data=(cls.prefix/sp['directory']/n).read_bytes()
                if checked.record(data)!={'size':e['size'],'sha256':e['sha256']} or checked.blob(data)!=e['blob']:
                    raise AssertionError('Installed interface does not match source-derived policy')
        # X11 headers supply declarations only; no host X11 library is linked.
        if not Path('/usr/include/X11/Xfuncproto.h').is_file():raise AssertionError('x11proto-dev test prerequisite missing')
        shutil.rmtree(cls.root/'ffmpeg');shutil.rmtree(cls.root/'xtrans');shutil.rmtree(build)

    def clients(self,prefix,root):
        root.mkdir();result={}
        for name,archive,arg in (('scale_video','libswscale.a','64x48'),('resample_audio','libswresample.a',None)):
            exe=root/name
            run(['cc','-I'+str(prefix/'include'),prefix/'share/ffmpeg/examples'/(name+'.c'),'-Wl,--start-group',
                 prefix/'lib'/archive,prefix/'lib/libavutil.a','-Wl,--end-group','-lm','-pthread','-o',exe],root)
            needed=set(re.findall(r'Shared library: \[([^\]]+)\]',run(['readelf','-d',exe],root).decode()))
            self.assertLessEqual(needed,{'libc.so.6','libm.so.6','ld-linux-x86-64.so.2','libpthread.so.0','librt.so.1'})
            output=root/(name+'.raw');run([exe,output]+([arg] if arg else []),root)
            data=output.read_bytes();self.assertGreater(len(set(data)),100)
            if name=='scale_video':self.assertEqual(len(data),100*64*48*3)
            else:self.assertGreater(len(data),2000000)
            result[name]=hashlib.sha256(data).hexdigest()
        source=root/'transport-client.c';source.write_text(XTRANS_CLIENT);exe=root/'transport-client'
        run(['cc','-D_DEFAULT_SOURCE','-I'+str(prefix/'share/xtrans/include'),source,'-o',exe],root);run([exe],root)
        needed=set(re.findall(r'Shared library: \[([^\]]+)\]',run(['readelf','-d',exe],root).decode()))
        self.assertLessEqual(needed,{'libc.so.6','ld-linux-x86-64.so.2'})
        return result

    def exercise(self,sdk,root):
        review=interfaces.verify(sdk);prefix=sdk/'installed'/T;before=fingerprint(prefix)
        baseline=self.clients(prefix,root/'baseline-clients')
        archive=root/'sdk.zip'
        with self.assertRaisesRegex(ValueError,'implementation source'):safeio.sdk_zip(sdk,archive)
        safeio.sdk_zip(sdk,archive,reviewed_interface_sources=review)
        self.assertEqual(fingerprint(prefix),before)
        moved=root/'moved';safeio.extract_zip(archive,moved);self.assertEqual(interfaces.verify(moved),review)
        shutil.rmtree(sdk)
        hidden=self.prefix.with_name('hidden-built-prefix');self.prefix.rename(hidden)
        self.addCleanup(lambda:hidden.rename(self.prefix) if hidden.exists() else None)
        self.assertFalse(self.prefix.exists())
        self.assertEqual(self.clients(moved/'installed'/T,root/'relocated-clients'),baseline)

    def test_real_installed_ffmpeg_samples_and_xtrans_inclusion_after_relocation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);sdk=root/'sdk';shutil.copytree(self.prefix,sdk/'installed'/T)
            for p in POLICY['packages']:owner(sdk,p)
            self.exercise(sdk,root)

    def test_real_vcpkg_transport_of_actual_libraries_and_both_source_interfaces(self):
        up=self.upstream
        if not (up/'bootstrap-vcpkg.sh').is_file():
            if os.environ.get('REQUIRE_CEF_SDK_INTERFACES')=='1':self.fail('Real vcpkg is required')
            self.skipTest('Real vcpkg is supplied in CI')
        if not (up/'vcpkg').is_file():run(['bash',up/'bootstrap-vcpkg.sh','-disableMetrics'],up)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            for pkg,sp in POLICY['packages'].items():
                port=root/'ports'/pkg;port.mkdir(parents=True);payload=port/'payload'
                if pkg=='ffmpeg':
                    shutil.copytree(self.prefix,payload);shutil.rmtree(payload/'share/xtrans')
                else:shutil.copytree(self.prefix/sp['directory'],payload/sp['directory'])
                (port/'vcpkg.json').write_text(json.dumps({'name':pkg,'version':sp['version']}))
                (port/'portfile.cmake').write_text('file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/payload/" DESTINATION "${CURRENT_PACKAGES_DIR}")\n'
                    'file(WRITE "${CURRENT_PACKAGES_DIR}/share/'+pkg+'/copyright" "Public upstream fixture licenses retained in source archives\n")\n'
                    + ('set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)\n' if pkg=='xtrans' else
                     'file(GLOB pcs "${CURRENT_PACKAGES_DIR}/lib/pkgconfig/*.pc")\n'
                     'foreach(pc IN LISTS pcs)\n'
                     'file(READ "${pc}" content)\n'
                     'string(REPLACE "'+self.prefix.as_posix()+'" "${CURRENT_INSTALLED_DIR}" content "${content}")\n'
                     'file(WRITE "${pc}" "${content}")\n'
                     'endforeach()\n'
                     'vcpkg_fixup_pkgconfig()\n'))
            args=['--triplet='+T,'--host-triplet='+T,'--overlay-triplets='+str(ROOT/'triplets'),'--overlay-ports='+str(root/'ports'),'--x-install-root='+str(root/'installed')]
            env=dict(os.environ,VCPKG_ROOT=str(up),VCPKG_DISABLE_METRICS='1')
            run([up/'vcpkg','install','ffmpeg','xtrans','--classic','--binarysource=clear',*args,
                 '--x-packages-root='+str(root/'packages'),'--x-buildtrees-root='+str(root/'buildtrees')],root,env=env)
            export=root/'export';export.mkdir();run([up/'vcpkg','export','ffmpeg','xtrans','--raw','--output=sdk','--output-dir='+str(export),*args],root,env=env)
            for n in ('ports','installed','packages','buildtrees'):shutil.rmtree(root/n)
            self.exercise(export/'sdk',root)


if __name__=='__main__':unittest.main()
