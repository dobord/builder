"""Versioned executable transport regressions, not actual protobuf/CEF qualification.

Execute the FULL pinned upstream protoc target definition with disposable
libraries and a tiny CLI. The mandatory vcpkg case exercises real installation,
raw export, ZIP/extraction, owner records and execution after deleting producers.
Production additionally runs the real installed protoc message codec itself.
"""
from __future__ import annotations
import copy
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from secure_release import cef_sdk_protoc as tool, cef_sdk_aliases as aliases
from secure_release import safeio, cef_sdk_example as checked

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/cef-sdk-protoc/protoc.cmake'
BLOB = '385a7a3f3989ff3ba75ef73b787fe3e6db10033e'
T = tool.TRIPLET
# Not protobuf: only a deterministic test CLI exercising preservation of an
# executable through native CMake/vcpkg/ZIP transport. No plugin execution.
CLI = r'''#include <cstdio>
#include <cstring>
int main(int argc,char**argv){
 if(argc<2)return 9;
 if(!strcmp(argv[1],"--version")){puts("libprotoc 33.4");return 0;}
 if(!strcmp(argv[1],"--encode=sdk_probe.Value")){fputc(8,stdout);fputc(7,stdout);return 0;}
 if(!strcmp(argv[1],"--decode=sdk_probe.Value")){puts("value: 7");return 0;}
 return 8;
}
'''


def run(args, root, env=None):
    result = subprocess.run(list(map(str,args)),cwd=root,env=env,capture_output=True,text=True,timeout=240)
    if result.returncode:
        raise AssertionError(result.stdout[-2000:] + result.stderr[-4000:])
    return result.stdout


def build_tool(root: Path, prefix: Path):
    src=root/'source';main=src/'src/google/protobuf/compiler/main.cc'
    main.parent.mkdir(parents=True);main.write_text(CLI)
    (src/'stub.cc').write_text('int tool_transport_fixture(void){return 0;}\n')
    (src/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(pinned_protoc CXX)\n'
        'set(protobuf_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")\nset(protobuf_VERSION 33.4.0)\n'
        'add_library(libprotoc STATIC stub.cc)\nadd_library(libprotobuf STATIC stub.cc)\n'
        'include("'+FIXTURE.as_posix()+'")\ninstall(TARGETS protoc RUNTIME DESTINATION tools/protobuf)\n')
    run(['cmake','-S',src,'-B',root/'build','-DCMAKE_INSTALL_PREFIX='+str(prefix)],root)
    run(['cmake','--build',root/'build','--target','install','-j2'],root)
    return src


def write_owner(installed: Path):
    info=installed/'vcpkg/info';info.mkdir(parents=True,exist_ok=True)
    listing=info/('protobuf_6.33.4#2_'+T+'.list')
    listing.write_text(T+'/'+tool.NAME+'\n'+T+'/tools/protobuf/'+tool.TARGET+'\n')
    return listing


def receipt(record):
    return dict(schema=1,kind='pinned-installed-protoc',origins=dict(tool.ORIGINS),record=record)


class PolicyTests(unittest.TestCase):
    def test_complete_upstream_target_is_pinned_and_executable_is_versioned(self):
        self.assertEqual(checked.blob(FIXTURE.read_bytes()),BLOB)
        self.assertIn('VERSION ${protobuf_VERSION}',FIXTURE.read_text())
        self.assertEqual(tool.ORIGINS['ports/protobuf/portfile.cmake'],
                         'b4ccf9fced440e9d84dda2e86e18ff2f89e5b2c5')

    def test_only_exact_host_tool_path_target_and_mode_can_extend_alias_policy(self):
        record=dict(target=tool.TARGET,size=1234,sha256='a'*64,mode=0o755)
        self.assertEqual(safeio._alias_review({safeio.PROTOC_ALIAS:record})[safeio.PROTOC_ALIAS],record)
        for name in (safeio.PROTOC_ALIAS.replace('tools','lib'),
                     safeio.PROTOC_ALIAS.replace('protobuf','other'),
                     safeio.PROTOC_ALIAS.replace('protoc','tool'),
                     safeio.PROTOC_ALIAS.replace(T,'other-triplet')):
            with self.subTest(name=name),self.assertRaises(ValueError):safeio._alias_review({name:record})
        for key,value in [('target','protoc-33.5.0'),('target','../protoc-33.4.0'),
                          ('mode',0o777),('mode',0o4755),('mode',True),('size',0),
                          ('size',safeio.MAX_REVIEWED_PROTOC_BYTES+1)]:
            bad=dict(record);bad[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):safeio._alias_review({safeio.PROTOC_ALIAS:bad})
        for name in ('installed/x/lib/liba.a','installed/x/lib/pkgconfig/a.pc'):
            bad=dict(record,target='libb.a' if name.endswith('.a') else 'b.pc')
            with self.assertRaises(ValueError):safeio._alias_review({name:bad})

    def test_missing_receipt_never_approved_and_orchestration_binds_before_export(self):
        with self.assertRaises(ValueError):tool.verify(Path('absent'),{})
        from secure_release import cef_strict_combined as combined
        text=inspect.getsource(combined.main)
        self.assertLess(text.index('cef_sdk_protoc.validate_sources(upstream)'),text.index('restore_checkpoint('))
        self.assertLess(text.index('protoc_review = cef_sdk_protoc.capture('),text.index('stage = "vcpkg-export"'))
        self.assertIn('protoc_review=protoc_review',text)
        self.assertLess(text.index('shutil.rmtree(export_root)'),text.index('stage = "relocated-protoc-proof"'))
        self.assertIn('cef_build.verify_consumer(',text)
        workflow=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn("REQUIRE_CEF_SDK_PROTOC: '1'",workflow)
        self.assertLess(workflow.index('-p test_cef_sdk_protoc.py'),workflow.index('name: Run checkpoint-resumed final'))


@unittest.skipUnless(sys.platform=='linux','Native versioned ELF fixture')
class NativeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.sdk=self.root/'sdk';self.installed=self.sdk/'installed'
        self.prefix=self.installed/T;self.prefix.mkdir(parents=True)
        build_tool(self.root,self.prefix)
        self.alias=self.prefix/tool.NAME;self.target=self.alias.with_name(tool.TARGET)
        self.listing=write_owner(self.installed)
        self.record,_=tool.payload(self.installed);self.review=receipt(self.record)

    def test_79_real_cmake_symlink_reproduces_then_regular_executable_roundtrips(self):
        self.assertTrue(self.alias.is_symlink());self.assertEqual(os.readlink(self.alias),tool.TARGET)
        before=(self.target.read_bytes(),self.target.stat().st_mtime_ns,self.alias.lstat().st_mtime_ns)
        with self.assertRaisesRegex(ValueError,'cannot package link'):
            safeio.sdk_zip(self.sdk,self.root/'old.zip')
        with mock.patch.object(tool,'validate_sources') as validate:
            self.assertEqual(tool.capture(self.installed,self.root/'upstream',self.root/'probe'),self.review)
            validate.assert_called_once()
        plan=tool.verify(self.installed,self.review)
        safeio.sdk_zip(self.sdk,self.root/'sdk.zip',reviewed_aliases=plan)
        with zipfile.ZipFile(self.root/'sdk.zip') as z:
            for n in (safeio.PROTOC_ALIAS,str(Path(safeio.PROTOC_ALIAS).with_name(tool.TARGET))):
                i=z.getinfo(n);self.assertEqual(stat.S_IFMT(i.external_attr>>16),stat.S_IFREG)
                self.assertEqual(stat.S_IMODE(i.external_attr>>16),0o755)
                self.assertEqual(z.read(n),before[0])
        self.assertEqual(before,(self.target.read_bytes(),self.target.stat().st_mtime_ns,self.alias.lstat().st_mtime_ns))
        relocated=self.root/'relocated';safeio.extract_zip(self.root/'sdk.zip',relocated)
        for p in (self.sdk,self.root/'source',self.root/'build'):shutil.rmtree(p)
        self.assertFalse((relocated/safeio.PROTOC_ALIAS).is_symlink())
        self.assertEqual(tool.verify(relocated/'installed',self.review,self.root/'moved-probe'),plan)

    def test_integrated_library_and_tool_alias_reviews_require_external_capture(self):
        from test_cef_sdk_aliases import AliasTests
        previous=AliasTests('test_default_78_failure_then_materialized_roundtrip_and_source_preserved')
        previous.setUp(); self.addCleanup(previous.doCleanups)
        shutil.copytree(self.prefix/'tools',previous.prefix/'tools',symlinks=True)
        write_owner(previous.sdk/'installed')
        with self.assertRaisesRegex(ValueError,'unreviewed links'):
            aliases.verify(previous.sdk,previous.manifest,previous.sha)
        plan=aliases.verify(previous.sdk,previous.manifest,previous.sha,protoc_review=self.review)
        self.assertEqual(len(plan),3)
        archive=self.root/'three.zip';safeio.sdk_zip(previous.sdk,archive,reviewed_aliases=plan)
        relocated=self.root/'three';safeio.extract_zip(archive,relocated)
        self.assertEqual(aliases.verify(relocated,previous.manifest,previous.sha,
                         expected=plan,protoc_review=self.review),plan)
        with self.assertRaisesRegex(ValueError,'bytes changed'):
            aliases.verify(relocated,previous.manifest,previous.sha,expected=plan)
        tool.verify(relocated/'installed',self.review,self.root/'three-probe')

    def test_byte_mode_and_kind_mutations_fail_before_export_and_after_capture(self):
        data=self.target.read_bytes()
        for mode in (0o644,0o777,0o4755):
            self.target.chmod(mode)
            with self.subTest(mode=mode),self.assertRaises(ValueError):tool.verify(self.installed,self.review)
        self.target.chmod(0o755)
        self.target.write_bytes(data[:-1]+bytes([data[-1]^1]))
        with self.assertRaisesRegex(ValueError,'bytes changed'):tool.verify(self.installed,self.review)
        self.target.write_bytes(b'#!/bin/sh\necho hello\n');self.target.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'native executable'):tool.payload(self.installed)

    def test_wrong_missing_duplicate_owner_and_version_are_rejected(self):
        original=self.listing.read_text()
        self.listing.write_text(original.splitlines()[0]+'\n')
        with self.assertRaisesRegex(ValueError,'unowned'):tool.verify(self.installed,self.review)
        self.listing.write_text(original+original)
        with self.assertRaisesRegex(ValueError,'owner'):tool.verify(self.installed,self.review)
        self.listing.write_text(original);renamed=self.listing.with_name('protobuf_6.34.0_'+T+'.list')
        self.listing.rename(renamed)
        with self.assertRaisesRegex(ValueError,'owner'):tool.verify(self.installed,self.review)

    def test_absolute_escape_chain_missing_parent_and_special_files_fail(self):
        for target in (str(self.target),'../protobuf/'+tool.TARGET,'elsewhere', '.', 'missing'):
            self.alias.unlink();self.alias.symlink_to(target)
            with self.subTest(target=target),self.assertRaises((ValueError,OSError)):tool.verify(self.installed,self.review)
        self.alias.unlink();self.alias.symlink_to(tool.TARGET)
        data=self.target.read_bytes();self.target.unlink();outside=self.root/'outside';outside.write_bytes(data);outside.chmod(0o755)
        self.target.symlink_to(outside)
        with self.assertRaises(ValueError):tool.verify(self.installed,self.review)
        self.target.unlink();os.mkfifo(self.target)
        with self.assertRaises(ValueError):tool.verify(self.installed,self.review)

    def test_same_verified_buffer_mode_written_and_raced_canonical_is_rejected(self):
        original=safeio._alias_bytes;calls=0
        def change_after_read(p,record):
            nonlocal calls
            data=original(p,record);calls+=1
            if calls==1:self.target.chmod(0o644)
            return data
        plan=tool.verify(self.installed,self.review)
        with mock.patch.object(safeio,'_alias_bytes',side_effect=change_after_read):
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.root/'bad.zip',reviewed_aliases=plan)
        self.assertFalse((self.root/'bad.zip').exists())

    def test_alias_self_receipt_invalid_origins_and_missing_mode_are_rejected(self):
        for field in ('origins','kind','schema','record'):
            bad=copy.deepcopy(self.review);bad[field]={}
            with self.subTest(field=field),self.assertRaises(ValueError):tool.verify(self.installed,bad)
        bad=copy.deepcopy(self.review);bad['record'].pop('mode')
        with self.assertRaises(ValueError):tool.verify(self.installed,bad)

    def test_all_nonregular_inventory_keeps_unknown_tools_fatal(self):
        report=self.root/'diag/links.json'
        with self.assertRaisesRegex(ValueError,'unreviewed links'):aliases.inventory_links(self.sdk,report)
        entries=json.loads(report.read_bytes())['entries'];self.assertEqual(len(entries),1)
        self.assertFalse(entries[0]['known_name']);report.unlink()
        aliases.inventory_links(self.sdk,report,protoc=True)
        self.assertTrue(json.loads(report.read_bytes())['entries'][0]['known_name'])
        (self.prefix/'tools/protobuf/other').symlink_to(tool.TARGET);report.unlink()
        with self.assertRaisesRegex(ValueError,'unreviewed links'):aliases.inventory_links(self.sdk,report,protoc=True)
        self.assertEqual(len(json.loads(report.read_bytes())['entries']),2)

    def test_protobuf_cli_failures_do_not_become_target_runtime_success(self):
        with mock.patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')):
            with self.assertRaisesRegex(ValueError,'host-tool'):tool.probe(self.installed,self.record,self.root/'bad-probe')
        self.assertNotIn('runtime_verified',self.review)


class RequiredSources(unittest.TestCase):
    def test_whole_pinned_port_and_version_policy_in_actual_ci(self):
        raw=os.environ.get('CEF_SDK_PROTOC_VCPKG_ROOT')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_PROTOC')=='1':self.fail('Pinned vcpkg is required')
            self.skipTest('Pinned full vcpkg source supplied by required CI')
        tool.validate_sources(Path(raw))


@unittest.skipUnless(sys.platform=='linux','Native vcpkg executable transport fixture')
class NativeVcpkgTests(unittest.TestCase):
    def test_real_vcpkg_install_export_and_owned_relocated_executable(self):
        raw=os.environ.get('CEF_SDK_PROTOC_VCPKG_ROOT')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_PROTOC')=='1':self.fail('Native vcpkg is required')
            self.skipTest('Real native vcpkg supplied by required CI')
        upstream=Path(raw).resolve(strict=True);tool.validate_sources(upstream)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();prebuilt=root/'prepared';prebuilt.mkdir()
            build_tool(root,prebuilt)
            ports=root/'ports';port=ports/'protobuf';port.mkdir(parents=True)
            (port/'vcpkg.json').write_text('{"name":"protobuf","version":"6.33.4","port-version":2}')
            shutil.copytree(prebuilt/'tools',port/'tools',symlinks=True)
            (port/'portfile.cmake').write_text('''file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/tools/" DESTINATION "${CURRENT_PACKAGES_DIR}/tools" USE_SOURCE_PERMISSIONS)
file(WRITE "${CURRENT_PACKAGES_DIR}/share/protobuf/copyright" "Disposable native transport fixture\\n")
set(VCPKG_POLICY_EMPTY_PACKAGE enabled)
''')
            env=dict(os.environ,VCPKG_ROOT=str(upstream),VCPKG_DISABLE_METRICS='1')
            if not (upstream/'vcpkg').is_file():run(['bash',upstream/'bootstrap-vcpkg.sh','-disableMetrics'],upstream,env)
            installed=root/'installed'
            args=['--triplet='+T,'--host-triplet='+T,'--overlay-triplets='+str(ROOT/'triplets'),
                  '--overlay-ports='+str(ports),'--x-install-root='+str(installed)]
            run([upstream/'vcpkg','install','protobuf','--classic','--binarysource=clear',*args,
                 '--x-packages-root='+str(root/'packages'),'--x-buildtrees-root='+str(root/'buildtrees')],root,env)
            review=tool.capture(installed,upstream,root/'install-proof')
            out=root/'export';out.mkdir()
            run([upstream/'vcpkg','export','protobuf','--raw','--output=sdk','--output-dir='+str(out),*args],root,env)
            sdk=out/'sdk';plan=tool.verify(sdk/'installed',review)
            safeio.sdk_zip(sdk,root/'sdk.zip',reviewed_aliases=plan)
            moved=root/'moved';safeio.extract_zip(root/'sdk.zip',moved)
            for p in (out,installed,ports,root/'packages',root/'buildtrees',root/'source',root/'build',prebuilt):
                if p.exists():shutil.rmtree(p)
            self.assertEqual(tool.verify(moved/'installed',review,root/'relocated-proof'),plan)
            self.assertEqual((moved/safeio.PROTOC_ALIAS).stat().st_mode&0o777,0o755)


if __name__=='__main__':unittest.main()
