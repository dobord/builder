"""Native regression for #82: installed OBJECT libraries are SDK link inputs.

Real CMake exports and real ELF objects; the small channel implementations are
fixtures, not a claim that the production FreeRDP/CEF runtime is qualified.
Required CI also executes the pinned upstream channel installation macros and
real vcpkg install/export/ownership/ZIP/relocation before expensive restore.
"""
from __future__ import annotations
import copy
import inspect
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from secure_release import cef_sdk_objects as objects, safeio, cef_sdk_example as checked

ROOT = Path(__file__).resolve().parents[1]
T = objects.TRIPLET


def run(args, cwd, *, ok=True, env=None):
    p = subprocess.run(list(map(str, args)), cwd=cwd, env=env, capture_output=True,
                       text=True, timeout=180)
    if ok and p.returncode:
        raise AssertionError(p.stdout[-2000:] + p.stderr[-4000:])
    return p


def build(root, prefix, upstream=None):
    src = root/'source'; src.mkdir()
    (src/'drdynvc_main.c').write_text('int channel_value(void){return 7;}\n')
    (src/'extra.c').write_text('int channel_extra(void){return 3;}\n')
    (src/'server.c').write_text('int server_value(void){return 11;}\n')
    (src/'api.h').write_text('int channel_value(void);\n')
    (src/'base.c').write_text('int sdk_base(void){return 1;}\n')
    if upstream is None:
        logic = '''add_library(drdynvc-client OBJECT drdynvc_main.c extra.c)
add_library(rdpdr-server OBJECT server.c)
install(TARGETS drdynvc-client DESTINATION lib/freerdp3 EXPORT FreeRDP-ClientTargets)
install(TARGETS rdpdr-server DESTINATION lib/freerdp3 EXPORT FreeRDP-ServerTargets)
'''
    else:
        channel = (upstream/'channels/CMakeLists.txt').read_bytes()
        rpath = (upstream/'cmake/ConfigureRPATH.cmake').read_bytes()
        if checked.blob(channel) != CHANNEL_BLOB or checked.blob(rpath) != RPATH_BLOB:
            raise AssertionError('Pinned full upstream install inputs changed')
        # Execute original macro bodies from the byte-bound complete file.
        # Only subsequent subdirectory discovery is omitted for the small fixture.
        (src/'channels.cmake').write_bytes(channel.split(b'set(FILENAME "ChannelOptions.cmake")')[0])
        (src/'rpath.cmake').write_bytes(rpath)
        logic = '''set(CMAKE_INSTALL_LIBDIR lib)
set(FREERDP_ADDIN_PATH lib/freerdp3)
set(FREERDP_VERSION_MAJOR 3)
set(BUILD_SHARED_LIBS OFF)
include(rpath.cmake)
include(channels.cmake)
set(CLIENT_SRCS drdynvc_main.c extra.c)
set(SERVER_SRCS server.c)
add_channel_client_library(CLIENT drdynvc-client drdynvc FALSE "entry")
add_channel_server_library(SERVER rdpdr-server rdpdr FALSE "entry")
'''
    (src/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(object_export C)\n'+logic+'''
install(EXPORT FreeRDP-ClientTargets DESTINATION share/freerdp-client3)
install(EXPORT FreeRDP-ServerTargets DESTINATION share/freerdp-server3)
install(FILES api.h DESTINATION include/freerdp3)
add_library(sdk-base STATIC base.c)
install(TARGETS sdk-base ARCHIVE DESTINATION lib)
''')
    run(['cmake','-S',src,'-B',root/'build','-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_INSTALL_PREFIX='+str(prefix)],root)
    run(['cmake','--build',root/'build','--target','install','-j2'],root)


def own(installed):
    listing=installed/'vcpkg/info'/('freerdp_3.31.1_'+T+'.list')
    listing.parent.mkdir(parents=True)
    listing.write_text(''.join(T+'/'+p.relative_to(installed/T).as_posix()+'\n'
                              for p in sorted((installed/T).rglob('*')) if p.is_file()))
    return listing


def consume(root, prefix, label='consumer', *, ok=True):
    src=root/(label+'-source');src.mkdir()
    (src/'main.c').write_text('int channel_value(void);int channel_extra(void);int server_value(void);\n'
                             'int main(void){return channel_value()+channel_extra()+server_value()!=21;}\n')
    (src/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(client C)\n'+
        ''.join('include("'+(prefix/(export+'.cmake')).as_posix()+'")\n' for export in objects.EXPORTS)+
        'add_executable(client main.c)\ntarget_link_libraries(client PRIVATE drdynvc-client rdpdr-server)\n')
    p=run(['cmake','-S',src,'-B',root/(label+'-build'),'-DCMAKE_BUILD_TYPE=Release'],root,ok=ok)
    if not ok:return p
    run(['cmake','--build',root/(label+'-build'),'-j2'],root)
    executable=root/(label+'-build/client');run([executable],root)
    elf=run(['readelf','-d',executable],root).stdout
    needed=__import__('re').findall(r'Shared library: \[([^]]+)\]',elf)
    if set(needed)-{'libc.so.6','ld-linux-x86-64.so.2'}:raise AssertionError('Non-OS fixture dependency')
    return p


CHANNEL_BLOB = '91a26e3c51c60ff691c11a27ba7dc819d947484c'
RPATH_BLOB = '0e11f77bba0bfc8230b59c70e3892639ae09f9e6'


@unittest.skipUnless(sys.platform=='linux', 'ELF64 native SDK object fixture')
class NativeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.sdk=self.root/'sdk';self.installed=self.sdk/'installed'
        self.prefix=self.installed/T
        build(self.root,self.prefix)
        self.owner=own(self.installed)
        self.receipt=objects.capture(self.installed)
        self.review=objects.verify(self.installed,self.receipt)
        self.file=self.sdk/next(iter(self.review))

    def test_82_missing_object_reproduces_real_import_failure_then_relocated_link_succeeds(self):
        before={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in self.prefix.rglob('*') if p.is_file()}
        # Reproduce #82's precise old .o omission with unchanged generated exports.
        with zipfile.ZipFile(self.root/'old.zip','w') as z:
            for p in self.sdk.rglob('*'):
                if p.is_file() and p.suffix!='.o':z.write(p,p.relative_to(self.sdk))
        old=self.root/'old';safeio.extract_zip(self.root/'old.zip',old)
        failed=consume(self.root,old/'installed'/T,'old-consumer',ok=False)
        self.assertNotEqual(failed.returncode,0)
        self.assertIn('does not exist',failed.stderr)
        self.assertIn('drdynvc_main.c.o',failed.stderr)
        safeio.sdk_zip(self.sdk,self.root/'sdk.zip',reviewed_objects=self.review)
        for p,identity in before.items():self.assertEqual((p.read_bytes(),p.stat().st_mtime_ns),identity)
        moved=self.root/'moved';safeio.extract_zip(self.root/'sdk.zip',moved)
        for path in (self.sdk,self.root/'source',self.root/'build'):shutil.rmtree(path)
        self.assertEqual(objects.verify(moved/'installed',self.receipt),self.review)
        consume(self.root,moved/'installed'/T)

    def test_default_never_silently_drops_installed_objects_or_changes_existing_zip(self):
        with self.assertRaisesRegex(ValueError,'unreviewed installed object'):
            safeio.sdk_zip(self.sdk,self.root/'sdk.zip')
        self.assertFalse((self.root/'sdk.zip').exists())
        (self.root/'sdk.zip').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):safeio.sdk_zip(self.sdk,self.root/'sdk.zip',reviewed_objects=self.review)
        self.assertEqual((self.root/'sdk.zip').read_bytes(),b'keep')

    def test_missing_or_modified_object_is_fatal_before_pack_and_after_relocation(self):
        original=self.file.read_bytes()
        self.file.write_bytes(original[:-1]+bytes([original[-1]^1]))
        with self.assertRaises(ValueError):objects.verify(self.installed,self.receipt)
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.root/'bad.zip',reviewed_objects=self.review)
        self.assertFalse((self.root/'bad.zip').exists())
        self.file.unlink()
        with self.assertRaises(ValueError):objects.verify(self.installed,self.receipt)
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.root/'absent.zip',reviewed_objects=self.review)

    def test_exact_export_metadata_and_external_receipt_cannot_be_self_blessed(self):
        with self.assertRaises(ValueError):objects.verify(self.installed,{})
        file=self.prefix/(objects.EXPORTS[0]+'-release.cmake')
        file.write_text(file.read_text()+'\n# changed after capture\n')
        with self.assertRaisesRegex(ValueError,'transport'):objects.verify(self.installed,self.receipt)

    def test_owner_missing_duplicate_or_other_package_or_version_fails(self):
        data=self.owner.read_text()
        for altered in ('', data+data, '\n'.join(line for line in data.splitlines() if not line.endswith('drdynvc_main.c.o'))+'\n'):
            self.owner.write_text(altered)
            with self.assertRaises(ValueError):objects.verify(self.installed,self.receipt)
        self.owner.write_text(data)
        for name in ('other_3.31.1_'+T+'.list','freerdp_3.31.2_'+T+'.list'):
            other=self.owner.with_name(name);self.owner.rename(other)
            with self.assertRaises(ValueError):objects.verify(self.installed,self.receipt)
            other.rename(self.owner)

    def test_redirected_paths_modes_and_nonrelocatable_elf_are_rejected(self):
        data=self.file.read_bytes()
        self.file.chmod(0o755)
        with self.assertRaises(ValueError):objects.verify(self.installed,self.receipt)
        self.file.chmod(0o644)
        for offset,value in ((16,3),(18,183),(4,1)):
            changed=bytearray(data);changed[offset]=value;self.file.write_bytes(changed)
            with self.assertRaises(ValueError):objects.capture(self.installed)
        self.file.write_bytes(data)
        target=self.root/'real.o';self.file.rename(target);self.file.symlink_to(target)
        with self.assertRaises(ValueError):objects.verify(self.installed,self.receipt)
        with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.root/'bad.zip',reviewed_objects=self.review)

    def test_unreferenced_object_or_changed_binding_or_config_fails(self):
        extra=self.file.with_name('unknown.c.o');extra.write_bytes(self.file.read_bytes())
        with self.assertRaisesRegex(ValueError,'Unreferenced'):objects.capture(self.installed)
        extra.unlink()
        decl=(self.prefix/(objects.EXPORTS[0]+'.cmake')).read_text()
        cfg=(self.prefix/(objects.EXPORTS[0]+'-release.cmake')).read_text()
        for value in (cfg.replace('IMPORTED_OBJECTS_RELEASE','IMPORTED_OBJECTS_DEBUG'),
                      cfg.replace('${_IMPORT_PREFIX}/lib','/usr/lib'),
                      cfg.replace('/drdynvc-client/','/other/'),
                      cfg.replace('drdynvc_main.c.o','../drdynvc_main.c.o')):
            with self.assertRaises(ValueError):objects.imported_objects(decl,value)

    def test_verified_object_buffer_not_reread_during_zip_write(self):
        original=self.file.read_bytes();open_zip=zipfile.ZipFile.open
        member=self.file.relative_to(self.sdk).as_posix()
        def writer(z,name,*args,**kwargs):
            if isinstance(name,zipfile.ZipInfo) and name.filename==member:
                self.file.write_bytes(b'changed')
            return open_zip(z,name,*args,**kwargs)
        with mock.patch.object(zipfile.ZipFile,'open',writer):
            safeio.sdk_zip(self.sdk,self.root/'race.zip',reviewed_objects=self.review)
        with zipfile.ZipFile(self.root/'race.zip') as z:self.assertEqual(z.read(member),original)

    def test_source_and_shared_library_rules_remain_mandatory(self):
        for name in ('lib/evil.so','include/leak.cpp'):
            path=self.prefix/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('not approved')
            with self.assertRaises(ValueError):safeio.sdk_zip(self.sdk,self.root/'bad.zip',reviewed_objects=self.review)
            path.unlink()


class PolicyTests(unittest.TestCase):
    def test_review_schema_scope_limits_and_no_arbitrary_object_permission(self):
        member='installed/'+T+'/lib/freerdp3/objects-Release/drdynvc-client/drdynvc_main.c.o'
        record={'size':256,'sha256':'a'*64}
        self.assertEqual(safeio._object_review({member:record}),{member:record})
        for name in (member.replace(T,'x'),member.replace('Release','Debug'),member.replace('freerdp3','other'),
                     member.replace('.c.o','.obj'),member.replace('lib/','bin/'),member.replace('/drdynvc_main','/../drdynvc_main')):
            with self.assertRaises(ValueError):safeio._object_review({name:record})
        for size in (0,True,safeio.MAX_REVIEWED_OBJECT_BYTES+1):
            with self.assertRaises(ValueError):safeio._object_review({member:dict(record,size=size)})
        with self.assertRaises(ValueError):safeio._object_review({})

    def test_production_order_and_required_native_preflight(self):
        from secure_release import cef_strict_combined as combined
        text=inspect.getsource(combined.main)
        self.assertLess(text.index('cef_sdk_objects.validate_sources(registry)'),text.index('restore_checkpoint('))
        self.assertLess(text.index('object_review = cef_sdk_objects.capture(installed)'),text.index('stage = "vcpkg-export"'))
        self.assertLess(text.index('reviewed_objects = cef_sdk_objects.verify('),text.index('safeio.sdk_zip(sdk,'))
        self.assertIn('reviewed_objects=reviewed_objects',text)
        self.assertLess(text.index('shutil.rmtree(export_root)'),text.rindex('cef_sdk_objects.verify('))
        self.assertIn('cef_build.verify_consumer(',text)
        workflow=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn("REQUIRE_CEF_SDK_OBJECTS: '1'",workflow)
        self.assertLess(workflow.index('-p test_cef_sdk_objects.py'),workflow.index('name: Run checkpoint-resumed final'))

    def test_actual_pinned_registry_origin_before_source_guards(self):
        raw=os.environ.get('CEF_SDK_OBJECTS_REGISTRY')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_OBJECTS')=='1':self.fail('Registry fixture required')
            self.skipTest('Pinned registry checkout required in CI')
        objects.validate_sources(Path(raw))


@unittest.skipUnless(sys.platform=='linux','Native exported object installation')
class UpstreamTests(unittest.TestCase):
    def source(self):
        raw=os.environ.get('CEF_SDK_OBJECTS_SOURCE')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_OBJECTS')=='1':self.fail('Pinned FreeRDP source required')
            self.skipTest('Pinned FreeRDP source supplied in CI')
        return Path(raw)

    def test_actual_full_pinned_channel_macros_install_relocatable_objects(self):
        source=self.source()
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();sdk=root/'sdk';installed=sdk/'installed'
            build(root,installed/T,source);own(installed)
            review=objects.capture(installed)
            safeio.sdk_zip(sdk,root/'sdk.zip',reviewed_objects=objects.verify(installed,review))
            moved=root/'moved';safeio.extract_zip(root/'sdk.zip',moved)
            for p in (sdk,root/'source',root/'build'):shutil.rmtree(p)
            objects.verify(moved/'installed',review);consume(root,moved/'installed'/T)

    def test_real_vcpkg_objects_raw_export_zip_owner_and_relocated_link(self):
        source=self.source();raw=os.environ.get('CEF_SDK_OBJECTS_VCPKG')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_OBJECTS')=='1':self.fail('Native vcpkg required')
            self.skipTest('Native vcpkg supplied in CI')
        upstream=Path(raw).resolve()
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve();prepared=root/'prepared';build(root,prepared,source)
            port=root/'ports/freerdp';port.mkdir(parents=True)
            (port/'vcpkg.json').write_text('{"name":"freerdp","version":"3.31.1"}')
            shutil.copytree(prepared,port/'payload')
            (port/'portfile.cmake').write_text('file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/payload/" DESTINATION "${CURRENT_PACKAGES_DIR}")\n'
                'file(WRITE "${CURRENT_PACKAGES_DIR}/share/freerdp/copyright" "Disposable channel object transport fixture\n")\n')
            env=dict(os.environ,VCPKG_ROOT=str(upstream),VCPKG_DISABLE_METRICS='1')
            if not (upstream/'vcpkg').is_file():run(['bash',upstream/'bootstrap-vcpkg.sh','-disableMetrics'],upstream,env=env)
            installed=root/'installed'
            args=['--triplet='+T,'--host-triplet='+T,'--overlay-triplets='+str(ROOT/'triplets'),
                  '--overlay-ports='+str(port.parent),'--x-install-root='+str(installed)]
            run([upstream/'vcpkg','install','freerdp','--classic','--binarysource=clear',*args,
                 '--x-packages-root='+str(root/'packages'),'--x-buildtrees-root='+str(root/'buildtrees')],root,env=env)
            receipt=objects.capture(installed);out=root/'export';out.mkdir()
            run([upstream/'vcpkg','export','freerdp','--raw','--output=sdk','--output-dir='+str(out),*args],root,env=env)
            sdk=out/'sdk';review=objects.verify(sdk/'installed',receipt)
            safeio.sdk_zip(sdk,root/'sdk.zip',reviewed_objects=review)
            moved=root/'moved';safeio.extract_zip(root/'sdk.zip',moved)
            for p in (out,installed,port.parent,root/'packages',root/'buildtrees',root/'source',root/'build',prepared):
                if p.exists():shutil.rmtree(p)
            objects.verify(moved/'installed',receipt);consume(root,moved/'installed'/T)


if __name__=='__main__':unittest.main()
