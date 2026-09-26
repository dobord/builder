"""Exact installed-example packaging and native relocation, not full CEF proof."""
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

from secure_release import cef_sdk_example as example, safeio

ROOT = Path(__file__).resolve().parents[1]
CPP = b'#include "freerdp_graphics_mode_args.hpp"\nextern "C" int value(void);\nint main(){return value()!=expected_value;}\n'
HEADER = b'#pragma once\nconstexpr int expected_value=73;\n'
PROJECT = b'''cmake_minimum_required(VERSION 3.24)
project(installed_example CXX)
add_executable(example freerdp_proxy_web_engine_view_cef.cpp)
target_link_libraries(example PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../lib/libfixture.a")
'''
FIXTURES = dict(zip(example.ORIGINS, (CPP, HEADER, PROJECT)))


def run(args, root, *, env=None, timeout=240):
    p = subprocess.run(list(map(str, args)), cwd=root, env=env, text=True,
                       capture_output=True, timeout=timeout)
    if p.returncode:
        raise AssertionError(p.stdout[-2000:] + p.stderr[-4000:])
    return p.stdout


def make_sources(root):
    lfc, registry = root / 'lfc-ui', root / 'registry'
    origins = {}
    for name, (owner, relative, _) in example.ORIGINS.items():
        path = (lfc if owner == 'lfc_ui' else registry) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = FIXTURES[name]; path.write_bytes(data)
        origins[name] = (owner, relative, example.blob(data))
    port = registry / 'ports/lfc-ui/portfile.cmake'
    port.write_bytes(b'# public synthetic port installation policy\n')
    return lfc, registry, origins, example.blob(port.read_bytes())


def populate(sdk):
    dest = sdk / 'installed' / example.TRIPLET / example.EXAMPLE
    dest.mkdir(parents=True)
    for name, data in FIXTURES.items():
        (dest / name).write_bytes(data)
    info = sdk / 'installed/vcpkg/info'; info.mkdir(parents=True)
    listing = info / ('lfc-ui_1.0_' + example.TRIPLET + '.list')
    listing.write_text(''.join(example.TRIPLET + '/' + example.EXAMPLE + '/' + name + '\n'
                               for name in FIXTURES))
    return dest, listing


class ExampleTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.root = Path(t.name).resolve()
        self.lfc, self.registry, origins, port = make_sources(self.root)
        m = mock.patch.object(example, 'ORIGINS', origins); m.start(); self.addCleanup(m.stop)
        m = mock.patch.object(example, 'PORT_BLOB', port); m.start(); self.addCleanup(m.stop)
        self.review = example.capture(self.lfc, self.registry)
        self.sdk = self.root / 'sdk'
        self.dest, self.listing = populate(self.sdk)
        self.archive = self.root / 'sdk.zip'

    def test_default_reproduces_source_failure_exact_review_roundtrips(self):
        with self.assertRaisesRegex(ValueError, 'implementation source'):
            safeio.sdk_zip(self.sdk, self.archive)
        self.assertFalse(self.archive.exists())
        approval = example.verify(self.sdk, self.review)
        self.assertEqual(len(approval), 1)
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.sdk.rglob('*') if p.is_file()}
        safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=approval)
        moved = self.root / 'consumer'; safeio.extract_zip(self.archive, moved)
        self.assertEqual(example.verify(moved, self.review), approval)
        self.assertEqual({p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}, before)

    def test_pinned_source_helper_project_and_port_drift_fail(self):
        paths = [self.registry / 'ports/lfc-ui/portfile.cmake'] + [
            (self.lfc if owner == 'lfc_ui' else self.registry) / rel
            for owner, rel, _ in example.ORIGINS.values()]
        for path in paths:
            with self.subTest(path=path.name):
                data = path.read_bytes(); path.write_bytes(data+b'changed')
                with self.assertRaisesRegex(ValueError, 'Pinned'):
                    example.capture(self.lfc, self.registry)
                path.write_bytes(data)

    def test_installed_and_relocated_sidecars_cannot_change(self):
        for name in FIXTURES:
            path = self.dest / name; data = path.read_bytes()
            path.write_bytes(data+b'changed')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'bytes differ'):
                example.verify(self.sdk, self.review)
            path.write_bytes(data)
        (self.dest / 'hidden.cpp').write_text('int internal;')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            example.verify(self.sdk, self.review)

    def test_owner_missing_wrong_or_duplicated_is_fatal(self):
        original = self.listing.read_bytes()
        self.listing.write_text(example.TRIPLET + '/share/unrelated\n')
        with self.assertRaisesRegex(ValueError, 'ownership'): example.verify(self.sdk, self.review)
        wrong = self.listing.with_name('other_1.0_' + example.TRIPLET + '.list')
        self.listing.rename(wrong); wrong.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'ownership'): example.verify(self.sdk, self.review)
        self.listing.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'Duplicate'): example.verify(self.sdk, self.review)

    def test_approval_does_not_admit_other_implementation_source(self):
        approval = example.verify(self.sdk, self.review)
        (self.sdk / 'internal.cpp').write_text('int internal;')
        with self.assertRaisesRegex(ValueError, 'implementation source'):
            safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=approval)
        self.assertFalse(self.archive.exists())

    def test_reviewed_missing_or_tampered_source_cannot_leave_a_zip(self):
        approval = example.verify(self.sdk, self.review)
        path = self.dest / 'freerdp_proxy_web_engine_view_cef.cpp'
        data = path.read_bytes(); path.write_bytes(data+b'\n')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=approval)
        self.assertFalse(self.archive.exists())
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=approval)
        self.assertFalse(self.archive.exists())

    def test_source_review_schema_paths_and_size_are_bounded(self):
        good = example.verify(self.sdk, self.review)
        name = next(iter(good))
        invalid = [{}, [], {name: {'size':True,'sha256':'a'*64}},
                   {name: {'size':1024**2+1,'sha256':'a'*64}},
                   {name: {'size':1,'sha256':'Z'*64}},
                   {name: {'size':1,'sha256':'a'*64,'optional':True}}]
        for bad in ('../escape.cpp', 'installed/x/lib/driver.cpp', '/root/demo.cpp',
                    'installed/x/share/owner/examples/demo/*.cpp', name+'/'):
            invalid.append({bad: good[name]})
        for review in invalid:
            with self.subTest(review=review), self.assertRaises(ValueError):
                safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=review)
            self.assertFalse(self.archive.exists())

    def test_approved_source_writes_same_verified_bytes_during_mutation(self):
        approval = example.verify(self.sdk, self.review)
        path = self.dest / 'freerdp_proxy_web_engine_view_cef.cpp'
        original = path.read_bytes()
        real_open = zipfile.ZipFile.open
        def raced(z, entry, mode='r', *args, **kwargs):
            if mode == 'w' and getattr(entry,'filename',None) in approval:
                path.write_bytes(b'int no_longer_the_reviewed_source;')
            return real_open(z, entry, mode, *args, **kwargs)
        with mock.patch.object(zipfile.ZipFile, 'open', new=raced):
            safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=approval)
        with zipfile.ZipFile(self.archive) as z:
            self.assertEqual(z.read(next(iter(approval))), original)

    def test_source_review_cannot_bypass_other_sdk_guards(self):
        approval = example.verify(self.sdk, self.review)
        for name in ('installed/x/lib/libforbidden.so.1','buildtrees/leak.hpp'):
            path = self.sdk / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('not permitted')
            with self.subTest(name=name), self.assertRaises(ValueError):
                safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=approval)
            self.assertFalse(self.archive.exists()); path.unlink()

    def test_existing_output_never_overwritten_or_deleted(self):
        self.archive.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            safeio.sdk_zip(self.sdk, self.archive, reviewed_sources=example.verify(self.sdk,self.review))
        self.assertEqual(self.archive.read_bytes(), b'existing')

    @unittest.skipUnless(sys.platform=='linux', 'Native symlinks')
    def test_redirected_source_sidecar_or_owner_records_are_rejected(self):
        approval = example.verify(self.sdk, self.review)
        for path in (self.dest/'freerdp_proxy_web_engine_view_cef.cpp', self.listing):
            data = path.read_bytes(); outside = self.root / 'outside'; outside.write_bytes(data)
            path.unlink(); path.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'Redirected'): example.verify(self.sdk,self.review)
            with self.assertRaises(ValueError): safeio.sdk_zip(self.sdk,self.archive,reviewed_sources=approval)
            self.assertFalse(self.archive.exists()); path.unlink(); path.write_bytes(data)

    @unittest.skipUnless(sys.platform=='linux', 'Native C/C++ fixture')
    def test_relocated_installed_consumer_rebuilds_without_source_trees(self):
        source = self.root / 'value.c'; source.write_text('int value(void){return 73;}\n')
        obj = self.root / 'value.o'
        run(['cc','-c',source,'-o',obj],self.root)
        lib = self.sdk / 'installed' / example.TRIPLET / 'lib'; lib.mkdir()
        run(['ar','rcsD',lib/'libfixture.a',obj],self.root)
        approved = example.verify(self.sdk,self.review)
        safeio.sdk_zip(self.sdk,self.archive,reviewed_sources=approved)
        moved = self.root / 'relocated'; safeio.extract_zip(self.archive,moved)
        shutil.rmtree(self.sdk); shutil.rmtree(self.lfc); shutil.rmtree(self.registry)
        source.unlink(); obj.unlink()
        example.verify(moved,self.review)
        project = moved / 'installed' / example.TRIPLET / example.EXAMPLE
        run(['cmake','-S',project,'-B',self.root/'build'],self.root)
        run(['cmake','--build',self.root/'build'],self.root)
        run([self.root/'build/example'],self.root)


class CompositionTests(unittest.TestCase):
    def test_actual_combined_review_pack_extract_and_recheck_order(self):
        from secure_release import cef_strict_combined
        code = inspect.getsource(cef_strict_combined.main)
        capture = code.index('cef_sdk_example.capture(')
        self.assertLess(capture,code.index('restore_checkpoint('))
        review = code.index('cef_sdk_example.verify(sdk,')
        pack = code.index('safeio.sdk_zip(sdk, sdk_zip, reviewed_sources=')
        extract = code.index('safeio.extract_zip(sdk_zip,')
        recheck = code.index('cef_sdk_example.verify(consumer_sdk,')
        self.assertLess(review,pack); self.assertLess(pack,extract); self.assertLess(extract,recheck)
        self.assertLess(recheck,code.index('shutil.rmtree(installed)'))
        self.assertIn('cef_build.verify_consumer(',code)
        flow=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        for path in ('secure_release/safeio.py','secure_release/cef_sdk_example.py','tests/test_cef_sdk_example.py'):
            self.assertIn('- '+path,flow)
        self.assertLess(flow.index('-p test_cef_sdk_example.py'),flow.index('name: Run checkpoint-resumed final'))
        self.assertIn("REQUIRE_CEF_SDK_EXAMPLE: '1'",flow)

    def test_exact_production_sources_and_port_in_required_ci(self):
        lfc = os.environ.get('CEF_SDK_EXAMPLE_LFC_UI_ROOT')
        registry = os.environ.get('CEF_SDK_EXAMPLE_REGISTRY_ROOT')
        if not lfc or not registry:
            if os.environ.get('REQUIRE_CEF_SDK_EXAMPLE')=='1': self.fail('Pinned checkouts required')
            self.skipTest('Exact private checkouts supplied only in qualified CI')
        review=example.capture(Path(lfc),Path(registry))
        self.assertEqual(len(review),3)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);sdk=root/'sdk'; dest,listing=populate(sdk)
            # Execute the exact byte-bound port installation block, not an
            # invented example-export rule. Only native library builds are stubbed
            # by the separate disposable-vcpkg test below.
            text=(Path(registry)/'ports/lfc-ui/portfile.cmake').read_text()
            first=text.index('if("cef" IN_LIST FEATURES AND "freerdp" IN_LIST FEATURES)')
            last=text.index('file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage"', first)
            script=root/'install.cmake';script.write_text(text[first:last])
            shutil.copyfile(Path(registry)/'ports/lfc-ui/freerdp-proxy-cef-example.CMakeLists.txt',
                            root/'freerdp-proxy-cef-example.CMakeLists.txt')
            for path in dest.iterdir(): path.unlink()
            run(['cmake','-DFEATURES=cef;freerdp','-DPORT=lfc-ui',
                 '-DCURRENT_PACKAGES_DIR='+str(sdk/'installed'/example.TRIPLET),
                 '-DSOURCE_PATH='+str(Path(lfc).resolve()),'-P',script],root)
            approved=example.verify(sdk,review)
            with self.assertRaisesRegex(ValueError,'implementation source'): safeio.sdk_zip(sdk,root/'sdk.zip')
            safeio.sdk_zip(sdk,root/'sdk.zip',reviewed_sources=approved)
            safeio.extract_zip(root/'sdk.zip',root/'relocated')
            self.assertEqual(example.verify(root/'relocated',review),approved)


@unittest.skipUnless(sys.platform=='linux','Actual native vcpkg source packaging fixture')
class NativeVcpkgTests(unittest.TestCase):
    def test_vcpkg_install_raw_export_zip_and_relocated_example(self):
        raw=os.environ.get('CEF_SDK_EXAMPLE_VCPKG_ROOT')
        if not raw:
            if os.environ.get('REQUIRE_CEF_SDK_EXAMPLE')=='1':self.fail('Native vcpkg checkout required')
            self.skipTest('Native vcpkg supplied by required combined preflight')
        upstream=Path(raw).resolve(strict=True)
        with tempfile.TemporaryDirectory() as t:
            root=Path(t).resolve()
            if not (upstream/'vcpkg').is_file():
                run(['bash',upstream/'bootstrap-vcpkg.sh','-disableMetrics'],upstream,timeout=300)
            lfc,registry,origins,port_blob=make_sources(root)
            ports=root/'ports';port=ports/'lfc-ui';port.mkdir(parents=True)
            (port/'vcpkg.json').write_text(json.dumps({'name':'lfc-ui','version':'1.0'}))
            for name,data in FIXTURES.items():(port/name).write_bytes(data)
            # Original package owns the example and library; export is unmodified.
            (port/'portfile.cmake').write_text('''file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/lib" "${CURRENT_PACKAGES_DIR}/share/lfc-ui/examples/freerdp-proxy-cef")
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/freerdp_proxy_web_engine_view_cef.cpp" "${CMAKE_CURRENT_LIST_DIR}/freerdp_graphics_mode_args.hpp" "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${CURRENT_PACKAGES_DIR}/share/lfc-ui/examples/freerdp-proxy-cef")
file(WRITE "${CURRENT_BUILDTREES_DIR}/value.c" "int value(void){return 73;}\\n")
find_program(_cc cc REQUIRED)
find_program(_ar ar REQUIRED)
execute_process(COMMAND "${_cc}" -c "${CURRENT_BUILDTREES_DIR}/value.c" -o "${CURRENT_BUILDTREES_DIR}/value.o" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${_ar}" rcsD "${CURRENT_PACKAGES_DIR}/lib/libfixture.a" "${CURRENT_BUILDTREES_DIR}/value.o" COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${CURRENT_PACKAGES_DIR}/share/lfc-ui/copyright" "Public domain synthetic fixture\\n")
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)
''')
            installed=root/'installed'; packages=root/'packages'; builds=root/'buildtrees'
            args=['--triplet='+example.TRIPLET,'--host-triplet='+example.TRIPLET,
                  '--overlay-triplets='+str(ROOT/'triplets'),'--overlay-ports='+str(ports),
                  '--x-install-root='+str(installed)]
            env=dict(os.environ,VCPKG_ROOT=str(upstream),VCPKG_DISABLE_METRICS='1')
            run([upstream/'vcpkg','install','lfc-ui','--classic','--binarysource=clear',*args,
                 '--x-packages-root='+str(packages),'--x-buildtrees-root='+str(builds)],root,env=env)
            export=root/'export';export.mkdir()
            run([upstream/'vcpkg','export','lfc-ui','--raw','--output=sdk','--output-dir='+str(export),*args],root,env=env)
            sdk=export/'sdk'
            with mock.patch.object(example,'ORIGINS',origins),mock.patch.object(example,'PORT_BLOB',port_blob):
                review=example.capture(lfc,registry)
                approval=example.verify(sdk,review)
                with self.assertRaisesRegex(ValueError,'implementation source'):
                    safeio.sdk_zip(sdk,root/'sdk.zip')
                safeio.sdk_zip(sdk,root/'sdk.zip',reviewed_sources=approval)
                moved=root/'relocated';safeio.extract_zip(root/'sdk.zip',moved)
                for path in (installed,packages,builds,lfc,registry,export,ports):shutil.rmtree(path)
                example.verify(moved,review)
                run(['cmake','-S',moved/'installed'/example.TRIPLET/example.EXAMPLE,'-B',root/'consumer'],root)
                run(['cmake','--build',root/'consumer'],root)
                run([root/'consumer/example'],root)


if __name__=='__main__':unittest.main()
