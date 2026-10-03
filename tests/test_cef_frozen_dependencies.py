"""Exact-byte dependency replay, real CMake gate and optional REAL vcpkg flow.

Native tests use disposable libraries, never the private engine or its logs.
Combined preflight requires the native vcpkg test before restoring Chromium.
"""
from __future__ import annotations

import hashlib
import importlib.util
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

from secure_release import cef_frozen_dependencies as replay
from secure_release import cef_strict_combined as combined

ROOT = Path(__file__).resolve().parents[1]
PORTS = ROOT / 'tests/fixtures/cef-frozen-dependencies/ports.cmake'
BASE = ROOT / 'triplets' / (replay.TRIPLET + '.cmake')


def run(args, cwd, good=True, env=None, timeout=120):
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=timeout)
    if good and result.returncode:
        raise AssertionError(result.stdout[-6000:] + result.stderr[-6000:])
    if not good and not result.returncode:
        raise AssertionError('Expected a rejected native dependency')
    return result


def setup(root):
    prefix = root / 'frozen'
    (prefix / 'lib/pkgconfig').mkdir(parents=True)
    (prefix / 'include').mkdir()
    source = root / 'library.c'
    source.write_text('int frozen_value(void) { return 73; }\n')
    run(['cc', '-O0', '-c', source, '-o', root/'original.o'], root)
    run(['ar', 'rcsD', prefix/'lib/libfrozen.a', root/'original.o'], root)
    (prefix/'include/frozen.h').write_text('int frozen_value(void);\n')
    (prefix/'lib/pkgconfig/frozen.pc').write_text('Name: frozen\nVersion: 1\nLibs: -lfrozen\n')
    value = {'schema': 1, 'kind': 'linux-x64-static-platform-build-inputs',
             'runtime_verified': False, 'archive_objects': {'lib/libfrozen.a': 1},
             'modules': {}, 'files': {p.relative_to(prefix).as_posix():
                {'sha256': replay.sha(p), 'size': p.stat().st_size}
                for p in prefix.rglob('*') if p.is_file()}}
    manifest = root/'manifest.json'; manifest.write_bytes(replay.canonical(value))
    packages = root/'packages'; packages.mkdir()
    overlays = replay.materialize(root/'triplets', BASE, manifest, prefix,
                                 replay.sha(manifest), packages, PORTS)
    spec = overlays/'frozen-dependencies.json'
    return prefix, packages, manifest, spec, overlays


def package(root, packages, name='frozenlib'):
    target = packages/(name+'_'+replay.TRIPLET)
    (target/'lib/pkgconfig').mkdir(parents=True)
    (target/'include').mkdir()
    (target/'include/frozen.h').write_text('int frozen_value(void);\n')
    (target/'lib/pkgconfig/frozen.pc').write_text('DO NOT MODIFY METADATA\n')
    run(['cc','-O2','-c',root/'library.c','-o',root/'rebuilt.o'],root)
    run(['ar','rcsD',target/'lib/libfrozen.a',root/'rebuilt.o'],root)
    return target


class PolicyTests(unittest.TestCase):
    def test_hook_order_is_bound_to_full_pinned_vcpkg_script(self):
        data = PORTS.read_bytes()
        self.assertEqual(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(), replay.PORTS_BLOB)
        text = data.decode()
        self.assertLess(text.index('include("${CURRENT_PORT_DIR}/portfile.cmake")'),
                        text.index('foreach(z_post_portfile_include'))
        self.assertLess(text.index('foreach(z_post_portfile_include'),text.index('include("${SCRIPTS}/build_info.cmake")'))

    def test_main_binds_before_abi_and_rechecks_after_relocation(self):
        text = inspect.getsource(combined.main)
        self.assertLess(text.index('cef_frozen_dependencies.materialize('), text.index('command = ['))
        self.assertIn('"--overlay-triplets=" + str(replay_triplets)',text)
        self.assertEqual(text.count('cef_frozen_dependencies.verify_installed('),2)
        self.assertIn('sdk, workspace / "triplets", TRIPLET',text)
        self.assertNotIn('cef_frozen_dependencies',BASE.read_text())


@unittest.skipUnless(sys.platform == 'linux', 'Native archive fixture requires Linux')
class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.prefix,self.packages,self.manifest,self.spec,self.overlay = setup(self.root)
        self.target = package(self.root,self.packages)

    def apply(self):
        return replay.replay(self.spec,replay.sha(self.spec),self.target,'frozenlib',replay.TRIPLET)

    def test_exact_archive_before_vcpkg_ownership_no_metadata_or_header_rewrite(self):
        old = replay.sha(self.target/'lib/libfrozen.a')
        wanted = replay.sha(self.prefix/'lib/libfrozen.a')
        self.assertNotEqual(old,wanted)
        before = {p: p.read_bytes() for p in self.target.rglob('*') if p.is_file() and p.suffix!='.a'}
        stamp=(self.prefix/'lib/libfrozen.a').stat().st_mtime_ns
        result=self.apply()
        self.assertEqual(result,{'archives':1,'replaced':1,'headers':1})
        self.assertEqual(replay.sha(self.target/'lib/libfrozen.a'),wanted)
        self.assertEqual((self.prefix/'lib/libfrozen.a').stat().st_mtime_ns,stamp)
        for p,data in before.items(): self.assertEqual(p.read_bytes(),data)
        receipt=json.loads((self.target/'share/frozenlib'/replay.RECEIPT).read_bytes())
        self.assertEqual(receipt['archives']['lib/libfrozen.a']['built_sha256'],old)
        consumer=self.root/'main.c';consumer.write_text('#include "frozen.h"\nint main(void){return frozen_value()!=73;}\n')
        run(['cc','-I'+str(self.target/'include'),consumer,self.target/'lib/libfrozen.a','-o',self.root/'consumer'],self.root)
        run([self.root/'consumer'],self.root)

    def test_real_cmake_hook_and_unchanged_pinned_exporter_hash_gate(self):
        recipe=Path(os.environ.get('CEF_NATIVE_LINK_RECIPE_FIXTURE',ROOT/'private-vcpkg/.full-cef'))
        source=recipe/'vcpkg/static/platform_export.py'
        if not source.is_file(): self.skipTest('Pinned public CEF recipe required')
        self.assertEqual(replay.sha(source),'d625533891594d77fa377c737ef72e155783d9b3ee7f64098a4b213ec5a59fda')
        # Run actual pinned generator in an isolated interpreter.
        script=self.root/'generate.py'
        script.write_text('import sys,json\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n'
            'from platform_export import PlatformExport\nx=PlatformExport.__new__(PlatformExport)\n'
            'x.archives=["lib/libfrozen.a"];x.value=json.loads(Path(sys.argv[2]).read_bytes());x.sha256=sys.argv[3]\n'
            'Path(sys.argv[4]).write_text("set(_cef_static_prefix "+sys.argv[5]+")\\n"+"\\n".join(x.cmake()[0]))\n')
        config=self.root/'config.cmake'
        run([sys.executable,script,source.parent,self.manifest,replay.sha(self.manifest),config,self.target],self.root)
        cmakesrc=self.root/'project';cmakesrc.mkdir()
        (cmakesrc/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.24)\nproject(consumer C)\ninclude("'+str(config)+'")\n')
        fail=run(['cmake','-S',cmakesrc,'-B',self.root/'before'],self.root,False)
        self.assertIn('Static CEF dependency changed',fail.stderr)
        hookscript=self.root/'hook.cmake'
        hookscript.write_text('set(PORT frozenlib)\nset(TARGET_TRIPLET '+replay.TRIPLET+')\n'
            'set(CURRENT_PACKAGES_DIR "'+str(self.target)+'")\ninclude("'+str(self.overlay/'frozen-dependencies.cmake')+'")\n')
        run(['cmake','-P',hookscript],self.root)
        run(['cmake','-S',cmakesrc,'-B',self.root/'after'],self.root)
        self.assertEqual(replay.sha(self.target/'lib/libfrozen.a'),replay.sha(self.prefix/'lib/libfrozen.a'))

    def test_changed_header_or_frozen_bytes_refuse_before_writes(self):
        for path in (self.target/'include/frozen.h',self.prefix/'lib/libfrozen.a'):
            original=path.read_bytes(); old=(self.target/'lib/libfrozen.a').read_bytes()
            path.write_bytes(original+b'changed')
            with self.assertRaisesRegex(ValueError,'bytes differ'): self.apply()
            self.assertEqual((self.target/'lib/libfrozen.a').read_bytes(),old)
            path.write_bytes(original)

    def test_reject_installed_directory_symlinks_and_unbound_spec(self):
        with self.assertRaisesRegex(ValueError,'staging directory'):
            replay.replay(self.spec,replay.sha(self.spec),self.prefix,'frozenlib',replay.TRIPLET)
        with self.assertRaisesRegex(ValueError,'specification changed'):
            replay.replay(self.spec,'0'*64,self.target,'frozenlib',replay.TRIPLET)
        path=self.target/'lib/libfrozen.a';path.unlink();path.symlink_to(self.prefix/'lib/libfrozen.a')
        with self.assertRaisesRegex(ValueError,'Redirected'): self.apply()

    def test_frozen_replay_must_not_drop_newly_requested_feature_symbols(self):
        extra=self.root/'extra.c';extra.write_text('int additional_feature(void){return 1;}\n')
        run(['cc','-c',extra,'-o',self.root/'extra.o'],self.root)
        run(['ar','r',self.target/'lib/libfrozen.a',self.root/'extra.o'],self.root)
        before=(self.target/'lib/libfrozen.a').read_bytes()
        with self.assertRaisesRegex(ValueError,'lose a built feature symbol'):self.apply()
        self.assertEqual((self.target/'lib/libfrozen.a').read_bytes(),before)

    def test_staging_failure_does_not_replace_archive(self):
        old=(self.target/'lib/libfrozen.a').read_bytes()
        with mock.patch.object(replay.shutil,'copyfile',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual((self.target/'lib/libfrozen.a').read_bytes(),old)
        self.assertFalse(list(self.target.rglob('.cef-frozen-*')))

    def test_actual_ownership_and_relocated_bytes_are_required(self):
        self.apply()
        sdk=self.root/'sdk'; installed=sdk/'installed'; target=installed/replay.TRIPLET
        shutil.copytree(self.target,target)
        info=installed/'vcpkg/info';info.mkdir(parents=True)
        listing=info/('frozenlib_1.0_'+replay.TRIPLET+'.list')
        listing.write_text(replay.TRIPLET+'/lib/libfrozen.a\n')
        result=replay.verify_installed(target,self.manifest,replay.sha(self.manifest))
        self.assertEqual(result['frozen_dependency_owners_verified'],1)
        moved=self.root/'relocated';shutil.move(str(sdk),moved)
        target=moved/'installed'/replay.TRIPLET
        replay.verify_installed(target,self.manifest,replay.sha(self.manifest))
        (moved/'installed/vcpkg/info'/listing.name).unlink()
        with self.assertRaisesRegex(ValueError,'package ownership'):
            replay.verify_installed(target,self.manifest,replay.sha(self.manifest))

    def test_abi_tracks_all_semantic_inputs_and_keeps_base_untouched(self):
        text=(self.overlay/BASE.name).read_text()
        self.assertIn('VCPKG_POST_PORTFILE_INCLUDES',text)
        self.assertIn('VCPKG_HASH_ADDITIONAL_FILES',text)
        for path in (BASE,self.manifest,self.spec,Path(replay.__file__),self.overlay/'frozen-dependencies.cmake'):
            self.assertIn(path.as_posix(),text)
        with self.assertRaisesRegex(ValueError,'destination'):
            replay.materialize(self.overlay,BASE,self.manifest,self.prefix,replay.sha(self.manifest),self.packages,PORTS)


@unittest.skipUnless(sys.platform=='linux','Real vcpkg replay qualification requires Linux')
class NativeVcpkgTests(unittest.TestCase):
    def test_real_vcpkg_build_abi_package_ownership_and_export(self):
        root_value=os.environ.get('CEF_FROZEN_VCPKG_ROOT')
        if not root_value:
            if os.environ.get('REQUIRE_CEF_FROZEN_VCPKG')=='1':self.fail('Required native vcpkg checkout missing')
            self.skipTest('Supplied by required combined preflight before engine restore')
        upstream=Path(root_value).resolve(strict=True)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            prefix,packages,manifest,spec,overlay=setup(root)
            # Explicit package/build roots avoid touching an engine or SDK build.
            if not (upstream/'vcpkg').is_file():run(['bash',upstream/'bootstrap-vcpkg.sh','-disableMetrics'],upstream,timeout=300)
            ports=root/'ports';ports.mkdir()
            lib=ports/'frozenlib';lib.mkdir()
            (lib/'vcpkg.json').write_text(json.dumps({'name':'frozenlib','version':'1.0'}))
            (lib/'portfile.cmake').write_text('''file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/lib" "${CURRENT_PACKAGES_DIR}/include" "${CURRENT_PACKAGES_DIR}/share/frozenlib")
file(WRITE "${CURRENT_BUILDTREES_DIR}/library.c" "int frozen_value(void){return 73;}\\n")
file(WRITE "${CURRENT_PACKAGES_DIR}/include/frozen.h" "int frozen_value(void);\\n")
find_program(_cc cc REQUIRED)
find_program(_ar ar REQUIRED)
execute_process(COMMAND "${_cc}" -O2 -c "${CURRENT_BUILDTREES_DIR}/library.c" -o "${CURRENT_BUILDTREES_DIR}/library.o" COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${_ar}" rcsD "${CURRENT_PACKAGES_DIR}/lib/libfrozen.a" "${CURRENT_BUILDTREES_DIR}/library.o" COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${CURRENT_PACKAGES_DIR}/share/frozenlib/copyright" "Public domain synthetic fixture\\n")
''')
            consumer=ports/'frozenconsumer';consumer.mkdir()
            (consumer/'vcpkg.json').write_text(json.dumps({'name':'frozenconsumer','version':'1.0','dependencies':['frozenlib']}))
            (consumer/'portfile.cmake').write_text('''file(SHA256 "${CURRENT_INSTALLED_DIR}/lib/libfrozen.a" _actual)
if(NOT _actual STREQUAL "'''+replay.sha(prefix/'lib/libfrozen.a')+'''")
 message(FATAL_ERROR "Static CEF dependency changed: lib/libfrozen.a")
endif()
file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/share/frozenconsumer")
file(WRITE "${CURRENT_PACKAGES_DIR}/share/frozenconsumer/copyright" "Public domain synthetic fixture\\n")
set(VCPKG_POLICY_EMPTY_PACKAGE enabled)
''')
            env=dict(os.environ,VCPKG_ROOT=str(upstream),VCPKG_DISABLE_METRICS='1')
            # Do not inherit a caller's binary cache or registry selection.
            args=[upstream/'vcpkg','install','frozenconsumer','--classic','--binarysource=clear',
                  '--triplet='+replay.TRIPLET,'--host-triplet='+replay.TRIPLET,
                  '--overlay-ports='+str(ports),'--x-packages-root='+str(packages),
                  '--x-buildtrees-root='+str(root/'buildtrees')]
            old=run([*args,'--overlay-triplets='+str(BASE.parent),'--x-install-root='+str(root/'old')],root,False,env,timeout=240)
            self.assertIn('Static CEF dependency changed',old.stdout+old.stderr)
            old_abi=replay.sha(root/'old'/replay.TRIPLET/'share/frozenlib/vcpkg_abi_info.txt')
            installed=root/'installed'
            common=['--overlay-triplets='+str(overlay),'--x-install-root='+str(installed)]
            run([*args,*common],root,env=env,timeout=240)
            replay.verify_installed(installed/replay.TRIPLET,manifest,replay.sha(manifest))
            self.assertNotEqual(old_abi,replay.sha(installed/replay.TRIPLET/'share/frozenlib/vcpkg_abi_info.txt'))
            export=root/'export';export.mkdir()
            run([upstream/'vcpkg','export','frozenconsumer','--raw','--output=sdk','--output-dir='+str(export),
                 '--triplet='+replay.TRIPLET,'--host-triplet='+replay.TRIPLET,'--overlay-ports='+str(ports),*common],root,env=env,timeout=120)
            sdk=root/'relocated';shutil.move(str(export/'sdk'),sdk)
            shutil.rmtree(installed);shutil.rmtree(packages);shutil.rmtree(prefix)
            replay.verify_installed(sdk/'installed'/replay.TRIPLET,manifest,replay.sha(manifest))
            source=root/'consumer.c';source.write_text('int frozen_value(void);int main(void){return frozen_value()!=73;}\n')
            run(['cc',source,sdk/'installed'/replay.TRIPLET/'lib/libfrozen.a','-o',root/'relocated-proof'],root)
            run([root/'relocated-proof'],root)


if __name__=='__main__':unittest.main()
