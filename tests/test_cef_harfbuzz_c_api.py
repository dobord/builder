"""Public C declarations versus a preserved HB_INTERNAL C provider.

The optional full-source test compiles the real pinned core (without FreeType)
and C/C++ clients. It is not the qualified engine's HarfBuzz/FreeType archive.
The combined preflight requires the source; no production archive is modified.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_harfbuzz_boundary as hb

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = 'hb_ucd_get_unicode_funcs'
PUBLIC = {('FUNC', 'GLOBAL', 'DEFAULT')}
PRIVATE = {('FUNC', 'GLOBAL', 'HIDDEN')}


def command(args, cwd, timeout=180):
    result = subprocess.run(list(map(str, args)), cwd=cwd, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(result.stdout[-2000:] + result.stderr[-4000:])
    return result.stdout


class DeclarationTests(unittest.TestCase):
    def setUp(self):
        self.defs = {'hb_probe': PUBLIC, INTERNAL: PRIVATE}

    def test_prefix_is_not_public_declaration_and_internal_is_preserved(self):
        original = {k: set(v) for k, v in self.defs.items()}
        api = hb.public_c_api(self.defs, self.defs, {'hb_probe'})
        self.assertEqual(api, {'hb_probe'})
        self.assertEqual(self.defs, original)

    def test_missing_or_added_internal_c_definition_is_not_waived(self):
        for a, b in [(self.defs, {'hb_probe': PUBLIC}), ({'hb_probe': PUBLIC}, self.defs)]:
            with self.assertRaisesRegex(ValueError, 'definitions changed'):
                hb.public_c_api(a, b, {'hb_probe'})

    def test_unknown_common_hidden_c_name_is_not_allowed(self):
        data = dict(self.defs, hb_unknown_internal=PRIVATE)
        with self.assertRaisesRegex(ValueError, 'declarations changed'):
            hb.public_c_api(data, data, {'hb_probe'})

    def test_internal_binding_data_visibility_or_public_exposure_is_rejected(self):
        for attributes in [('FUNC','WEAK','HIDDEN'), ('FUNC','GLOBAL','DEFAULT'),
                           ('OBJECT','GLOBAL','HIDDEN'), ('TLS','GLOBAL','HIDDEN')]:
            data = dict(self.defs); data[INTERNAL] = {attributes}
            with self.subTest(attributes=attributes), self.assertRaisesRegex(ValueError, 'internal C'):
                hb.public_c_api(data, data, {'hb_probe'})
        with self.assertRaisesRegex(ValueError, 'internal C'):
            hb.public_c_api(self.defs, self.defs, {'hb_probe', INTERNAL})

    def test_public_symbols_and_metadata_stay_strict(self):
        data = dict(self.defs, hb_new_feature=PUBLIC)
        with self.assertRaises(ValueError):
            hb.public_c_api(data, self.defs, {'hb_probe', 'hb_new_feature'})
        data = dict(self.defs); data['hb_probe'] = PRIVATE
        with self.assertRaisesRegex(ValueError, 'entry-point'):
            hb.public_c_api(data, data, {'hb_probe'})

    def test_both_mandatory_stages_use_same_classification(self):
        self.assertIn('public_c_api(b, f, declared)', inspect.getsource(hb.closed_difference))
        self.assertIn('public_c_api(built_elf, frozen_elf, declarations)', inspect.getsource(hb._verify))
        self.assertIn('native_probe(', inspect.getsource(hb._verify))
        workflow = (ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn('- tests/test_cef_harfbuzz_c_api.py', workflow)
        self.assertLess(workflow.index('-p test_cef_harfbuzz_c_api.py'),
                        workflow.index('name: Run checkpoint-resumed final'))


@unittest.skipUnless(sys.platform == 'linux', 'Native ELF regression is Linux-only')
class NativeTests(unittest.TestCase):
    def test_actual_elf_hidden_c_provider_and_private_difference_reproduce_old_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archives = []
            body = ('extern "C" __attribute__((visibility("default"))) int hb_probe(){return 73;}\n'
                    'extern "C" __attribute__((visibility("hidden"))) void *'
                    + INTERNAL + '(){return nullptr;}\n')
            for name, extra in [('built', 'struct Internal{__attribute__((noinline)) int f(){return 1;}};'
                    '__attribute__((visibility("hidden"))) int root(){return Internal().f();}'),
                    ('frozen', '__attribute__((visibility("hidden"))) int root(){return 1;}')]:
                src=root/(name+'.cc'); src.write_text(body+extra)
                obj=src.with_suffix('.o'); archive=src.with_suffix('.a')
                command(['c++','-O0','-fno-exceptions','-fno-rtti','-fvisibility=hidden',
                         '-fvisibility-inlines-hidden','-c',src,'-o',obj],root)
                command(['ar','rcsD',archive,obj],root); archives.append(archive)
            b,f = (hb.symbols(a)[0] for a in archives)
            self.assertFalse({n for n in b if n.startswith('hb_')} <= {'hb_probe'})
            before=[(p.read_bytes(),p.stat().st_mtime_ns) for p in archives]
            api,proof=hb.closed_difference(*archives, {'hb_probe'}, [])
            self.assertEqual(api, {'hb_probe'});self.assertEqual(proof['private_built_only'],1)
            self.assertEqual(before,[(p.read_bytes(),p.stat().st_mtime_ns) for p in archives])

    def test_uploaded_whole_core_cpp_proof_keeps_hidden_provider_out_of_public_client(self):
        from test_cef_harfbuzz_uploaded_proof import Boundary
        case=Boundary('runTest');case.setUp()
        try:
            source=case.root/'internal.c'
            source.write_text('__attribute__((visibility("hidden"))) void *'+INTERNAL+'(void){return 0;}')
            obj=source.with_suffix('.o');command(['cc','-c',source,'-o',obj],case.root)
            for archive in (case.source,case.target):command(['ar','r',archive,obj],case.root)
            from secure_release import cef_frozen_dependencies as replay
            case.built=replay.exports(case.target);case.frozen=replay.exports(case.source)
            case.review['archive_sha256']=replay.sha(case.source)
            proof=case.verify()
            self.assertTrue(proof['static_link_and_api_verified'])
            self.assertNotIn(INTERNAL,json.dumps(proof))
        finally:
            case.doCleanups()


@unittest.skipUnless(sys.platform == 'linux', 'Full public source test requires Linux')
class PublicSourceTests(unittest.TestCase):
    def test_real_full_core_and_cpp_client_preserve_internal_ucd_without_public_declaration(self):
        raw=os.environ.get('CEF_HARFBUZZ_SOURCE_FIXTURE')
        if not raw:
            if os.environ.get('REQUIRE_CEF_HARFBUZZ_BOUNDARY')=='1':self.fail('Pinned source is required')
            self.skipTest('Pinned public source not supplied')
        source=Path(raw);src=source/'src'
        for name, expected in {'hb-unicode.hh':'485f3f527380c1e0253acf2d9d1d13d2a8612aec',
                               'hb-ucd.cc':'4c8b1ee5e612340458761b6d1f66ab40359e47cc'}.items():
            data=(src/name).read_bytes()
            self.assertEqual(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),expected)
        self.assertIn('extern "C" HB_INTERNAL hb_unicode_funcs_t *'+INTERNAL+' ();',
                      (src/'hb-unicode.hh').read_text())
        policy=json.loads(hb.INTERFACE.read_bytes())
        for name, expected in policy['headers'].items():self.assertEqual(hb.digest(src/name),expected)
        declared=set(re.findall(r'^hb_\w+(?= \()', '\n'.join((src/n).read_text()
                      for n in policy['core_headers'] if n.endswith('.h')), re.M))
        self.assertNotIn(INTERNAL,declared)
        with tempfile.TemporaryDirectory(prefix='hb-real-core-') as tmp:
            root=Path(tmp); build=root/'build'
            command(['cmake','-S',source,'-B',build,'-G','Ninja','-DBUILD_SHARED_LIBS=OFF',
                     '-DHB_BUILD_SUBSET=OFF','-DHB_BUILD_RASTER=OFF','-DHB_BUILD_VECTOR=OFF',
                     '-DHB_BUILD_GPU=OFF','-DHB_HAVE_FREETYPE=OFF','-DCMAKE_BUILD_TYPE=Release',
                     '-DCMAKE_CXX_FLAGS_RELEASE=-O0 -g0 -fno-exceptions -fno-rtti'], root)
            command(['cmake','--build',build,'--target','harfbuzz','-j2'], root, timeout=240)
            archive=build/'libharfbuzz.a';defs,_=hb.symbols(archive)
            prefixed={n for n in defs if n.startswith('hb_')}
            self.assertEqual(prefixed-declared,{INTERNAL})  # Original #74 predicate fails.
            self.assertEqual(defs[INTERNAL],PRIVATE)
            api=hb.public_c_api(defs,defs,declared);self.assertGreater(len(api),400)
            c=root/'api.c';cpp=root/'wrapper.cc'
            c.write_text('#include <hb.h>\n#include <hb-ot.h>\n#include <hb-aat.h>\n'
                'void (*volatile const entries[])(void)={'+','.join('(void(*)(void))&'+n for n in sorted(api))+'};\n'
                'extern int wrapper(void);int main(void){unsigned a,b,c;hb_version(&a,&b,&c);'
                'if(a!=14||b!=2||c!=1||!entries[0])return 1;return wrapper();}')
            cpp.write_text('#include <hb-cplusplus.hh>\nextern "C" int wrapper(void){'
                'hb::shared_ptr<hb_buffer_t> a(hb_buffer_create());hb::shared_ptr<hb_buffer_t> b(a);'
                'hb::unique_ptr<hb_buffer_t> c(hb_buffer_create());'
                'if(!a||!b||!c||a.get()!=b.get())return 2;'
                'hb_buffer_add_utf8(c.get(),"abc",3,0,3);hb_buffer_guess_segment_properties(c.get());'
                'hb_shape(hb_font_get_empty(),c.get(),nullptr,0);return hb_buffer_get_length(c.get())!=3;}')
            inc=['-I'+str(build/'src'),'-I'+str(src)]
            command(['cc','-O0',*inc,'-c',c,'-o',root/'api.o'],root)
            command(['c++','-std=c++17','-O0','-fno-exceptions','-fno-rtti',*inc,'-c',cpp,'-o',root/'cpp.o'],root)
            exe=root/'consumer'
            command(['cc','-static-libgcc',root/'api.o',root/'cpp.o','-Wl,--whole-archive',archive,
                     '-Wl,--no-whole-archive','-lm','-ldl','-pthread','-o',exe],root)
            needed=set(re.findall(r'Shared library: \[([^\]]+)\]',command(['readelf','-d',exe],root)))
            self.assertTrue(needed <= hb.OS_NEEDED)
            command([exe],root)
            self.assertEqual(hb.symbols(archive)[0],defs)


if __name__ == '__main__':unittest.main()
