"""Source-bound HB C API versus whole-archive private implementation variation.

Native objects here are disposable fixtures, not the compiled engine. Optional
public-source regression uses exact HarfBuzz 14.2.1 internal headers and O1/O3;
combined CI requires it before downloading the large checkpoint.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_harfbuzz_boundary as hb
from secure_release import cef_frozen_dependencies as replay

ROOT=Path(__file__).resolve().parents[1]


def run(args,cwd):
    r=subprocess.run(list(map(str,args)),cwd=cwd,capture_output=True,text=True,timeout=120)
    if r.returncode:raise AssertionError(r.stdout[-2000:]+r.stderr[-2000:])
    return r


class PolicyTests(unittest.TestCase):
    def test_public_policy_is_exact_and_not_a_symbol_exception_list(self):
        self.assertEqual(hb.digest(hb.INTERFACE),hb.INTERFACE_SHA256)
        p=json.loads(hb.INTERFACE.read_bytes())
        self.assertEqual(len(p['headers']),37)
        self.assertIn('hb-cplusplus.hh',p['headers'])
        self.assertEqual(p['version'],'14.2.1')
        self.assertNotIn('symbols',p)

    def test_unreviewed_versions_features_and_owner_are_not_waived(self):
        for features,version in [('core;c-linker','14.2.1'),('core;c-linker;freetype','14.3.0')]:
            with self.assertRaisesRegex(ValueError,'Unreviewed'):
                hb.verify(package=Path('no-owner'),prefix=Path('no-prefix'),inventory={},
                          version=version,features=features,installed=Path('missing'),output=Path('missing'))

    def test_abi_tracks_the_whole_boundary_and_hook_passes_consumer_prefix(self):
        import inspect
        text=inspect.getsource(replay.materialize)
        self.assertIn('VCPKG_HASH_ADDITIONAL_FILES',text)
        self.assertIn('boundary, interface',text)
        self.assertIn('${CURRENT_INSTALLED_DIR}',text)
        self.assertIn('HarfBuzz boundary input changed',text)


    def test_required_source_preflight_and_watch_paths(self):
        workflow=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn('REQUIRE_CEF_HARFBUZZ_BOUNDARY',workflow)
        self.assertIn('sha512sum -c -',workflow)
        self.assertIn('- ci/cef-harfbuzz-interface.json',workflow)
        self.assertLess(workflow.index('name: Verify pinned HarfBuzz C boundary'),
                        workflow.index('name: Run checkpoint-resumed final'))


@unittest.skipUnless(sys.platform=='linux','Native ELF boundary fixture requires Linux')
class NativeTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)

    def lib(self,label,body):
        source=self.root/(label+'.cc');source.write_text(body)
        obj=source.with_suffix('.o');a=source.with_suffix('.a')
        run(['c++','-std=c++17','-O0','-fno-exceptions','-fno-rtti','-fvisibility=hidden',
             '-fvisibility-inlines-hidden','-c',source,'-o',obj],self.root)
        run(['ar','rcsD',a,obj],self.root);return a

    def pair(self,extra='',fextra=''):
        api='extern "C" __attribute__((visibility("default"))) int hb_probe(void){return 73;}\n'
        private='struct Internal{__attribute__((noinline)) int local(){return 73;}};\n'
        b=self.lib('built',private+api+'__attribute__((visibility("hidden"))) int internal_root(){return Internal().local();}\n'+extra)
        f=self.lib('frozen',api+'__attribute__((visibility("hidden"))) int internal_root(){return 73;}\n'+fextra)
        return b,f

    def test_whole_archive_internal_difference_preserves_c_entry_and_relinks(self):
        b,f=self.pair()
        original=b.read_bytes();stamp=b.stat().st_mtime_ns
        api,proof=hb.closed_difference(b,f,{'hb_probe'},[])
        self.assertEqual(api,{'hb_probe'});self.assertEqual(proof['private_built_only'],1)
        main=self.root/'main.c';main.write_text('extern int hb_probe(void);int main(void){return hb_probe()!=73;}')
        for a in (b,f):
            run(['cc',main,a,'-o',self.root/'app'],self.root);run([self.root/'app'],self.root)
        self.assertEqual(b.read_bytes(),original);self.assertEqual(b.stat().st_mtime_ns,stamp)

    def test_missing_public_c_function_is_fatal_even_with_private_difference(self):
        b,f=self.pair('extern "C" __attribute__((visibility("default"))) int hb_new_feature(void){return 2;}')
        with self.assertRaisesRegex(ValueError,'private function|C API'):
            hb.closed_difference(b,f,{'hb_probe','hb_new_feature'},[])

    def test_public_cpp_wrapper_is_not_private_despite_hidden_weak_binding(self):
        b,f=self.pair('namespace hb {struct Public{__attribute__((noinline)) int get(){return 1;}};} '
                      '__attribute__((visibility("hidden"))) int call_public(){return hb::Public().get();}',
                      '__attribute__((visibility("hidden"))) int call_public(){return 1;}')
        with self.assertRaisesRegex(ValueError,r'public C\+\+'):hb.closed_difference(b,f,{'hb_probe'},[])

    def test_weak_hidden_data_and_visible_or_strong_differences_still_fail(self):
        for extra in ['__attribute__((weak,visibility("hidden"))) int extra_data=3;',
                      '__attribute__((visibility("hidden"))) int additional_private(){return 3;}',
                      '__attribute__((weak,visibility("default"))) int visible(){return 3;}']:
            with self.subTest(extra=extra):
                # ar is rebuilt in a fresh subdirectory per test data to avoid stale members.
                b,f=self.pair(extra)
                with self.assertRaisesRegex(ValueError,'private function'):hb.closed_difference(b,f,{'hb_probe'},[])

    def test_other_archive_reference_to_removed_internal_is_not_ignored(self):
        b,f=self.pair();bn=set(hb.symbols(b)[0])-set(hb.symbols(f)[0]);self.assertEqual(len(bn),1)
        # The name is from a disposable fixture, never real private diagnostics.
        name=next(iter(bn))
        external=self.lib('external','extern int used() asm("'+name+'"); int caller(){return used();}')
        with self.assertRaisesRegex(ValueError,'Another archive'):
            hb.closed_difference(b,f,{'hb_probe'},[external])

    def test_surviving_archive_may_resolve_its_own_private_references(self):
        b,f=self.pair();name=next(iter(set(hb.symbols(b)[0])-set(hb.symbols(f)[0])))
        user=self.lib('self-user','extern int used() asm("'+name+'"); int caller(){return used();}')
        run(['ar','r',user,self.root/'built.o'],self.root)
        api,proof=hb.closed_difference(b,f,{'hb_probe'},[user])
        self.assertEqual(proof['reference_archives'],1)

    def test_unresolved_removed_internal_in_replacement_is_fatal(self):
        b,f=self.pair();name=next(iter(set(hb.symbols(b)[0])-set(hb.symbols(f)[0])))
        f=self.lib('broken','extern int used() asm("'+name+'");'
            'extern "C" __attribute__((visibility("default"))) int hb_probe(){return used();}'
            '__attribute__((visibility("hidden"))) int internal_root(){return 73;}')
        with self.assertRaisesRegex(ValueError,'unresolved removed'):
            hb.closed_difference(b,f,{'hb_probe'},[])

    def test_probe_requires_every_api_link_root_and_os_only_executable(self):
        prefix=self.root/'prefix';(prefix/'include/harfbuzz').mkdir(parents=True);(prefix/'lib').mkdir()
        header='typedef void hb_buffer_t;typedef void hb_font_t;typedef void hb_glyph_info_t;\n'
        signatures={'hb_buffer_create':'void *hb_buffer_create(void)',
            'hb_buffer_add_utf8':'void hb_buffer_add_utf8(void*b,const char*s,int n,unsigned o,int l)',
            'hb_buffer_guess_segment_properties':'void hb_buffer_guess_segment_properties(void*b)',
            'hb_font_create':'void *hb_font_create(void*f)', 'hb_face_get_empty':'void *hb_face_get_empty(void)',
            'hb_shape':'void hb_shape(void*f,void*b,void*x,unsigned n)',
            'hb_buffer_get_glyph_infos':'void *hb_buffer_get_glyph_infos(void*b,unsigned*n)',
            'hb_font_destroy':'void hb_font_destroy(void*f)','hb_buffer_destroy':'void hb_buffer_destroy(void*b)'}
        body='static int data;\n'
        for n,sig in signatures.items():
            header+=sig+';\n'
            ret='return &data;' if sig.startswith('void *') else ''
            if n=='hb_buffer_get_glyph_infos':ret='*n=3;return &data;'
            body+='extern "C" __attribute__((visibility("default"))) '+sig+'{'+ret+'}\n'
        (prefix/'include/harfbuzz/hb.h').write_text(header)
        for name in ('hb-ot.h','hb-aat.h','hb-ft.h'):
            (prefix/'include/harfbuzz'/name).write_text('/* fixture declarations are in hb.h */\n')
        a=self.lib('mock-c-api',body);shutil.copyfile(a,prefix/'lib/libharfbuzz.a')
        inv={'archive_objects':{'lib/libharfbuzz.a':1}}
        hb.link_probe(prefix,inv,set(signatures),self.root/'proof')
        with self.assertRaisesRegex(ValueError,'C-link proof failed'):
            hb.link_probe(prefix,inv,set(signatures)|{'hb_missing'},self.root/'missing-proof')


@unittest.skipUnless(sys.platform=='linux','Public native source fixture requires Linux')
class PublicSourceTests(unittest.TestCase):
    def setUp(self):
        env=os.environ.get('CEF_HARFBUZZ_SOURCE_FIXTURE')
        if not env:
            if os.environ.get('REQUIRE_CEF_HARFBUZZ_BOUNDARY')=='1':self.fail('Pinned public source is required')
            self.skipTest('Pinned public HarfBuzz source not supplied')
        self.source=Path(env)/'src'
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)

    def test_complete_source_headers_and_cpp_wrapper_are_byte_bound(self):
        policy=json.loads(hb.INTERFACE.read_bytes())
        package=self.root/'harfbuzz_x64-linux-static-release';prefix=self.root/'frozen'
        for root in (package,prefix):
            (root/'include/harfbuzz').mkdir(parents=True)
            for n,digest in policy['headers'].items():
                self.assertEqual(hb.digest(self.source/n),digest)
                shutil.copyfile(self.source/n,root/'include/harfbuzz'/n)
            (root/'include/harfbuzz/hb-features.h').write_text('/* test generated features */\n')
        inv={'files':{p.relative_to(prefix).as_posix():{'sha256':hb.digest(p),'size':p.stat().st_size}
                      for p in prefix.rglob('*') if p.is_file()}}
        api=hb.interface(package,prefix,inv)
        self.assertIn('hb_ft_font_create',api);self.assertGreater(len(api),400)
        target=package/'include/harfbuzz/hb-cplusplus.hh';target.write_text(target.read_text()+'// changed')
        with self.assertRaisesRegex(ValueError,'header'):hb.interface(package,prefix,inv)

    def test_actual_harfbuzz_internal_headers_o1_o3_boundary_and_c_relink(self):
        # Real upstream vector implementation, not an imitation of its templates.
        for n in ('hb.hh','hb-vector.hh'):
            self.assertTrue((self.source/n).is_file())
        code='#include "hb.hh"\nextern "C" __attribute__((visibility("default"))) int hb_boundary_value(void);\n'
        code+='int hb_boundary_value(void){hb_vector_t<int> a; a.push(17); a.push(25);return a[0]+a[1];}\n'
        cc=self.root/'real.cc';cc.write_text(code)
        archives=[]
        for opt in ('1','3'):
            obj=self.root/('o'+opt+'.o');a=obj.with_suffix('.a')
            run(['c++','-std=c++17','-O'+opt,'-fno-exceptions','-fno-rtti','-fvisibility=hidden',
                 '-fvisibility-inlines-hidden','-I'+str(self.source),'-c',cc,'-o',obj],self.root)
            run(['ar','rcsD',a,obj],self.root);archives.append(a)
        api,proof=hb.closed_difference(*archives,{'hb_boundary_value'},[])
        self.assertGreater(proof['private_built_only'],0)
        # Disposable alloc/pool provider for the selected upstream vector TU;
        # not claimed as a full HarfBuzz build or its real FreeType dependency.
        alloc=self.root/'alloc.c';alloc.write_text('#include <stdlib.h>\n'
            'const unsigned long long _hb_NullPool[8192]={0};unsigned long long _hb_CrapPool[8192];'
            'void *hb_malloc(size_t n){return malloc(n);}void *hb_realloc(void*p,size_t n){return realloc(p,n);}'
            'void hb_free(void*p){free(p);}')
        main=self.root/'main.c';main.write_text('extern int hb_boundary_value(void);int main(void){return hb_boundary_value()!=42;}')
        for a in archives:
            run(['cc',main,alloc,a,'-o',self.root/'consumer'],self.root);run([self.root/'consumer'],self.root)


if __name__=='__main__':unittest.main()
