"""Native boundary regressions use disposable archives, NOT HarfBuzz qualification."""
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
from secure_release import cef_frozen_dependencies as replay
from secure_release import cef_harfbuzz_boundary as hb

ROOT = Path(__file__).resolve().parents[1]
HEADER = '''#pragma once
#ifdef __cplusplus
extern "C" {
#endif
typedef struct hb_buffer_t {unsigned count;} hb_buffer_t;
typedef struct hb_font_t {int value;} hb_font_t;
typedef struct hb_glyph_info_t {unsigned codepoint;} hb_glyph_info_t;
void
hb_version (unsigned*,unsigned*,unsigned*);
hb_buffer_t *
hb_buffer_create (void);
hb_buffer_t *
hb_buffer_reference (hb_buffer_t*);
void
hb_buffer_destroy (hb_buffer_t*);
int
hb_buffer_allocation_successful (hb_buffer_t*);
void
hb_buffer_add_utf8 (hb_buffer_t*, const char*, int, unsigned, int);
void
hb_buffer_guess_segment_properties (hb_buffer_t*);
void
hb_shape (hb_font_t*,hb_buffer_t*,const void*,unsigned);
hb_font_t *
hb_font_get_empty (void);
hb_glyph_info_t *
hb_buffer_get_glyph_infos (hb_buffer_t*,unsigned*);
unsigned
hb_buffer_get_length (hb_buffer_t*);
#ifdef __cplusplus
}
#endif
'''
CPP = '''#pragma once
#include "hb.h"
namespace hb {
template<class T> struct shared_ptr {
 T *p; explicit shared_ptr(T *v):p(v){} shared_ptr(const shared_ptr &a):p(hb_buffer_reference(a.p)){}
 ~shared_ptr(){hb_buffer_destroy(p);} T* get()const{return p;} explicit operator bool()const{return p;}
};
template<class T> using unique_ptr=shared_ptr<T>;
}
'''
IMPL = '''#include "hb.h"
static hb_buffer_t buffer;
static hb_font_t font;
static hb_glyph_info_t glyph;
void hb_version(unsigned*a,unsigned*b,unsigned*c){*a=14;*b=2;*c=1;}
hb_buffer_t *hb_buffer_create(void){buffer.count=0;return &buffer;}
hb_buffer_t *hb_buffer_reference(hb_buffer_t*b){return b;}
void hb_buffer_destroy(hb_buffer_t*b){(void)b;}
int hb_buffer_allocation_successful(hb_buffer_t*b){return b!=0;}
void hb_buffer_add_utf8(hb_buffer_t*b,const char*t,int n,unsigned o,int l){(void)t;(void)o;(void)l;b->count=n;}
void hb_buffer_guess_segment_properties(hb_buffer_t*b){(void)b;}
void hb_shape(hb_font_t*f,hb_buffer_t*b,const void*v,unsigned n){(void)f;(void)b;(void)v;(void)n;}
hb_font_t *hb_font_get_empty(void){return &font;}
hb_glyph_info_t *hb_buffer_get_glyph_infos(hb_buffer_t*b,unsigned*n){*n=b->count;return &glyph;}
unsigned hb_buffer_get_length(hb_buffer_t*b){return b->count;}
'''

def run(args, cwd):
    value=subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True,text=True,timeout=60)
    if value.returncode:raise AssertionError(value.stderr)
    return value.stdout

@unittest.skipUnless(sys.platform=='linux','Native ELF static link boundary is Linux-only')
class Boundary(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.prefix=self.root/'prefix'
        self.package=self.root/'packages'/('harfbuzz_'+replay.TRIPLET)
        self.installed=self.root/'installed'/replay.TRIPLET;self.installed.mkdir(parents=True)
        for root in (self.prefix,self.package):
            (root/'include/harfbuzz').mkdir(parents=True);(root/'lib').mkdir()
            (root/'include/harfbuzz/hb.h').write_text(HEADER)
            (root/'include/harfbuzz/hb-cplusplus.hh').write_text(CPP)
        self.obj=[]
        for index,root in enumerate((self.prefix,self.package)):
            src=self.root/f'core{index}.c';src.write_text(IMPL)
            obj=src.with_suffix('.o');run(['cc','-I'+str(root/'include/harfbuzz'),'-O2','-c',src,'-o',obj],self.root)
            # Different whole implementations expose the same public C API.
            # Their private emitted template is not the public interface.
            cpp=self.root/f'private{index}.cc';cpp.write_text(
                'template<int N> __attribute__((visibility("hidden"),noinline)) int local_impl(){return N;}\n'
                f'template int local_impl<{index}>();\n')
            cobj=cpp.with_suffix('.o');run(['c++','-O0','-c',cpp,'-o',cobj],self.root)
            run(['ar','rcsD',root/'lib/libharfbuzz.a',obj,cobj],self.root)
            self.obj.append(obj)
        self.source=self.prefix/'lib/libharfbuzz.a';self.target=self.package/'lib/libharfbuzz.a'
        self.built=replay.exports(self.target);self.frozen=replay.exports(self.source)
        headers={p.relative_to(self.prefix).as_posix():{'size':p.stat().st_size,'sha256':replay.sha(p)}
                 for p in (self.prefix/'include').rglob('*') if p.is_file()}
        self.value={'schema':1,'kind':'linux-x64-static-platform-build-inputs','runtime_verified':False,
                    'files':{**headers,'lib/libharfbuzz.a':{'size':self.source.stat().st_size,'sha256':replay.sha(self.source)}},
                    'archive_objects':{'lib/libharfbuzz.a':2},
                    'modules':{'harfbuzz':{'libraries':['lib/libharfbuzz.a'],'link_options':['-pthread']}}}
        self.review={'archive_sha256':replay.sha(self.source),'headers_sha256':hashlib.sha256(replay.canonical(headers)).hexdigest()}
        for label,names in [('built_only',self.built-self.frozen),('frozen_only',self.frozen-self.built)]:
            self.review[label+'_sha256']=hb.digest_names(names);self.review[label+'_count']=len(names)
        self.patch=mock.patch.object(hb,'REVIEW',self.review);self.patch.start();self.addCleanup(self.patch.stop)
        self.spec={'prefix':str(self.prefix),'installed':str(self.installed)}

    def verify(self, **kwargs):
        args=dict(spec=self.spec,value=self.value,package=self.package,port='harfbuzz',features='core;c-linker;freetype',
                  version='14.2.1',name='lib/libharfbuzz.a',built=self.built,frozen=self.frozen)
        args.update(kwargs);return hb.reviewed_verify(**args)

    def test_complete_native_link_and_c_and_cpp_abi_execute_without_writes(self):
        before=(self.target.read_bytes(),self.target.stat().st_mtime_ns,self.source.read_bytes())
        proof=self.verify()
        self.assertTrue(proof['static_link_and_api_verified']);self.assertEqual(proof['private_definitions_reviewed'],1)
        self.assertEqual((self.target.read_bytes(),self.target.stat().st_mtime_ns,self.source.read_bytes()),before)
        self.assertNotIn(next(iter(self.built-self.frozen)),json.dumps(proof))

    def test_same_weak_hidden_category_is_not_a_generic_waiver(self):
        self.review['built_only_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'unreviewed symbol'):self.verify()

    def test_profile_header_archive_and_public_symbol_drift_rejected(self):
        for kwargs in [dict(port='other'),dict(version='14.2.2'),dict(features='core;freetype;icu'),dict(name='lib/libother.a')]:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.verify(**kwargs)
        header=self.package/'include/harfbuzz/hb.h';header.write_text(HEADER+'/*changed*/')
        with self.assertRaisesRegex(ValueError,'bytes differ'):self.verify()
        header.write_text(HEADER)
        with (self.package/'include/harfbuzz/private.hh').open('w') as f:f.write('/* new public surface */')
        with self.assertRaisesRegex(ValueError,'public boundary'):self.verify()

    def test_real_incoming_consumer_blocks_discard_even_for_hidden_template(self):
        missing=next(iter(self.built-self.frozen));s=self.root/'client.c'
        s.write_text('extern int needed(void) __asm__("'+missing+'"); int consumer(void){return needed();}\n')
        o=s.with_suffix('.o');run(['cc','-c',s,'-o',o],self.root)
        (self.installed/'lib').mkdir()
        run(['ar','rcsD',self.installed/'lib/libclient.a',o],self.root)
        with self.assertRaisesRegex(ValueError,'another consumer'):self.verify()

    def test_an_archive_which_defines_its_own_comdat_is_not_an_incoming_edge(self):
        # A sibling can have an independent definition, not demand the core one.
        (self.installed/'lib').mkdir();shutil.copyfile(self.target,self.installed/'lib/libselfcontained.a')
        self.assertTrue(self.verify()['static_link_and_api_verified'])

    def test_missing_frozen_core_definition_cannot_pass_whole_archive_link(self):
        s=self.root/'broken.c';s.write_text('extern int unavailable(void); int hb_broken(void){return unavailable();}\n')
        o=s.with_suffix('.o');run(['cc','-c',s,'-o',o],self.root)
        run(['ar','rcsD',self.source,o],self.root)
        self.review['archive_sha256']=replay.sha(self.source)
        # Explicitly isolate the link proof: it must see the unreferenced broken
        # member because the frozen core is whole-archived, not lazily linked.
        with tempfile.TemporaryDirectory() as f,self.assertRaises(ValueError):
            hb.native_probe(Path(f),self.prefix,self.package,self.value,
                            {n for n in self.built if n.startswith('hb_')},self.built-self.frozen,self.target)

    def test_metadata_checks_do_not_accept_visible_or_global_exceptions(self):
        with mock.patch.object(replay,'elf_details',return_value={next(iter(self.built-self.frozen)):[
            {'type':'FUNC','binding':'GLOBAL','visibility':'DEFAULT'}]}):
            with self.assertRaisesRegex(ValueError,'private implementation'):self.verify()

    def test_required_consumer_root_and_redirected_input_fail_closed(self):
        with self.assertRaises(ValueError):self.verify(spec={'prefix':str(self.prefix)})
        (self.installed/'link.a').symlink_to(self.target)
        with self.assertRaisesRegex(ValueError,'redirected'):self.verify()

    def test_failed_native_proof_preserves_private_diagnostics_and_original_bytes(self):
        path=self.root/'proof-diagnostics'
        before=self.target.read_bytes()
        with mock.patch.object(hb,'native_probe',side_effect=ValueError('native-boundary-fixture')):
            with self.assertRaises(ValueError):
                hb.reviewed_verify(self.spec,self.value,self.package,'harfbuzz','core;c-linker;freetype',
                          '14.2.1','lib/libharfbuzz.a',self.built,self.frozen,diagnostics=path)
        record=json.loads((path/'harfbuzz.json').read_bytes())
        self.assertFalse(record['runtime_verified'])
        self.assertEqual(record['reason'],'native-boundary-fixture')
        self.assertEqual((path/'harfbuzz.json').stat().st_mode & 0o777,0o600)
        self.assertEqual(self.target.read_bytes(),before)

    def test_existing_qualifier_requires_uploaded_proof_before_return(self):
        original = self.package / "lib/libharfbuzz.a"
        before = (original.read_bytes(), original.stat().st_mtime_ns)
        with mock.patch.object(hb, "interface", return_value={"hb_shape"}), \
             mock.patch.object(hb, "closed_difference", return_value=({
                 "hb_shape", "hb_buffer_create", "hb_ft_font_create",
                 "hb_ft_face_create", "hb_version_string"}, {})), \
             mock.patch.object(hb, "link_probe") as old_probe, \
             mock.patch.object(hb, "reviewed_verify", side_effect=ValueError("strict uploaded proof")) as added:
            with self.assertRaisesRegex(ValueError, "strict uploaded proof"):
                hb.verify(package=self.package, prefix=self.prefix, inventory=self.value,
                          version="14.2.1", features="core;c-linker;freetype",
                          installed=self.installed, output=self.root/"composed")
            old_probe.assert_called_once()
            added.assert_called_once()
        self.assertEqual((original.read_bytes(), original.stat().st_mtime_ns), before)

    def test_real_post_portfile_top_level_import_runs_whole_boundary(self):
        # The actual hook executes cef_frozen_dependencies.py as a script, so
        # its HarfBuzz helper has no package context. Exercise that import mode
        # in an isolated fresh process, not the package imported by unittest.
        payload = {"review": self.review, "spec": self.spec, "value": self.value,
                   "package": str(self.package), "built": sorted(self.built),
                   "frozen": sorted(self.frozen)}
        script = """import sys, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import cef_harfbuzz_boundary as boundary
assert not boundary.__package__
payload = json.load(sys.stdin)
boundary.REVIEW = payload['review']
proof = boundary.reviewed_verify(
    payload['spec'], payload['value'], Path(payload['package']),
    'harfbuzz', 'core;c-linker;freetype', '14.2.1', 'lib/libharfbuzz.a',
    set(payload['built']), set(payload['frozen']))
print(json.dumps(proof))
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", script, str(ROOT / "secure_release")],
            input=json.dumps(payload), capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['static_link_and_api_verified'])

    def test_installed_receipt_policy_remains_bound_to_composed_module(self):
        import inspect
        text = inspect.getsource(replay.materialize)
        self.assertIn("boundary, interface", text)
        self.assertIn("VCPKG_HASH_ADDITIONAL_FILES", text)
        self.assertIn("HarfBuzz boundary input changed", text)

if __name__=='__main__':unittest.main()
