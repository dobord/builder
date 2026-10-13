"""Pinned Torque parent-size regression, with real native C++ layout controls.

Execute FirstFieldStart extracted from the full pinned generator, then compile
its emitted expression against the exact public Map data-member declarations,
packing macros and JSInterceptorMap header. Support types and ClassType metadata
are small fixtures. This is not the full Torque compiler or V8/CEF qualification.
"""
from __future__ import annotations
import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_layout_inputs import fixture_bytes, public_input, verify_public, INPUTS

GENERATOR = 'src/torque/implementation-visitor.cc'
OLD_KEY = '277e5a566407e239fc70c7b7c144cd1961b2efb786989bfaf4fa132315e3d81f'


def populate(work):
    for relative, _, _, _ in repair.CORRECTIONS:
        p = work/relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(public_input("include/v8-template.h")
                      if relative == repair.TEMPLATE_HEADER
                      else fixture_bytes(p.name))


def generator_probe(raw):
    text = raw.decode()
    start = '  static std::string FirstFieldStart('
    stop = '\n  std::ostream& hdr_;'
    assert text.count(start) == text.count(stop) == 1
    method = text[text.index(start):text.index(stop)]
    return r'''
#include <cassert>
#include <cstddef>
#include <iostream>
#include <optional>
#include <string>
struct ResidueClass {
 std::optional<size_t> value;
 std::optional<size_t> SingleValue() const { return value; }
};
struct ClassType {
 std::string n; bool cpp, shape, fixed; size_t bytes;
 std::string name() const {return n;}
 bool IsLayoutDefinedInCpp() const {return cpp;}
 bool IsShape() const {return shape;}
 bool HasStaticSize() const {return fixed;}
 ResidueClass size() const {return {fixed ? std::optional<size_t>(bytes) : std::nullopt};}
};
''' + method + r'''
int main(int argc, char** argv) {
 assert(argc==2);
 const size_t tagged=std::stoul(argv[1]); assert(tagged==4 || tagged==8);
 const size_t map_size=(tagged==4 ? 40 : 72);
 ClassType parent{"ExtendedMap",true,false,true,map_size+1};
 ClassType child{"JSInterceptorMap",true,false,true,0};
 // These policy controls must not depend on the repair.
 ClassType dynamic{"Dynamic",true,false,false,0};
 ClassType opaque{"Opaque",false,false,true,16};
 ClassType shape{"Shape",false,true,true,16};
 ClassType legacy{"Legacy",false,false,true,0};
 assert(FirstFieldStart(&child,&dynamic,false)=="sizeof(Dynamic)");
 assert(FirstFieldStart(&child,&opaque,false)=="sizeof(Opaque)");
 assert(FirstFieldStart(&legacy,&shape,false)=="Shape::kSize");
 assert(FirstFieldStart(&legacy,&opaque,false)=="Opaque::kHeaderSize");
 assert(FirstFieldStart(&legacy,&shape,true)=="P::kSize");
 assert(FirstFieldStart(&legacy,&opaque,true)=="P::kHeaderSize");
 std::cout << "#define TORQUE_START " << FirstFieldStart(&child,&parent,false) << "\n";
}
'''


def install_layout(include, tagged):
    macros = public_input('src/objects/object-macros.h').decode()
    # Unchanged public packing definitions, not a replacement packing policy.
    macros = macros[macros.index('#if V8_CC_GNU'):macros.index('#define V8_OBJECT_INNER_CLASS ')]
    map_h = public_input('src/objects/map.h').decode()
    start = '  std::atomic<uint8_t> instance_size_in_words_;'
    fields = map_h[map_h.index(start):map_h.index('} V8_OBJECT_END;', map_h.index(start))]
    assert fields.count('TaggedMember<') == 8
    extended = '  std::atomic<uint8_t> bit_field_ex_;'
    assert map_h.count(extended) == 1
    objects = include/'src/objects'; objects.mkdir(parents=True, exist_ok=True)
    (objects/'object-macros.h').write_text(macros)
    (objects/'object-macros-undef.h').write_text('')
    (objects/'js-interceptor-map.h').write_bytes(public_input('src/objects/js-interceptor-map.h'))
    support = r'''
#include <atomic>
#include <cstdint>
#include <type_traits>
#include "src/objects/object-macros.h"
namespace v8::internal {
constexpr int kTaggedSize = TAGGED_SIZE_8_BYTES ? 8 : 4;
using TaggedWord=std::conditional_t<TAGGED_SIZE_8_BYTES,uint64_t,uint32_t>;
template<class T> struct TaggedMember {TaggedWord value_;};
template<class T> struct Tagged {};
template<class... T> struct UnionOf {};
template<class T> struct MaybeWeak {};
class Map; class JSPrototype; class Object; class DescriptorArray; class WasmStruct;
class DependentCode; class Smi; class Cell; class TransitionArray; class PrototypeInfo;
class PrototypeSharedClosureInfo;
namespace base {template<class,int,int,class> struct BitField {};}
enum WriteBarrierMode {UPDATE_WRITE_BARRIER};
V8_OBJECT class HeapObject {public: TaggedMember<Map> map_;} V8_OBJECT_END;
V8_OBJECT class Map : public HeapObject {public:
'''
    support += fields + '} V8_OBJECT_END;\nV8_ABSTRACT_OBJECT class ExtendedMap : public Map {public:\n'
    support += extended + '\n} V8_OBJECT_END;\n}\n'
    (objects/'map.h').write_text(support)
    return r'''
#include <cassert>
#include <cstddef>
#include <cstdio>
#include "src/objects/js-interceptor-map.h"
#include "generated.h"
using namespace v8::internal;
static constexpr int map_size = kTaggedSize==4 ? 40 : 72;
static_assert(sizeof(Map)==map_size);
static_assert(offsetof(ExtendedMap,bit_field_ex_)==map_size);
// Mirror the unchanged sequential offsets emitted by ClassFieldOffsetGenerator.
static constexpr int kFlagsOffset=TORQUE_START;
static constexpr int kExtendedPaddingOffset=kFlagsOffset+1;
static constexpr int kNamedInterceptorOffset=kExtendedPaddingOffset+kTaggedSize-2;
static constexpr int kIndexedInterceptorOffset=kNamedInterceptorOffset+kTaggedSize;
static constexpr int kFastCaseValidityCellOffset=kIndexedInterceptorOffset+kTaggedSize;
static constexpr int kSize=kFastCaseValidityCellOffset+kTaggedSize;
static_assert(kFlagsOffset==offsetof(JSInterceptorMap,flags_),"flags_offset_mismatch");
static_assert(kExtendedPaddingOffset==offsetof(JSInterceptorMap,extended_padding_),"padding_offset_mismatch");
static_assert(kNamedInterceptorOffset==offsetof(JSInterceptorMap,named_interceptor_),"named_offset_mismatch");
static_assert(kIndexedInterceptorOffset==offsetof(JSInterceptorMap,indexed_interceptor_),"indexed_offset_mismatch");
static_assert(kFastCaseValidityCellOffset==offsetof(JSInterceptorMap,fast_case_validity_cell_),"cell_offset_mismatch");
static_assert(kSize==sizeof(JSInterceptorMap),"size_mismatch");
static_assert(kNamedInterceptorOffset%kTaggedSize==0);
static_assert(kSize==(kTaggedSize==4 ? 56 : 104));
int main() {
 JSInterceptorMap object{};
 object.flags_=3;
 object.named_interceptor_.value_=11;
 object.indexed_interceptor_.value_=22;
 object.fast_case_validity_cell_.value_=33;
 assert(object.flags_==3 && object.named_interceptor_.value_==11);
 assert(object.indexed_interceptor_.value_==22 && object.fast_case_validity_cell_.value_==33);
 printf("CEF_TORQUE_LAYOUT_CONTROL tagged=%d parent_size=%zu flags=%d size=%d\n",kTaggedSize,sizeof(ExtendedMap),kFlagsOffset,kSize);
}
'''


class TorqueLayoutRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='torque layout test ')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.work = self.root/'work'; populate(self.work)
        self.path = self.work/repair.TORQUE_SOURCE
        self.key = repair.build_key(repair.BASE_KEY)

    def apply(self, origin='legacy'):
        return repair.apply(self.work, self.key, origin)

    def test_full_public_source_and_only_reviewed_generator_edits(self):
        raw = self.path.read_bytes()
        self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                         '08caa5038e4416c68df79e4a6283599da6fd8c4f')
        self.assertEqual(hashlib.sha256(raw).hexdigest(), repair.TORQUE_BEFORE)
        fixed = repair.transform(raw, repair.TORQUE_SOURCE)
        restored = fixed
        torque = next(c for c in repair.CORRECTIONS if c[0] == repair.TORQUE_SOURCE)
        for old, new in reversed(torque[3]):
            self.assertEqual(restored.count(new), 1)
            restored = restored.replace(new, old, 1)
        self.assertEqual(restored, raw)
        self.assertEqual(fixed.count(b'static_assert('), raw.count(b'static_assert(') + 1)
        new = torque[3][0][1]
        self.assertIn(b'parent && parent->IsLayoutDefinedInCpp() && parent->HasStaticSize()',fixed)
        self.assertNotIn(b'JSInterceptorMap',new)  # No class-specific magic offset.

    def test_public_input_identity_and_bounded_paths(self):
        for path in INPUTS:
            data=public_input(path)
            self.assertIs(verify_public(path,data),data)
            with self.assertRaises(ValueError): verify_public(path,data+b'x')
        with self.assertRaises(ValueError): public_input('../../private.key')
        with self.assertRaises(ValueError): fixture_bytes('../private.key')
        tq=public_input('src/objects/map.tq')
        self.assertIn(b'extern class ExtendedMap extends Map {\n  bit_field_ex: ExtendedMapBitFields;',tq)
        self.assertIn(b'Leaves kTaggedSize-1 unused bytes',tq)
        tq=public_input('src/objects/js-interceptor-map.tq')
        for field in (b'flags: uint8;',b'extended_padding[2]',b'extended_padding[6]',b'named_interceptor:',b'indexed_interceptor:',b'fast_case_validity_cell:'):
            self.assertIn(field,tq)

    def test_sixth_bad_input_leaves_prior_five_untouched(self):
        previous={self.work/c[0]:(self.work/c[0]).read_bytes() for c in repair.CORRECTIONS[:5]}
        self.path.write_bytes(b'unreviewed generator')
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual(previous,{p:p.read_bytes() for p in previous})
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_generator_bound_is_local_not_a_global_limit_waiver(self):
        self.assertGreater(len(self.path.read_bytes()),65536)
        with self.assertRaises(ValueError): repair._read(self.work,repair.TORQUE_SOURCE)
        self.assertEqual(self.apply(),'applied')
        self.assertEqual(self.apply('resume'),'already-applied')
        self.path.write_bytes(b'x'*262145)
        with self.assertRaises(ValueError): self.apply('resume')
        old=self.work/repair.HEADER;old.write_bytes(b'x'*65537)
        with self.assertRaises(ValueError): repair._read(self.work,repair.HEADER)

    def test_sixth_hardlink_rejected_before_writes(self):
        os.link(self.path,self.root/'alias')
        previous=(self.work/repair.HEADER).read_bytes()
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual((self.work/repair.HEADER).read_bytes(),previous)
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_sixth_replacement_race_never_publishes_marker(self):
        original=repair._path;seen=0
        def race(work,relative):
            nonlocal seen
            if relative==repair.TORQUE_SOURCE:
                seen+=1
                if seen==2:self.path.write_bytes(b'concurrent generator edit')
            return original(work,relative)
        with mock.patch.object(repair,'_path',side_effect=race):
            with self.assertRaises(ValueError):self.apply()
        self.assertEqual(self.path.read_bytes(),b'concurrent generator edit')
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_v5_partial_sources_and_failed40_rejected(self):
        for selected in (dict(repair.LEGACY,build_key=OLD_KEY),dict(repair.LEGACY,run=37133379255)):
            with self.assertRaises(ValueError):repair.restore_contract(selected,repair.BASE_KEY)
        self.assertNotEqual(self.key,OLD_KEY)
        for relative,_,_,_ in repair.CORRECTIONS[:5]:
            p=self.work/relative;p.write_bytes(repair.transform(p.read_bytes(),relative))
        with self.assertRaises(ValueError):self.apply()
        self.assertFalse((self.work/repair.MARKER).exists())

    def test_resume_requires_full_generator_and_profile(self):
        self.apply();fixed=self.path.read_bytes()
        self.path.write_bytes(public_input(GENERATOR))
        with self.assertRaises(ValueError):self.apply('resume')
        self.path.write_bytes(fixed)
        self.assertEqual(self.apply('resume'),'already-applied')
        value={'base_build_key':repair.BASE_KEY,'source_repair_verified':True,'source_repair':repair.profile()}
        repair.verify_summary(value,{'build_key':self.key})
        bad=copy.deepcopy(value);bad['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError):repair.verify_summary(bad,{'build_key':self.key})

    def test_generator_newlines_idempotence_and_extra_edits_rejected(self):
        raw=self.path.read_bytes()
        for newline in (b'\n',b'\r\n'):
            old=raw.replace(b'\n',newline);fixed=repair.transform(old,repair.TORQUE_SOURCE)
            self.assertEqual(repair.transform(fixed,repair.TORQUE_SOURCE),fixed)
        for bad in (raw+b'\n',raw.replace(b'HasStaticSize',b'IsAbstract'),raw.replace(b'\n',b'\r\n',1)):
            with self.assertRaises(ValueError):repair.transform(bad,repair.TORQUE_SOURCE)

    def compiler(self,source,output,tagged=4,extra=()):
        include=source.parent/'include'
        if os.name=='nt':
            vswhere=Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
            self.assertTrue(vswhere.is_file())
            vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
            clang=Path(os.environ.get('ProgramFiles','C:/Program Files'))/'LLVM/bin/clang-cl.exe'
            self.assertTrue(clang.is_file())
            batch=source.parent/'compile.cmd'
            # offsetof on these intentional non-standard-layout V8 objects is an
            # accepted extension; all actual static assertions remain -Werror.
            cmdline='"'+str(clang)+'" /nologo /std:c++20 /EHsc /W4 /WX -Werror -Wno-invalid-offsetof'
            cmdline+=' /DV8_CC_GNU=0 /DV8_CC_MSVC=1 /DTAGGED_SIZE_8_BYTES='+str(int(tagged==8))+' /DV8_ENABLE_WEBASSEMBLY=1'
            cmdline+=' /I"'+str(include)+'" "'+str(source)+'" /Fe:"'+str(output)+'"\n'
            batch.write_text('@echo off\ncall "'+vs+'/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\nif errorlevel 1 exit /b 90\n'+cmdline)
            command=['cmd.exe','/d','/c',str(batch)]
        else:
            clang=shutil.which('clang++');self.assertTrue(clang)
            command=[clang,'-std=c++20','-Wall','-Wextra','-Werror','-Wno-invalid-offsetof','-DV8_CC_GNU=1','-DV8_CC_MSVC=0',f'-DTAGGED_SIZE_8_BYTES={int(tagged==8)}','-DV8_ENABLE_WEBASSEMBLY=1','-I'+str(include),str(source),'-o',str(output),*extra]
        return subprocess.run(command,cwd=source.parent,text=True,capture_output=True,errors='replace',timeout=75)

    def test_native_generator_layout_and_fail_closed_assertions(self):
        original=self.path.read_bytes();fixed=repair.transform(original,repair.TORQUE_SOURCE)
        old_failures=0
        for tagged in (4,8):
            case=self.root/str(tagged);case.mkdir()
            layout=install_layout(case/'include',tagged)
            source=case/'generator.cc'; exe=case/('generator.exe' if os.name=='nt' else 'generator')
            verify=case/'verify.cc';out=case/('verify.exe' if os.name=='nt' else 'verify')
            verify.write_text(layout)
            for repaired,raw in ((False,original),(True,fixed)):
                source.write_text(generator_probe(raw))
                result=self.compiler(source,exe,tagged);self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                generated=subprocess.check_output([str(exe),str(tagged)],cwd=case,text=True,timeout=10)
                if repaired:self.assertEqual(generated.strip(),f'#define TORQUE_START {41 if tagged==4 else 73}')
                (case/'include/generated.h').write_text(generated)
                result=self.compiler(verify,out,tagged)
                if not repaired and os.name=='nt':
                    old_failures+=1
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('flags_offset_mismatch',result.stdout+result.stderr)
                    self.assertIn('size_mismatch',result.stdout+result.stderr)
                else:
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    subprocess.run([str(out)],cwd=case,capture_output=True,check=True,timeout=10)
            # A changed field offset or final size MUST still fail compilation.
            for bad in (layout.replace('kFlagsOffset=TORQUE_START','kFlagsOffset=TORQUE_START+1'),layout.replace('kSize=kFastCaseValidityCellOffset+kTaggedSize','kSize=kFastCaseValidityCellOffset+kTaggedSize+1')):
                verify.write_text(bad);result=self.compiler(verify,out,tagged)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('static assertion',result.stdout+result.stderr)
            verify.write_text(layout)
            if os.name!='nt':
                result=self.compiler(verify,out,tagged,('-fsanitize=address,undefined','-fno-omit-frame-pointer'))
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                subprocess.run([str(out)],cwd=case,capture_output=True,check=True,timeout=10)
        print(f'CEF_TORQUE_PARENT_LAYOUT_VERIFIED old_windows_failures={old_failures} tagged_sizes=2 field_assertions=5 size_assertion=true negative_controls=4')

    @unittest.skipIf(os.name=='nt','Native Unix Ninja generator dependency regression')
    def test_ninja_rebuilds_generator_and_regenerates_assertions_only(self):
        ninja,clang=shutil.which('ninja'),shutil.which('clang++');self.assertTrue(ninja and clang)
        build=self.root/'ninja';build.mkdir()
        source=build/'generator.cc';source.write_text(generator_probe(self.path.read_bytes()))
        layout=install_layout(build/'include',4)
        (build/'verify.cc').write_text(layout);(build/'other.cc').write_text('int unrelated(){return 1;}\n')
        (build/'build.ninja').write_text(
            f'rule generator\n  command = "{clang}" -std=c++20 $in -o $out\n'
            'rule generate\n  command = ./generator 4 > $out\n'
            f'rule compile\n  command = "{clang}" -std=c++20 -Werror -Wno-invalid-offsetof -DV8_CC_GNU=1 -DV8_CC_MSVC=0 -DTAGGED_SIZE_8_BYTES=0 -DV8_ENABLE_WEBASSEMBLY=1 -Iinclude -MMD -MF $out.d -c $in -o $out\n  depfile = $out.d\n  deps = gcc\n'
            'build generator: generator generator.cc\nbuild include/generated.h: generate generator\nbuild verify.o: compile verify.cc || include/generated.h\nbuild other.o: compile other.cc\n')
        subprocess.run([ninja],cwd=build,capture_output=True,check=True,timeout=75)
        names=('generator','include/generated.h','verify.o','other.o')
        before={n:((build/n).read_bytes(),(build/n).stat().st_mtime_ns) for n in names}
        self.apply();source.write_text(generator_probe(self.path.read_bytes()))
        subprocess.run([ninja],cwd=build,capture_output=True,check=True,timeout=75)
        for n in names[:-1]:self.assertGreater((build/n).stat().st_mtime_ns,before[n][1])
        self.assertEqual(((build/'other.o').read_bytes(),(build/'other.o').stat().st_mtime_ns),before['other.o'])
        self.apply('resume')
        result=subprocess.run([ninja],cwd=build,capture_output=True,text=True,check=True,timeout=30)
        self.assertIn('no work to do',result.stdout)
