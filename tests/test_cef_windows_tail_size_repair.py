"""Native regression for Torque logical data extent versus complete C++ size.

Execute the actual GenerateCppObjectLayoutDefinitionAsserts method, plus its
actual WriteField/WriteMarker/FirstFieldStart helpers, extracted from the pinned
public generator. ClassType/Field metadata and field scheduling are small test
adapters; C++ layout comes from the public Map fields and packing definitions.
This is not a build of the full Torque compiler, V8 or the CEF runtime.
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

from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_layout_inputs import public_input
from tests import test_cef_windows_layout_repair as layout

GENERATOR = 'src/torque/implementation-visitor.cc'
V6_KEY = '87e54ca80f456a52ac85ea50a925866eba5bce50108d727fc31378b45d81896e'
V6_DIGEST = 'e1bba1f74d36cbbb9bcdd8810f6f2e91ea9197fd6ab6e3a98d07f2787b035359'
TORQUE_CORRECTION = next(c for c in repair.CORRECTIONS if c[0] == repair.TORQUE_SOURCE)


def previous_generator(raw):
    old, new = TORQUE_CORRECTION[3][0]
    result = raw.replace(old, new, 1)
    if hashlib.sha256(result).hexdigest() != V6_DIGEST:
        raise ValueError('Previous generator identity mismatch')
    return result


def assertion_generator(raw):
    """Extract production methods verbatim; keep support metadata explicit."""
    text = raw.decode('utf-8')
    block = text[text.index('class ClassFieldOffsetGenerator :'):text.index('class CppClassGenerator {')]
    write = block[block.index('  void WriteField('):block.index('  void WriteFieldOffsetGetter(')]
    marker = block[block.index('  void WriteMarker('):block.index('\n private:')]
    first = block[block.index('  static std::string FirstFieldStart('):block.index('\n  std::ostream& hdr_;')]
    start = 'void CppClassGenerator::GenerateCppObjectLayoutDefinitionAsserts() {'
    method = text[text.index(start):text.index('SourcePosition CppClassGenerator::Position()')]
    # override belongs to the real base interface. Supply that same interface.
    return r'''
#include <cassert>
#include <cctype>
#include <cstddef>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
struct SourcePosition {
 struct Scope { explicit Scope(const SourcePosition&) {} };
};
using CurrentSourcePosition = SourcePosition;
std::ostream& operator<<(std::ostream& os,const SourcePosition&) {return os<<"public fixture";}
std::string CamelifyString(const std::string& s) {
 std::string out; bool upper=true;
 for (char c:s) {if(c=='_'){upper=true;continue;} out+=upper ? static_cast<char>(std::toupper(static_cast<unsigned char>(c))) : c;upper=false;}
 return out;
}
struct FieldType {bool structure=false;bool IsStructType() const{return structure;}};
struct NameAndType {std::string name;const FieldType* type;};
struct Field {
 SourcePosition pos;
 NameAndType name_and_type;
 std::optional<int> offset;
 std::optional<int> index;
 bool index_is_constant;
 size_t bytes;
};
struct ResidueClass {std::optional<size_t> value;std::optional<size_t> SingleValue() const{return value;}};
struct ClassType {
 std::string n;const ClassType* parent;size_t bytes;std::vector<Field> own;
 bool abstract=false,fixed=true;
 const std::string& name() const{return n;}
 const std::vector<Field>& fields() const{return own;}
 const ClassType* GetSuperClass() const{return parent;}
 bool IsAbstract() const{return abstract;}
 bool HasStaticSize() const{return fixed;}
 bool IsLayoutDefinedInCpp() const{return true;}
 bool IsShape() const{return false;}
 ResidueClass size() const{return {fixed ? std::optional<size_t>(bytes) : std::nullopt};}
};
class FieldOffsetsGenerator {
 public:
 virtual ~FieldOffsetsGenerator()=default;
 virtual void WriteField(const Field&,const std::string&)=0;
 virtual void WriteMarker(const std::string&)=0;
};
class ClassFieldOffsetGenerator : public FieldOffsetsGenerator {
 public:
 ClassFieldOffsetGenerator(std::ostream& hdr,std::ostream&,const ClassType* type,
     const std::string&,const ClassType* parent,bool templates,bool)
   :hdr_(hdr),previous_field_end_(FirstFieldStart(type,parent,templates)),type_(type){}
 void RecordOffsetFor(const Field& field) {
   if(field.offset.has_value()) WriteField(field,std::to_string(field.bytes));
 }
 void Finish(){if(!type_->IsAbstract() && type_->HasStaticSize()) WriteMarker("kSize");}
''' + write + marker + first + r'''
 private:
 std::ostream& hdr_;std::string previous_field_end_;const ClassType* type_;
};
class CppClassGenerator {
 public:
 CppClassGenerator(const ClassType* type,std::ostream& out)
   :type_(type),name_(type->name()),gen_name_("TorqueGenerated"+name_),impl_(out){}
 void GenerateCppObjectLayoutDefinitionAsserts();
 private:
 SourcePosition Position(){return {};}
 const ClassType* type_;std::string name_,gen_name_;std::ostream& impl_;
};
''' + method + r'''
int main(int argc,char** argv) {
 assert(argc>=2);
 const size_t tagged=std::stoul(argv[1]);assert(tagged==4 || tagged==8);
 const size_t map_bytes=tagged==4 ? 40 : 72;
 const std::string mode=argc==3 ? argv[2] : "valid";
 const FieldType scalar{};
 const Field ex{{},{"bit_field_ex",&scalar},0,std::nullopt,false,mode=="wrong-width" ? 2u : 1u};
 ClassType map{"Map",nullptr,map_bytes,{}};
 ClassType extended{"ExtendedMap",&map,map_bytes+1,{ex}};
 ClassType child{"JSInterceptorMap",&extended,map_bytes+4*tagged,{
   {{},{"flags",&scalar},0,std::nullopt,false,1},
   {{},{"extended_padding",&scalar},0,2,true,tagged-2},
   {{},{"named_interceptor",&scalar},0,std::nullopt,false,tagged},
   {{},{"indexed_interceptor",&scalar},0,std::nullopt,false,tagged},
   {{},{"fast_case_validity_cell",&scalar},0,std::nullopt,false,tagged}}};
 if(mode=="abstract") extended.abstract=true;
 if(mode=="dynamic") extended.fixed=false;
 std::cout<<"namespace v8::internal {\n";
 CppClassGenerator(&extended,std::cout).GenerateCppObjectLayoutDefinitionAsserts();
 if(mode=="valid") CppClassGenerator(&child,std::cout).GenerateCppObjectLayoutDefinitionAsserts();
 std::cout<<"}\n";
}
'''


VERIFY = r'''
#include <cassert>
#include <cstddef>
#include "src/objects/js-interceptor-map.h"
#include "generated.h"
using namespace v8::internal;
static_assert(sizeof(JSInterceptorMap)==(kTaggedSize==4 ? 56 : 104));
static_assert(offsetof(JSInterceptorMap,flags_)==(kTaggedSize==4 ? 41 : 73));
int main(){
 ExtendedMap base{};base.bit_field_ex_.store(7);
 assert(base.bit_field_ex_.load()==7);
 JSInterceptorMap child{};child.flags_=3;child.named_interceptor_.value_=11;
 child.indexed_interceptor_.value_=22;child.fast_case_validity_cell_.value_=33;
 assert(child.flags_==3 && child.named_interceptor_.value_==11);
 assert(child.indexed_interceptor_.value_==22 && child.fast_case_validity_cell_.value_==33);
}
'''


class TorqueTailSizeTests(unittest.TestCase):
    compiler = layout.TorqueLayoutRepairTests.compiler

    def setUp(self):
        folder=tempfile.TemporaryDirectory(prefix='torque tail size ')
        self.addCleanup(folder.cleanup)
        self.root=Path(folder.name).resolve()
        self.raw=public_input(GENERATOR)
        self.fixed=repair.transform(self.raw,repair.TORQUE_SOURCE)
        self.v6=previous_generator(self.raw)

    def test_exact_profile_keeps_source_set_and_rejects_v6(self):
        self.assertEqual(repair.profile()['id'],'windows-accessibility-default-iterator-v10')
        self.assertEqual(len(repair.CORRECTIONS),10)
        self.assertEqual(repair.profile()['v8_commit'],'4323497a6a73839e6d5260f6acd7ec0212cb3321')
        self.assertNotEqual(repair.build_key(repair.BASE_KEY),V6_KEY)
        for selected in (dict(repair.LEGACY,build_key=V6_KEY),dict(repair.LEGACY,run=37144079381)):
            with self.assertRaises(ValueError):repair.restore_contract(selected,repair.BASE_KEY)

    def test_generator_edit_preserves_offsets_and_adds_extent_checks(self):
        self.assertEqual(len(TORQUE_CORRECTION[3]),3)
        self.assertIn(b'kSize + alignof(',self.fixed)
        self.assertIn(b'End + 1 == ',self.fixed)
        self.assertEqual(self.raw.count(b'static_assert(')+1,self.fixed.count(b'static_assert('))
        for old,new in TORQUE_CORRECTION[3][1:]:
            self.assertNotIn(b'ExtendedMap',new)
            self.assertNotIn(b'#if',new)
            self.assertEqual(self.v6.count(old),1)
        # Changes are confined to existing assertion generation and v6's parent fix.
        restored=self.fixed
        for old,new in reversed(TORQUE_CORRECTION[3]):restored=restored.replace(new,old,1)
        self.assertEqual(restored,self.raw)

    def test_half_applied_generator_and_previous_marker_are_rejected(self):
        work=self.root/'work';layout.populate(work)
        path=work/repair.TORQUE_SOURCE;path.write_bytes(self.v6)
        before={p:p.read_bytes() for p in work.rglob('*') if p.is_file()}
        with self.assertRaises(ValueError):repair.apply(work,repair.build_key(repair.BASE_KEY),'legacy')
        self.assertEqual(before,{p:p.read_bytes() for p in before})
        self.assertFalse((work/repair.MARKER).exists())
        for i in (1,2):
            old,new=TORQUE_CORRECTION[3][i]
            with self.assertRaises(ValueError):repair.transform(self.v6.replace(old,new,1),repair.TORQUE_SOURCE)

    def test_fixed_generator_resume_is_idempotent_and_proof_exact(self):
        work=self.root/'work';layout.populate(work);key=repair.build_key(repair.BASE_KEY)
        repair.apply(work,key,'legacy');before={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in work.rglob('*') if p.is_file()}
        self.assertEqual(repair.apply(work,key,'resume'),'already-applied')
        self.assertEqual(before,{p:(p.read_bytes(),p.stat().st_mtime_ns) for p in before})
        summary={'base_build_key':repair.BASE_KEY,'source_repair_verified':True,'source_repair':repair.profile()}
        repair.verify_summary(summary,{'build_key':key})
        bad=copy.deepcopy(summary);bad['source_repair']['corrections'][-1]['after_sha256']=V6_DIGEST
        with self.assertRaises(ValueError):repair.verify_summary(bad,{'build_key':key})

    def test_native_actual_emitter_checks_parent_child_and_bad_layouts(self):
        old_failures=negative=0
        for tagged in (4,8):
            case=self.root/str(tagged);case.mkdir();include=case/'include'
            layout.install_layout(include,tagged)
            source=case/'emitter.cc';exe=case/('emitter.exe' if os.name=='nt' else 'emitter')
            verify=case/'verify.cc';out=case/('verify.exe' if os.name=='nt' else 'verify')
            verify.write_text(VERIFY)
            for label,raw in (('v6',self.v6),('v7',self.fixed)):
                source.write_text(assertion_generator(raw))
                result=self.compiler(source,exe,tagged);self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                generated=subprocess.check_output([str(exe),str(tagged)],cwd=case,text=True,timeout=10)
                self.assertIn('TorqueGeneratedExtendedMapAsserts',generated)
                self.assertIn('TorqueGeneratedJSInterceptorMapAsserts',generated)
                self.assertEqual(generated.count('static_assert('),13 if label=='v7' else 8)
                (include/'generated.h').write_text(generated)
                result=self.compiler(verify,out,tagged)
                if label=='v6' and os.name=='nt':
                    old_failures+=1;self.assertNotEqual(result.returncode,0)
                    self.assertIn('kSize == sizeof',result.stdout+result.stderr)
                else:
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    subprocess.run([str(out)],cwd=case,capture_output=True,check=True,timeout=10)
            # Mutations that must be rejected, including a wrong width whose
            # rounded size alone would still match on Windows (42 -> 44).
            wrong_width=subprocess.check_output([str(exe),str(tagged),'wrong-width'],cwd=case,text=True,timeout=10)
            variants=[wrong_width,generated.replace('kFlagsOffset = '+str(41 if tagged==4 else 73),
                                                     'kFlagsOffset = '+str(42 if tagged==4 else 74),1)]
            for bad in variants:
                self.assertNotEqual(bad,generated)
                (include/'generated.h').write_text(bad)
                result=self.compiler(verify,out,tagged);self.assertNotEqual(result.returncode,0)
                self.assertIn('static assertion',result.stdout+result.stderr);negative+=1
            (include/'generated.h').write_text(generated)
            map_path=include/'src/objects/map.h';original=map_path.read_text()
            for mutation in (original.replace('std::atomic<uint8_t> bit_field_ex_;','std::atomic<uint16_t> bit_field_ex_;'),
                             original.replace('std::atomic<uint8_t> bit_field_ex_;','std::atomic<uint8_t> bit_field_ex_;\n  uint8_t extra_[4];')):
                map_path.write_text(mutation)
                result=self.compiler(verify,out,tagged);self.assertNotEqual(result.returncode,0)
                self.assertIn('static assertion',result.stdout+result.stderr);negative+=1
            map_path.write_text(original)
            for mode in ('abstract','dynamic'):
                skipped=subprocess.check_output([str(exe),str(tagged),mode],cwd=case,text=True,timeout=10)
                self.assertNotIn('sizeof(ExtendedMap)',skipped)
                self.assertIn('kBitFieldExOffset == offsetof',skipped)
            if os.name!='nt':
                result=self.compiler(verify,out,tagged,('-fsanitize=address,undefined','-fno-omit-frame-pointer'))
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                subprocess.run([str(out)],cwd=case,capture_output=True,check=True,timeout=10)
        print(f'CEF_TORQUE_TAIL_SIZE_VERIFIED old_windows_failures={old_failures} tagged_sizes=2 parent_and_child=true field_extents=true negative_controls={negative}')

    @unittest.skipIf(os.name=='nt','Native Unix Ninja generated assertion dependency test')
    def test_ninja_emitter_change_regenerates_header_and_dependent_only(self):
        ninja=shutil.which('ninja');clang=shutil.which('clang++');self.assertTrue(ninja and clang)
        case=self.root/'ninja';case.mkdir();layout.install_layout(case/'include',4)
        source=case/'emitter.cc';source.write_text(assertion_generator(self.v6))
        (case/'verify.cc').write_text(VERIFY);(case/'other.cc').write_text('int unrelated(){return 1;}\n')
        (case/'build.ninja').write_text(
            f'rule emitter\n  command = "{clang}" -std=c++20 $in -o $out\n'
            'rule generate\n  command = ./emitter 4 > $out\n'
            f'rule compile\n  command = "{clang}" -std=c++20 -Werror -Wno-invalid-offsetof -DV8_CC_GNU=1 -DV8_CC_MSVC=0 -DTAGGED_SIZE_8_BYTES=0 -DV8_ENABLE_WEBASSEMBLY=1 -Iinclude -MMD -MF $out.d -c $in -o $out\n  depfile = $out.d\n  deps = gcc\n'+
            'build emitter: emitter emitter.cc\nbuild include/generated.h: generate emitter\nbuild verify.o: compile verify.cc || include/generated.h\nbuild other.o: compile other.cc\n')
        subprocess.run([ninja],cwd=case,capture_output=True,check=True,timeout=75)
        names=('emitter','include/generated.h','verify.o','other.o')
        before={n:((case/n).read_bytes(),(case/n).stat().st_mtime_ns) for n in names}
        source.write_text(assertion_generator(self.fixed))
        subprocess.run([ninja],cwd=case,capture_output=True,check=True,timeout=75)
        for name in names[:-1]:self.assertGreater((case/name).stat().st_mtime_ns,before[name][1])
        self.assertEqual(((case/'other.o').read_bytes(),(case/'other.o').stat().st_mtime_ns),before['other.o'])
        result=subprocess.run([ninja],cwd=case,capture_output=True,text=True,check=True,timeout=30)
        self.assertIn('no work to do',result.stdout)
