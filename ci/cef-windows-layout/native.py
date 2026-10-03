"""Public small native ABI control; not engine qualification."""
from pathlib import Path
import os, subprocess, tempfile
SOURCE = r'''
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstddef>
#pragma pack(push,4)
struct Map {
 uint32_t map_word_;
 uint8_t instance_size_in_words_, inobject_properties_start_or_constructor_function_index_, used_or_unused_instance_size_in_words_, visitor_id_;
 uint16_t instance_type_;
 uint8_t bit_field_;
 std::atomic<uint8_t> bit_field2_;
 std::atomic<uint32_t> bit_field3_;
 uint32_t prototype_, constructor_or_back_pointer_or_native_context_, instance_descriptors_, dependent_code_, prototype_validity_cell_, transitions_or_prototype_info_;
};
#pragma pack(pop)
#pragma pack(push,1)
struct ExtendedMap : Map { std::atomic<uint8_t> bit_field_ex_; };
#pragma pack(pop)
#pragma pack(push,4)
struct JSInterceptorMap : ExtendedMap {
 uint8_t flags_, extended_padding_[2];
 uint32_t named_interceptor_, indexed_interceptor_, fast_case_validity_cell_;
};
#pragma pack(pop)
int main() {
 printf("PUBLIC_LAYOUT atomic8=%zu/%zu map=%zu/%zu extended=%zu/%zu flags=%zu named=%zu size=%zu\n",sizeof(std::atomic<uint8_t>),alignof(std::atomic<uint8_t>),sizeof(Map),alignof(Map),sizeof(ExtendedMap),alignof(ExtendedMap),offsetof(JSInterceptorMap,flags_),offsetof(JSInterceptorMap,named_interceptor_),sizeof(JSInterceptorMap));
}
'''
with tempfile.TemporaryDirectory() as d:
 root=Path(d); src=root/'probe.cc';src.write_text(SOURCE)
 if os.name=='nt':
  vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
  vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
  clang=Path(os.environ['ProgramFiles'])/'LLVM/bin/clang-cl.exe'
  batch=root/'compile.cmd'; out=root/'probe.exe'
  batch.write_text('@echo off\ncall "'+vs+'/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\nif errorlevel 1 exit /b 90\n"'+str(clang)+'" /nologo /std:c++20 /EHsc probe.cc /Fe:probe.exe\n')
  cmd=['cmd.exe','/d','/c',str(batch)]
 else:
  out=root/'probe';cmd=['clang++','-std=c++20',str(src),'-o',str(out)]
 subprocess.run(cmd,cwd=root,check=True,timeout=60)
 subprocess.run([str(out)],cwd=root,check=True,timeout=10)
