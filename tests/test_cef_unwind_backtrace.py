"""Static stack-capture regression, not complete CEF runtime qualification."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_unwind_backtrace as repair

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/cef-backtrace/collect_stack_trace.cc"


def synthetic_source(relative):
    # Independent full-source preflight uses the real pinned files on the runner.
    # These tiny sources exercise each validation/atomicity failure in unit tests.
    return ("// synthetic\n" + "\n".join(old for old, _ in repair.edits(relative))).encode()


class SourceTests(unittest.TestCase):
    def test_header_digest_and_no_loader_or_runtime_override(self):
        self.assertEqual(hashlib.sha256(repair.HEADER.read_bytes()).hexdigest(), repair.HEADER_SHA256)
        attributes = (ROOT / ".gitattributes").read_text()
        self.assertIn("secure_release/cef_unwind_backtrace.h text eol=lf", attributes)
        self.assertIn("tests/fixtures/cef-backtrace/collect_stack_trace.cc text eol=lf", attributes)
        header = repair.HEADER.read_text()
        self.assertIn("_Unwind_Backtrace", header)
        for forbidden in ("dlopen", "dlsym", "pthread_cancel", "malloc(", "backtrace("):
            self.assertNotIn(forbidden, header)
        self.assertIn("state.count >= state.addresses.size()", header)

    def test_exact_original_idempotence_and_reject_unrelated_changes(self):
        for relative in repair.BLOBS:
            with self.subTest(relative=relative):
                source = synthetic_source(relative)
                with mock.patch.dict(repair.BLOBS, {relative: repair.blob(source)}):
                    out = repair.transform(relative, source)
                    self.assertEqual(repair.transform(relative, out), out)
                    for bad in (source+b"tamper", out+b"tamper", out.replace(b"CEF_STATIC_", b"BAD_STATIC_", 1)):
                        with self.assertRaises(ValueError): repair.transform(relative, bad)
                    # One exact edit is insufficient: no partial file is blessed.
                    old, new = repair.edits(relative)[0]
                    partial = source.decode().replace(old,new).encode()
                    with self.assertRaises(ValueError): repair.transform(relative, partial)

    def test_flag_is_private_and_only_default_strict_linux_uses_it(self):
        selected = repair.GN_SELECTION
        self.assertIn('if (is_linux)', selected)
        self.assertIn('cef_static_platform_manifest != ""', selected)
        self.assertIn('current_toolchain == default_toolchain', selected)
        self.assertIn('assert(use_custom_libunwind', selected)
        self.assertNotIn('defines', selected)
        self.assertIn('#elif defined(HAVE_BACKTRACE)', repair.CPP_BRANCH_NEW)
        self.assertTrue(repair.CPP_BRANCH_NEW.startswith(repair.CPP_BRANCH.split('#elif')[0]))

    def test_install_validates_all_files_and_owned_header_before_writing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            originals = {p:synthetic_source(p) for p in repair.BLOBS}
            for p,b in originals.items():
                path=root/p;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b)
            with mock.patch.dict(repair.BLOBS,{p:repair.blob(b) for p,b in originals.items()}), \
                 mock.patch.object(repair.subprocess,'check_output',return_value=repair.CHROMIUM+'\n'):
                target=root/repair.HEADER_TARGET
                target.write_bytes(b'unowned')
                with self.assertRaises(ValueError): repair.install(root)
                for p,b in originals.items():self.assertEqual((root/p).read_bytes(),b)
                target.unlink()
                changed_file=root/'base/debug/stack_trace_posix.cc'
                changed_file.write_bytes(b'unknown')
                with self.assertRaises(ValueError): repair.install(root)
                self.assertEqual((root/'base/BUILD.gn').read_bytes(), originals['base/BUILD.gn'])
                self.assertFalse(target.exists())
                changed_file.write_bytes(originals['base/debug/stack_trace_posix.cc'])
                report=repair.install(root)
                self.assertEqual(report['changed_files'],3)
                stamps={p:(root/p).stat().st_mtime_ns for p in [*repair.BLOBS,repair.HEADER_TARGET]}
                self.assertEqual(repair.install(root)['changed_files'],0)
                self.assertEqual(stamps,{p:(root/p).stat().st_mtime_ns for p in stamps})
                target.write_bytes(b'tampered')
                with self.assertRaises(ValueError): repair.install(root)

    def test_wrong_revision_and_redirected_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            with mock.patch.object(repair.subprocess,'check_output',return_value='0'*40):
                with self.assertRaisesRegex(ValueError,'revision'):repair.install(root)
            if os.name != 'nt':
                actual=root/'real';actual.mkdir()
                link=root/'link';link.symlink_to(actual,target_is_directory=True)
                with self.assertRaises(ValueError):repair.install(link)
                (root/'base').symlink_to(actual,target_is_directory=True)
                (actual/'BUILD.gn').write_text('anything')
                with self.assertRaises(ValueError):repair.check_source(root)

    def test_workflow_has_native_and_full_pinned_source_preflight(self):
        text=(ROOT/'.github/workflows/cef-strict-engine-iteration.yml').read_text()
        self.assertIn('test_cef_unwind_backtrace.py',text)
        self.assertIn('secure_release.cef_unwind_backtrace --check-source',text)
        self.assertIn('secure_release/cef_unwind_backtrace.h',text)


PRELUDE = r'''
#include <span>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <execinfo.h>
#define BUILDFLAG(X) X
#define EXCLUDE_UNWIND_TABLES 0
#define CAN_UNWIND_WITH_FRAME_POINTERS 0
#define HAVE_BACKTRACE
namespace base {
template<class T,class U> T saturated_cast(U v) { return static_cast<T>(v); }
namespace debug {
using std::span;
'''
MAIN = r'''
} }
static int mapped_libgcc() {
  FILE* f=fopen("/proc/self/maps","r"); if(!f) return -1;
  char line[2048];int found=0;
  while(fgets(line,sizeof(line),f)) if(strstr(line,"libgcc_s.so.1")) found=1;
  fclose(f);return found;
}
extern "C" __attribute__((noinline)) size_t capture_caller() {
  const void* values[32]={};
  size_t n=base::debug::CollectStackTrace(std::span<const void*>(values));
  if(n<2 || n>32) abort();
  for(size_t i=0;i<n;++i) if(!values[i]) abort();
  return n;
}
int main() {
  if(mapped_libgcc()!=0) return 20;
  const void* zero[1]={};
  if(base::debug::CollectStackTrace(std::span<const void*>(zero,0))!=0) return 21;
#if CEF_STATIC_UNWIND_BACKTRACE
  if(base::debug::CollectStackTrace(std::span<const void*>())!=0) return 25;
#endif
  const void* sentinel=reinterpret_cast<const void*>(1234);
  const void* small[3]={sentinel,sentinel,sentinel};
  if(base::debug::CollectStackTrace(std::span<const void*>(small,1))!=1) return 22;
  if(small[1]!=sentinel || small[2]!=sentinel) return 23;
  size_t n=capture_caller();
  if(mapped_libgcc()!=EXPECTED_LIBGCC) return 24;
  printf("frames=%zu expected_loader_behavior_verified=1\n",n);
  return 0;
}
'''


@unittest.skipUnless(sys.platform=='linux', 'Linux ELF/unwinder regression')
class NativeTests(unittest.TestCase):
    def test_real_glibc_hidden_load_then_direct_static_unwind(self):
        compilers=[shutil.which('g++'),shutil.which('clang++')]
        linker=shutil.which('gcc')
        self.assertTrue(all(compilers) and linker, 'Linux regression requires GCC and Clang')
        original=FIXTURE.read_text()
        self.assertEqual(original.count(repair.CPP_BRANCH),1)
        repaired=original.replace(repair.CPP_BRANCH,repair.CPP_BRANCH_NEW,1)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for compiler in compilers:
                for optimize in ('-O0','-O2'):
                    for mode,body,flag,expected in [('old',original,0,1),('normal',repaired,0,1),('static',repaired,1,0)]:
                        with self.subTest(compiler=compiler,optimize=optimize,mode=mode):
                            source=root/'test.cc';obj=root/'test.o';exe=root/'test'
                            text=(f'#define CEF_STATIC_UNWIND_BACKTRACE {flag}\n'
                                  f'#define EXPECTED_LIBGCC {expected}\n'
                                  f'#include "{repair.HEADER.as_posix()}"\n'+PRELUDE+body+MAIN)
                            source.write_text(text)
                            subprocess.run([compiler,'-std=c++20',optimize,'-g','-fno-omit-frame-pointer',
                                            '-fno-optimize-sibling-calls','-fno-exceptions','-fno-rtti',
                                            '-Wall','-Wextra','-Werror','-c',str(source),'-o',str(obj)],
                                           check=True,capture_output=True,text=True,timeout=30)
                            subprocess.run([linker,'-static-libgcc','-rdynamic',str(obj),'-o',str(exe)],
                                           check=True,capture_output=True,text=True,timeout=30)
                            dynamic=subprocess.check_output(['readelf','-d',str(exe)],text=True,timeout=10)
                            self.assertNotIn('libgcc_s',dynamic)
                            self.assertNotIn('libstdc++',dynamic)
                            env={k:v for k,v in os.environ.items() if not k.startswith('LD_')}
                            result=subprocess.run([str(exe)],env=env,capture_output=True,text=True,timeout=10)
                            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                            self.assertIn('expected_loader_behavior_verified=1',result.stdout)
                            names=subprocess.check_output(['nm','-u',str(obj)],text=True,timeout=10)
                            if flag:
                                self.assertIn('_Unwind_Backtrace',names)
                                self.assertFalse(any(l.split()[-1]=='backtrace' for l in names.splitlines()))
                            else:
                                self.assertTrue(any(l.split()[-1]=='backtrace' for l in names.splitlines()))

    def test_callback_boundaries_recursive_pc_and_stalled_unwinder(self):
        source=r'''
#include <span>
#include <cstdint>
#include <cassert>
#include "HEADER"
struct Fake { uintptr_t ip,cfa; };
extern "C" _Unwind_Ptr _Unwind_GetIP(_Unwind_Context* p) {return reinterpret_cast<Fake*>(p)->ip;}
extern "C" _Unwind_Word _Unwind_GetCFA(_Unwind_Context* p) {return reinterpret_cast<Fake*>(p)->cfa;}
using S=cef_static_backtrace::State<std::span<const void*>>;
int main() {
 const void* sentinel=reinterpret_cast<const void*>(99);
 const void* a[4]={sentinel,sentinel,sentinel,sentinel};S s{std::span<const void*>(a,3)};
 Fake f{7,100};auto call=[&](){return S::Append(reinterpret_cast<_Unwind_Context*>(&f),&s);};
 assert(call()==_URC_NO_REASON && s.count==0); // skip own frame
 assert(call()==_URC_NO_REASON && s.count==1);
 assert(call()==_URC_END_OF_STACK && s.count==1); // same IP+CFA: stop
 f.cfa=200;assert(call()==_URC_NO_REASON && s.count==2); // recursion: keep
 f.ip=0;assert(call()==_URC_END_OF_STACK && s.count==2); // no null suffix
 f.ip=8;assert(call()==_URC_END_OF_STACK && s.count==3); // exact capacity
 assert(call()==_URC_END_OF_STACK && s.count==3 && a[3]==sentinel);
 S empty{std::span<const void*>()};empty.skip_self=false;
 assert(S::Append(nullptr,&empty)==_URC_END_OF_STACK);
}
'''.replace('HEADER',repair.HEADER.as_posix())
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);p=root/'bounds.cc';exe=root/'bounds';p.write_text(source)
            for c in ['g++','clang++']:
                subprocess.run([c,'-std=c++20','-Wall','-Wextra','-Werror',str(p),'-o',str(exe)],
                               check=True,capture_output=True,text=True,timeout=30)
                subprocess.run([str(exe)],check=True,capture_output=True,text=True,timeout=10)


if __name__=='__main__':unittest.main()
