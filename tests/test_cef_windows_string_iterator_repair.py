"""MSVC/Perfetto regression for blink::String iterator return-type completeness.

The full pinned wtf_string.h and CodePointIterator header are hash/blob checked.
The native probe uses the exact public begin/end declarations and unchanged
Perfetto overload excerpt. The shell only supplies CodePointIterator support
headers; it is not a full Blink/CEF runtime proof.
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

from secure_release import cef_windows_iteration as worker
from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_string_inputs import INPUTS, public_input, verify_public

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/cef-windows"
WTF = "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
ITERATOR = "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"
INCLUDE = '#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"'
DECL = "  CodePointIterator begin() const;\n  CodePointIterator end() const;\n"


def probe_source(wtf_bytes):
    text = wtf_bytes.decode("utf-8")
    if text.count(DECL) != 1:
        raise ValueError("Pinned blink::String iterator declarations changed")
    include = INCLUDE + "\n" if text.count(INCLUDE) == 1 else ""
    if text.count(INCLUDE) not in (0, 1):
        raise ValueError("Unexpected CodePointIterator include count")
    return r"""
#include <cassert>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>
""" + include + r"""
namespace perfetto {
struct TraceState { int strings = 0; int arrays = 0; int elements = 0; };
struct TracedValue {
  TraceState* state;
  struct Array {
    TraceState* state;
    template <class T> void Append(const T&) { ++state->elements; }
  };
  Array WriteArray() && { ++state->arrays; return {state}; }
};
namespace base {
template <int N> struct priority_tag : priority_tag<N-1> {};
template <> struct priority_tag<0> {};
}
template <class T> struct check_traced_value_support { using type = void; };
namespace internal {
#include "perfetto_iterator_overloads.inc"
}
template <class T> void WriteIntoTracedValue(TracedValue context, T&& value) {
  internal::WriteImpl(base::priority_tag<4>{}, context, std::forward<T>(value));
}
}
namespace blink {
class CodePointIterator;
class String {
 public:
  CodePointIterator begin() const;
  CodePointIterator end() const;
  void WriteIntoTrace(perfetto::TracedValue context) const {
    ++context.state->strings;
  }
};
}
int main() {
  perfetto::TraceState state;
  const blink::String constant;
  perfetto::WriteIntoTracedValue({&state}, constant);
  blink::String mutable_string;
  perfetto::WriteIntoTracedValue({&state}, mutable_string);
  std::vector<int> control{1, 2, 3};
  perfetto::WriteIntoTracedValue({&state}, control);
  assert(state.strings == 2);
  assert(state.arrays == 1 && state.elements == 3);
}
"""


def write_headers(root):
    files = {
        "unicode/utf16.h":
            "#pragma once\n#include <cstdint>\n"
            "void ProbeNext(const char16_t*,uint32_t&,uint32_t,int32_t&);\n"
            "void ProbeForward(const char16_t*,uint32_t&,uint32_t);\n"
            "#define U16_NEXT(s,i,n,c) ProbeNext(s,i,n,c)\n"
            "#define U16_FWD_1(s,i,n) ProbeForward(s,i,n)\n",
        "base/check_op.h":
            "#pragma once\n#include <cassert>\n"
            "#define CHECK_GE(a,b) assert((a)>=(b))\n"
            "#define CHECK_LE(a,b) assert((a)<=(b))\n"
            "#define DCHECK_EQ(a,b) assert((a)==(b))\n",
        "base/compiler_specific.h":
            "#pragma once\n#define UNSAFE_BUFFERS(...) __VA_ARGS__\n",
        "base/containers/span.h":
            "#pragma once\n#include <span>\n"
            "namespace base { template<class T> using span=std::span<T>; }\n",
        "base/memory/stack_allocated.h":
            "#pragma once\n#define STACK_ALLOCATED() static_assert(true)\n",
        "base/numerics/safe_conversions.h":
            "#pragma once\nnamespace base { template<class D,class S> "
            "constexpr D checked_cast(S v){return static_cast<D>(v);} }\n",
        "base/types/to_address.h":
            "#pragma once\n#include <memory>\nnamespace base { using std::to_address; }\n",
        "third_party/blink/renderer/platform/wtf/forward.h":
            "#pragma once\n#include <cstdint>\nnamespace blink { "
            "using UChar=char16_t; using UChar32=int32_t; using wtf_size_t=uint32_t; }\n",
    }
    for name, value in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    target = root / ITERATOR
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(public_input(ITERATOR))
    (root / "perfetto_iterator_overloads.inc").write_bytes(
        (FIXTURES / "perfetto_iterator_overloads.inc").read_bytes()
    )


class StringIteratorCompletenessTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="blink string iterator ")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.raw = public_input(WTF)
        self.fixed = repair.transform(self.raw, repair.WTF_STRING_HEADER)
        self.key = repair.build_key(repair.BASE_KEY)

    def test_public_inputs_exact_and_correction_is_one_include(self):
        for path in INPUTS:
            raw = public_input(path)
            self.assertEqual(verify_public(path, raw), raw)
            for invalid in (raw[:-1], raw + b"\n", b"X" + raw[1:]):
                with self.assertRaises(ValueError):
                    verify_public(path, invalid)
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), repair.WTF_STRING_BEFORE)
        self.assertEqual(hashlib.sha256(self.fixed).hexdigest(), repair.WTF_STRING_AFTER)
        self.assertEqual(self.raw.count(INCLUDE.encode()), 0)
        self.assertEqual(self.fixed.count(INCLUDE.encode()), 1)
        self.assertEqual(self.fixed.replace((INCLUDE + "\n").encode(), b"", 1), self.raw)
        self.assertEqual(self.raw.count(DECL.encode()), 1)
        self.assertEqual(self.fixed.count(DECL.encode()), 1)
        for newline in (b"\n", b"\r\n"):
            source = self.raw.replace(b"\n", newline)
            changed = repair.transform(source, repair.WTF_STRING_HEADER)
            self.assertEqual(repair.transform(changed, repair.WTF_STRING_HEADER), changed)

    def test_v11_profile_lock_and_failed45_not_resume_inputs(self):
        profile = repair.profile()
        self.assertEqual(profile["id"], "windows-watermark-string-include-v22")
        self.assertEqual(len(profile["corrections"]), 23)
        self.assertEqual(profile["corrections"][10], {
            "path": WTF,
            "before_sha256": repair.WTF_STRING_BEFORE,
            "after_sha256": repair.WTF_STRING_AFTER,
        })
        self.assertEqual(worker.qualification_lock(ROOT)["source_repair"], profile)
        with self.assertRaises(ValueError):
            repair.restore_contract(dict(repair.LEGACY, run=37220692089), repair.BASE_KEY)
        for field in ("path", "before_sha256", "after_sha256"):
            altered = copy.deepcopy(profile)
            altered["corrections"][10][field] = "0" * len(altered["corrections"][10][field])
            with mock.patch.object(repair, "profile", return_value=altered):
                self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_native_msvc_incomplete_return_original_fails_fixed_passes(self):
        include = self.root / "include"
        write_headers(include)
        source = self.root / "probe.cc"
        binary = self.root / ("probe.exe" if os.name == "nt" else "probe")
        if os.name == "nt":
            vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
            vs = Path(subprocess.check_output([
                str(vswhere), "-latest", "-products", "*", "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property", "installationPath",
            ], text=True).strip())
            version = (vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt").read_text().strip()
            self.assertEqual(version, "14.44.35207")
            clang = Path(os.environ["ProgramFiles"]) / "LLVM/bin/clang-cl.exe"
            self.assertTrue(clang.is_file())
            batch = self.root / "compile.cmd"
            batch.write_text(
                '@echo off\ncall "' + str(vs / "VC/Auxiliary/Build/vcvarsall.bat") + '" x64 >nul\n'
                'if errorlevel 1 exit /b 90\n'
                '"' + str(clang) + '" /nologo /std:c++20 /EHsc /W4 /WX '
                '/I"' + str(include) + '" "' + str(source) + '" '
                '/Fe:"' + str(binary) + '" /Fo:"' + str(self.root / "probe.obj") + '"\n',
                encoding="utf-8",
            )
            command = ["cmd.exe", "/d", "/c", str(batch)]
            source.write_text(probe_source(self.raw), encoding="utf-8")
            old = subprocess.run(command, cwd=self.root, capture_output=True, text=True,
                                 errors="replace", timeout=90)
            old_text = old.stdout + old.stderr
            self.assertNotEqual(old.returncode, 0)
            self.assertNotEqual(old.returncode, 90)
            self.assertIn("incomplete return type", old_text)
            self.assertIn("CodePointIterator", old_text)
            source.write_text(probe_source(self.fixed), encoding="utf-8")
            fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True,
                                   errors="replace", timeout=90)
            self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
            subprocess.run([str(binary)], cwd=self.root, check=True, capture_output=True, timeout=30)
            print("CEF_WTF_STRING_ITERATOR_NATIVE toolset=" + version +
                  " original_failed=true fixed_compiles=true string_priority=true")
            return
        for compiler in ("clang++", "g++"):
            executable = shutil.which(compiler)
            self.assertIsNotNone(executable)
            command = [executable, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                       "-I", str(include), str(source), "-o", str(binary)]
            source.write_text(probe_source(self.raw), encoding="utf-8")
            old = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=90)
            if old.returncode == 0:
                subprocess.run([str(binary)], cwd=self.root, check=True, capture_output=True, timeout=30)
            else:
                self.assertIn("CodePointIterator", old.stdout + old.stderr)
            source.write_text(probe_source(self.fixed), encoding="utf-8")
            fixed = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=90)
            self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
            subprocess.run([str(binary)], cwd=self.root, check=True, capture_output=True, timeout=30)
            if compiler == "clang++":
                sanitized = subprocess.run(
                    command + ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
                    cwd=self.root, capture_output=True, text=True, timeout=90,
                )
                self.assertEqual(sanitized.returncode, 0, sanitized.stdout + sanitized.stderr)
                subprocess.run([str(binary)], cwd=self.root, check=True, capture_output=True, timeout=30)
        print("CEF_WTF_STRING_ITERATOR_NATIVE unix_fixed_compiles=true string_priority=true")


if __name__ == "__main__":
    unittest.main()
