"""Native Windows regression for V8 CFunction completeness in v8-template.h."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from secure_release import cef_windows_source_repair as repair


SOURCE_ROOT = os.environ.get("CEF_WINDOWS_CFUNCTION_SOURCE_ROOT")


def pinned_template() -> bytes:
    if not SOURCE_ROOT:
        raise unittest.SkipTest("CEF_WINDOWS_CFUNCTION_SOURCE_ROOT is not set")
    path = Path(SOURCE_ROOT) / "include/v8-template.h"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != repair.TEMPLATE_BEFORE:
        raise ValueError("Pinned public v8-template.h mismatch")
    return data


class CFunctionSpanRepairTests(unittest.TestCase):
    def setUp(self):
        self.raw = pinned_template()

    def test_exact_single_include_edit_and_digest(self):
        fixed = repair.transform(self.raw, repair.TEMPLATE_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.TEMPLATE_AFTER)
        anchor = b'#include "v8-function-callback.h"  // NOLINT(build/include_directory)\n'
        inserted = b'#include "v8-fast-api-calls.h"      // NOLINT(build/include_directory)\n'
        self.assertEqual(self.raw.count(anchor), 1)
        self.assertNotIn(inserted, self.raw)
        self.assertEqual(fixed.count(inserted), 1)
        self.assertEqual(fixed.replace(inserted, b"", 1), self.raw)
        self.assertEqual(repair.transform(fixed, repair.TEMPLATE_HEADER), fixed)

    def test_unreviewed_template_is_rejected(self):
        for bad in (
            self.raw + b"\n",
            self.raw.replace(b"class CFunction;", b"class CFunctionX;", 1),
            self.raw.replace(b"\n", b"\r\n", 1),
        ):
            with self.subTest(digest=hashlib.sha256(bad).hexdigest()):
                with self.assertRaises(ValueError):
                    repair.transform(bad, repair.TEMPLATE_HEADER)

    @unittest.skipUnless(os.name == "nt", "MSVC STL regression is Windows-specific")
    def test_native_msvc_stl_original_fails_fixed_header_compiles(self):
        root = Path(tempfile.mkdtemp(prefix="cef cfunction span ")).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        source_root = Path(SOURCE_ROOT).resolve()
        original_include = source_root / "include"
        fixed_include = root / "include"
        shutil.copytree(original_include, fixed_include)
        (fixed_include / "v8-template.h").write_bytes(
            repair.transform(self.raw, repair.TEMPLATE_HEADER)
        )
        source = root / "probe.cc"
        source.write_text('#include "v8-template.h"\nint main(){return 0;}\n',
                          encoding="utf-8")

        vswhere = (Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
                   / "Microsoft Visual Studio/Installer/vswhere.exe")
        clang = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin/clang-cl.exe"
        self.assertTrue(vswhere.is_file(), str(vswhere))
        self.assertTrue(clang.is_file(), str(clang))
        vs = subprocess.check_output([
            str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ], text=True).strip()

        def compile_with(include: Path, name: str):
            obj = root / f"{name}.obj"
            batch = root / f"{name}.cmd"
            command = (
                f'"{clang}" /nologo /std:c++20 /EHsc /W4 /WX '
                f'-Wno-unused-parameter -Wno-cast-function-type-mismatch '
                f'/I"{include}" /c "{source}" /Fo:"{obj}"'
            )
            batch.write_text(
                '@echo off\n'
                f'call "{vs}/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\n'
                'if errorlevel 1 exit /b 90\n'
                + command + "\n",
                encoding="utf-8",
            )
            return subprocess.run(
                ["cmd.exe", "/d", "/c", str(batch)],
                cwd=root, text=True, capture_output=True,
                errors="replace", timeout=90,
            )

        old = compile_with(original_include, "old")
        self.assertNotEqual(old.returncode, 0, old.stdout + old.stderr)
        old_text = (old.stdout + old.stderr).lower()
        self.assertIn("cfunction", old_text)
        self.assertTrue(
            "incomplete" in old_text or "pointer arithmetic" in old_text,
            old.stdout + old.stderr,
        )

        fixed = compile_with(fixed_include, "fixed")
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        print("CEF_V8_CFUNCTION_SPAN_VERIFIED original_failed=true fixed_compiles=true")


if __name__ == "__main__":
    unittest.main()
