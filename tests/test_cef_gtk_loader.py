"""Actual C++ frontend regression for static GTK, plus fail-closed migrations.

The native fixture tests the loader closure, NOT the complete CEF executable,
GTK initialization, a GType registry, or a browser/renderer runtime proof.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from secure_release import cef_gtk_loader as loader

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/gtk/gtk_compat_loaders.cc"

PREAMBLE = r'''
#include <cstdlib>
#include <dlfcn.h>
#include <memory>
#include <string>
#include <utility>
struct CheckStream {
  bool ok;
  ~CheckStream() { if (!ok) std::abort(); }
  template<class T> CheckStream& operator<<(T&&) { return *this; }
};
#define CHECK(x) CheckStream{bool(x)}
#define RAW_PTR_EXCLUSION
#define DISABLE_CFI_DLSYM
namespace ui { enum class LinuxUiBackend { kX11, kWayland }; }
namespace switches { inline constexpr char kGtkVersionFlag[] = "gtk-version"; }
namespace base {
class CommandLine {
 public:
  static CommandLine* ForCurrentProcess() { static CommandLine c; return &c; }
  std::string GetSwitchValueASCII(const char*) { return {}; }
  bool HasSwitch(const char*) { return false; }
};
inline bool StringToUint(const std::string&, unsigned* n) { *n=0; return false; }
struct Environment {
  static std::unique_ptr<Environment> Create() { return std::make_unique<Environment>(); }
};
namespace nix {
inline constexpr int DESKTOP_ENVIRONMENT_GNOME = 1;
inline int GetDesktopEnvironment(Environment*) { return 0; }
}
}
struct GtkBorder { int top=0, left=0, bottom=0, right=0; };
namespace gfx {
struct Insets { static Insets TLBR(int, int, int, int) { return {}; } };
}
inline bool GtkCheckVersion(unsigned) { return false; }
namespace gtk { namespace {
'''
SUFFIX = r'''
} }
int main() {
  (void)gtk::InsetsFromGtkBorder(GtkBorder{});
  if (!gtk::LoadGtk(ui::LinuxUiBackend::kX11)) return 1;
#if defined(CEF_STATIC_GTK3)
  if (gtk::GetLibGtk() != RTLD_DEFAULT) return 2;
  // This function exists ONLY in a separate static archive. The linker must
  // pull and export it for the same RTLD_DEFAULT mechanism as gtk_compat.
  auto probe = gtk::DlSym<int()>(gtk::GetLibGtk(), "cef_gtk_archive_probe");
  if (!probe.fn || probe() != 42) return 3;
#else
  (void)gtk::GetLibGtk();
#endif
  return 0;
}
'''
STUB_HEADER = '''namespace ui_gtk {
inline void InitializeGdk_pixbuf(void*) {}
inline void InitializeGdk(void*) {}
inline void InitializeGtk(void*) {}
inline void InitializeGio(void*) {}
inline void InitializeGsk(void*) {}
}
'''


class GtkLoaderGuardsTests(unittest.TestCase):
    def setUp(self):
        self.original = FIXTURE.read_text(encoding="utf-8")

    def test_migration_preserves_compatibility_lookup(self):
        patched = loader.guarded_source(self.original)
        self.assertEqual(patched.count(loader.TAG), 6)
        self.assertIn("return RTLD_DEFAULT;", patched)
        self.assertIn("bool LoadGtk(ui::LinuxUiBackend backend)", patched)
        # Guards exclude code; they do not delete/alter the upstream fallback.
        for _, start, end, _ in loader.SECTIONS:
            self.assertIn(self.original[self.original.index(start):self.original.index(end)], patched)

    def test_idempotent(self):
        patched = loader.guarded_source(self.original)
        self.assertEqual(loader.guarded_source(patched), patched)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            loader.guarded_source(self.original.replace("// CEF_STATIC_DIRECT_GTK3_V1\n", ""))

    def test_changed_loader_body_rejected_before_or_after_migration(self):
        for text in (self.original, loader.guarded_source(self.original)):
            for old in ("(void)library_name;", 'DlOpen("libgio-2.0.so.0")', "ui_gtk::InitializeGtk(GetLibGtk3())"):
                with self.subTest(old=old), self.assertRaises(ValueError):
                    loader.guarded_source(text.replace(old, old + " /* changed */", 1))

    def test_missing_and_duplicate_anchors_rejected(self):
        for _, start, _, _ in loader.SECTIONS:
            for text in (self.original.replace(start, "changed", 1), self.original + start):
                with self.subTest(anchor=start), self.assertRaises(ValueError):
                    loader.guarded_source(text)

    def test_partial_and_malformed_guards_rejected(self):
        text = loader.guarded_source(self.original)
        opening, closing = loader._guards("handles")
        for changed in (text.replace(closing, "", 1), text + opening,
                        text.replace(opening, opening.replace("!defined", "defined"), 1)):
            with self.subTest(changed=changed[-60:]), self.assertRaises(ValueError):
                loader.guarded_source(changed)

    def test_relocated_guard_rejected(self):
        text = loader.guarded_source(self.original)
        opening, _ = loader._guards("handles")
        text = opening + text.replace(opening, "", 1)
        with self.assertRaises(ValueError):
            loader.guarded_source(text)

    def test_worker_invokes_shared_fix(self):
        worker = (ROOT / "secure_release/cef_strict_iteration.py").read_text(encoding="utf-8")
        self.assertIn("cef_gtk_loader.guarded_source(compat_text)", worker)
        self.assertIn('summary["runtime_gtk_loader_guards_verified"] = True', worker)
        # The existing combined worker calls this same GTK installer.
        combined = ROOT / "secure_release/cef_strict_combined.py"
        if combined.exists():
            self.assertIn("cef_strict_iteration.ensure_static_linux_gtk(", combined.read_text(encoding="utf-8"))


@unittest.skipUnless(sys.platform == "linux", "ELF/dlfcn regression is Linux-only")
class GtkLoaderNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compilers = list({
            str(Path(path).resolve()): path for name in ("clang++", "c++")
            if (path := shutil.which(name))
        }.values())
        if not cls.compilers or not shutil.which("nm") or not shutil.which("ar"):
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise RuntimeError("Linux GTK native regression requires C++, nm and ar")
            raise unittest.SkipTest("Native C++, nm or ar unavailable")

    def test_old_error_and_both_repaired_compilation_modes(self):
        original = FIXTURE.read_text(encoding="utf-8")
        repaired = loader.guarded_source(original)
        for compiler in self.compilers:
            with self.subTest(compiler=compiler), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                header = root / "ui/gtk/gtk_stubs.h"
                header.parent.mkdir(parents=True)
                header.write_text(STUB_HEADER, encoding="utf-8")
                cc, obj = root / "fixture.cc", root / "fixture.o"
                common = [compiler, "-std=c++17", "-O0", "-Wall", "-Wextra", "-Werror", "-I", str(root)]
                def compile_fixture(text, static):
                    cc.write_text(PREAMBLE + text + SUFFIX, encoding="utf-8")
                    return subprocess.run(common + (["-DCEF_STATIC_GTK3=1"] if static else [])
                                          + ["-c", str(cc), "-o", str(obj)],
                                          capture_output=True, text=True, timeout=60)
                # Negative control must reproduce the real declaration bug.
                failed = compile_fixture(original, True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("ui_gtk", failed.stderr)
                self.assertIn("InitializeGdk_pixbuf", failed.stderr)
                for static in (False, True):
                    result = compile_fixture(repaired, static)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    undefined = subprocess.check_output(["nm", "-u", str(obj)], text=True, timeout=30)
                    self.assertEqual(" dlopen" in undefined, not static)
                # Last object is static. Exercise compatibility symbol lookup
                # using a disposable archive, with no GTK/system library loaded.
                probe = root / "probe.cc"
                probe.write_text('extern "C" int cef_gtk_archive_probe() { return 42; }\n', encoding="utf-8")
                subprocess.run([compiler, "-c", str(probe), "-o", str(root / "probe.o")], check=True, capture_output=True, timeout=60)
                subprocess.run(["ar", "rcs", str(root / "libprobe.a"), str(root / "probe.o")], check=True, capture_output=True, timeout=30)
                exe = root / "probe"
                subprocess.run([compiler, str(obj), str(root / "libprobe.a"), "-ldl",
                                "-Wl,-u,cef_gtk_archive_probe", "-Wl,--export-dynamic", "-o", str(exe)],
                               check=True, capture_output=True, timeout=60)
                subprocess.run([str(exe)], check=True, capture_output=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
