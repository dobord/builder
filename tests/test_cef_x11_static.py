"""Pinned native loader and strict ELF regressions, not CEF qualification."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from secure_release import cef_x11_static as desktop

FIXTURE_ROOT = Path(__file__).parent / 'fixtures/x11'
FIXTURE_PARTS = tuple(f'pinned-sources.zip.part{i}' for i in range(3))
FIXTURE_SHA = '51970038ba9ae130d7041444d4e0bd9081b06712cf4d6b247b48d0e33ae32770'


def fixture_files():
    raw = b''.join((FIXTURE_ROOT / name).read_bytes() for name in FIXTURE_PARTS)
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA:
        raise ValueError('Pinned public X11 fixture changed')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return {n: z.read(n) for n in z.namelist()}


def fake_platform(root):
    prefix = root / 'prefix'
    (prefix / 'lib').mkdir(parents=True)
    files, objects, modules = {}, {}, {}
    names = ('X11', 'Xcomposite', 'Xdamage', 'Xext', 'Xfixes', 'Xrandr', 'Xrender', 'Xtst', 'xcb')
    for module, name in zip(desktop.X_MODULES, names):
        relative = 'lib/lib' + name + '.a'
        data = b'!<arch>\n'  # parser fixture only; native test uses real archives.
        (prefix / relative).write_bytes(data)
        files[relative] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        objects[relative] = 1
        modules[module] = {'libraries': [relative]}
    value = {'schema': 1, 'kind': 'linux-x64-static-platform-build-inputs',
             'runtime_verified': False, 'modules': modules, 'files': files,
             'archive_objects': objects}
    manifest = root / 'platform.json'
    manifest.write_text(json.dumps(value))
    return manifest, prefix, hashlib.sha256(manifest.read_bytes()).hexdigest()


class DesktopTransformTests(unittest.TestCase):
    def test_pinned_xlib_sources_and_v1_migration(self):
        originals = fixture_files()
        for relative in desktop.LEGACY_PATCHED:
            original = originals[relative]
            result = desktop.transform(relative, original, original)
            self.assertEqual(hashlib.sha256(result).hexdigest(), desktop.PATCHED[relative])
            self.assertEqual(desktop.transform(relative, result, original), result)
            with self.assertRaises(ValueError):
                desktop.transform(relative, result + b'\n', original)
        text = desktop.patch_xlib_support(originals['ui/gfx/x/xlib_support.cc'].decode())
        self.assertIn('#if !defined(CEF_STATIC_X11_DIRECT)\nXlibXcbLoader*', text)
        gn = desktop.patch_x_build(originals['ui/gfx/x/BUILD.gn'].decode())
        self.assertIn('deps -= [ ":xlib_xcb_loader" ]', gn)
        self.assertIn('assert(!enable_vulkan,', gn)

    def test_compiler_failure_checkpoint_migration_is_exact(self):
        relative = 'ui/gfx/x/xlib_support.cc'
        original = fixture_files()[relative]
        good = desktop.transform(relative, original, original)
        anchor = b'  CHECK(false) << "Xlib/XCB bridge is unavailable in the static no-Vulkan profile";\n'
        previous = good.replace(anchor, anchor + b'  return nullptr;\n', 1)
        self.assertEqual(hashlib.sha256(previous).hexdigest(),
                         desktop.COMPILE_FAILURE_PATCHED[relative])
        self.assertEqual(desktop.transform(relative, previous, original), good)
        self.assertEqual(desktop.transform(relative, good, original), good)
        for altered in (previous + b'\n', previous.replace(b'CHECK(false)', b'CHECK(true)'),
                        good.replace(b'#if !defined(CEF_STATIC_X11_DIRECT)', b'#if 0', 1)):
            with self.assertRaises(ValueError):
                desktop.transform(relative, altered, original)

    def test_resume_changes_only_failed_source_and_keeps_other_clocks(self):
        originals = fixture_files()
        selected = {n: desktop.PATCHERS[n] for n in desktop.LEGACY_PATCHED}
        relative = 'ui/gfx/x/xlib_support.cc'
        anchor = b'  CHECK(false) << "Xlib/XCB bridge is unavailable in the static no-Vulkan profile";\n'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, prefix, sha = fake_platform(root)
            source = root / 'src'
            for name in selected:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                data = desktop.transform(name, originals[name], originals[name])
                if name == relative:
                    data = data.replace(anchor, anchor + b'  return nullptr;\n', 1)
                path.write_bytes(data)
            def git(args, **kwargs):
                if 'rev-parse' in args:
                    return desktop.WEBRTC if Path(args[2]).name == 'webrtc' else desktop.CHROMIUM
                return originals[args[-1].split(':', 1)[1]]
            clocks = {n: (source / n).stat().st_mtime_ns for n in selected if n != relative}
            with patch.object(desktop, 'PATCHERS', selected), patch.object(desktop.subprocess, 'check_output', side_effect=git):
                result = desktop.install(source, manifest, prefix, sha)
                self.assertEqual(result['changed_files'], 1)
                self.assertEqual(clocks, {n: (source / n).stat().st_mtime_ns for n in clocks})
                stamps = {n: (source / n).stat().st_mtime_ns for n in selected}
                self.assertEqual(desktop.install(source, manifest, prefix, sha)['changed_files'], 0)
                self.assertEqual(stamps, {n: (source / n).stat().st_mtime_ns for n in selected})

    def test_unknown_original_and_partial_edits_rejected(self):
        originals = fixture_files()
        relative = 'ui/gfx/x/xlib_support.cc'
        original = originals[relative]
        with self.assertRaises(ValueError):
            desktop.transform(relative, original, original + b'\n')
        with self.assertRaises(ValueError):
            desktop.transform(relative, original.replace(b'namespace x11', b'namespace bad'), original)

    def test_install_is_atomic_before_validation_and_idempotent(self):
        originals = fixture_files()
        selected = {n: desktop.PATCHERS[n] for n in desktop.LEGACY_PATCHED}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, prefix, sha = fake_platform(root)
            source = root / 'src'
            for relative in selected:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(originals[relative])
            def git(args, **kwargs):
                if 'rev-parse' in args:
                    return desktop.WEBRTC if Path(args[2]).name == 'webrtc' else desktop.CHROMIUM
                return originals[args[-1].split(':', 1)[1]]
            with patch.object(desktop, 'PATCHERS', selected), patch.object(desktop.subprocess, 'check_output', side_effect=git):
                bad = source / 'ui/gfx/x/xlib_support.cc'
                bad.write_bytes(bad.read_bytes() + b'tampered')
                with self.assertRaises(ValueError):
                    desktop.install(source, manifest, prefix, sha)
                self.assertEqual((source / 'ui/gfx/x/BUILD.gn').read_bytes(), originals['ui/gfx/x/BUILD.gn'])
                bad.write_bytes(originals['ui/gfx/x/xlib_support.cc'])
                self.assertEqual(desktop.install(source, manifest, prefix, sha)['changed_files'], 3)
                stamps = {n: (source / n).stat().st_mtime_ns for n in selected}
                self.assertEqual(desktop.install(source, manifest, prefix, sha)['changed_files'], 0)
                self.assertEqual(stamps, {n: (source / n).stat().st_mtime_ns for n in selected})

    def test_gtk_software_selection_precedes_initialization(self):
        text = '  env->SetVar("NO_AT_BRIDGE", "1");\n  GtkInitFromCommandLine();\n'
        result = desktop.patch_gtk_software(text)
        self.assertLess(result.index('"GDK_GL", "disable"'), result.index('GtkInitFromCommandLine'))
        self.assertIn('#if defined(CEF_STATIC_GTK3)', result)
        self.assertIn('if (!env->SetVar(', result)
        self.assertNotIn('use_gtk = false', result)
        with self.assertRaises(ValueError):
            desktop.patch_gtk_software(text * 2)

    def test_webrtc_retains_capture_and_routes_static_dependencies(self):
        # Extract the reviewed public anchor, not any private build output.
        import ast
        tree = ast.parse(Path(desktop.__file__).read_text())
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'patch_desktop_capture')
        assignment = next(n for n in fn.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'original' for t in n.targets))
        source = 'import("//build/config/ui.gni")\n' + ast.literal_eval(assignment.value)
        result = desktop.patch_desktop_capture(source)
        self.assertIn('configs += [ ":cef_static_capture_x11" ]', result)
        self.assertIn('current_toolchain == default_toolchain', result)
        for name in ('x11', 'xcomposite', 'xdamage', 'xrandr', 'xrender', 'xtst'):
            self.assertIn('"' + name + '"', result)
        self.assertIn('"Xcomposite"', result)  # ordinary builds are unchanged.
        with self.assertRaises(ValueError):
            desktop.patch_desktop_capture(source.replace('"Xdamage"', '"wrong"'))

    def test_frozen_archives_and_manifest_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            manifest, prefix, sha = fake_platform(Path(folder))
            result = desktop._validated_platform(manifest, prefix, sha)
            self.assertEqual(result['module_count'], 9)
            (prefix / 'lib/libX11.a').write_bytes(b'bad-archive')
            with self.assertRaises(ValueError):
                desktop._validated_platform(manifest, prefix, sha)
            with self.assertRaises(ValueError):
                desktop._validated_platform(manifest, prefix, '0' * 64)

    @unittest.skipIf(os.name == 'nt', 'native Linux path policy')
    def test_archive_parent_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest, prefix, sha = fake_platform(root)
            (prefix / 'lib').rename(prefix / 'real')
            (prefix / 'lib').symlink_to('real', target_is_directory=True)
            with self.assertRaises(ValueError):
                desktop._validated_platform(manifest, prefix, sha)

    def test_native_elf_gate_does_not_accept_gn_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            exe = root / 'out/CEF_Static_Platform_Release_x64/cef_static_smoke'
            exe.parent.mkdir(parents=True); exe.write_bytes(b'fixture')
            text = ' 0x1 (NEEDED) Shared library: [libc.so.6]\n 0x1 (NEEDED) Shared library: [libXcomposite.so.1]\n'
            with patch.object(desktop.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, text, '')):
                result = desktop.audit_native(root)
            self.assertFalse(result['runtime_native_elf_verified'])
            self.assertEqual(result['runtime_native_elf_unexpected_count'], 1)


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('c++') and shutil.which('ar') and shutil.which('nm'), 'native Linux C++ tools')
class DesktopNativeTests(unittest.TestCase):
    def test_complete_xlib_translation_unit_and_real_archive(self):
        self._exercise_native('c++')

    def test_clang_logging_check_noreturn_and_runtime_guard(self):
        compiler = shutil.which('clang++')
        self.assertIsNotNone(compiler, 'Clang is required for the Linux warning regression')
        self._exercise_native(compiler, clang=True)

    def test_clang_official_check_noreturn_and_runtime_guard(self):
        compiler = shutil.which('clang++')
        self.assertIsNotNone(compiler, 'Clang is required for the Linux warning regression')
        self._exercise_native(compiler, clang=True, official=True)

    def _exercise_native(self, compiler, *, clang=False, official=False):
        originals = fixture_files()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, data in originals.items():
                dest = root / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data)
            support = root / 'ui/gfx/x/xlib_support.cc'
            original = support.read_bytes()
            support.write_bytes(desktop.transform('ui/gfx/x/xlib_support.cc', original, original))
            scaffolds = {
                # Model the pinned base/check.h control flow, including its
                # [[noreturn]] fatal destructor and official-build crash path.
                # A returning fake CHECK hid run 74's unreachable return.
                # These are disposable base stand-ins, not a CEF runtime proof.
                'base/check.h': '''#pragma once
#include <cstdlib>
struct Check { template<class T> Check& operator<<(const T&) { return *this; } ~Check(){} };
struct FatalCheck : Check { [[noreturn]] ~FatalCheck(){std::abort();} };
[[noreturn]] inline void CheckFailure(){std::abort();}
struct Voidify { void operator&(Check&){} };
inline Check* swallow_stream = nullptr;
#define EAT_CHECK_PARAMS true ? (void)0 : Voidify{} & (*swallow_stream)
#if defined(CEF_FIXTURE_OFFICIAL_CHECK)
#define CHECK(x) switch(0) case 0: default: if (!((x) ? true : false)) CheckFailure(); else EAT_CHECK_PARAMS
#else
#define CHECK(x) switch(0) case 0: default: if ((x) ? true : false) [[likely]]; else FatalCheck{}
#endif
''',
                'base/logging.h': '#pragma once\n#include "base/check.h"\n#define DVLOG(x) Check{}\n',
                'base/compiler_specific.h': '#pragma once\n#define DISABLE_CFI_DLSYM\n',
                'base/component_export.h': '#pragma once\n#define COMPONENT_EXPORT(x)\n',
                'base/no_destructor.h': '#pragma once\nnamespace base { template<class T> struct NoDestructor { T value; T* get(){return &value;} }; }\n',
                'base/memory/raw_ptr.h': '#pragma once\ntemplate<class T> class raw_ptr { T* p; public: raw_ptr(T* v):p(v){} operator T*() const{return p;} T* ExtractAsDangling(){T* v=p;p=nullptr;return v;} };\n',
            }
            for name, data in scaffolds.items():
                dest = root/name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text(data)
            generated = root/'library_loaders'; generated.mkdir()
            generator = root/'tools/generate_library_loader/generate_library_loader.py'
            funcs = ['XInitThreads','XOpenDisplay','XCloseDisplay','XFlush','XSynchronize','XSetErrorHandler','XFree','XPending']
            def run(args, expected=0):
                r = subprocess.run(list(map(str,args)), cwd=root, capture_output=True, text=True, timeout=40)
                self.assertEqual(r.returncode, expected, r.stderr)
                return r
            for mode in (0,1):
                for cls, stem, header, functions in [ ('XlibLoader','xlib_loader','ui/gfx/x/xlib.h',funcs), ('XlibXcbLoader','xlib_xcb_loader','ui/gfx/x/xlib_xcb.h',['XGetXCBConnection']) ]:
                    run([sys.executable, generator, '--name',cls,'--output-h',generated/(stem+'.h'),'--output-cc',generated/(stem+'.cc'),'--header','"'+header+'"','--link-directly',str(mode),*functions])
                common = [compiler,'-std=c++20','-O0','-Wall','-Wextra','-Werror','-I',root]
                # Upstream generated direct mode leaves two unused parameters;
                # Chromium's compiler config suppresses this warning as well.
                common += ['-Wno-unused-parameter']
                if clang:
                    common += ['-Wunreachable-code', '-Wunreachable-code-return']
                if official:
                    common += ['-DCEF_FIXTURE_OFFICIAL_CHECK=1']
                defs = ['-DCEF_STATIC_X11_DIRECT=1'] if mode else []
                if mode:
                    good_source = support.read_text()
                    check = '  CHECK(false) << "Xlib/XCB bridge is unavailable in the static no-Vulkan profile";\n'
                    previous = good_source.replace(check, check + '  return nullptr;\n', 1)
                    self.assertEqual(hashlib.sha256(previous.encode()).hexdigest(),
                                     desktop.COMPILE_FAILURE_PATCHED['ui/gfx/x/xlib_support.cc'])
                    # The logging CHECK used by run 74 exposes this warning;
                    # official CHECK discards the stream through a ternary.
                    if clang and not official:
                        support.write_text(previous)
                        failed = subprocess.run([*map(str,common),*defs,'-c',str(support),'-o','run74.o'],
                                                cwd=root,capture_output=True,text=True,timeout=40)
                        self.assertNotEqual(failed.returncode, 0)
                        self.assertIn('-Wunreachable-code-return', failed.stderr)
                        support.write_text(good_source)
                    legacy = previous
                    for body in ('#include "library_loaders/xlib_xcb_loader.h"\n',
                                 'XlibXcbLoader* GetXlibXcbLoader() {\n  static base::NoDestructor<XlibXcbLoader> xlib_xcb_loader;\n  return xlib_xcb_loader.get();\n}\n'):
                        legacy = legacy.replace('#if !defined(CEF_STATIC_X11_DIRECT)\n' + body + '#endif\n', body)
                    self.assertEqual(hashlib.sha256(legacy.encode()).hexdigest(), desktop.LEGACY_PATCHED['ui/gfx/x/xlib_support.cc'])
                    support.write_text(legacy)
                    failed = subprocess.run([*map(str,common),*defs,'-c',str(support),'-o','old.o'],cwd=root,capture_output=True,text=True)
                    self.assertNotEqual(failed.returncode, 0)
                    if clang:
                        self.assertTrue('GetXlibXcbLoader' in failed.stderr or
                                        '-Wunreachable-code-return' in failed.stderr, failed.stderr)
                    else:
                        self.assertIn('GetXlibXcbLoader', failed.stderr)
                    support.write_text(good_source)
                run([*common,*defs,'-c',support,'-o','support.o'])
                run([*common,'-c',generated/'xlib_loader.cc','-o','loader.o'])
                table = run(['nm','-u','loader.o']).stdout
                self.assertEqual('dlopen' in table, mode == 0)
                if not mode:
                    continue
                provider = root/'provider.cc'
                provider.write_text('''#include "ui/gfx/x/xlib.h"
struct _XDisplay {int value;}; static _XDisplay display{42};
extern "C" {
int XInitThreads(){return 1;} _XDisplay* XOpenDisplay(const char*){return &display;}
int XCloseDisplay(_XDisplay*){return 0;} int XFlush(_XDisplay*){return 0;}
int XSynchronize(_XDisplay*,int){return 0;} int XSetErrorHandler(int(*)(void*,void*)){return 0;}
void XFree(void*){} int XPending(_XDisplay*){return 0;}
}
''')
                app = root/'app.cc'
                app.write_text('''#include "ui/gfx/x/xlib_support.h"
#include <sys/resource.h>
namespace x11 { class Connection { public:
 static void Test(bool forbidden){XlibDisplay display("");if(forbidden)display.GetXcbConnection();}
}; }
int main(int argc,char**){
 struct rlimit limit{0,0};if(setrlimit(RLIMIT_CORE,&limit))return 19;
 x11::InitXlib();x11::InitXlib();x11::XlibFree(nullptr);x11::Connection::Test(argc>1);
}
''')
                run([*common,'-c',provider,'-o','provider.o'])
                run(['ar','rcs','libXfixture.a','provider.o'])
                # Real link must fail when the required archive is missing.
                bad = subprocess.run([*map(str,common),'support.o','loader.o',str(app),'-o','bad'],cwd=root,capture_output=True)
                self.assertNotEqual(bad.returncode,0)
                run([*common,'support.o','loader.o',app,'libXfixture.a','-o','test-loader'])
                run([root/'test-loader'])
                # The unavailable bridge must still terminate, never return a
                # null connection or silently relax the no-Vulkan contract.
                import signal
                run([root/'test-loader', 'forbidden-bridge'], expected=-signal.SIGABRT)
                imports = run(['readelf','-d','test-loader']).stdout
                self.assertNotIn('libX11.so', imports)
                self.assertNotIn('libX11-xcb.so', imports)


if __name__ == '__main__': unittest.main()
