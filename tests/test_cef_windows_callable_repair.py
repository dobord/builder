"""Exact V8 inherited-callable traits and authenticated eight-source transition.

Compile the entire pinned bind-internal.h, not a replacement implementation.
The FunctionRef compatibility predicate is extracted verbatim from its pinned
public header. Its surrounding test adapter has no Abseil/reference storage;
this proves signature acceptance and actual trait invocation, not full V8/CEF.
Windows additionally exercises the real MSVC STL std::function inheritance.
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
from secure_release import cef_windows_iteration as worker
from tests.cef_windows_layout_inputs import fixture_bytes, verify_public, INPUTS

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/cef-windows'
V8_KEY = '694a95bdc213910273834d853d3cb1c96ec9373b0d34b85150b0d1288ab1c38a'
BIND_BLOB = '160664af5dd63f662953183b08fc8f815d579f7e'
FUNCTION_REF_BLOB = 'e15152d3c593d96054c69bc6520dfc1fa2ed97b1'


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def populate(work):
    for relative, _, _, _ in repair.CORRECTIONS:
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture_bytes(path.name))


def snapshot(work):
    return {p.relative_to(work): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in work.rglob('*') if p.is_file()}


def probe_source():
    raw = (FIXTURES / 'function-ref.h').read_bytes()
    if blob(raw) != FUNCTION_REF_BLOB:
        raise ValueError('Pinned public FunctionRef fixture mismatch')
    text = raw.decode('utf-8')
    start = '  template <typename Functor,\n'
    end = '\n public:\n'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('FunctionRef predicate extraction boundary changed')
    predicate = text[text.index(start):text.index(end)]
    if predicate.count('kCompatibleFunctor') != 1:
        raise ValueError('FunctionRef predicate extraction mismatch')
    template = (FIXTURES / 'callable-proof.inc').read_text('utf-8')
    if template.count('// INSERT_ACTUAL_COMPATIBILITY_PREDICATE') != 1:
        raise ValueError('Callable test adapter boundary mismatch')
    return template.replace('// INSERT_ACTUAL_COMPATIBILITY_PREDICATE', predicate)


class CallableRepairTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='cef inherited callable ')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.raw = fixture_bytes('bind-internal.h')
        self.key = repair.build_key(repair.BASE_KEY)

    def test_exact_public_blob_and_only_declaring_class_edit(self):
        self.assertEqual(blob(self.raw), BIND_BLOB)
        self.assertEqual(len(self.raw), 10698)
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), repair.BIND_BEFORE)
        fixed = repair.transform(self.raw, repair.BIND_HEADER)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), repair.BIND_AFTER)
        correction = repair.CORRECTIONS[-1]
        self.assertEqual(correction[0], repair.BIND_HEADER)
        self.assertEqual(len(correction[3]), 1)
        before, after = correction[3][0]
        self.assertEqual(self.raw.count(before), 1)
        self.assertEqual(fixed.replace(after, before, 1), self.raw)
        self.assertIn(b'R (Receiver::*)(Args...) quals', after)
        self.assertNotIn(b'std::function', after)
        for nl in (b'\n', b'\r\n'):
            source = self.raw.replace(b'\n', nl)
            changed = repair.transform(source, repair.BIND_HEADER)
            self.assertEqual(repair.transform(changed, repair.BIND_HEADER), changed)
            self.assertEqual(changed.count(b'\r\n'), changed.count(b'\n') if nl == b'\r\n' else 0)
        for invalid in (self.raw+b'\n', self.raw.replace(b'noexcept', b'const', 1),
                        self.raw.replace(b'\n', b'\r\n', 1)):
            with self.assertRaises(ValueError):
                repair.transform(invalid, repair.BIND_HEADER)

    def test_exact_profile_and_current_repository_lock(self):
        profile = repair.profile()
        self.assertEqual(profile['id'], 'windows-v8-inherited-callable-v9')
        self.assertEqual(len(profile['corrections']), 8)
        self.assertEqual(worker.qualification_lock(ROOT)['source_repair'], profile)
        self.assertEqual(profile['implementation_sha256'], hashlib.sha256(Path(repair.__file__).read_bytes()).hexdigest())
        for stale in (V8_KEY, '45d4c9074ab014a263f4c81a1a8e929951adaba4cc1b8c5232bccc13e72e5920'):
            with self.assertRaises(ValueError):
                repair.restore_contract(dict(repair.LEGACY, build_key=stale), repair.BASE_KEY)
        with self.assertRaises(ValueError):
            repair.restore_contract(dict(repair.LEGACY, run=37191476160), repair.BASE_KEY)
        self.assertEqual(repair.restore_contract(repair.LEGACY, repair.BASE_KEY), (repair.BASE_KEY, 'legacy'))
        for index in range(8):
            for field in ('path', 'before_sha256', 'after_sha256'):
                altered = copy.deepcopy(profile)
                altered['corrections'][index][field] = '0' * len(altered['corrections'][index][field])
                with mock.patch.object(repair, 'profile', return_value=altered):
                    self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_final_bad_input_and_hardlink_cannot_partially_apply(self):
        for mode in ('digest', 'hardlink', 'partial-v8'):
            with self.subTest(mode=mode):
                work = self.root / mode; populate(work)
                path = work / repair.BIND_HEADER
                if mode == 'digest': path.write_bytes(b'unreviewed final header')
                elif mode == 'hardlink': os.link(path, self.root / 'alias')
                else:
                    for relative, _, _, _ in repair.CORRECTIONS[:7]:
                        p = work / relative; p.write_bytes(repair.transform(p.read_bytes(), relative))
                before = snapshot(work)
                with self.assertRaises(ValueError): repair.apply(work, self.key, 'legacy')
                self.assertEqual(snapshot(work), before)
                self.assertFalse((work / repair.MARKER).exists())

    def test_all_eight_inputs_resume_and_proof_are_required(self):
        work = self.root / 'work'; populate(work)
        self.assertEqual(repair.apply(work, self.key, 'legacy'), 'applied')
        original = snapshot(work)
        self.assertEqual(repair.apply(work, self.key, 'resume'), 'already-applied')
        self.assertEqual(snapshot(work), original)
        for relative, _, _, _ in repair.CORRECTIONS:
            path = work / relative; fixed = path.read_bytes()
            path.write_bytes(fixture_bytes(path.name))
            with self.assertRaises(ValueError): repair.apply(work, self.key, 'resume')
            path.write_bytes(fixed)
        value = {'base_build_key': repair.BASE_KEY, 'source_repair': repair.profile(), 'source_repair_verified': True}
        repair.verify_summary(value, {'build_key': self.key})
        for invalid in (False, None):
            with self.assertRaises(ValueError):
                repair.verify_summary(dict(value, source_repair_verified=invalid), {'build_key': self.key})
        bad = copy.deepcopy(value); bad['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError): repair.verify_summary(bad, {'build_key': self.key})

    def test_public_fixture_size_is_mandatory(self):
        for name, (size, _) in INPUTS.items():
            self.assertGreater(size, 0)
            with self.assertRaises(ValueError): verify_public(name, b'x' * (size+1))
        self.assertIn('std::same_as<internal::ExtractArgs<RunType>', probe_source())

    def test_native_complete_traits_and_exact_signature_policy(self):
        compilers = ['clang-cl'] if os.name == 'nt' else ['clang++', 'g++']
        total_negative = 0
        for compiler in compilers:
            case = self.root / compiler; case.mkdir()
            source = case / 'probe.cc'; source.write_text(probe_source(), encoding='utf-8')
            header = case / 'bind-internal.h'
            binary = case / ('probe.exe' if os.name == 'nt' else 'probe')
            if os.name == 'nt':
                vswhere = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
                self.assertTrue(vswhere.is_file())
                vs = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
                executable = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'LLVM/bin/clang-cl.exe'
                self.assertTrue(executable.is_file())
            else:
                executable = shutil.which(compiler); self.assertIsNotNone(executable)
            def compile_case(inherited=0, stdfunction=0, negative=0, extra=()):
                defines = [f'TEST_INHERITED={inherited}', f'TEST_STDFUNCTION={stdfunction}', f'NEGATIVE={negative}']
                if os.name == 'nt':
                    batch = case / 'compile.cmd'
                    line = f'"{executable}" /nologo /std:c++20 /EHsc /W4 /WX ' + ' '.join('/D'+d for d in defines)
                    line += f' "{source}" /Fe:"{binary}" /Fo:"{case / "probe.obj"}"'
                    batch.write_text(f'@echo off\ncall "{vs}/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\nif errorlevel 1 exit /b 90\necho VCToolsVersion=%VCToolsVersion%\n{line}\n', encoding='utf-8')
                    args = ['cmd.exe', '/d', '/c', str(batch)]
                else:
                    args = [executable, '-std=c++20', '-Wall', '-Wextra', '-Werror', *['-D'+d for d in defines], str(source), '-o', str(binary), *extra]
                return subprocess.run(args, cwd=case, capture_output=True, text=True, errors='replace', timeout=90)
            header.write_bytes(self.raw)
            baseline = compile_case(); self.assertEqual(baseline.returncode, 0, baseline.stdout+baseline.stderr)
            subprocess.run([str(binary)], cwd=case, check=True, capture_output=True, timeout=10)
            inherited = compile_case(inherited=1)
            self.assertNotEqual(inherited.returncode, 0)
            self.assertIn('ExtractCallableRunTypeImpl', inherited.stdout+inherited.stderr)
            std = compile_case(stdfunction=1)
            if os.name == 'nt':
                self.assertNotEqual(std.returncode, 0)
                self.assertIn('ExtractCallableRunTypeImpl', std.stdout+std.stderr)
                self.assertIn('function', std.stdout+std.stderr)
            else:
                self.assertEqual(std.returncode, 0, std.stdout+std.stderr)
            header.write_bytes(repair.transform(self.raw, repair.BIND_HEADER))
            fixed = compile_case(1, 1); self.assertEqual(fixed.returncode, 0, fixed.stdout+fixed.stderr)
            ran = subprocess.run([str(binary)], cwd=case, capture_output=True, text=True, check=True, timeout=10)
            for negative in range(1, 9):
                bad = compile_case(1, 1, negative)
                self.assertNotEqual(bad.returncode, 0)
                self.assertIn('policy-negative-', bad.stdout+bad.stderr)
                total_negative += 1
            if os.name != 'nt':
                sanitized = compile_case(1, 1, extra=('-fsanitize=address,undefined', '-fno-omit-frame-pointer'))
                self.assertEqual(sanitized.returncode, 0, sanitized.stdout+sanitized.stderr)
                subprocess.run([str(binary)], cwd=case, capture_output=True, check=True, timeout=10)
            print(f'CEF_CALLABLE_NATIVE compiler={compiler} inherited_old_rejected=true std_function_old_rejected={os.name == "nt"} fixed_compiles_and_runs=true qualifiers=4 negatives=8')
            print(fixed.stdout.strip()); print(ran.stdout.strip())
        self.assertEqual(total_negative, 8*len(compilers))
