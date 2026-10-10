"""Native ranges/default-iterator regression and complete source-transition guards.

The iterator declarations and bodies are extracted verbatim from complete,
independently pinned public Chromium files. The complete base::Reversed headers
are compiled, not a predicate-only adapter. Only tree data, delegate types,
raw_ptr representation and annotation/DCHECK macros are supplied by the shell.
This is an iterator subsystem proof, not full Chromium/accessibility runtime.
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
from tests.cef_windows_accessibility_inputs import INPUTS, public_input, verify_public
from tests.cef_windows_layout_inputs import fixture_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/cef-windows'
PREFIX = 'ui/accessibility/platform/'
V9_KEY = '2aea8f513a929241bbe31aacd9411d0ff88541f96f69418c68c79d9e86ef2c7d'


def populate(work):
    for relative, _, _, _ in repair.CORRECTIONS:
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture_bytes(path.name))


def snapshot(work):
    return {p.relative_to(work): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in work.rglob('*') if p.is_file()}


def between(text, start, stop):
    if text.count(start) != 1 or text.count(stop) != 1:
        raise ValueError('Public iterator extraction boundary changed')
    first, last = text.index(start), text.index(stop)
    if first >= last:
        raise ValueError('Public iterator extraction order changed')
    return text[first:last]


def probe_source(fixed, *, omit_index_guard=False):
    header = public_input(PREFIX + 'browser_accessibility.h')
    source = public_input(PREFIX + 'browser_accessibility.cc')
    if fixed:
        header = repair.transform(header, repair.ACCESSIBILITY_HEADER)
        source = repair.transform(source, repair.ACCESSIBILITY_SOURCE)
        if omit_index_guard:
            before, after = repair.CORRECTIONS[9][3][1]
            if source.count(after) != 1:
                raise ValueError('Index guard control boundary changed')
            source = source.replace(after, before, 1)
    ax = public_input('ui/accessibility/ax_node.h').decode()
    decl = between(ax, '  template <typename NodeType,\n',
                   '  // The constructor requires a parent, id, and index in parent, but\n')
    ax_boundary = 'AX_EXPORT std::ostream& operator<<(std::ostream& stream, const AXNode* node);\n\n'
    impl = between(ax, ax_boundary, '}  // namespace ui\n')[len(ax_boundary):]
    source = source.decode(); header = header.decode()
    chunks = {
        '// INSERT_AX_ITERATOR_DECLARATION': decl,
        '// INSERT_AX_ITERATOR_IMPLEMENTATION': impl,
        '// INSERT_PLATFORM_ITERATOR_AND_RANGE': between(header,
            '  // Iterator over platform children.\n',
            '  // If this object is exposed to the platform\'s accessibility layer, returns\n'),
        '// INSERT_PLATFORM_BEGIN_END': between(source,
            'BrowserAccessibility::PlatformChildIterator\nBrowserAccessibility::PlatformChildrenBegin() const {\n',
            'bool BrowserAccessibility::IsDescendantOf(\n'),
        '// INSERT_PLATFORM_ITERATOR_IMPLEMENTATION': between(source,
            ('BrowserAccessibility::PlatformChildIterator::PlatformChildIterator()\n'
             if fixed else 'BrowserAccessibility::PlatformChildIterator::PlatformChildIterator(\n    const PlatformChildIterator& it)\n'),
            'std::unique_ptr<ChildIterator> BrowserAccessibility::ChildrenBegin() const {\n'),
    }
    template = (FIXTURES / 'accessibility-iterator-proof.inc').read_text('utf-8')
    for marker, value in chunks.items():
        if template.count(marker) != 1:
            raise ValueError('Iterator proof marker changed')
        template = template.replace(marker, value, 1)
    return template


def write_headers(root):
    for path in ('base/containers/adapters.h', 'base/containers/adapters_internal.h',
                 PREFIX + 'child_iterator.h'):
        target = root / path; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(public_input(path))
    stubs = {
        'base/compiler_specific.h': '#pragma once\n#define LIFETIME_BOUND\n',
        'base/memory/raw_ptr_exclusion.h': '#pragma once\n#define RAW_PTR_EXCLUSION\n',
        'base/component_export.h': '#pragma once\n#define COMPONENT_EXPORT(x)\n',
        PREFIX + 'ax_platform_node_delegate.h':
            '#pragma once\n#include <cstddef>\n#include <optional>\n'
            'namespace gfx { using NativeViewAccessible = void*; }\n'
            'namespace ui { class AXPlatformNodeDelegate { public:\n'
            'virtual ~AXPlatformNodeDelegate() = default; }; }\n',
    }
    for path, text in stubs.items():
        target = root / path; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')


class AccessibilityIteratorTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='cef accessibility iterator ')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.key = repair.build_key(repair.BASE_KEY)

    def test_complete_public_sources_and_narrow_correction(self):
        for path in INPUTS:
            raw = public_input(path)
            self.assertEqual(verify_public(path, raw), raw)
            for invalid in (raw[:-1], raw+b'\n', b'X'+raw[1:]):
                with self.assertRaises(ValueError): verify_public(path, invalid)
        with self.assertRaises(ValueError): public_input('../unreviewed.h')
        for relative, before, after, edits in repair.CORRECTIONS[8:10]:
            raw = fixture_bytes(Path(relative).name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), before)
            changed = repair.transform(raw, relative)
            self.assertEqual(hashlib.sha256(changed).hexdigest(), after)
            for old, new in reversed(edits):
                self.assertEqual(changed.count(new), 1)
                changed = changed.replace(new, old, 1)
            self.assertEqual(changed, raw)
        self.assertEqual([len(item[3]) for item in repair.CORRECTIONS[8:10]], [1, 2])
        self.assertIn(b'for (const auto& child : base::Reversed(range))',
                      public_input(PREFIX + 'browser_accessibility_manager.cc'))
        self.assertIn('DCHECK(parent);', probe_source(True))
        self.assertEqual(probe_source(False).count('DCHECK(child_);'), 3)
        self.assertEqual(probe_source(True).count('DCHECK(child_);'), 3)

    def test_new_profile_and_repository_lock_reject_v9_and_failed44(self):
        profile = repair.profile()
        self.assertEqual(profile['id'], 'windows-watermark-string-include-v22')
        self.assertEqual(len(profile['corrections']), 23)
        self.assertEqual(worker.qualification_lock(ROOT)['source_repair'], profile)
        selected = worker.qualification_lock(ROOT)['checkpoint']
        self.assertIn(repair.restore_contract(selected, repair.BASE_KEY)[1],
                      ('legacy', 'resume', 'upgrade-v14', 'upgrade-v15', 'upgrade-v16', 'upgrade-v19', 'upgrade-v21'))
        self.assertEqual(repair.restore_contract(repair.LEGACY, repair.BASE_KEY), (repair.BASE_KEY, 'legacy'))
        for old in (dict(repair.LEGACY, build_key=V9_KEY),
                    dict(repair.LEGACY, run=37207948153)):
            with self.assertRaises(ValueError): repair.restore_contract(old, repair.BASE_KEY)
        for index in (8, 9):
            for field in ('path', 'before_sha256', 'after_sha256'):
                altered = copy.deepcopy(profile)
                altered['corrections'][index][field] = '0' * len(altered['corrections'][index][field])
                with mock.patch.object(repair, 'profile', return_value=altered):
                    self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_newlines_idempotence_and_partial_corrections_rejected(self):
        for relative, _, _, edits in repair.CORRECTIONS[8:10]:
            raw = fixture_bytes(Path(relative).name)
            for nl in (b'\n', b'\r\n'):
                original = raw.replace(b'\n', nl)
                fixed = repair.transform(original, relative)
                self.assertEqual(repair.transform(fixed, relative), fixed)
                self.assertEqual(fixed.count(b'\r\n'), fixed.count(b'\n') if nl == b'\r\n' else 0)
            for invalid in (raw+b'\n', raw.replace(b'\n', b'\r\n', 1)):
                with self.assertRaises(ValueError): repair.transform(invalid, relative)
            if len(edits) > 1:
                old, new = edits[0]
                with self.assertRaises(ValueError): repair.transform(raw.replace(old, new, 1), relative)

    def test_tenth_bad_digest_hardlink_and_partial_v9_precede_every_write(self):
        for mode in ('digest', 'hardlink', 'partial-v9'):
            with self.subTest(mode=mode):
                work = self.root / mode; populate(work)
                path = work / repair.ACCESSIBILITY_SOURCE
                if mode == 'digest': path.write_bytes(b'unreviewed final source')
                elif mode == 'hardlink': os.link(path, self.root / 'alias.cc')
                else:
                    for relative, _, _, _ in repair.CORRECTIONS[:8]:
                        p = work / relative; p.write_bytes(repair.transform(p.read_bytes(), relative))
                before = snapshot(work)
                with self.assertRaises(ValueError): repair.apply(work, self.key, 'legacy')
                self.assertEqual(snapshot(work), before)
                self.assertFalse((work / repair.MARKER).exists())

    def test_source_bound_is_path_local_and_precedes_transform(self):
        self.assertEqual(repair.source_limit(repair.ACCESSIBILITY_SOURCE), 131072)
        self.assertEqual(repair.source_limit(repair.TORQUE_SOURCE), 262144)
        for path in (repair.ACCESSIBILITY_HEADER, repair.BIND_HEADER, 'unreviewed.cc'):
            self.assertEqual(repair.source_limit(path), 65536)
        work = self.root / 'work'; populate(work)
        (work / repair.ACCESSIBILITY_SOURCE).write_bytes(b'x' * 131073)
        before = snapshot(work)
        original = repair.transform
        seen = []
        def checked(raw, relative=repair.HEADER):
            seen.append(relative)
            return original(raw, relative)
        with mock.patch.object(repair, 'transform', side_effect=checked):
            with self.assertRaises(ValueError): repair.apply(work, self.key, 'legacy')
        self.assertNotIn(repair.ACCESSIBILITY_SOURCE, seen)
        self.assertEqual(snapshot(work), before)

    def test_complete_resume_keeps_mtimes_and_checks_both_new_sources(self):
        work = self.root / 'work'; populate(work)
        self.assertEqual(repair.apply(work, self.key, 'legacy'), 'applied')
        before = snapshot(work)
        self.assertEqual(repair.apply(work, self.key, 'resume'), 'already-applied')
        self.assertEqual(snapshot(work), before)
        for relative, _, _, _ in repair.CORRECTIONS[8:10]:
            p = work / relative; fixed = p.read_bytes()
            p.write_bytes(fixture_bytes(p.name))
            with self.assertRaises(ValueError): repair.apply(work, self.key, 'resume')
            p.write_bytes(fixed)
        proof = {'base_build_key': repair.BASE_KEY, 'source_repair': repair.profile(), 'source_repair_verified': True}
        repair.verify_summary(proof, {'build_key': self.key})
        proof['source_repair']['corrections'].pop()
        with self.assertRaises(ValueError): repair.verify_summary(proof, {'build_key': self.key})

    def test_tenth_replacement_race_never_publishes_marker(self):
        work = self.root / 'work'; populate(work)
        original = os.replace
        def raced(src, dst):
            original(src, dst)
            if Path(dst) == work / repair.ACCESSIBILITY_SOURCE:
                (work / repair.ACCESSIBILITY_HEADER).write_bytes(b'raced first accessibility input')
        with mock.patch.object(repair.os, 'replace', side_effect=raced):
            with self.assertRaises(ValueError): repair.apply(work, self.key, 'legacy')
        self.assertFalse((work / repair.MARKER).exists())

    def test_native_ranges_singular_state_and_unchanged_traversal(self):
        compilers = ['clang-cl'] if os.name == 'nt' else ['clang++', 'g++']
        for compiler in compilers:
            case = self.root / compiler; case.mkdir(); write_headers(case)
            source = case / 'probe.cc'
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
            def compile_case(defaults=1, extra=()):
                if os.name == 'nt':
                    batch = case / 'compile.cmd'
                    line = f'"{executable}" /nologo /std:c++20 /EHsc /W4 /WX /DTEST_DEFAULT={defaults}'
                    line += f' /I"{case}" "{source}" /Fe:"{binary}" /Fo:"{case / "probe.obj"}"'
                    batch.write_text(f'@echo off\ncall "{vs}/VC/Auxiliary/Build/vcvarsall.bat" x64 >nul\nif errorlevel 1 exit /b 90\necho VCToolsVersion=%VCToolsVersion%\n{line}\n', encoding='utf-8')
                    args = ['cmd.exe', '/d', '/c', str(batch)]
                else:
                    args = [executable, '-std=c++20', '-Wall', '-Werror', f'-DTEST_DEFAULT={defaults}',
                            '-I'+str(case), str(source), '-o', str(binary), *extra]
                return subprocess.run(args, cwd=case, capture_output=True, text=True, errors='replace', timeout=90)
            source.write_text(probe_source(False), encoding='utf-8')
            old = compile_case(0)
            old_text = old.stdout + old.stderr
            if os.name == 'nt':
                self.assertNotEqual(old.returncode, 0)
                self.assertIn('PlatformChildIterator', old_text)
                self.assertIn('reverse_iterator', old_text)
            elif old.returncode == 0:
                subprocess.run([str(binary)], cwd=case, check=True, capture_output=True, timeout=10)
            else:
                self.assertIn('Reversed', old_text)
            missing_default = compile_case(1)
            self.assertNotEqual(missing_default.returncode, 0)
            self.assertIn('PlatformChildIterator', missing_default.stdout + missing_default.stderr)
            source.write_text(probe_source(True), encoding='utf-8')
            fixed = compile_case()
            self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
            run = subprocess.run([str(binary)], cwd=case, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('ACCESSIBILITY_ITERATOR_RUNTIME_OK', run.stdout)
            for mode in ('bad-parent', 'singular-get', 'singular-deref', 'end-deref'):
                guard = subprocess.run([str(binary), mode], cwd=case, capture_output=True, timeout=10)
                self.assertEqual(guard.returncode, 86, mode)
            source.write_text(probe_source(True, omit_index_guard=True), encoding='utf-8')
            incomplete = compile_case()
            self.assertEqual(incomplete.returncode, 0, incomplete.stdout + incomplete.stderr)
            incomplete_run = subprocess.run([str(binary)], cwd=case, capture_output=True, timeout=10)
            self.assertNotEqual(incomplete_run.returncode, 0, 'Constructor alone must not qualify')
            if os.name != 'nt':
                source.write_text(probe_source(True), encoding='utf-8')
                sanitized = compile_case(extra=('-fsanitize=address,undefined', '-fno-omit-frame-pointer'))
                self.assertEqual(sanitized.returncode, 0, sanitized.stdout + sanitized.stderr)
                checked = subprocess.run([str(binary)], cwd=case, capture_output=True, text=True, timeout=10)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            print(f'CEF_ACCESSIBILITY_ITERATOR_NATIVE compiler={compiler} old_range_rejected={old.returncode != 0} '
                  'old_default_rejected=true fixed_compiles_and_runs=true constructor_only_rejected=true guards=4')
            print(fixed.stdout.strip()); print(run.stdout.strip())
