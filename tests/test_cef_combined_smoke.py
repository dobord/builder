"""Literal CMake marker uniqueness, pinned source composition and native calls.

No private source fixtures or diagnostic logs are stored in this repository.
The required CI preflight reads the original pinned checkouts. Native fixture
execution tests the C/C++ callback boundary, not actual Chromium/SDK runtime.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_combined_smoke as subject

ROOT = Path(__file__).resolve().parents[1]
GUARD = '    set(_marker "  cef_run_message_loop();")\n'
FAIL = '        message(FATAL_ERROR "marker must be unique")\n    endif()\n'
INJECT = ('    string(REPLACE "${_marker}" "  if (sdk_component_probe() != 0) return 16;\\n${_marker}" '
          '_source "${_source}")\n')
SMOKE = '''#include <stdio.h>
static void cef_run_message_loop(void) { puts("LOOP"); }
int main(void) {
  puts("BEFORE");
  cef_run_message_loop();
  puts("AFTER");
  return 0;
}
'''
NATIVE_MAIN = '''#include <stdio.h>
#include <stdlib.h>
extern "C" int sdk_component_probe(void) {
  puts("COMPONENT"); return getenv("COMBINED_PROBE_FAIL") ? 1 : 0;
}
#ifndef CEF_COMBINED_PROBE
int main() { return sdk_component_probe(); }
#endif
'''


def execute(args, *, ok=True, env=None):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                            timeout=120, env=env)
    if ok and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result


@unittest.skipUnless(shutil.which("cmake"), "CMake required")
class LiteralTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def guard(self, text, old=False):
        source = self.root / "source.c"
        source.write_text(text, encoding="utf-8")
        script = self.root / "guard.cmake"
        script.write_text('cmake_minimum_required(VERSION 3.24)\n'
                          'file(READ "' + source.as_posix() + '" _source)\n' + GUARD +
                          (subject.LEGACY if old else subject.LITERAL) + FAIL + INJECT +
                          'file(WRITE "' + (self.root / 'generated.c').as_posix() + '" "${_source}")\n')
        return execute(["cmake", "-P", script], ok=False)

    def test_old_single_statement_is_two_list_elements_new_literal_is_unique(self):
        self.assertNotEqual(self.guard(SMOKE, old=True).returncode, 0)
        self.assertEqual(self.guard(SMOKE).returncode, 0)
        expected = SMOKE.replace(subject.MARKER.decode(),
                                '  if (sdk_component_probe() != 0) return 16;\n' + subject.MARKER.decode())
        self.assertEqual((self.root / "generated.c").read_text(), expected)

    def test_zero_and_duplicate_markers_remain_fatal(self):
        for text in (SMOKE.replace(subject.MARKER.decode(), ""), SMOKE + subject.MARKER.decode()):
            with self.subTest(text=text):
                self.assertNotEqual(self.guard(text).returncode, 0)

    def test_unrelated_semicolons_lists_and_utf8_do_not_change_uniqueness(self):
        text = '/* punctuation ;;; [a;b] and Unicode: Ж */\n' + SMOKE
        self.assertEqual(self.guard(text).returncode, 0)
        self.assertIn('Ж', (self.root / 'generated.c').read_text(encoding="utf-8"))

    def test_complete_statement_is_required_not_prefix_match(self):
        self.assertNotEqual(self.guard(SMOKE.replace('cef_run_message_loop();',
                                                    'cef_run_message_loop() /* changed */;')).returncode, 0)


class CompositionTests(unittest.TestCase):
    def test_production_preflight_and_copy_are_before_configure_without_pin_changes(self):
        from secure_release import cef_strict_combined as combined
        import inspect
        source = inspect.getsource(combined.main)
        self.assertLess(source.index('cef_combined_smoke.prepare('), source.index('consumer-configure.log'))
        self.assertIn('consumer_source, smoke_build, consumer_sdk, TRIPLET', source)
        self.assertIn('str(consumer_source / "smoke.c")', source)
        for check in ('verify_isolated_runtime_symbols', 'verify_os_only_elf', 'cef_build.verify_consumer'):
            self.assertIn(check, source)
        flow = (ROOT / '.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn("REQUIRE_CEF_COMBINED_SMOKE: '1'", flow)
        self.assertLess(flow.index('test_cef_combined_smoke.py -v'),
                        flow.index('Run checkpoint-resumed final combined SDK qualification'))

    def test_production_builds_both_final_consumers_serially_with_separate_evidence(self):
        from secure_release import cef_strict_combined as combined
        import inspect
        source = inspect.getsource(combined.main)
        start = source.index('stage = "combined-consumer"')
        end = source.index('stage = "lfc-ui-freerdp-cef-consumer"')
        final = source[start:end]
        sdk = final.index('"--target", "sdk_smoke", "--parallel", "1", "--verbose"')
        cef = final.index('"--target", "cef_static_combined_smoke", "--parallel", "1", "--verbose"')
        self.assertLess(sdk, cef)
        self.assertIn('stage = "combined-consumer-sdk-build"', final)
        self.assertIn('stage = "combined-consumer-cef-build"', final)
        self.assertIn('consumer-sdk-build.log', final)
        self.assertIn('consumer-cef-build.log', final)
        self.assertIn('summary["combined_sdk_smoke_built"] = True', final)
        self.assertIn('summary["combined_cef_smoke_built"] = True', final)
        self.assertNotIn('"--parallel", "2"', final)
        self.assertEqual(combined.SDK_VCPKG, '1e0d7db7127a2395fe73bc83c88d5f92b20ec33a')
        self.assertEqual(combined.CEF, '2aff22e09daaa5c28780c5766a70ee13e61c93b6')


class ConsumerFailureDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self):
        from secure_release import cef_strict_combined as combined
        installed = self.root / "installed"
        prefix = installed / combined.TRIPLET
        bindings = {
            "needed-target": ["lib/freerdp3/objects-Release/needed-target/needed.o"],
            "other-target": ["lib/freerdp3/objects-Release/other-target/other.o"],
        }
        for paths in bindings.values():
            for relative in paths:
                path = prefix / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
        return combined, installed, {"bindings": bindings}

    def test_undefined_symbols_publish_only_provider_names_and_counts(self):
        combined, installed, review = self.fixture()
        log = self.root / "consumer-sdk-build.log"
        required = "fixture_missing_symbol"
        unmatched = "fixture_unmatched_symbol"
        log.write_text(
            "ld.lld: error: undefined symbol: " + required + "\n"
            "ld.lld: error: undefined symbol: " + unmatched + "\n",
            encoding="utf-8",
        )

        def inspect(command, **kwargs):
            output = (
                "0000000000000000 T " + required + "\n"
                if "needed-target" in command[-1] else
                "0000000000000000 T unrelated_provider\n"
            )
            return subprocess.CompletedProcess(command, 0, output, "")

        with mock.patch.object(combined.shutil, "which", return_value="/usr/bin/nm"), \
             mock.patch.object(combined.subprocess, "run", side_effect=inspect):
            summary = combined.summarize_consumer_sdk_build_failure(log, installed, review)

        self.assertEqual(summary["consumer_sdk_build_error_kind"], "undefined-symbols")
        self.assertEqual(summary["consumer_sdk_build_undefined_symbol_count"], 2)
        self.assertEqual(summary["consumer_sdk_build_object_provider_targets"], ["needed-target"])
        self.assertEqual(summary["consumer_sdk_build_object_provider_count"], 1)
        self.assertEqual(summary["consumer_sdk_build_object_provider_symbol_count"], 1)
        self.assertEqual(summary["consumer_sdk_build_unmatched_undefined_symbol_count"], 1)
        self.assertNotIn(required, json.dumps(summary))
        self.assertNotIn(unmatched, json.dumps(summary))

    def test_non_undefined_linker_failure_does_not_scan_objects(self):
        combined, installed, review = self.fixture()
        log = self.root / "consumer-sdk-build.log"
        log.write_text("ld.lld: error: duplicate symbol: fixture_name\n", encoding="utf-8")
        with mock.patch.object(combined.subprocess, "run") as inspect:
            summary = combined.summarize_consumer_sdk_build_failure(log, installed, review)
        inspect.assert_not_called()
        self.assertEqual(summary["consumer_sdk_build_error_kind"], "duplicate-symbols")
        self.assertEqual(summary["consumer_sdk_build_undefined_symbol_count"], 0)
        self.assertNotIn("fixture_name", json.dumps(summary))

    def test_production_failure_path_records_bounded_diagnostic_then_reraises(self):
        from secure_release import cef_strict_combined as combined
        import inspect
        source = inspect.getsource(combined.main)
        start = source.index('stage = "combined-consumer-sdk-build"')
        end = source.index('summary["combined_sdk_smoke_built"] = True', start)
        failure = source[start:end]
        self.assertIn("summarize_consumer_sdk_build_failure(", failure)
        self.assertIn('consumer_sdk_build_diagnostic_invalid', failure)
        self.assertIn("raise", failure)


@unittest.skipUnless(shutil.which("cmake"), "CMake required")
class PinnedTests(unittest.TestCase):
    def setUp(self):
        project = os.environ.get('CEF_COMBINED_SMOKE_PROJECT')
        smoke = os.environ.get('CEF_COMBINED_SMOKE_RECIPE')
        if not project or not smoke:
            if os.environ.get('REQUIRE_CEF_COMBINED_SMOKE') == '1':
                self.fail('Required pinned combined consumer inputs are unavailable')
            self.skipTest('Exact registry and CEF checkouts are CI inputs')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'registry'
        shutil.copytree(project, self.source)
        self.recipe = self.root / 'recipe'
        self.recipe.mkdir()
        self.smoke = self.recipe / 'smoke.c'
        shutil.copyfile(smoke, self.smoke)
        subject.validate(self.source, self.smoke)
        self.output = self.root / 'consumer'

    def snapshot(self):
        return {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in
                (self.source / 'CMakeLists.txt', self.source / 'main.cpp', self.smoke)}

    def packages(self, parent):
        prefix = parent / 'sdk'
        for package, version, code in (
            ('lockfreecoro', '0.3.1', 'add_library(lockfreecoro::all INTERFACE IMPORTED)\n'),
            ('lfc-ui', None, 'add_library(lfc::ui INTERFACE IMPORTED)\n'),
            ('cef-static', '152.0.6', 'add_library(CEF::static INTERFACE IMPORTED)\n'
             'set(CEF_STATIC_CAPI_ONLY ON)\nset(CEF_STATIC_ENGINE_CONFIGURATION Release)\n'
             'function(cef_static_deploy_resources target)\n'
             'file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/resource-target.txt" "${target}")\nendfunction()\n')):
            dest = prefix / 'share' / package
            dest.mkdir(parents=True)
            (dest / (package + '-config.cmake')).write_text(code)
            if version:
                (dest / (package + '-config-version.cmake')).write_text(
                    f'set(PACKAGE_VERSION {version})\n'
                    'if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)\n'
                    'set(PACKAGE_VERSION_EXACT TRUE)\nset(PACKAGE_VERSION_COMPATIBLE TRUE)\nendif()\n')
        return prefix

    def configure(self, source, smoke, prefix, build, ok=True):
        return execute(['cmake', '-S', source, '-B', build, '-DCMAKE_BUILD_TYPE=Release',
                        '-DCMAKE_PREFIX_PATH=' + prefix.as_posix(),
                        '-DCEF_STATIC_SMOKE_SOURCE=' + smoke.as_posix()], ok=ok)

    def test_complete_pinned_project_reproduces_83_then_generates_exact_full_cef_source(self):
        prefix = self.packages(self.root)
        before = self.snapshot()
        failed = self.configure(self.source, self.smoke, prefix, self.root / 'old', ok=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('Pinned CEF smoke fixture changed', failed.stderr)
        subject.prepare(self.source, self.smoke, self.output)
        self.configure(self.output, self.output / 'smoke.c', prefix, self.root / 'fixed')
        expected = b'extern int sdk_component_probe(void);\n' + self.smoke.read_bytes().replace(
            subject.MARKER, b'  if (sdk_component_probe() != 0) return 16;\n' + subject.MARKER)
        self.assertEqual((self.root / 'fixed/cef_combined.c').read_bytes(), expected)
        self.assertEqual((self.output / 'main.cpp').read_bytes(), (self.source / 'main.cpp').read_bytes())
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((self.root / 'fixed/resource-target.txt').read_text(), 'cef_static_combined_smoke')
        tests = json.loads(execute(['ctest', '--test-dir', self.root / 'fixed', '--show-only=json-v1']).stdout)
        self.assertEqual([t['name'] for t in tests['tests']], ['sdk_smoke'])

    @unittest.skipUnless(shutil.which('cc') and shutil.which('c++'), 'Native C/C++ required')
    def test_same_pinned_cmake_links_c_callback_once_and_failure_prevents_loop_after_relocation(self):
        prefix = self.packages(self.root)
        subject.prepare(self.source, self.smoke, self.output)
        # Only this disposable runtime test substitutes tiny implementations.
        # The preceding test verifies byte-for-byte generation of REAL smoke.c.
        (self.output / 'main.cpp').write_text(NATIVE_MAIN)
        (self.output / 'smoke.c').write_text(SMOKE)
        moved = self.root / 'moved'
        moved.mkdir()
        shutil.move(prefix, moved / 'sdk')
        shutil.move(self.output, moved / 'consumer')
        shutil.rmtree(self.source)
        shutil.rmtree(self.recipe)
        self.configure(moved / 'consumer', moved / 'consumer/smoke.c', moved / 'sdk', moved / 'build')
        execute(['cmake', '--build', moved / 'build', '--config', 'Release'])
        candidates = [p for p in (moved / 'build').rglob('cef_static_combined_smoke*')
                      if p.is_file() and p.name in ('cef_static_combined_smoke', 'cef_static_combined_smoke.exe')]
        self.assertEqual(len(candidates), 1)
        env = dict(os.environ)
        env.pop('COMBINED_PROBE_FAIL', None)
        self.assertEqual(execute([candidates[0]], env=env).stdout.splitlines(),
                         ['BEFORE', 'COMPONENT', 'LOOP', 'AFTER'])
        result = execute([candidates[0]], ok=False, env=dict(env, COMBINED_PROBE_FAIL='1'))
        self.assertEqual(result.returncode, 16)
        self.assertEqual(result.stdout.splitlines(), ['BEFORE', 'COMPONENT'])
        execute(['ctest', '--test-dir', moved / 'build', '-C', 'Release', '--output-on-failure'], env=env)

    def test_each_changed_source_or_extra_file_rejected_before_any_copy(self):
        for path in (self.source / 'CMakeLists.txt', self.source / 'main.cpp', self.smoke):
            before = path.read_bytes()
            path.write_bytes(before + b'\n/* drift */\n')
            with self.assertRaises(ValueError): subject.prepare(self.source, self.smoke, self.output)
            self.assertFalse(self.output.exists())
            path.write_bytes(before)
        (self.source / 'extra.cmake').write_text('# unknown')
        with self.assertRaises(ValueError): subject.prepare(self.source, self.smoke, self.output)
        self.assertFalse(self.output.exists())

    def test_preexisting_output_and_overlapping_roots_are_untouched(self):
        before = self.snapshot()
        self.output.mkdir()
        sentinel = self.output / 'keep'
        sentinel.write_text('keep')
        with self.assertRaises(ValueError): subject.prepare(self.source, self.smoke, self.output)
        self.assertEqual(sentinel.read_text(), 'keep')
        for output in (self.source, self.source / 'new', self.recipe / 'new', self.root):
            with self.assertRaises(ValueError): subject.prepare(self.source, self.smoke, output)
        self.assertEqual(before, self.snapshot())

    @unittest.skipIf(os.name == 'nt', 'Native symlinks require platform privilege')
    def test_redirected_input_and_output_parent_fail(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError): subject.prepare(alias, self.smoke, self.output)
        alias.unlink()
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): subject.prepare(self.source, self.smoke, alias / 'new')
        self.assertFalse(self.output.exists())

    def test_partial_write_failure_cleans_only_new_output(self):
        before = self.snapshot()
        original = Path.open
        def fail(path, *args, **kwargs):
            if path == self.output / 'main.cpp': raise OSError('fixture write failure')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'open', fail), self.assertRaises(OSError):
            subject.prepare(self.source, self.smoke, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(before, self.snapshot())


if __name__ == '__main__':
    unittest.main()
