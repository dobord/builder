"""Fail-fast reference-app diagnostics, not actual CEF runtime qualification."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from secure_release import cef_smoke_progress as progress
from secure_release import cef_strict_iteration_runtime as runtime


def synthetic_source():
    # Every reviewed anchor is exercised locally. The workflow separately
    # verifies the COMPLETE real pinned fixture before downloading a checkpoint.
    tree = ast.parse(Path(progress.__file__).read_text())
    transform = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'transform')
    assignment = next(n for n in transform.body if isinstance(n, ast.Assign))
    expression = ast.Expression(assignment.value)
    edits = eval(compile(expression, '<test-anchor-inventory>', 'eval'), vars(progress))
    return '\n'.join(old for old, _ in edits)


class SmokeProgressTests(unittest.TestCase):
    def test_all_anchors_are_exact_and_success_checks_remain(self):
        source = synthetic_source()
        output = progress.transform(source)
        self.assertIn(progress.NEW_GATE, output)
        self.assertNotIn(progress.OLD_GATE, output)
        self.assertIn('if (text_is(title, "CEF_STATIC_42")) javascript_ok = 1;', output)
        self.assertIn('int third_party = third_party_modules_are_static();', output)
        for bad in (source.replace(progress.OLD_GATE, ''), source + progress.OLD_GATE):
            with self.assertRaises(ValueError):
                progress.transform(bad)

    def test_install_is_digest_bound_idempotent_and_preserves_recipe(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'src'; (source / 'cef/static').mkdir(parents=True)
            fixture = root / 'smoke.c'; fixture.write_text(synthetic_source(), newline="\n")
            data = fixture.read_bytes()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            target = source / 'cef/static/smoke.c'; target.write_bytes(data)
            with self.assertRaises(ValueError):
                progress.install(source, fixture)
            with patch.object(progress, 'SOURCE_BLOB', blob):
                result = progress.install(source, fixture)
                stamp = target.stat().st_mtime_ns
                self.assertEqual(progress.install(source, fixture), result)
                self.assertEqual(target.stat().st_mtime_ns, stamp)
                self.assertEqual(fixture.read_bytes(), data)
                target.write_bytes(target.read_bytes() + b'changed')
                with self.assertRaises(ValueError):
                    progress.install(source, fixture)

    def test_partial_and_redirected_outputs_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'src'
            payload = source / 'cef/static'; payload.mkdir(parents=True)
            fixture = root / 'recipe.c'; fixture.write_text(synthetic_source(), newline="\n")
            data = fixture.read_bytes()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            (payload / 'smoke.c').write_bytes(data)
            (payload / progress.HEADER.name).write_text('unowned')
            with patch.object(progress, 'SOURCE_BLOB', blob):
                with self.assertRaises(ValueError): progress.install(source, fixture)

    def test_bounded_classification_never_copies_log_strings(self):
        with tempfile.TemporaryDirectory() as folder:
            logs = Path(folder); root = logs / 'runtime-progress'; root.mkdir()
            row = dict(schema=1, pid=42, role=0, stage=14, sequence=7,
                       initialized=1, context=1, proof_received=1, javascript=0, paint=0)
            (root / 'smoke-progress-42.json').write_text(json.dumps(row))
            (root / 'smoke-modules-42.txt').write_text('libc.so.6\nlibtest-private.so\n')
            (root / 'smoke-progress-43.json').write_text(json.dumps(dict(row, pid=43, raw_log='DO_NOT_PUBLISH')))
            result = progress.classify(logs)
            self.assertEqual(result['runtime_progress_process_count'], 1)
            self.assertEqual(result['runtime_failure_category'], 'renderer-proof-rejected')
            self.assertEqual(result['runtime_waiting_for'], ['javascript', 'paint'])
            self.assertEqual(result['runtime_browser_unexpected_module_count'], 1)
            text = json.dumps(result)
            self.assertNotIn('private', text); self.assertNotIn('DO_NOT_PUBLISH', text)
            self.assertNotIn('runtime_verified', result)

    def test_no_evidence_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(progress.classify(Path(folder)), {'runtime_progress_available': False})

    def test_adapter_runs_after_successful_check_only_and_restores_globals(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); temp = root / 'temp'; temp.mkdir()
            (temp / 'cef-strict-engine-logs').mkdir()
            calls = []
            def run(command, **kwargs):
                calls.append('base-run')
                return types.SimpleNamespace(returncode=0)
            def classify(logs): return {'runtime_failure_category': 'smoke-timeout'}
            module = types.SimpleNamespace(run=run, classify_engine_runtime=classify)
            command = [sys.executable, str(root / 'private-vcpkg/.full-cef/vcpkg/ports/cef-static/source_build.py'), 'check']
            def install(*args): calls.append('install'); return {'patched_sha256': 'a'*64}
            with patch.object(progress, 'install', side_effect=install):
                with self.assertRaisesRegex(RuntimeError, 'original-error'):
                    with runtime.observed_runtime(module, root, temp):
                        module.run(['unrelated', 'command'])
                        self.assertEqual(calls, ['base-run'])
                        module.run(command)
                        self.assertEqual(calls, ['base-run', 'base-run', 'install'])
                        value = module.classify_engine_runtime(temp / 'cef-strict-engine-logs')
                        self.assertEqual(value['runtime_failure_category'], 'smoke-timeout')
                        self.assertNotIn('ready', value)
                        raise RuntimeError('original-error')
            self.assertIs(module.run, run); self.assertIs(module.classify_engine_runtime, classify)

    def test_workflow_uses_observed_entrypoint_and_preflights_pinned_fixture(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    '.github/workflows/cef-strict-engine-iteration.yml').read_text()
        self.assertIn('run: python -m secure_release.cef_strict_iteration_runtime', workflow)
        self.assertIn('--check-recipe private-vcpkg/.full-cef/vcpkg/ports/cef-static/smoke.c', workflow)
        self.assertLess(workflow.index('--check-recipe'), workflow.index('id: strict'))
        self.assertIn('secure_release/cef_smoke_progress.h', workflow)

    def test_failed_check_is_never_instrumented(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            module = types.SimpleNamespace(run=lambda *a, **kw: types.SimpleNamespace(returncode=1),
                                           classify_engine_runtime=lambda logs: {})
            command = [sys.executable, str(root / 'private-vcpkg/.full-cef/vcpkg/ports/cef-static/source_build.py'), 'check']
            with patch.object(progress, 'install') as install:
                with runtime.observed_runtime(module, root, root): module.run(command, check=False)
                install.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('cc'), 'native Linux C compiler required')
class NativeSmokeGateTests(unittest.TestCase):
    def test_negative_renderer_proof_closes_instead_of_hanging(self):
        c = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int javascript_ok, paint_ok, renderer_pid, renderer_modules_ok;
static int renderer_third_party_modules_ok, closing, passed;
static int process_id(void) { return (int)getpid(); }
#include "cef_smoke_progress.h"
typedef struct { int unused; } cef_browser_t;
static int closed;
static int strict_third_party_mode(void) { return 1; }
static int engine_modules_are_static(void) { return 1; }
static int third_party_modules_are_static(void) { return 1; }
static void close_browser(cef_browser_t* browser) { (void)browser; ++closed; }
static void finish(cef_browser_t* browser) {
GATE
  closing = 1;
  int modules = engine_modules_are_static();
  int third_party = third_party_modules_are_static();
  if (modules && third_party) passed = 1;
  close_browser(browser);
}
int main(int argc, char** argv) {
  smoke_set_role(argc, argv); smoke_trace(SMOKE_START); smoke_modules();
  if (argc != 2) return 10;
  smoke_proof_received = 1; renderer_pid = process_id() + 1;
  renderer_modules_ok = renderer_third_party_modules_ok = 1;
  int want_closed = 1, want_passed = 0;
  if (!strcmp(argv[1], "dirty")) renderer_third_party_modules_ok = 0;
  else if (!strcmp(argv[1], "engine-dirty")) renderer_modules_ok = 0;
  else if (!strcmp(argv[1], "same-pid")) renderer_pid = process_id();
  else if (!strcmp(argv[1], "invalid-pid")) renderer_pid = 0;
  else if (!strcmp(argv[1], "valid")) javascript_ok = paint_ok = want_passed = 1;
  else if (!strcmp(argv[1], "waiting")) smoke_proof_received = renderer_pid = want_closed = 0;
  else if (!strcmp(argv[1], "no-paint")) { javascript_ok = 1; want_closed = 0; }
  else return 11;
  cef_browser_t browser = {0}; finish(&browser);
  return closed == want_closed && passed == want_passed ? 0 : 12;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); shutil.copy2(progress.HEADER, root / progress.HEADER.name)
            env = dict(os.environ, CEF_STATIC_SMOKE_PROGRESS_DIR=str(root))
            for label, gate in (('old', progress.OLD_GATE), ('new', progress.NEW_GATE)):
                source = root / (label + '.c'); source.write_text(c.replace('GATE', gate))
                exe = root / label
                result = subprocess.run(['cc', '-std=c11', '-O0', '-Wall', '-Wextra', '-Werror',
                                         str(source), '-o', str(exe)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                for mode in ('dirty', 'engine-dirty', 'same-pid', 'invalid-pid', 'valid', 'waiting', 'no-paint'):
                    run = subprocess.run([str(exe), mode], env=env, capture_output=True, timeout=5)
                    expected = 12 if label == 'old' and mode in ('dirty', 'engine-dirty', 'same-pid', 'invalid-pid') else 0
                    self.assertEqual(run.returncode, expected, (label, mode))
            rows = [json.loads(p.read_text()) for p in root.glob('smoke-progress-*.json')]
            rejected = [r for r in rows if r['stage'] == 14]
            self.assertEqual(len(rejected), 4)
            self.assertTrue(all(r['closing'] == 1 and r['passed'] == 0 for r in rejected))


if __name__ == '__main__': unittest.main()
