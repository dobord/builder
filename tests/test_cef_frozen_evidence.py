"""Rejected archive evidence must not silently authorize a different ABI.

Small real C/C++ archives reproduce both new public APIs and compiler-generated
weak/hidden definitions. Neither is waived. Full symbol names stay only in the
runner-local JSON selected by the existing encrypted-log collector.
"""
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_frozen_dependencies as replay
from secure_release import cef_frozen_evidence as observer
from secure_release import encrypted_logs
import test_cef_frozen_dependencies as native


class EvidenceContractTests(unittest.TestCase):
    def test_summary_step_cannot_change_worker_success_or_failure(self):
        workflow = (native.ROOT / '.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn("failure() && steps.combined.outcome == 'failure'", workflow)
        self.assertIn('run: python -m secure_release.cef_strict_combined', workflow)
        self.assertIn('run: python -m secure_release.cef_frozen_evidence', workflow)
        self.assertNotIn('continue-on-error', workflow)
        self.assertLess(workflow.index('python -m secure_release.cef_strict_combined'),
                        workflow.index('python -m secure_release.cef_frozen_evidence'))
        policy = inspect.getsource(replay.replay)
        self.assertIn('if not built_names <= frozen_names:', policy)
        self.assertLess(policy.index('if mismatches:'), policy.index('for target, temporary in staged:'))
        self.assertNotIn('continue', policy.split('if mismatches:', 1)[1].split('try:', 1)[0])

    def test_workflow_runs_native_failure_evidence_regression_without_public_upload(self):
        text = (native.ROOT / '.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn('test_cef_frozen_evidence.py -v', text)
        self.assertNotIn('path: ${{ runner.temp }}/cef-strict-combined/qualified-triplets', text)
        self.assertIn('path: ${{ runner.temp }}/cef-strict-combined-summary.json', text)


@unittest.skipUnless(sys.platform == 'linux', 'Native ELF archive evidence requires Linux')
class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.prefix, self.packages, self.manifest, self.spec, self.overlay = native.setup(self.root)
        self.package = native.package(self.root, self.packages)
        self.archive = self.package / 'lib/libfrozen.a'
        self.report = self.overlay / replay.SYMBOL_EVIDENCE / 'frozenlib.json'

    def apply(self):
        return replay.replay(self.spec, replay.sha(self.spec), self.package,
                             'frozenlib', replay.TRIPLET, features='core;optional', version='1.0')

    def add_feature(self):
        extra = self.root / 'extra.c'
        extra.write_text('int private_fixture_new_api(void){return 1;}\n')
        native.run(['cc', '-c', extra, '-o', self.root / 'extra.o'], self.root)
        native.run(['ar', 'r', self.archive, self.root / 'extra.o'], self.root)

    def reject_and_check_unchanged(self):
        before = {p: p.read_bytes() for root in (self.package, self.prefix)
                  for p in root.rglob('*') if p.is_file()}
        clocks = {p: p.stat().st_mtime_ns for p in before}
        with self.assertRaisesRegex(ValueError, 'lose a built feature symbol'):
            self.apply()
        for p, data in before.items():
            self.assertEqual(p.read_bytes(), data)
            self.assertEqual(p.stat().st_mtime_ns, clocks[p])
        self.assertFalse((self.package / 'share/frozenlib' / replay.RECEIPT).exists())
        return json.loads(self.report.read_bytes())

    def test_public_feature_delta_is_bound_and_remains_fatal(self):
        self.add_feature()
        value = self.reject_and_check_unchanged()
        self.assertFalse(value['runtime_verified'])
        self.assertEqual(value['features'], ['core', 'optional'])
        self.assertEqual(value['version'], '1.0')
        self.assertEqual(value['spec_sha256'], replay.sha(self.spec))
        record = value['archives'][0]
        self.assertEqual(record['built_sha256'], replay.sha(self.archive))
        self.assertEqual(record['frozen_sha256'], replay.sha(self.prefix / 'lib/libfrozen.a'))
        self.assertEqual(set(record['built_only']), {'private_fixture_new_api'})
        summary = replay.mismatch_summary(self.overlay, replay.sha(self.manifest))
        self.assertTrue(summary['frozen_symbol_evidence_verified'])
        self.assertEqual(summary['frozen_symbol_visible_global_count'], 1)
        self.assertEqual(summary['frozen_symbol_built_only_count'], 1)
        self.assertNotIn('private_fixture_new_api', json.dumps(summary))
        self.assertNotIn(str(self.root), json.dumps(summary))
        self.assertEqual(self.report.stat().st_mode & 0o777, 0o600)
        self.assertIn(self.report, list(encrypted_logs.iter_logs(self.overlay)))
        self.assertNotIn(self.report, list(encrypted_logs.iter_logs(self.package)))

    def test_weak_hidden_cpp_codegen_is_described_but_not_waived(self):
        source = self.root / 'generated.cpp'
        source.write_text('template<class T> __attribute__((noinline,visibility("hidden"))) '
                          'T emitted_template(T x){return x+1;}\n'
                          'extern "C" int frozen_value(void){return emitted_template<int>(72);}\n')
        native.run(['g++', '-O0', '-fno-exceptions', '-fno-rtti', '-c', source,
                    '-o', self.root / 'generated.o'], self.root)
        self.archive.unlink()
        native.run(['ar', 'rcsD', self.archive, self.root / 'generated.o'], self.root)
        # Both providers have the same public prototype and test output. This
        # fixture does NOT establish compatibility of unknown production deltas.
        main = self.root / 'main.c'
        main.write_text('int frozen_value(void);int main(void){return frozen_value()!=73;}\n')
        for index, archive in enumerate((self.archive, self.prefix / 'lib/libfrozen.a')):
            exe = self.root / f'consumer{index}'
            native.run(['cc', main, archive, '-o', exe], self.root)
            native.run([exe], self.root)
        self.reject_and_check_unchanged()
        summary = replay.mismatch_summary(self.overlay, replay.sha(self.manifest))
        self.assertGreater(summary['frozen_symbol_weak_count'], 0)
        self.assertGreater(summary['frozen_symbol_hidden_count'], 0)
        self.assertGreater(summary['frozen_symbol_cpp_mangled_count'], 0)
        self.assertEqual(summary['frozen_symbol_visible_global_count'], 0)
        self.assertTrue(summary['frozen_symbol_elf_metadata_complete'])

    def test_same_surface_replays_without_evidence_or_extra_elf_command(self):
        with mock.patch.object(replay, 'elf_details', side_effect=AssertionError('not needed')):
            result = self.apply()
        self.assertEqual(result['replaced'], 1)
        self.assertFalse(self.report.exists())
        self.assertEqual(replay.mismatch_summary(self.overlay, replay.sha(self.manifest)), {})

    def test_all_archives_reject_before_first_replacement(self):
        self.add_feature()
        self.reject_and_check_unchanged()
        self.assertFalse(list(self.package.rglob('.cef-frozen-*')))

    def test_unbound_or_malformed_reports_are_rejected(self):
        self.add_feature(); self.reject_and_check_unchanged()
        original = self.report.read_bytes()
        for field, changed in (('policy_sha256', '0'*64), ('spec_sha256', '0'*64),
                               ('platform_sha256', '0'*64), ('port', '../bad')):
            value = json.loads(original); value[field] = changed
            self.report.write_bytes(replay.canonical(value))
            with self.assertRaises(ValueError):
                replay.mismatch_summary(self.overlay, replay.sha(self.manifest))
        self.report.write_bytes(original)
        with self.assertRaises(ValueError):
            replay.mismatch_summary(self.overlay, '0'*64)
        value = json.loads(original)
        value['archives'][0]['archive'] = 'lib/unknown.a'
        self.report.write_bytes(replay.canonical(value))
        with self.assertRaises(ValueError):
            replay.mismatch_summary(self.overlay, replay.sha(self.manifest))

    def test_redirected_evidence_cannot_modify_inputs(self):
        self.add_feature()
        self.report.parent.symlink_to(self.prefix, target_is_directory=True)
        before = self.archive.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Redirected'):
            self.apply()
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertFalse((self.prefix / self.report.name).exists())

    def test_existing_evidence_is_not_overwritten_and_collection_is_bounded(self):
        self.add_feature(); self.reject_and_check_unchanged()
        before = self.report.read_bytes(); archive_before = self.archive.read_bytes()
        with self.assertRaises(FileExistsError): self.apply()
        self.assertEqual(self.report.read_bytes(), before)
        self.assertEqual(self.archive.read_bytes(), archive_before)
        with mock.patch.object(replay, 'EVIDENCE_LIMIT', 1):
            with self.assertRaises(ValueError):
                replay.mismatch_summary(self.overlay, replay.sha(self.manifest))

    def test_actual_summary_publication_does_not_change_failure_or_leak_symbols(self):
        self.add_feature(); self.reject_and_check_unchanged()
        temp = self.root / 'runner'; temp.mkdir()
        combined_root = temp / 'cef-strict-combined'; combined_root.mkdir()
        # Recreate the real Actions layout without modifying the bound spec.
        shutil.copytree(self.overlay, combined_root / 'qualified-triplets')
        path = temp / 'cef-strict-combined-summary.json'
        base = {'schema': 1, 'kind': 'cef-strict-combined-sdk-qualification',
                'status': 'failed', 'failure_stage': 'vcpkg-install',
                'failure_type': 'RuntimeError', 'runtime_verified': False,
                'platform_sha256': replay.sha(self.manifest)}
        path.write_bytes(replay.canonical(base))
        self.assertTrue(observer.publish_failure(temp))
        result = json.loads(path.read_bytes())
        for key, value in base.items(): self.assertEqual(result[key], value)
        self.assertEqual(result['frozen_symbol_built_only_count'], 1)
        self.assertNotIn('private_fixture_new_api', path.read_text())
        self.assertNotIn(str(self.root), path.read_text())
        base['status'] = 'success'; base['runtime_verified'] = True
        path.write_bytes(replay.canonical(base)); raw = path.read_bytes()
        self.assertFalse(observer.publish_failure(temp))
        self.assertEqual(path.read_bytes(), raw)
        path.unlink()
        self.assertFalse(observer.publish_failure(temp))

    def test_real_hook_passes_metadata_without_printing_symbols(self):
        self.add_feature()
        script = self.root / 'hook.cmake'
        script.write_text('set(PORT frozenlib)\nset(VERSION 1.0)\nset(FEATURES core optional)\n'
            'set(TARGET_TRIPLET '+replay.TRIPLET+')\nset(CURRENT_PACKAGES_DIR "'+str(self.package)+'")\n'
            'include("'+str(self.overlay / 'frozen-dependencies.cmake')+'")\n')
        before = self.archive.read_bytes()
        result = native.run(['cmake', '-P', script], self.root, good=False)
        self.assertNotIn('private_fixture_new_api', result.stdout + result.stderr)
        self.assertEqual(self.archive.read_bytes(), before)
        value = json.loads(self.report.read_bytes())
        self.assertEqual(value['features'], ['core', 'optional'])
        self.assertEqual(value['version'], '1.0')


if __name__ == '__main__':
    unittest.main()
