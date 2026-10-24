"""A/A calibration binds both roles to one independently byte-verified product."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from secure_release import project_ci_runner as runner
from tests.test_project_ci_baseline import fixture


COMMAND = ('python3 scripts/measure-paired-benchmarks.py '
           'out/build/performance-baseline/benchmarks out/build/performance/benchmarks out/performance')
NAMES = ('queue_throughput', 'runtime', 'io_backend_submission', 'filesystem', 'timer_wheel', 'variant')


class SelfBaselineTests(unittest.TestCase):
    def products(self, root):
        for build in ('performance-baseline', 'performance'):
            folder = root / 'out/build' / build / 'benchmarks'
            folder.mkdir(parents=True)
            for name in NAMES:
                (folder / ('lfc_' + name + '_benchmark')).write_bytes(('synthetic-' + name).encode())

    def test_exact_approved_self_comparison_uses_one_unchanged_physical_product(self):
        value, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.products(root)
            audit = root / 'audit.json'
            original = 'python3 tests/tooling/paired_benchmark_samples_test.py\n' + COMMAND + '\n'
            actual = runner.self_baseline_command(original, root, value, 'performance', audit)
            self.assertEqual(actual, original.replace('out/build/performance-baseline/benchmarks',
                                                      'out/build/performance/benchmarks'))
            record = json.loads(audit.read_text())
            self.assertEqual(record['source_sha'], value['source_sha'])
            self.assertEqual(record['baseline_sha'], value['baseline_sha'])
            self.assertEqual(len(record['products']), 6)
            for item in record['products']:
                before, after = Path(item['baseline']), Path(item['candidate'])
                self.assertEqual(before.read_bytes(), after.read_bytes())
                self.assertEqual(item['baseline_identity']['sha256'], item['candidate_identity']['sha256'])
            self.assertEqual(record['mode'], 'owner-approved-identical-artifact-calibration')
            self.assertEqual(record['original_command_sha256'], runner.ci.digest_bytes(original.encode()))
            self.assertEqual(record['executed_command_sha256'], runner.ci.digest_bytes(actual.encode()))

    def test_other_steps_sources_profiles_or_nonexception_requests_are_untouched(self):
        value, _ = fixture()
        changes = ({'schema': 1}, {'source_sha': '0' * 40}, {'baseline_tag': 'v0.4.0'},
                   {'suite': 'ci'}, {'baseline_tag': 'owner-approved-' + '0' * 40})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for change in changes:
                self.assertEqual(runner.self_baseline_command(COMMAND, root, dict(value, **change),
                                                             'performance', root / 'audit.json'), COMMAND)
            self.assertEqual(runner.self_baseline_command(COMMAND, root, value, 'ci', root / 'audit.json'), COMMAND)
            for command in ('cmake --build .', COMMAND + ' --unexpected', COMMAND.replace('out/performance', 'other')):
                self.assertEqual(runner.self_baseline_command(command, root, value, 'performance', root / 'audit.json'), command)
            self.assertFalse((root / 'audit.json').exists())

    def test_different_missing_or_linked_products_fail_before_any_execution(self):
        value, _ = fixture()
        for failure in ('different', 'missing', 'linked'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                self.products(root)
                product = root / 'out/build/performance-baseline/benchmarks/lfc_variant_benchmark'
                if failure == 'different':
                    product.write_bytes(b'not the same program')
                else:
                    product.unlink()
                    if failure == 'linked':
                        try:
                            product.symlink_to(root / 'out/build/performance/benchmarks/lfc_variant_benchmark')
                        except OSError:
                            continue  # Other negative cases still execute without Windows symlink privilege.
                with self.assertRaises((ValueError, FileNotFoundError)):
                    runner.self_baseline_command(COMMAND, root, value, 'performance', root / 'audit.json')
                self.assertFalse((root / 'audit.json').exists())

    def test_existing_audit_cannot_be_overwritten(self):
        value, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.products(root)
            audit = root / 'audit.json'
            audit.write_bytes(b'prior evidence')
            with self.assertRaises(FileExistsError):
                runner.self_baseline_command(COMMAND, root, value, 'performance', audit)
            self.assertEqual(audit.read_bytes(), b'prior evidence')

    def test_native_runner_records_selection_and_executes_the_calibration_command(self):
        value, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / 'workspace/private-source'
            work = root / 'runner/project-ci'
            work.mkdir(parents=True)
            self.products(source)
            (work / 'request.json').write_bytes(runner.crypto.canonical(value))
            lane = {'id': 'synthetic', 'profile': 'performance', 'matrix': {},
                    'runner': ['ubuntu-24.04'], 'job': {'steps': [{'run': COMMAND}]}}
            env = {'GITHUB_WORKSPACE': str(root / 'workspace'), 'RUNNER_TEMP': str(root / 'runner'),
                   'CI_LANE': 'synthetic', 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_NUMBER': '1',
                   'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_OS': 'Linux', 'GH_TOKEN': 'SYNTHETIC'}
            def execute(command, cwd, environment, log, **kwargs):
                self.assertNotIn('GH_TOKEN', environment)
                self.assertEqual((work / 'step-0.sh').read_text().count('out/build/performance/benchmarks'), 2)
                self.assertTrue((work / 'owner-self-baseline.json').is_file())
                return 0
            with patch.dict(os.environ, env), patch.object(runner.ci, 'recipes', return_value=[lane]), \
                    patch.object(runner.ci, 'quiet', side_effect=execute) as command:
                runner.run()
            command.assert_called_once()


if __name__ == '__main__':
    unittest.main()
