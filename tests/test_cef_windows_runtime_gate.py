"""Windows iteration enables the native strict module audit and rejects false proof."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_iteration as worker
from secure_release import cef_windows_source_repair as repair
from tests.cef_windows_source_repair_base import populate


class WindowsRuntimeGateTests(unittest.TestCase):
    def exercise(self, third_party_static, source_verified=True, linkage='static'):
        key = repair.build_key(repair.BASE_KEY)
        cfg = {'schema': 1, 'recipe_commit': worker.CEF, 'profile': 'static-third-party',
               'release_lock': None, 'slice_seconds': 9000, 'jobs': 4,
               'platforms': {p: {'mode': 'source-fresh', 'checkpoint': None, 'binary_cache': None}
                             for p in ('linux', 'windows')}}
        with tempfile.TemporaryDirectory(prefix='windows-runtime-gate-') as folder:
            root = Path(folder).resolve()
            temp = root / 'temp'; temp.mkdir()
            registry = root / 'private-vcpkg/ci'; registry.mkdir(parents=True)
            (registry / 'release-plan.json').write_text(json.dumps({'cef': cfg}))
            (root / 'ci').mkdir()
            (root / 'ci/cef-windows-engine-lock.json').write_text(json.dumps({
                'schema': 2, 'platform': 'windows', 'vcpkg_commit': worker.VCPKG,
                'cef_recipe_commit': worker.CEF, 'source_repair': repair.profile(),
                'checkpoint': dict(repair.UPGRADE_V26, run=101, producer_sha='a' * 40, build_key=key)}))
            work = temp / 'w'
            logs = temp / 'cef-windows-engine-logs'
            commands = []
            def run(command, **kwargs):
                args = list(map(str, command)); commands.append(args)
                env = kwargs['env']
                self.assertNotIn('GITHUB_TOKEN', env)
                self.assertNotIn('BUILDER_INPUT_PRIVATE_KEY', env)
                if 'restore' in args:
                    populate(work)
                    repair.apply(work, key, 'legacy')
                elif 'slice' in args:
                    self.assertEqual(env['CEF_STATIC_STRICT_THIRD_PARTY'], '0')
                    Path(args[args.index('--state') + 1]).write_text(json.dumps({
                        'ready': True, 'checkpoint_ready': False,
                        'progress': {'status': 'complete', 'engine_compilation_complete': True}}))
                elif 'build' in args:
                    self.assertEqual(env['CEF_STATIC_STRICT_THIRD_PARTY'], '1')
                    logs.mkdir(exist_ok=True)
                    (logs / 'engine-build-receipt.json').write_text(json.dumps({
                        'source_build_verified': source_verified, 'engine_linkage': linkage,
                        'smoke': {'javascript': True, 'paint': True, 'browser_modules_clean': True,
                                  'renderer_modules_clean': True, 'browser_pid': 10, 'renderer_pid': 20,
                                  'third_party_modules_static': third_party_static}}))
                return subprocess.CompletedProcess(args, 0)
            env = {'GITHUB_WORKSPACE': str(root), 'RUNNER_TEMP': str(temp), 'GITHUB_RUN_ID': '102',
                   'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'b' * 40, 'GITHUB_TOKEN': 'synthetic-test-token',
                   'BUILDER_INPUT_PRIVATE_KEY': 'synthetic-not-a-key', 'ImageVersion': '20261004.326.1',
                   'CEF_STATIC_STRICT_THIRD_PARTY': '0'}
            def head(path):
                if path.name == 'private-vcpkg': return worker.VCPKG
                if path.name == 'private-cef': return worker.CEF
                if path.name == 'pdfium': return repair.PDFIUM
                return repair.CHROMIUM
            def restore(selected, destination, contract, private):
                destination.mkdir()
                return {}
            valid = third_party_static and source_verified and linkage == 'static'
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(worker.sys, 'platform', 'win32'), \
                    mock.patch.object(worker, 'git_head', side_effect=head), \
                    mock.patch.object(worker, 'verify_producer_summary', return_value={}), \
                    mock.patch.object(worker, 'checkpoint_image_identity', return_value='20260927.320.1'), \
                    mock.patch.object(worker, 'checkpoint_workspace_paths', return_value=(work, work)), \
                    mock.patch.object(worker, 'restore_checkpoint', side_effect=restore), \
                    mock.patch.object(worker, 'run', side_effect=run):
                if valid:
                    worker.main()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'strict CEF runtime receipt is incomplete'):
                        worker.main()
            summary = json.loads((temp / 'cef-windows-engine-summary.json').read_text())
            self.assertEqual(summary['status'], 'success' if valid else 'failed')
            self.assertEqual(summary['runtime_verified'], valid)
            self.assertEqual([args[2] for args in commands], ['restore', 'prepare', 'slice', 'build'])
            if valid:
                self.assertTrue(summary['ready'])
                self.assertTrue(summary['progress']['engine_compilation_complete'])
            else:
                self.assertEqual(summary['failure_stage'], 'engine-runtime')

    def test_runtime_overrides_ambient_flag_and_requires_real_static_module_proof(self):
        self.exercise(True)

    def test_false_module_proof_still_fails_closed(self):
        self.exercise(False)

    def test_missing_source_or_static_engine_proof_still_fails_closed(self):
        for source_verified, linkage in ((False, 'static'), (True, 'shared')):
            with self.subTest(source_verified=source_verified, linkage=linkage):
                self.exercise(True, source_verified, linkage)


if __name__ == '__main__':
    unittest.main()
