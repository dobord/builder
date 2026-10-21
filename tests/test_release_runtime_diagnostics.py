"""Keep failed release runtime evidence encrypted, never in public output."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import tasks


class RuntimeDiagnosticsTests(unittest.TestCase):
    def test_module_maps_and_smoke_receipts_reach_only_encrypted_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'build.log').write_bytes(b'SYNTHETIC_BUILD\n')
            runtime = root / 'upstream/buildtrees/cef-static/diagnostics'
            names = ['runtime-progress/smoke-modules-42.txt',
                     'attempt/01/static-smoke.log',
                     'attempt/01/static-smoke-status.json', 'smoke-runs.json']
            for name in names:
                path = runtime / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(('PRIVATE_SYNTHETIC_' + name).encode())
            (runtime / 'unrelated.txt').write_bytes(b'DO_NOT_COLLECT')
            captured = []
            def encrypt(source, target, public, context):
                captured.append(source.read_bytes())
            environment = {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
                           'GITHUB_SHA': 'a' * 40, 'TARGET_PLATFORM': 'linux',
                           'DIAGNOSTIC_DIR': str(root / 'cipher'),
                           'ARTIFACT_ENCRYPTION_PUBLIC_KEY': 'synthetic-public-key'}
            console = io.StringIO()
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch.object(tasks, 'guard'), mock.patch.object(tasks, 'work', return_value=root), \
                 mock.patch.object(tasks, 'event', return_value={'inputs': {'release_id': 'r', 'salt': 's'}}), \
                 mock.patch.object(tasks, 'file_context', return_value={'synthetic': True}), \
                 mock.patch.object(tasks.crypto, 'encrypt_file', side_effect=encrypt), \
                 contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                tasks.diagnostics()
            self.assertEqual(console.getvalue(), '')
            self.assertEqual(len(captured), 1)
            for name in names:
                self.assertIn(('PRIVATE_SYNTHETIC_' + name).encode(), captured[0])
            self.assertNotIn(b'DO_NOT_COLLECT', captured[0])
