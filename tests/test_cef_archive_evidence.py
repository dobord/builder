"""Worker wiring tests; mocked runtime is never native qualification evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from secure_release import cef_build, static_audit
from test_cef_contract import config
from test_static_audit import ar, elf


class EvidenceTests(unittest.TestCase):
    def test_audit_is_bound_to_final_zip_and_all_fallback_trees_are_hidden(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ('cef-recipe', 'smoke-build', 'installed', 'consumer-sdk', 'cef-work', 'export/sdk'):
                (root / name).mkdir(parents=True)
            (root / 'smoke-build/cef_static_combined_smoke').write_bytes(b'not executed fixture')
            (root / 'smoke-build/icudtl.dat').write_bytes(b'fixture')
            with zipfile.ZipFile(root / 'sdk.zip', 'w') as z:
                z.writestr('installed/x64-linux-static-release/lib/a.a', ar(elf()))
            calls = []
            def execute(command, **options):
                calls.append(command)
                state = Path(command[command.index('--state') + 1])
                state.parent.mkdir(parents=True)
                state.write_text('{"kind":"consumer-verification"}')
            with patch.object(cef_build, 'validate_evidence') as validation:
                proof = cef_build.verify_consumer(root, config(), 'linux', execute)
                validation.assert_called_once()
            hidden = [Path(calls[0][i + 1]) for i, value in enumerate(calls[0]) if value == '--hide']
            self.assertEqual(set(hidden), {root/n for n in ('installed', 'consumer-sdk', 'cef-work', 'export/sdk', 'smoke-build')})
            report = json.loads((root/'cef-consumer-evidence/target-archive-audit.json').read_bytes())
            self.assertEqual(proof['target_archive_audit'], static_audit.summarize(report))
            self.assertTrue(proof['target_archive_audit']['target_archives_static'])
            self.assertFalse(proof['target_archive_audit']['runtime_dependencies_verified'])

    def test_report_summary_changes_when_zip_changes(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sdk.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('installed/x64-linux-static-release/lib/a.a', ar(elf()))
            first = static_audit.summarize(static_audit.inspect_sdk(path, 'linux'))
            with zipfile.ZipFile(path, 'a') as z:
                z.writestr('installed/x64-linux-static-release/lib/b.so.1', elf(3))
            second = static_audit.summarize(static_audit.inspect_sdk(path, 'linux'))
            self.assertNotEqual(first['sdk_sha256'], second['sdk_sha256'])
            self.assertNotEqual(first['report_sha256'], second['report_sha256'])
            self.assertFalse(second['target_archives_static'])


if __name__ == '__main__':
    unittest.main()
