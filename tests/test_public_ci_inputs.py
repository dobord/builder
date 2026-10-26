"""Exact public compiler fixtures must work without network, including subprocesses."""
import io
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

from tests import public_ci_inputs as inputs
from tools.vendor_public_ci_inputs import inventory


class PublicCiInputTests(unittest.TestCase):
    def test_every_manifest_input_is_local_bounded_and_hash_verified(self):
        with zipfile.ZipFile(io.BytesIO(inputs.archive_bytes())) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            for license in manifest['licenses']:
                raw = archive.read(license['name'])
                self.assertEqual(len(raw), license['size'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), license['sha256'])
        self.assertGreater(len(manifest['files']), 30)
        with patch('urllib.request.urlopen', side_effect=AssertionError('Network forbidden')):
            for record in manifest['files']:
                with self.subTest(url=record['url']):
                    raw = inputs.public_bytes(record['url'], record['size'])
                    self.assertEqual(len(raw), record['size'])

    def test_archive_matches_every_existing_declarative_fixture_pin(self):
        with zipfile.ZipFile(io.BytesIO(inputs.archive_bytes())) as archive:
            manifest = json.loads(archive.read('manifest.json'))
        actual = {record['url']: record for record in manifest['files']}
        expected = inventory()
        self.assertEqual(set(actual), {record['url'] for record in expected})
        for record in expected:
            for key, value in record.items():
                if value is not None:
                    self.assertEqual(actual[record['url']][key], value)

    def test_unknown_url_wrong_size_and_modified_archive_fail_closed(self):
        with self.assertRaises(ValueError):
            inputs.public_bytes('https://example.com/unreviewed', 10)
        with zipfile.ZipFile(io.BytesIO(inputs.archive_bytes())) as archive:
            record = json.loads(archive.read('manifest.json'))['files'][0]
        with self.assertRaises(ValueError):
            inputs.public_bytes(record['url'], record['size'] + 1)
        with patch.object(inputs, 'ARCHIVE_SHA256', '0' * 64), self.assertRaises(ValueError):
            inputs.archive_bytes.__wrapped__()

    def test_fixture_imports_in_clean_subprocess_never_download(self):
        root = Path(__file__).resolve().parents[1]
        script = """
import urllib.request
def forbidden(*args, **kwargs):
    raise AssertionError('Network forbidden during public fixture import')
urllib.request.urlopen = forbidden
from tests import cef_windows_layout_inputs
from tests import test_cef_windows_dom_memory_repair as dom
for name in dom.PUBLIC:
    dom.public_bytes(name)
"""
        result = subprocess.run([sys.executable, '-c', script], cwd=root,
                                capture_output=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
