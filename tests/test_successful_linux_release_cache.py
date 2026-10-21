"""Exact successful-release cache selection, without private source fixtures."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import cef_cache as cache, protocol


class SuccessfulLinuxCacheTests(unittest.TestCase):
    def setUp(self):
        self.selected = {'run': 38608203966, 'attempt': 1, 'artifact_id': 11927207987,
                         'artifact_sha256': '839a22eeecbb6644f69723df9dd69b95f3a83ad6927b756154229be18622ed3e'}
        self.revision = '4ce8f380b24fb16dd80018cc12cd42d2e2bb2348'

    def test_exact_producer_context_and_image_are_preserved(self):
        self.assertEqual(cache.selected_revision(self.selected, 'linux', 'vcpkg-binaries', 'a' * 40), self.revision)
        self.assertEqual(cache.binary_cache_image(self.selected, 'linux', 'a' * 40), '20261004.327.1')

    def test_other_platform_purpose_attempt_and_artifact_are_rejected(self):
        for platform, kind in [('windows', 'vcpkg-binaries'), ('linux', 'cef-checkpoint')]:
            with self.subTest(platform=platform, kind=kind), self.assertRaises(ValueError):
                cache.selected_revision(self.selected, platform, kind, 'a' * 40)
        for field, value in [('attempt', 2), ('artifact_id', 1), ('artifact_sha256', '0' * 64)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                cache.selected_revision(dict(self.selected, **{field: value}), 'linux', 'vcpkg-binaries', 'a' * 40)

    def test_producer_failure_or_rerun_rejected_before_artifact_download(self):
        producer = {'repository': {'id': protocol.IDS[protocol.BUILDER]},
                    'head_repository': {'id': protocol.IDS[protocol.BUILDER]},
                    'path': '.github/workflows/build-combined-release.yml',
                    'head_sha': self.revision, 'run_attempt': 1, 'event': 'workflow_dispatch',
                    'status': 'completed', 'conclusion': 'success'}
        for changes in ({'conclusion': 'failure'}, {'conclusion': 'cancelled'}, {'run_attempt': 2}):
            api = mock.Mock()
            api.get.side_effect = [dict(producer, **changes), dict(producer, **changes)]
            with tempfile.TemporaryDirectory() as folder, self.subTest(changes=changes), self.assertRaises(ValueError):
                cache.fetch(api, self.selected, Path(folder) / 'restored', platform='linux',
                            kind='vcpkg-binaries', key='b' * 64, revision='a' * 40, private='unused')
            api.artifacts.assert_not_called()
            api.download.assert_not_called()
