"""Recover 0.5.0 package caches without treating them as new SDK evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import cef_cache as cache, protocol


class PreviousReleaseCacheTests(unittest.TestCase):
    def selected(self, platform):
        record = cache.RELEASE_050_BINARY_CACHES[platform]
        return {key: record[key] for key in ('run', 'attempt', 'artifact_id', 'artifact_sha256')}

    def test_exact_previous_release_contexts_and_images_survive_builder_update(self):
        for platform, artifact, image in [('linux', 12129986122, '20261012.334.1'),
                                          ('windows', 12129087010, '20261012.333.1')]:
            selected = self.selected(platform)
            self.assertEqual(selected['run'], 39103476664)
            self.assertEqual(selected['artifact_id'], artifact)
            self.assertEqual(cache.selected_revision(selected, platform, 'vcpkg-binaries', 'a' * 40),
                             '93560bb7133492bd1e62dbf6a8a666f200691056')
            self.assertEqual(cache.binary_cache_image(selected, platform, 'a' * 40), image)
            with self.assertRaises(ValueError):
                cache.selected_revision(selected, platform, 'cef-checkpoint', 'a' * 40)
            other = 'linux' if platform == 'windows' else 'windows'
            with self.assertRaises(ValueError):
                cache.selected_revision(selected, other, 'vcpkg-binaries', 'a' * 40)
            for field, value in [('attempt', 2), ('artifact_id', 1), ('artifact_sha256', '0' * 64)]:
                with self.subTest(platform=platform, field=field), self.assertRaises(ValueError):
                    cache.selected_revision(dict(selected, **{field: value}), platform, 'vcpkg-binaries', 'a' * 40)

    def test_previous_release_must_remain_successful_before_any_download(self):
        for platform in ('linux', 'windows'):
            producer = {'repository': {'id': protocol.IDS[protocol.BUILDER]},
                        'head_repository': {'id': protocol.IDS[protocol.BUILDER]},
                        'path': '.github/workflows/build-combined-release.yml',
                        'head_sha': cache.RELEASE_050_BINARY_CACHES[platform]['revision'],
                        'run_attempt': 1, 'event': 'workflow_dispatch',
                        'status': 'completed', 'conclusion': 'success'}
            for changes in ({'conclusion': 'failure'}, {'conclusion': 'cancelled'}, {'run_attempt': 2}):
                api = mock.Mock()
                api.get.side_effect = [dict(producer, **changes), dict(producer, **changes)]
                with tempfile.TemporaryDirectory() as folder, self.subTest(platform=platform, changes=changes), \
                     self.assertRaises(ValueError):
                    cache.fetch(api, self.selected(platform), Path(folder) / 'restored', platform=platform,
                                kind='vcpkg-binaries', key='b' * 64, revision='a' * 40, private='unused')
                api.artifacts.assert_not_called()
                api.download.assert_not_called()
