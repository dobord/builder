import copy
import json
import os
import sys
import unittest
from unittest.mock import patch
from secure_release import cef_cache, linux_checkpoint_host as host


class LinuxCheckpointHostTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true',
                         'Native hosted Linux fingerprint proof')
    def test_native_host_retains_exact_critical_toolchain_fingerprint(self):
        observed = host.fingerprint()
        print('LINUX_CHECKPOINT_NATIVE_HOST ' + json.dumps(observed, sort_keys=True))
        self.assertEqual(observed, host.HOST)

    def test_each_critical_host_field_remains_mandatory_for_current_images(self):
        record = cef_cache.LINUX_RELEASE_CONTINUATION
        artifact, digest = record['artifacts']['cef-checkpoint']
        selected = dict(run=record['run'], attempt=1, artifact_id=artifact, artifact_sha256=digest)
        original = {'image': host.IMAGES[0], 'recipe': 'exact', 'platform_inputs': {'sha256': 'exact'}}
        for image in ('20261025.353.1', '20261026.354.1'):
            self.assertIn(image, host.IMAGES)
            expected = dict(original, image=image)
            for field in host.HOST:
                altered = dict(host.HOST, **{field: 'changed'})
                with self.subTest(image=image, field=field), \
                     patch.dict('os.environ', GITHUB_SHA='a'*40, ImageVersion=image), \
                     patch.object(host, 'fingerprint', return_value=altered), \
                     self.assertRaises(ValueError):
                    host.prepare(selected, expected, original, {})

    def test_reviewed_migration_retains_all_other_identity_fields(self):
        record = cef_cache.LINUX_RELEASE_CONTINUATION
        artifact, digest = record['artifacts']['cef-checkpoint']
        selected = dict(run=record['run'], attempt=1, artifact_id=artifact, artifact_sha256=digest)
        original = {'image': host.IMAGES[0], 'recipe': 'exact', 'platform_inputs': {'sha256': 'exact'}}
        expected = dict(original, image=host.IMAGES[1])
        with patch.dict('os.environ', GITHUB_SHA='a'*40, ImageVersion=host.IMAGES[1]), patch.object(host, 'fingerprint', return_value=host.HOST):
            environment = {}
            result = host.prepare(selected, expected, original, environment)
            self.assertEqual(environment['ImageVersion'], host.IMAGES[0])
            self.assertEqual(result['runner_image_actual'], host.IMAGES[1])
            for field in ('recipe', 'platform_inputs'):
                altered = copy.deepcopy(expected)
                altered[field] = 'different'
                with self.assertRaises(ValueError):
                    host.prepare(selected, altered, original, {})
            with patch.object(host, 'fingerprint', return_value=dict(host.HOST, gcc14='15.0.0')):
                with self.assertRaises(ValueError):
                    host.prepare(selected, expected, original, {})
            with self.assertRaises(ValueError):
                host.prepare(dict(selected, artifact_sha256='0'*64), expected, original, {})
            for image in host.IMAGES[2:]:
                with self.subTest(image=image), patch.dict('os.environ', ImageVersion=image):
                    result = host.prepare(selected, dict(expected, image=image), original, {})
                    self.assertEqual(result['runner_image_actual'], image)
                    # New image admission must never waive content identity.
                    with patch.object(host, 'fingerprint', return_value=dict(host.HOST, ninja='99.0.0')):
                        with self.assertRaises(ValueError):
                            host.prepare(selected, dict(expected, image=image), original, {})
            with patch.dict('os.environ', ImageVersion='20990101.1.1'):
                with self.assertRaises(ValueError):
                    host.prepare(selected, dict(expected, image='20990101.1.1'), original, {})
