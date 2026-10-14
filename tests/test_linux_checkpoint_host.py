import copy
import unittest
from unittest.mock import patch
from secure_release import cef_cache, linux_checkpoint_host as host


class LinuxCheckpointHostTests(unittest.TestCase):
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
            with patch.dict('os.environ', ImageVersion=host.IMAGES[2]):
                host.prepare(selected, dict(expected, image=host.IMAGES[2]), original, {})
            with patch.dict('os.environ', ImageVersion='20990101.1.1'):
                with self.assertRaises(ValueError):
                    host.prepare(selected, dict(expected, image='20990101.1.1'), original, {})
