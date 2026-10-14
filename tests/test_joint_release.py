import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import zipfile

from secure_release import crypto, joint_release, protocol, publish, safeio, cef_cache


class JointReleaseTests(unittest.TestCase):
    def test_combined_verification_requires_two_scoped_signatures_for_one_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            private, public = crypto.generate('encrypt')
            signing, verify = crypto.generate('sign')
            now = int(time.time())
            common = {'version': 2, 'release_id': str(uuid.uuid4()), 'salt': crypto.b64(os.urandom(32)),
                      'source_sha': 'b'*40, 'source_tag': 'v0.3.0', 'builder_sha': 'a'*40,
                      'request_run': 1, 'request_attempt': 1, 'created': now, 'expires': now+300,
                      'input_key': '0'*64, 'output_key': crypto.fingerprint(public),
                      'source_id': protocol.IDS[protocol.SOURCE], 'builder_id': protocol.IDS[protocol.BUILDER],
                      'bin_id': protocol.IDS[protocol.BIN], 'plan': {'version': 1, 'upstream_sha': 'c'*40,
                      'ports': [{'name': 'test', 'repository': 'dobord/test', 'sha': 'd'*40}],
                      'smoke_path': 'ci/smoke', 'platforms': {p: {'packages': ['test']} for p in ('linux', 'windows')}}}
            artifacts, transports = [], {}
            for index, platform in enumerate(('linux', 'windows')):
                payload = dict(common, platforms=[platform])
                signed = crypto.sign(payload, signing)
                protocol.verified(signed, verify)
                bundle = root/platform
                bundle.mkdir()
                with zipfile.ZipFile(bundle/'sdk.zip', 'w') as sdk:
                    sdk.writestr('scripts/buildsystems/vcpkg.cmake', '# public fixture\n')
                    sdk.writestr(f'installed/x64-{platform}-static-release/lib/test.' + ('a' if platform == 'linux' else 'lib'), b'!<arch>\n')
                manifest = {'version': 1, 'platform': platform, 'triplet': f'x64-{platform}-static-release',
                            'builder_sha': 'a'*40, 'source_sha': 'b'*40, 'upstream_sha': 'c'*40,
                            'build_run': 99, 'build_attempt': 1, 'sdk_sha256': crypto.digest(bundle/'sdk.zip'),
                            'request_sha256': hashlib.sha256(crypto.canonical(signed)).hexdigest()}
                (bundle/'manifest.json').write_bytes(crypto.canonical(manifest))
                (bundle/'request.json').write_bytes(crypto.canonical(signed))
                safeio.pack_tar(bundle, root/f'{platform}.tgz')
                cipher = root/f'{platform}.enc'
                crypto.encrypt_file(root/f'{platform}.tgz', cipher, public, protocol.file_context(
                    payload['release_id'], payload['salt'], 99, 1, 'a'*40, 'sdk', platform))
                transport = root/f'{platform}.zip'
                with zipfile.ZipFile(transport, 'w') as archive:
                    archive.write(cipher, 'sdk.enc')
                artifact = {'id': 12+index, 'name': f'sdk-{platform}-99-1', 'expired': False,
                            'digest': 'sha256:'+crypto.digest(transport), 'workflow_run': {'id':99,'head_sha':'a'*40}}
                artifacts.append(artifact)
                transports[f'/repos/{protocol.BUILDER}/actions/artifacts/{12+index}/zip'] = transport
            class Api:
                def artifacts(self, repo, run):
                    return artifacts
                def download(self, endpoint, target, digest):
                    target.write_bytes(transports[endpoint].read_bytes())
                    assert crypto.digest(target) == digest
            env = {'RUNNER_TEMP': str(root), 'STAGING_DIR':str(root/'staging'), 'GITHUB_OUTPUT':str(root/'outputs'),
                   'ARTIFACT_DECRYPTION_PRIVATE_KEY':private, 'ARTIFACT_ENCRYPTION_PUBLIC_KEY':public,
                   'REQUEST_VERIFY_PUBLIC_KEY':verify}
            with patch.dict(os.environ,env), patch.object(publish,'_trusted_builder_result',return_value=(Api(),99,1,'a'*40,joint_release.WORKFLOW)):
                publish.verify_result()
            manifest = crypto.parse((root/'staging/release-manifest.json').read_bytes())
            self.assertEqual(manifest['release_platforms'],['linux','windows'])
            self.assertEqual(set(manifest['platform_requests']),{'linux','windows'})
            self.assertEqual(set(p.name for p in (root/'staging').iterdir()), {
                'vcpkg-v0.3.0-linux-x64-static-release.zip','vcpkg-v0.3.0-windows-x64-static-release.zip',
                'release-manifest.json','SHA256SUMS'})
            alternate = copy.deepcopy(common)
            alternate['source_sha'] = 'e'*40
            self.assertNotEqual(joint_release.identity(common),joint_release.identity(alternate))
            alternate = copy.deepcopy(common)
            alternate['plan']['platforms']['windows']['packages'] = ['different']
            self.assertNotEqual(joint_release.identity(common),joint_release.identity(alternate))

    def test_reviewed_binary_cache_cannot_cross_platform_or_digest(self):
        record = cef_cache.WINDOWS_RELEASE_BINARY_CACHE
        selected = {k:record[k] for k in ('run','attempt','artifact_id','artifact_sha256')}
        self.assertEqual(cef_cache.selected_revision(selected,'windows','vcpkg-binaries','a'*40),record['revision'])
        with self.assertRaises(ValueError):
            cef_cache.selected_revision(selected,'linux','vcpkg-binaries','a'*40)
        with self.assertRaises(ValueError):
            cef_cache.selected_revision(dict(selected,artifact_sha256='0'*64),'windows','vcpkg-binaries','a'*40)


if __name__ == '__main__':
    unittest.main()
