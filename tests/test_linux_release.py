import hashlib
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import urllib.error
import zipfile

from secure_release import crypto, linux_sdk, protocol, publish, safeio

ROOT = Path(__file__).resolve().parents[1]


class LinuxReleaseTests(unittest.TestCase):
    def test_final_replay_starts_fresh_and_preserves_preflight_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            installed = root/'installed'
            (installed/'vcpkg').mkdir(parents=True)
            (installed/'vcpkg/status').write_text('public synthetic owner\n')
            (installed/'old-package').write_bytes(b'preflight bytes')
            linux_sdk.fresh_replay_installation(root)
            self.assertFalse(installed.exists())
            preserved = root/'platform-installed-before-replay'
            self.assertEqual((preserved/'old-package').read_bytes(), b'preflight bytes')
            installed.mkdir()
            (installed/'new-replay-receipt').write_bytes(b'owned final replay')
            self.assertFalse((installed/'old-package').exists())
            with self.assertRaises(ValueError):
                linux_sdk.fresh_replay_installation(root)
            self.assertEqual((preserved/'vcpkg/status').read_text(), 'public synthetic owner\n')

    def test_linux_publication_revalidates_exact_workflow_attempt(self):
        run = {'id': 99, 'workflow_id': 7, 'run_attempt': 1,
               'repository': {'id': protocol.IDS[protocol.BUILDER]},
               'head_repository': {'id': protocol.IDS[protocol.BUILDER]},
               'path': '.github/workflows/build-linux-release.yml',
               'head_sha': 'a'*40, 'event': 'workflow_dispatch',
               'status': 'completed', 'conclusion': 'success'}

        class Api:
            def get(self, path):
                if '/workflows/' in path:
                    return {'id': 7}
                if '/attempts/' in path:
                    return exact
                return current

        with (patch.dict(os.environ, BUILDER_COMMIT_SHA='a'*40, BUILDER_READ_TOKEN='fixture'),
              patch.object(publish, 'guard'),
              patch.object(publish, 'event', return_value={'workflow_run': run}),
              patch.object(publish, 'Client', return_value=Api())):
            exact, current = copy.deepcopy(run), copy.deepcopy(run)
            self.assertEqual(publish._trusted_builder_result()[1:],
                             (99, 1, 'a'*40, 'build-linux-release.yml'))
            for field, value in [('id', 100), ('workflow_id', 8), ('run_attempt', 2),
                                 ('path', '.github/workflows/build-release.yml'),
                                 ('head_sha', 'b'*40), ('conclusion', 'failure'),
                                 ('head_repository', {'id': 999})]:
                with self.subTest(field=field):
                    exact = dict(run, **{field: value})
                    with self.assertRaises(ValueError):
                        publish._trusted_builder_result()
            exact = copy.deepcopy(run)
            current = dict(run, run_attempt=2)
            with self.assertRaisesRegex(ValueError, 'changed'):
                publish._trusted_builder_result()

    def test_signed_selection_and_workflow_are_explicit(self):
        self.assertEqual(protocol.release_platforms({'version': 1}), ('linux', 'windows'))
        self.assertEqual(protocol.release_platforms({'version': 2, 'platforms': ['linux']}), ('linux',))
        for payload in ({'version': 2}, {'version': 1, 'platforms': ['linux']},
                        {'version': 2, 'platforms': ['windows']},
                        {'version': 2, 'platforms': ['linux', 'windows']}, {'version': True}):
            with self.assertRaises(ValueError):
                protocol.release_platforms(payload)
        self.assertEqual(protocol.build_workflow('.github/workflows/build-linux-release.yml'), 'build-linux-release.yml')
        with self.assertRaises(ValueError):
            protocol.build_workflow('.github/workflows/not-a-release.yml')

    def test_linux_workflow_has_no_windows_job_or_matrix(self):
        workflow = (ROOT/'.github/workflows/build-linux-release.yml').read_text()
        self.assertNotIn('windows', workflow.lower())
        self.assertNotIn('matrix:', workflow)
        self.assertIn('TARGET_PLATFORM: linux', workflow)
        self.assertIn("steps.build-sdk.outputs.sdk_ready != 'true'", workflow)
        publisher = (ROOT/'.github/workflows/request-publication.yml').read_text()
        self.assertIn('Build static Linux SDK', publisher)

    def test_cpp_evidence_rejects_root_success_with_crashed_children(self):
        proof = {'status': 'success', 'usage_exit': 2, 'shutdown_exit': 0,
                 'listener_started': True, 'renderer_stable': True,
                 'child_crashes_detected': False, 'executable_sha256': 'a'*64,
                 'needed': ['libc.so.6'], 'loaded_shared_modules': ['libc.so.6']}
        linux_sdk.validate_cpp_proof(proof)
        for field, value in [('child_crashes_detected', True), ('renderer_stable', False),
                             ('loaded_shared_modules', ['libstdc++.so.6']), ('needed', [])]:
            with self.assertRaises(ValueError):
                linux_sdk.validate_cpp_proof(dict(proof, **{field: value}))

    def test_source_reviews_bind_the_actual_published_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder)/'sdk.zip'
            name = 'installed/x64-linux-static-release/share/lfc-ui/examples/freerdp-proxy-cef/main.cpp'
            data = b'int main() { return 0; }\n'
            with zipfile.ZipFile(archive, 'w') as sdk:
                sdk.writestr(name, data)
            review = {'examples': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}},
                      'headers': None, 'docs': None, 'interfaces': None}
            self.assertEqual(linux_sdk.validate_archive_sources(archive, review), {name})
            review['examples'][name]['sha256'] = '0'*64
            with self.assertRaises(ValueError):
                linux_sdk.validate_archive_sources(archive, review)

    def test_linux_verification_downloads_no_windows_artifact(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            input_private, output_public = crypto.generate('encrypt')
            signing_private, signing_public = crypto.generate('sign')
            now = int(time.time())
            payload = {'version': 2, 'platforms': ['linux'],
                       'release_id': str(uuid.uuid4()), 'salt': crypto.b64(os.urandom(32)),
                       'source_sha': 'b'*40, 'source_tag': 'v1.2.3', 'request_run': 1, 'request_attempt': 1,
                       'builder_sha': 'a'*40, 'output_key': crypto.fingerprint(output_public),
                       'input_key': '0'*64, 'created': now, 'expires': now+300,
                       'source_id': protocol.IDS[protocol.SOURCE], 'builder_id': protocol.IDS[protocol.BUILDER],
                       'bin_id': protocol.IDS[protocol.BIN],
                       'plan': {'version': 1, 'upstream_sha': 'c'*40, 'smoke_path': 'ci/smoke',
                                'ports': [{'name': 'test', 'repository': 'dobord/test', 'sha': 'd'*40}],
                                'platforms': {'linux': {'packages': ['test']}, 'windows': {'packages': ['test']}}}}
            document = crypto.sign(payload, signing_private)
            protocol.verified(document, signing_public)
            bundle = root/'bundle'
            bundle.mkdir()
            sdk = bundle/'sdk.zip'
            with zipfile.ZipFile(sdk, 'w') as archive:
                archive.writestr('scripts/buildsystems/vcpkg.cmake', '# toolchain\n')
                archive.writestr('installed/x64-linux-static-release/lib/libtest.a', b'!<arch>\n')
            manifest = {'version': 1, 'platform': 'linux', 'triplet': 'x64-linux-static-release',
                        'builder_sha': payload['builder_sha'], 'source_sha': payload['source_sha'],
                        'upstream_sha': payload['plan']['upstream_sha'], 'build_run': 99, 'build_attempt': 1,
                        'request_sha256': hashlib.sha256(crypto.canonical(document)).hexdigest(),
                        'sdk_sha256': crypto.digest(sdk)}
            (bundle/'manifest.json').write_bytes(crypto.canonical(manifest))
            (bundle/'request.json').write_bytes(crypto.canonical(document))
            tar = root/'bundle.tgz'
            safeio.pack_tar(bundle, tar)
            context = protocol.file_context(payload['release_id'], payload['salt'], 99, 1, 'a'*40, 'sdk', 'linux')
            cipher = root/'cipher'
            cipher.mkdir()
            crypto.encrypt_file(tar, cipher/'sdk.enc', output_public, context)
            transport = root/'artifact.zip'
            with zipfile.ZipFile(transport, 'w') as archive:
                archive.write(cipher/'sdk.enc', 'sdk.enc')
            artifact = {'name': 'sdk-linux-99-1', 'expired': False, 'id': 12,
                        'workflow_run': {'id': 99, 'head_sha': 'a'*40}, 'digest': 'sha256:'+crypto.digest(transport)}

            class Api:
                downloads = []
                def artifacts(self, repo, run):
                    return [artifact]
                def download(self, path, destination, expected):
                    self.downloads.append(path)
                    destination.write_bytes(transport.read_bytes())
                    if crypto.digest(destination) != expected:
                        raise ValueError('transport mismatch')

            api = Api()
            environment = {'RUNNER_TEMP': str(root), 'STAGING_DIR': str(root/'staging'),
                           'GITHUB_OUTPUT': str(root/'outputs'), 'ARTIFACT_DECRYPTION_PRIVATE_KEY': input_private,
                           'ARTIFACT_ENCRYPTION_PUBLIC_KEY': output_public, 'REQUEST_VERIFY_PUBLIC_KEY': signing_public}
            with patch.dict(os.environ, environment), patch.object(publish, '_trusted_builder_result',
                    return_value=(api, 99, 1, 'a'*40, 'build-linux-release.yml')):
                publish.verify_result()
            release = crypto.parse((root/'staging/release-manifest.json').read_bytes())
            self.assertEqual(release['release_platforms'], ['linux'])
            self.assertEqual(set(release['platforms']), {'linux'})
            self.assertEqual(set(p.name for p in (root/'staging').iterdir()),
                             {'vcpkg-v1.2.3-linux-x64-static-release.zip', 'release-manifest.json', 'SHA256SUMS'})
            self.assertEqual(len(api.downloads), 1)

            class PublisherApi:
                assets = []
                release = None
                def __init__(self, token):
                    pass
                def get(self, path):
                    if path == f'/repos/{protocol.BIN}':
                        return {'id': protocol.IDS[protocol.BIN], 'private': True, 'default_branch': 'main'}
                    if path.endswith('/git/ref/heads/main'):
                        return {'object': {'type': 'commit', 'sha': 'e'*40}}
                    if '/releases/tags/' in path:
                        raise urllib.error.HTTPError(path, 404, 'not found', None, None)
                    if '/assets?' in path:
                        return list(self.assets)
                    if path.endswith('/releases?per_page=100&page=1'):
                        return []
                    raise AssertionError('Unexpected publication API operation')
                def json(self, method, path, body):
                    if method == 'POST':
                        PublisherApi.release = dict(body, id=7)
                    else:
                        PublisherApi.release.update(body)
                    return PublisherApi.release
                def upload_asset(self, repo, release_id, file):
                    asset = {'name': file.name, 'digest': 'sha256:'+crypto.digest(file)}
                    self.assets.append(asset)
                    return asset

            environment.update(PUBLISH_ENABLED='true', PUBLISH_TOKEN='test-token',
                               STAGING_DIGEST=crypto.digest(root/'staging/SHA256SUMS'))
            with (patch.dict(os.environ, environment), patch.object(publish, '_trusted_builder_result',
                  return_value=(api, 99, 1, 'a'*40, 'build-linux-release.yml')),
                  patch.object(publish, 'Client', PublisherApi)):
                publish.publish_release()
            self.assertFalse(PublisherApi.release['draft'])
            self.assertEqual({asset['name'] for asset in PublisherApi.assets},
                             {'vcpkg-v1.2.3-linux-x64-static-release.zip', 'release-manifest.json', 'SHA256SUMS'})


if __name__ == '__main__':
    unittest.main()
