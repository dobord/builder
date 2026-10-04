"""Synthetic cache bytes prove exact workflow scope and original-context transfer."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from secure_release import cef_cache, crypto, protocol


class LinuxCacheTests(unittest.TestCase):
    RECORD = 'LINUX_CONTINUATION'
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.private, self.public = crypto.generate('encrypt')
        self.review = copy.deepcopy(getattr(cef_cache, self.RECORD))
        self.current = 'a'*40
        self.run = self.review['run']
        source = self.root/'source'
        source.mkdir()
        (source/'checkpoint.json').write_text('{"synthetic":true}\n')
        (source/'workspace.tar.gz.part0000').write_bytes(b'public synthetic checkpoint')
        base = cef_cache.context('cef-checkpoint', 'linux', 'b'*64, self.run, 1,
                                 self.review['revision'], 'index')
        cipher = self.root/'cipher'
        cef_cache.seal(source, cipher, self.public, base)
        self.transport = self.root/'transport.zip'
        with zipfile.ZipFile(self.transport, 'w') as archive:
            for file in cipher.iterdir():
                archive.write(file, file.name)
        self.review['artifacts']['cef-checkpoint'] = (123, crypto.digest(self.transport))
        self.selected = {'run': self.run, 'attempt': 1, 'artifact_id': 123,
                         'artifact_sha256': crypto.digest(self.transport)}
        self.producer = {'repository': {'id': protocol.IDS[protocol.BUILDER]},
                         'head_repository': {'id': protocol.IDS[protocol.BUILDER]},
                         'path': '.github/workflows/build-linux-release.yml',
                         'head_sha': self.review['revision'], 'run_attempt': 1,
                         'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'failure'}
        self.artifact = {'id': 123, 'name': f'cef-checkpoint-linux-{self.run}-1',
                         'expired': False, 'digest': 'sha256:'+crypto.digest(self.transport),
                         'workflow_run': {'id': self.run, 'head_sha': self.review['revision']}}
        self.api = self
        self.downloaded = False
        self.patcher = patch.object(cef_cache, self.RECORD, self.review)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def get(self, path):
        return dict(self.producer)

    def artifacts(self, repo, run):
        self.assertEqual((repo, run), (protocol.BUILDER, self.run))
        return [self.artifact]

    def download(self, path, target, expected, **kwargs):
        self.downloaded = True
        self.assertEqual(expected, crypto.digest(self.transport))
        target.write_bytes(self.transport.read_bytes())

    def restore(self, destination, **kwargs):
        args = dict(platform='linux', kind='cef-checkpoint', key='b'*64,
                    revision=self.current, private=self.private)
        args.update(kwargs)
        return cef_cache.fetch(self.api, self.selected, destination, **args)

    def test_reviewed_producer_decrypts_only_under_its_original_context(self):
        destination = self.root/'restored'
        result = self.restore(destination)
        self.assertFalse(result['sdk_verified'])
        self.assertEqual((destination/'workspace.tar.gz.part0000').read_bytes(),
                         b'public synthetic checkpoint')
        with self.assertRaises(Exception):
            self.restore(self.root/'wrong-key', key='c'*64)
        self.assertFalse((self.root/'wrong-key').exists())

    def test_unreviewed_old_producer_is_not_a_transfer_exception(self):
        self.run = 42
        self.selected['run'] = 42
        self.artifact['name'] = 'cef-checkpoint-linux-42-1'
        self.artifact['workflow_run']['id'] = 42
        with self.assertRaisesRegex(ValueError, 'untrusted workflow run'):
            self.restore(self.root/'unreviewed')
        self.assertFalse(self.downloaded)

    def test_exact_artifact_and_linux_workflow_scope_are_mandatory(self):
        for field, value in [('artifact_id', 124), ('artifact_sha256', 'c'*64), ('attempt', 2)]:
            original = dict(self.selected)
            self.selected[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.restore(self.root/field)
            self.selected = original
        for path in ('.github/workflows/build-release.yml', '.github/workflows/other.yml'):
            self.producer['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.restore(self.root/'wrong-workflow')
        self.producer['path'] = '.github/workflows/build-linux-release.yml'
        with self.assertRaises(ValueError):
            self.restore(self.root/'windows', platform='windows')
        self.artifact['expired'] = True
        with self.assertRaises(ValueError):
            self.restore(self.root/'expired')
        self.assertFalse(self.downloaded)

    def test_new_linux_workflow_is_accepted_without_transfer(self):
        # A newly produced cache is bound to the current revision, not the
        # closed historical producer. Use fresh ciphertext with that context.
        self.run = 42
        self.producer['head_sha'] = self.current
        self.selected['run'] = 42
        self.artifact['name'] = 'cef-checkpoint-linux-42-1'
        self.artifact['workflow_run'] = {'id': 42, 'head_sha': self.current}
        # The old ciphertext MUST fail authentication even though its artifact
        # provenance now matches. This also proves no header-driven context use.
        with self.assertRaises(Exception):
            self.restore(self.root/'wrong-context')
        self.assertTrue(self.downloaded)
        self.assertFalse((self.root/'wrong-context').exists())
        cipher = self.root/'new-cipher'
        base = cef_cache.context('cef-checkpoint', 'linux', 'b'*64, 42, 1, self.current, 'index')
        cef_cache.seal(self.root/'source', cipher, self.public, base)
        with zipfile.ZipFile(self.transport, 'w') as archive:
            for file in cipher.iterdir():
                archive.write(file, file.name)
        self.selected['artifact_sha256'] = crypto.digest(self.transport)
        self.artifact['digest'] = 'sha256:'+crypto.digest(self.transport)
        result = self.restore(self.root/'new-restored')
        self.assertFalse(result['sdk_verified'])


class RuntimeCheckpointCacheTests(LinuxCacheTests):
    RECORD = 'LINUX_RUNTIME_CONTINUATION'


class InstalledCheckpointCacheTests(LinuxCacheTests):
    RECORD = 'LINUX_INSTALL_CONTINUATION'


class InventoryCheckpointCacheTests(LinuxCacheTests):
    RECORD = 'LINUX_INVENTORY_CONTINUATION'


class SmokeCheckpointCacheTests(LinuxCacheTests):
    RECORD = 'LINUX_SMOKE_CONTINUATION'


class AuditCheckpointCacheTests(LinuxCacheTests):
    RECORD = 'LINUX_AUDIT_CONTINUATION'


if __name__ == '__main__':
    unittest.main()
