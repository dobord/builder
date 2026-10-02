"""Exact original ZIPs, not new producer identity, survive backup transport."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

from secure_release import cef_checkpoint_backup as backup
from secure_release import cef_checkpoint_availability as availability
from secure_release import cef_strict_iteration as engine
from secure_release import cef_cache, crypto
from secure_release.protocol import BUILDER, IDS


def sha(data):
    return hashlib.sha256(data).hexdigest()


def zip_bytes(entries, *, method=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=method) as stream:
        for name, data in entries:
            if isinstance(name, zipfile.ZipInfo):
                stream.writestr(name, data)
            else:
                with stream.open(name, 'w', force_zip64=True) as member:
                    member.write(data)
    return output.getvalue()


def summary_value(selected):
    return {'schema': 1, 'status': 'success', 'ready': True,
            'runtime_verified': True, 'checkpoint_ready': True,
            'platform_graph_qualified': True, 'gn_graph_qualified': True,
            'build_key': selected['build_key'], 'platform_sha256': selected['platform_sha256'],
            'vcpkg_commit': engine.VCPKG, 'cef_recipe_commit': engine.CEF}


class API:
    def __init__(self, data=b''):
        self.data, self.calls, self.downloads = data, [], 0
        self.change = lambda path, value: None

    def get(self, path):
        self.calls.append(path)
        if path == f'/repos/{BUILDER}/actions/artifacts/{backup.BACKUP_ID}':
            value = {'id': backup.BACKUP_ID, 'name': backup.BACKUP_NAME,
                     'digest': 'sha256:' + backup.BACKUP_DIGEST,
                     'size_in_bytes': backup.BACKUP_BYTES, 'expired': False,
                     'expires_at': '2999-01-01T00:00:00Z',
                     'workflow_run': {'id': backup.BACKUP_RUN, 'head_sha': backup.BACKUP_SHA,
                                      'head_branch': backup.BACKUP_BRANCH}}
        elif '/actions/runs/' in path:
            number = int(path.split('/actions/runs/')[1].split('/')[0])
            original = number == backup.ORIGINAL['run']
            assert original or number == backup.BACKUP_RUN
            value = {'id': number, 'run_attempt': backup.ORIGINAL['attempt'] if original else backup.BACKUP_ATTEMPT,
                     'head_sha': backup.ORIGINAL['producer_sha'] if original else backup.BACKUP_SHA,
                     'head_branch': 'feature/cef-static-integration' if original else backup.BACKUP_BRANCH,
                     'path': '.github/workflows/' + ('cef-strict-engine-iteration.yml' if original else backup.BACKUP_WORKFLOW),
                     'event': 'push', 'repository': {'id': IDS[BUILDER], 'full_name': BUILDER},
                     'head_repository': {'id': IDS[BUILDER], 'full_name': BUILDER},
                     'status': 'completed', 'conclusion': 'success'}
        else:
            raise AssertionError('No discovery or substitute artifact API is allowed')
        self.change(path, value)
        return value

    def download(self, endpoint, target, expected, *, max_size):
        assert endpoint == f'/repos/{BUILDER}/actions/artifacts/{backup.BACKUP_ID}/zip'
        assert expected == backup.BACKUP_DIGEST and max_size == backup.BACKUP_BYTES
        self.downloads += 1
        target.write_bytes(self.data)

    def artifacts(self, *args):
        return []  # Both original artifacts really are missing in this fixture.


@contextmanager
def fixture(root, *, summary=None, checkpoint=None, mutate_receipt=None, mutate_entries=None):
    backup.cleanup()
    selected = deepcopy(backup.ORIGINAL)
    summary = summary_value(selected) if summary is None else summary
    summary_zip = zip_bytes([('cef-strict-iteration-summary.json', crypto.canonical(summary))])
    checkpoint_zip = zip_bytes([('index.enc', b'ciphertext-fixture-not-a-key')]) if checkpoint is None else checkpoint
    selected.update(artifact_sha256=sha(checkpoint_zip), summary_artifact_sha256=sha(summary_zip))
    receipt = {'schema': 1, 'kind': 'strict-cef-exact-ciphertext-backup', 'sdk_qualified': False,
               'original_producer': {'repository': BUILDER, 'run': selected['run'],
                                     'attempt': selected['attempt'], 'sha': selected['producer_sha']},
               'backup_run': backup.BACKUP_RUN, 'backup_attempt': backup.BACKUP_ATTEMPT,
               'original_zip_hashes_verified': True, 'not_for_direct_lock_substitution': True,
               'checkpoint': {'original_artifact_id': selected['artifact_id'],
                              'sha256': selected['artifact_sha256'], 'size': len(checkpoint_zip)},
               'summary': {'original_artifact_id': selected['summary_artifact_id'],
                           'sha256': selected['summary_artifact_sha256'], 'size': len(summary_zip)}}
    if mutate_receipt:
        mutate_receipt(receipt)
    entries = [('checkpoint.zip', checkpoint_zip), ('summary.zip', summary_zip),
               ('transport-receipt.json', crypto.canonical(receipt))]
    if mutate_entries:
        entries = mutate_entries(entries)
    data = zip_bytes(entries)
    api = API(data)
    with mock.patch.object(backup, 'ORIGINAL', selected), \
         mock.patch.object(backup, 'BACKUP_DIGEST', sha(data)), \
         mock.patch.object(backup, 'BACKUP_BYTES', len(data)), \
         mock.patch.dict(os.environ, {'RUNNER_TEMP': str(root)}):
        try:
            yield api, selected, summary_zip, checkpoint_zip
        finally:
            backup.cleanup()


class MetadataTests(unittest.TestCase):
    def test_transport_is_separate_from_unchanged_combined_lock(self):
        root = Path(__file__).resolve().parents[1]
        lock = json.loads((root / 'ci/cef-strict-combined-lock.json').read_bytes())
        self.assertEqual(lock['checkpoint'], backup.ORIGINAL)
        self.assertNotEqual(backup.BACKUP_RUN, lock['checkpoint']['run'])
        self.assertNotEqual(backup.BACKUP_ID, lock['checkpoint']['artifact_id'])
        source = (root / 'secure_release/cef_strict_iteration.py').read_text()
        self.assertIn('"cef-checkpoint", "linux", build_key, run, attempt, revision, "index"', source)
        self.assertNotIn('cef_cache.context(backup', source)

    def test_only_exact_original_selector_is_reviewed(self):
        self.assertTrue(backup.applies(deepcopy(backup.ORIGINAL)))
        for key, value in backup.ORIGINAL.items():
            selected = dict(backup.ORIGINAL)
            selected[key] = value + 1 if type(value) is int else '0' * len(value)
            self.assertFalse(backup.applies(selected), key)
        self.assertFalse(backup.applies(dict(backup.ORIGINAL, attempt=True)))
        self.assertFalse(backup.applies(dict(backup.ORIGINAL, backup_run=backup.BACKUP_RUN)))
        self.assertFalse(backup.applies(None))

    def test_guard_checks_both_run_attempts_and_does_not_download(self):
        api = API()
        now = datetime(2026, 10, 2, tzinfo=timezone.utc)
        proof = availability.verify_available(backup.ORIGINAL, api, now=now)
        self.assertEqual(proof['run'], 36069973563)
        self.assertEqual(proof['backup_run'], 36975195624)
        self.assertEqual(proof['artifact_count'], 1)
        self.assertEqual(proof['contained_original_archive_count'], 2)
        self.assertEqual(api.downloads, 0)
        self.assertEqual(len(api.calls), 5)
        self.assertFalse(any('/artifacts/108' in path for path in api.calls))

    def test_original_or_backup_rerun_wrong_workflow_event_branch_or_repository_fails(self):
        for number in (backup.ORIGINAL['run'], backup.BACKUP_RUN):
            for field, value in [('run_attempt', 2), ('run_attempt', True), ('head_sha', '0' * 40),
                                 ('path', '.github/workflows/unreviewed.yml'), ('event', 'pull_request'),
                                 ('head_branch', 'main'), ('status', 'in_progress'), ('conclusion', 'failure'),
                                 ('repository', {'id': 1}), ('head_repository', {'id': 1})]:
                with self.subTest(run=number, field=field):
                    api = API()
                    api.change = lambda path, result: result.update({field: value}) if f'/runs/{number}' in path else None
                    with self.assertRaises(ValueError):
                        backup.verify_available(backup.ORIGINAL, api)
                    self.assertEqual(api.downloads, 0)

    def test_artifact_identity_lifetime_and_http_errors_are_fatal(self):
        changes = [('id', 1), ('name', 'other'), ('digest', 'sha256:' + '0' * 64),
                   ('size_in_bytes', backup.BACKUP_BYTES + 1), ('expired', True),
                   ('expires_at', '2026-01-01T00:00:00Z'), ('expires_at', '2099-99-99T00:00:00Z'),
                   ('workflow_run', {'id': backup.ORIGINAL['run'], 'head_sha': backup.ORIGINAL['producer_sha']})]
        for field, value in changes:
            api = API()
            api.change = lambda path, result: result.update({field: value}) if '/artifacts/' in path else None
            with self.assertRaises(ValueError):
                backup.verify_available(backup.ORIGINAL, api)
        for status in (404, 410, 403, 500):
            api = mock.Mock()
            api.get.side_effect = urllib.error.HTTPError('secret-url', status, 'secret-body', {}, None)
            with self.assertRaisesRegex(ValueError, '^CEF_CHECKPOINT_BACKUP_API_UNAVAILABLE$'):
                backup.verify_available(backup.ORIGINAL, api)
            api.download.assert_not_called()

    def test_exact_six_hour_retention_boundary_and_utc(self):
        expiry = datetime(2026, 12, 31, 6, 46, 42, tzinfo=timezone.utc)
        api = API()
        api.change = lambda path, value: value.update(expires_at='2026-12-31T06:46:42Z') if '/artifacts/' in path else None
        backup.verify_available(backup.ORIGINAL, api, now=expiry - timedelta(hours=6))
        for now in (expiry - timedelta(hours=6) + timedelta(seconds=1), datetime(2026, 10, 2)):
            with self.assertRaises(ValueError):
                backup.verify_available(backup.ORIGINAL, api, now=now)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name).resolve()

    def tearDown(self):
        backup.cleanup()
        self.folder.cleanup()

    def test_exact_nested_zip64_originals_are_fetched_once_and_cleaned(self):
        with fixture(self.root) as (api, selected, summary, checkpoint):
            for role, expected in [('summary', summary), ('summary', summary), ('checkpoint', checkpoint)]:
                target = self.root / (role + str(len(list(self.root.iterdir()))) + '.zip')
                backup.copy_original(api, selected, role, target)
                self.assertEqual(target.read_bytes(), expected)
                self.assertFalse(any(self.root.rglob('transport.zip')))
            self.assertEqual(api.downloads, 1)
            self.assertIsNone(backup._cache)
            self.assertFalse(list(self.root.glob('.cef-engine83-backup-*')))

    def test_outer_hash_and_each_inner_hash_are_mandatory_before_summary_publication(self):
        for role in ('outer', 'summary.zip', 'checkpoint.zip'):
            def mutate(entries):
                return [(name, data + b'tamper' if name == role else data) for name, data in entries]
            with fixture(self.root, mutate_entries=mutate) as (api, selected, *_):
                if role == 'outer':
                    api.data = api.data[:-1] + bytes([api.data[-1] ^ 1])
                with self.assertRaises(ValueError):
                    backup.copy_original(api, selected, 'summary', self.root / 'published.zip')
                self.assertFalse((self.root / 'published.zip').exists())
                self.assertIsNone(backup._cache)
                self.assertFalse(list(self.root.glob('.cef-engine83-backup-*')))

    def test_no_nested_unknown_duplicate_link_directory_or_unsupported_method(self):
        symlink = zipfile.ZipInfo('checkpoint.zip')
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        def compressed(entries):
            result = []
            for name, data in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_BZIP2
                result.append((info, data))
            return result
        mutations = [lambda e: e + [('extra', b'x')], lambda e: e + [e[0]],
                     lambda e: [("../checkpoint.zip", e[0][1]), *e[1:]],
                     lambda e: [('checkpoint.zip/', e[0][1]), *e[1:]],
                     lambda e: [(symlink, e[0][1]), *e[1:]], compressed,
                     lambda e: [e[0], e[1], (e[2][0], b'X' * (backup.RECEIPT_LIMIT + 1))]]
        for change in mutations:
            with self.subTest(change=change), fixture(self.root, mutate_entries=change) as (api, selected, *_):
                with self.assertRaises(ValueError):
                    backup.copy_original(api, selected, 'summary', self.root / 'published.zip')
                self.assertFalse((self.root / 'published.zip').exists())

    def test_level_zero_deflate_transport_keeps_both_original_hashes(self):
        def deflate(entries):
            result = []
            for name, data in entries:
                info = zipfile.ZipInfo(name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info._compresslevel = 0
                result.append((info, data))
            return result
        with fixture(self.root, mutate_entries=deflate) as (api, selected, summary, _):
            target = self.root / 'summary.zip'
            backup.copy_original(api, selected, 'summary', target)
            self.assertEqual(target.read_bytes(), summary)

    def test_redirected_parent_and_concurrent_output_creator_are_not_overwritten(self):
        with fixture(self.root) as (api, selected, *_):
            parent = self.root / 'redirect'
            try:
                parent.symlink_to(self.root, target_is_directory=True)
            except OSError:
                if os.name == 'nt':
                    self.skipTest('Windows symlink privilege unavailable')
                raise
            with self.assertRaisesRegex(ValueError, 'REDIRECTED_PATH'):
                backup.copy_original(api, selected, 'summary', parent / 'result.zip')
            self.assertEqual(api.downloads, 0)
            parent.unlink()
            target = self.root / 'result.zip'
            original = api.download
            def race(*args, **kwargs):
                original(*args, **kwargs)
                target.write_bytes(b'concurrent-owner')
            api.download = race
            with self.assertRaises(FileExistsError):
                backup.copy_original(api, selected, 'summary', target)
            self.assertEqual(target.read_bytes(), b'concurrent-owner')
            self.assertIsNone(backup._cache)

    def test_receipt_cannot_authorize_different_original_or_fake_success(self):
        for mutate in [lambda r: r.update(sdk_qualified=True),
                       lambda r: r['original_producer'].update(run=backup.BACKUP_RUN),
                       lambda r: r['checkpoint'].update(sha256='0' * 64),
                       lambda r: r['summary'].update(size=1),
                       lambda r: r.update(backup_attempt=2),
                       lambda r: r.update(not_for_direct_lock_substitution=False)]:
            with fixture(self.root, mutate_receipt=mutate) as (api, selected, *_):
                with self.assertRaises(ValueError):
                    backup.copy_original(api, selected, 'summary', self.root / 'published.zip')
                self.assertFalse((self.root / 'published.zip').exists())

    def test_existing_target_low_disk_and_partial_download_publish_nothing(self):
        target = self.root / 'existing.zip'; target.write_bytes(b'keep')
        with fixture(self.root) as (api, selected, *_):
            with self.assertRaises(ValueError):
                backup.copy_original(api, selected, 'summary', target)
            self.assertEqual(api.downloads, 0)
            self.assertEqual(target.read_bytes(), b'keep')
            with mock.patch.object(backup.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(100, 99, 1)):
                with self.assertRaisesRegex(ValueError, 'DISK_SPACE'):
                    backup.copy_original(api, selected, 'summary', self.root / 'new.zip')
            self.assertEqual(api.downloads, 0)
            def partial(*args, **kwargs):
                args[1].write_bytes(b'partial')
                raise TimeoutError('synthetic timeout')
            api.download = partial
            with self.assertRaises(TimeoutError):
                backup.copy_original(api, selected, 'summary', self.root / 'new.zip')
            self.assertFalse((self.root / 'new.zip').exists())
            self.assertFalse(list(self.root.glob('.cef-engine83-backup-*')))

    def test_metadata_changed_during_download_prevents_publication(self):
        with fixture(self.root) as (api, selected, *_):
            def drift(path, value):
                if api.downloads and f'/runs/{backup.BACKUP_RUN}' in path:
                    value['run_attempt'] = 2
            api.change = drift
            with self.assertRaises(ValueError):
                backup.copy_original(api, selected, 'summary', self.root / 'new.zip')
            self.assertFalse((self.root / 'new.zip').exists())
            self.assertIsNone(backup._cache)

    def test_corrupted_process_cache_still_fails_the_original_hash(self):
        with fixture(self.root) as (api, selected, *_):
            backup.copy_original(api, selected, 'summary', self.root / 'summary.zip')
            (Path(backup._cache.name) / 'original/checkpoint.zip').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                backup.copy_original(api, selected, 'checkpoint', self.root / 'checkpoint.zip')
            self.assertFalse((self.root / 'checkpoint.zip').exists())
            self.assertIsNone(backup._cache)

    def test_original_summary_is_still_subject_to_every_qualification_gate(self):
        for field in ('runtime_verified', 'ready', 'checkpoint_ready', 'platform_graph_qualified', 'gn_graph_qualified'):
            value = summary_value(backup.ORIGINAL); value[field] = False
            with fixture(self.root, summary=value) as (api, selected, *_):
                with self.assertRaisesRegex(ValueError, 'does not qualify'):
                    engine.verify_producer_summary(api, selected, allow_resumable=False)

    def test_unknown_selector_never_uses_the_backup(self):
        selected = dict(backup.ORIGINAL, run=123)
        api = API()
        with self.assertRaisesRegex(ValueError, 'summary artifact is missing'):
            engine.verify_producer_summary(api, selected, allow_resumable=False)
        self.assertEqual(api.downloads, 0)

    def test_real_tink_roundtrip_retains_original_context_and_rejects_wrong_context(self):
        try:
            crypto._tink()
        except ImportError:
            if os.environ.get('REQUIRE_TINK_TESTS') == '1':
                raise
            self.skipTest('official Tink is unavailable; CI installs the pinned wheel')
        private, public = crypto.generate('encrypt')  # Disposable test key only.
        source = self.root / 'source'; source.mkdir()
        (source / 'checkpoint.json').write_bytes(b'{"fixture":true}')
        (source / 'workspace.tar.gz.part0000').write_bytes(b'PUBLIC-SYNTHETIC-CHECKPOINT')
        for wrong_context in (False, True):
            sealed = self.root / ('encrypted' + str(wrong_context))
            context = cef_cache.context('cef-checkpoint', 'linux', backup.ORIGINAL['build_key'],
                                        backup.BACKUP_RUN if wrong_context else backup.ORIGINAL['run'],
                                        backup.ORIGINAL['attempt'], backup.ORIGINAL['producer_sha'], 'index')
            cef_cache.seal(source, sealed, public, context)
            ciphertext = zip_bytes([(p.name, p.read_bytes()) for p in sorted(sealed.iterdir())])
            with fixture(self.root, checkpoint=ciphertext) as (api, selected, *_), \
                 mock.patch.object(engine, 'Client', return_value=api), \
                 mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'disposable-test-token'}):
                target = self.root / ('restored' + str(wrong_context))
                if wrong_context:
                    with self.assertRaises(ValueError):
                        engine.restore_checkpoint(selected, target, selected['build_key'], private, allow_resumable=False)
                    self.assertFalse(target.exists())
                else:
                    result = engine.restore_checkpoint(selected, target, selected['build_key'], private, allow_resumable=False)
                    self.assertEqual(result['context']['run'], 36069973563)
                    self.assertIs(result['sdk_verified'], False)
                    self.assertEqual((target / 'checkpoint.json').read_bytes(), b'{"fixture":true}')
                    self.assertEqual((target / 'workspace.tar.gz.part0000').read_bytes(), b'PUBLIC-SYNTHETIC-CHECKPOINT')
                    self.assertEqual(api.downloads, 1)
            self.assertIsNone(backup._cache)


if __name__ == '__main__':
    unittest.main()
