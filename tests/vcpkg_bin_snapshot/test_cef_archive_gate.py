"""Synthetic format/manifest fixtures, never real SDK qualification evidence."""
import hashlib
import struct
import unittest
from unittest.mock import patch
import zipfile
from secure_release import static_audit
import test_cef_publication as fixture
import cef_archive_gate as gate


def archive(payload):
    header = b'object.o/       ' + b'0           ' + b'0     ' + b'0     ' + b'100644  ' + str(len(payload)).encode().ljust(10) + b'`\n'
    return b'!<arch>\n' + header + payload + (b'\n' if len(payload) & 1 else b'')


class ArchiveGateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.PublicationTests(methodName='test_only_exact_reviewed_contracts_are_admitted')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def bundle(self, profile='static-third-party', shared=False, evidence=True):
        setup = self.fixture
        _, keys = setup.bundle(profile=profile)
        for platform in ('linux', 'windows'):
            setup.policy['admitted_contracts'][platform] = [keys[platform]]
            path = setup.root / f'vcpkg-v1.2.3-{platform}-x64-static-release.zip'
            payload = (b'\x7fELF\x02\x01\x01' + b'\0'*9 + struct.pack('<HHI', 1, 62, 1) + b'\0'*40) if platform == 'linux' else \
                struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 0, 0) + b'.text\0\0\0' + b'\0'*32
            with zipfile.ZipFile(path, 'a') as z:
                z.writestr(f'installed/x64-{platform}-static-release/lib/a.' + ('a' if platform == 'linux' else 'lib'), archive(payload))
                if shared:
                    z.writestr(f'installed/x64-{platform}-static-release/lib/unexpected.' + ('so.1' if platform == 'linux' else 'dll'), b'shared fixture')
            record = setup.manifest['platforms'][platform]
            record['sdk_sha256'] = setup.files[path.name] = fixture.gate.digest(path)
            if evidence:
                record['cef']['consumer']['target_archive_audit'] = static_audit.summarize(static_audit.inspect_sdk(path, platform))
        return setup.resign()

    def test_recomputes_the_exact_checksum_bound_archive_report(self):
        expected = self.bundle()
        report = gate.inspect(self.fixture.root, expected, self.fixture.policy)
        self.assertTrue(report['publication_allowed'])
        self.assertFalse(report['sdk_code_executed'])
        self.assertEqual(set(report['archive_audits']), {'linux', 'windows'})
        self.assertFalse(report['archive_audits']['linux']['runtime_dependencies_verified'])

    def test_engine_profile_cannot_be_upgraded_by_clean_archives(self):
        expected = self.bundle(profile='engine-static')
        self.assertFalse(gate.inspect(self.fixture.root, expected, self.fixture.policy)['publication_allowed'])

    def test_missing_audit_is_not_accepted(self):
        expected = self.bundle(evidence=False)
        self.assertFalse(gate.inspect(self.fixture.root, expected, self.fixture.policy)['publication_allowed'])

    def test_shared_files_are_not_accepted_even_with_matching_report(self):
        expected = self.bundle(shared=True)
        self.assertFalse(gate.inspect(self.fixture.root, expected, self.fixture.policy)['publication_allowed'])

    def test_forged_audit_summary_is_not_accepted(self):
        expected = self.bundle()
        self.fixture.manifest['platforms']['linux']['cef']['consumer']['target_archive_audit']['report_sha256'] = '0'*64
        expected = self.fixture.resign()
        self.assertFalse(gate.inspect(self.fixture.root, expected, self.fixture.policy)['publication_allowed'])

    def test_legacy_release_does_not_require_archive_parser(self):
        expected, _ = self.fixture.bundle(cef=False)
        with patch.object(static_audit, 'inspect_sdk', side_effect=AssertionError('must not inspect non-CEF release')):
            self.assertTrue(gate.inspect(self.fixture.root, expected, self.fixture.policy)['publication_allowed'])


if __name__ == '__main__':
    unittest.main()
