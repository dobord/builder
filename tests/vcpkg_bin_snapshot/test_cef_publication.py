"""Synthetic SDK metadata. No SDK binary, source, credentials or network needed."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cef_publication as gate

class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = {'schema': 1, 'required_profile': 'static-third-party', 'admitted_contracts': {'linux': [], 'windows': []}}

    def bundle(self, cef=True, profile='engine-static', missing=False):
        manifest = {'source_tag': 'v1.2.3', 'platforms': {}}
        keys, files = {}, {}
        for platform in ('linux', 'windows'):
            triplet = f'x64-{platform}-static-release'
            name = f'vcpkg-v1.2.3-{platform}-x64-static-release.zip'
            data = {'triplet': triplet, 'platform': platform}
            present = cef and not (missing and platform == 'windows')
            with zipfile.ZipFile(self.root / name, 'w') as archive:
                archive.writestr(f'installed/{triplet}/include/example.h', '/* fixture */')
                if present:
                    contract = {'schema': 1, 'profile': profile, 'triplet': triplet,
                                'platform_sha256': None}
                    consumer = {'kind': 'consumer-verification', 'engine_linkage': 'static', 'capi_only': True}
                    if profile == 'static-third-party':
                        closure = {'kind': 'windows-native-os-abi', 'manifest_sha256': None}
                        if platform == 'linux':
                            payload = b'!<arch>\nfixture-static-archive'
                            relative = 'lib/libfixture.a'
                            archive.writestr(f'installed/{triplet}/{relative}', payload)
                            build_inputs = gate.canonical({'schema': 1, 'fixture': 'frozen-platform-inputs'})
                            manifest_sha256 = hashlib.sha256(build_inputs).hexdigest()
                            contract['platform_sha256'] = manifest_sha256
                            archive.writestr(f'installed/{triplet}/share/cef-static/platform-build-inputs.json',
                                             build_inputs)
                            inventory = {'schema': 1, 'kind': 'external-vcpkg-archives',
                                         'manifest_sha256': manifest_sha256,
                                         'archives': [{'path': relative, 'size': len(payload),
                                                       'sha256': hashlib.sha256(payload).hexdigest()}],
                                         'runtime_verified': False}
                            inventory_bytes = gate.canonical(inventory)
                            archive.writestr(f'installed/{triplet}/share/cef-static/static-platform-inventory.json',
                                             inventory_bytes)
                            preflight = {'schema': 1, 'kind': 'cef-static-platform-preflight',
                                         'status': 'success', 'full_platform_graph_qualified': True,
                                         'cef_runtime_verified': False, 'gpu_runtime_qualified': False,
                                         'module_count': 36, 'manifest_sha256': manifest_sha256}
                            qualification_sha256 = hashlib.sha256(gate.canonical(preflight) + b'\n').hexdigest()
                            closure = {'kind': 'linux-frozen-vcpkg',
                                       'manifest_sha256': manifest_sha256,
                                       'inventory_sha256': hashlib.sha256(inventory_bytes).hexdigest(),
                                       'qualification_sha256': qualification_sha256,
                                       'full_platform_graph_qualified': True,
                                       'archive_count': 1}
                        consumer.update(
                            third_party_libraries_static=True,
                            smoke={'third_party_modules_static': True, 'browser_modules_clean': True,
                                   'renderer_modules_clean': True},
                            target_archive_audit={'kind': 'target-archive-audit-summary',
                                                  'target_archives_static': True, 'violation_count': 0},
                            platform_closure=closure)
                    keys[platform] = hashlib.sha256(gate.canonical(contract)).hexdigest()
                    archive.writestr(f'installed/{triplet}/share/cef-static/build-contract.json',
                                     gate.canonical(contract))
                    data['cef'] = {'profile': profile, 'build_contract_sha256': keys[platform],
                                   'consumer': consumer}
                    if profile == 'static-third-party' and platform == 'linux':
                        data['cef']['platform_preflight'] = preflight
            data['sdk_sha256'] = files[name] = gate.digest(self.root / name)
            manifest['platforms'][platform] = data
        self.manifest = manifest
        (self.root / 'release-manifest.json').write_bytes(gate.canonical(manifest))
        files['release-manifest.json'] = gate.digest(self.root / 'release-manifest.json')
        self.files = files
        return self.resign(), keys

    def resign(self):
        (self.root / 'release-manifest.json').write_bytes(gate.canonical(self.manifest))
        self.files['release-manifest.json'] = gate.digest(self.root / 'release-manifest.json')
        (self.root / 'SHA256SUMS').write_text(''.join(f'{sha}  {name}\n' for name, sha in sorted(self.files.items())))
        return gate.digest(self.root / 'SHA256SUMS')

    def test_legacy_non_cef_release_is_unchanged(self):
        expected, _ = self.bundle(cef=False)
        report = gate.inspect(self.root, expected, self.policy)
        self.assertTrue(report['publication_allowed'])
        self.assertFalse(report['cef_present'])

    def test_engine_static_remains_inspectable_but_not_publishable(self):
        expected, _ = self.bundle()
        report = gate.inspect(self.root, expected, self.policy)
        self.assertFalse(report['publication_allowed'])
        self.assertEqual(len(report['reasons']), 4)
        self.assertFalse(report['sdk_code_executed'])

    def test_profile_string_is_not_a_qualification(self):
        expected, _ = self.bundle(profile='static-third-party')
        self.assertFalse(gate.inspect(self.root, expected, self.policy)['publication_allowed'])

    def test_strict_profile_without_native_closure_proof_is_rejected(self):
        expected, _ = self.bundle(profile='static-third-party')
        self.manifest['platforms']['linux']['cef']['consumer']['third_party_libraries_static'] = False
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_only_exact_reviewed_contracts_are_admitted(self):
        expected, keys = self.bundle(profile='static-third-party')
        for platform, key in keys.items():
            self.policy['admitted_contracts'][platform] = [key]
        self.assertTrue(gate.inspect(self.root, expected, self.policy)['publication_allowed'])

    def test_strict_build_input_manifest_is_rechecked(self):
        expected, keys = self.bundle(profile='static-third-party')
        for platform, key in keys.items():
            self.policy['admitted_contracts'][platform] = [key]
        path = self.root / 'vcpkg-v1.2.3-linux-x64-static-release.zip'
        rewritten = self.root / 'tampered-manifest.zip'
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(rewritten, 'w') as target:
            for entry in source.infolist():
                data = source.read(entry)
                if entry.filename.endswith('/share/cef-static/platform-build-inputs.json'):
                    data += b'tamper'
                target.writestr(entry, data)
        rewritten.replace(path)
        self.files[path.name] = gate.digest(path)
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_strict_inventory_bytes_are_rechecked(self):
        expected, keys = self.bundle(profile='static-third-party')
        for platform, key in keys.items():
            self.policy['admitted_contracts'][platform] = [key]
        path = self.root / 'vcpkg-v1.2.3-linux-x64-static-release.zip'
        rewritten = self.root / 'tampered.zip'
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(rewritten, 'w') as target:
            for entry in source.infolist():
                data = source.read(entry)
                if entry.filename.endswith('/lib/libfixture.a'):
                    data += b'tamper'
                target.writestr(entry, data)
        rewritten.replace(path)
        self.files[path.name] = gate.digest(path)
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_strict_full_platform_preflight_is_required(self):
        expected, keys = self.bundle(profile='static-third-party')
        for platform, key in keys.items():
            self.policy['admitted_contracts'][platform] = [key]
        self.manifest['platforms']['linux']['cef']['consumer']['platform_closure']['full_platform_graph_qualified'] = False
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_strict_embedded_preflight_hash_is_rechecked(self):
        expected, keys = self.bundle(profile='static-third-party')
        for platform, key in keys.items():
            self.policy['admitted_contracts'][platform] = [key]
        self.manifest['platforms']['linux']['cef']['platform_preflight']['module_count'] = 35
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_strict_contract_platform_digest_is_rechecked(self):
        expected, keys = self.bundle(profile='static-third-party')
        for platform, key in keys.items():
            self.policy['admitted_contracts'][platform] = [key]
        self.manifest['platforms']['linux']['cef']['consumer']['platform_closure']['manifest_sha256'] = 'f' * 64
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_file_mutation_is_rejected(self):
        expected, _ = self.bundle()
        path = self.root / 'vcpkg-v1.2.3-linux-x64-static-release.zip'
        with path.open('ab') as stream:
            stream.write(b'tamper')
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_one_sided_pair_rejected(self):
        expected, _ = self.bundle(missing=True)
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_missing_evidence_cannot_bypass_policy(self):
        expected, _ = self.bundle()
        del self.manifest['platforms']['linux']['cef']
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_contract_substitution_rejected(self):
        expected, _ = self.bundle()
        self.manifest['platforms']['linux']['cef']['build_contract_sha256'] = '0' * 64
        expected = self.resign()
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_unexpected_staging_file_rejected(self):
        expected, _ = self.bundle()
        (self.root / 'execute.py').write_text('raise RuntimeError()')
        with self.assertRaises(ValueError):
            gate.inspect(self.root, expected, self.policy)

    def test_duplicate_json_field_rejected(self):
        with self.assertRaises(ValueError):
            gate.decode(b'{"schema":1,"schema":2}')

if __name__ == '__main__':
    unittest.main()
