"""Native host-tool Release policy; no network, credentials or project sources."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from secure_release import build_support as policy


class NativeHostTripletTests(unittest.TestCase):
    def test_native_platform_mapping(self):
        for system, machine, expected in (
            ('Linux', 'x86_64', 'x64-linux-static-release'),
            ('Windows', 'AMD64', 'x64-windows-static-release'),
        ):
            with self.subTest(system=system), patch.object(policy.platform, 'system', return_value=system), patch.object(policy.platform, 'machine', return_value=machine):
                self.assertEqual(policy.native_host_triplet(), expected)

    def test_unsupported_native_platform_rejected(self):
        for system, machine in [('Darwin', 'x86_64'), ('Linux', 'aarch64'), ('Windows', 'ARM64')]:
            with self.subTest(system=system, machine=machine), patch.object(policy.platform, 'system', return_value=system), patch.object(policy.platform, 'machine', return_value=machine):
                with self.assertRaises(ValueError):
                    policy.native_host_triplet()

    def test_install_pins_both_roles_on_each_platform(self):
        for triplet in sorted(policy.RELEASE_TRIPLETS):
            with self.subTest(triplet=triplet), patch.object(policy, 'native_host_triplet', return_value=triplet):
                options = ['--triplet=' + triplet, '--overlay-triplets=/synthetic']
                before = list(options)
                command = policy.install_command('vcpkg', ['fixture[core,extra]'], options)
                self.assertEqual(command.count('--triplet=' + triplet), 1)
                self.assertEqual(command.count('--host-triplet=' + triplet), 1)
                self.assertEqual(options, before)
                self.assertIn('--clean-buildtrees-after-build', command)
                self.assertNotIn('--clean-after-build', command)

    def test_defaults_are_explicit_release_not_inherited(self):
        target = policy.native_host_triplet()
        with patch.dict(os.environ, {'VCPKG_DEFAULT_HOST_TRIPLET': 'unreviewed-default'}):
            options = policy.native_release_options([])
            self.assertEqual(options, ['--triplet=' + target, '--host-triplet=' + target])
            environment = policy.build_environment({'VCPKG_DEFAULT_HOST_TRIPLET': 'unreviewed-default'}, Path('/downloads'), Path('/upstream'))
            self.assertEqual(environment['VCPKG_DEFAULT_HOST_TRIPLET'], target)

    def test_matching_options_are_idempotent(self):
        target = policy.native_host_triplet()
        options = ['--triplet=' + target, '--host-triplet=' + target]
        self.assertEqual(policy.native_release_options(options), options)

    def test_mismatched_or_ambiguous_roles_rejected(self):
        target = policy.native_host_triplet()
        for options in (
            ['--triplet=' + target, '--host-triplet=x64-linux'],
            ['--triplet=' + target, '--host-triplet=x64-windows'],
            ['--triplet=' + target, '--host-triplet='],
            ['--triplet=' + target, '--host-triplet'],
            ['--triplet', target],
            ['--triplet='],
            ['--triplet=arm64-linux'],
            ['--triplet=' + target, '--triplet=' + target],
            ['--triplet=' + target, '--host-triplet=' + target, '--host-triplet=' + target],
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                policy.native_release_options(options)

    def test_cross_platform_target_rejected(self):
        with patch.object(policy, 'native_host_triplet', return_value='x64-linux-static-release'):
            with self.assertRaises(ValueError):
                policy.native_release_options(['--triplet=x64-windows-static-release'])

    def test_cmake_consumer_pins_both_roles(self):
        for triplet in sorted(policy.RELEASE_TRIPLETS):
            with self.subTest(triplet=triplet), patch.object(policy, 'native_host_triplet', return_value=triplet):
                sdk = Path('SDK with spaces')
                command = policy.consumer_configure_command(Path('source'), Path('build'), sdk, triplet)
                self.assertEqual(command.count('-DVCPKG_TARGET_TRIPLET=' + triplet), 1)
                self.assertEqual(command.count('-DVCPKG_HOST_TRIPLET=' + triplet), 1)
                self.assertIn('-DCMAKE_TOOLCHAIN_FILE=' + str(sdk / 'scripts/buildsystems/vcpkg.cmake'), command)
                self.assertIn('-DVCPKG_MANIFEST_MODE=OFF', command)
                self.assertIn('-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded', command)

    def test_cmake_consumer_refuses_non_native_triplet(self):
        with patch.object(policy, 'native_host_triplet', return_value='x64-linux-static-release'):
            with self.assertRaises(ValueError):
                policy.consumer_configure_command(Path('s'), Path('b'), Path('sdk'), 'x64-windows-static-release')

    def test_package_cannot_override_triplet_policy(self):
        for package in ['--host-triplet=x64-linux', '@options.rsp', 'fixture:x64-linux']:
            with self.subTest(package=package), self.assertRaises(ValueError):
                policy.install_command('vcpkg', [package], [])


if __name__ == '__main__':
    unittest.main()
