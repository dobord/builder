"""Public-only regressions for the source-preservation and process policies."""
import contextlib
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from secure_release import build_support, process


class BuildPolicyTests(unittest.TestCase):
    def test_downloads_preserved(self):
        command = build_support.install_command('vcpkg', ['fixture'], [])
        self.assertNotIn('--clean-after-build', command)
        self.assertNotIn('--clean-downloads-after-build', command)
        self.assertIn('--clean-buildtrees-after-build', command)
        self.assertIn('--clean-packages-after-build', command)

    def test_unsafe_options_rejected(self):
        for option in ('--clean-after-build', '--clean-downloads-after-build', '--head'):
            with self.subTest(option=option), self.assertRaises(ValueError):
                build_support.install_command('vcpkg', ['fixture'], [option])

    def test_noninteractive_environment(self):
        environment = build_support.build_environment({}, Path('/downloads'), Path('/upstream'))
        self.assertEqual(environment['GCM_INTERACTIVE'], 'never')
        self.assertEqual(environment['GIT_TERMINAL_PROMPT'], '0')
        self.assertEqual(environment['VCPKG_BINARY_SOURCES'], 'clear')

    @unittest.skipUnless(shutil.which('cmake'), 'CMake is unavailable')
    def test_cmake_source_guard_present_missing_and_modified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            port = root / 'ports/fixture'
            port.mkdir(parents=True)
            downloads = root / 'downloads'
            downloads.mkdir()
            archive = downloads / ('fixture-' + 'a' * 40 + '.tar.gz')
            archive.write_bytes(b'authenticated synthetic archive')
            marker = root / 'executed'
            (port / 'portfile.cmake').write_text(f'file(WRITE "{marker.as_posix()}" "synthetic")\n')
            build_support.protect_source_archives(root, downloads, [{'name': 'fixture', 'sha': 'a' * 40}])
            cmd = ['cmake', '-DDOWNLOADS=' + downloads.as_posix(), '-P', str(port / 'portfile.cmake')]
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            self.assertTrue(marker.exists())
            marker.unlink()
            archive.unlink()
            missing = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn(b'RELEASE_SOURCE_ARCHIVE_MISSING', missing.stderr)
            self.assertFalse(marker.exists())
            archive.write_bytes(b'tampered')
            modified = subprocess.run(cmd, capture_output=True)
            self.assertNotEqual(modified.returncode, 0)
            self.assertIn(b'RELEASE_SOURCE_ARCHIVE_MISMATCH', modified.stderr)
            self.assertFalse(marker.exists())


class ProcessTests(unittest.TestCase):
    def test_output_is_private_and_stdin_is_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / 'build.log'
            public = io.StringIO()
            code = "import sys; print('SYNTHETIC_PRIVATE_TEXT'); assert sys.stdin.read() == ''"
            with contextlib.redirect_stdout(public):
                process.run([sys.executable, '-c', code], log, environment=dict(os.environ), timeout=10,
                            stage='preflight', public_progress=True)
            self.assertNotIn('SYNTHETIC_PRIVATE_TEXT', public.getvalue())
            self.assertIn('SYNTHETIC_PRIVATE_TEXT', log.read_text())

    def test_exit_has_fixed_error(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(process.StageFailure) as caught:
                process.run([sys.executable, '-c', 'raise SystemExit(7)'], Path(temp) / 'log',
                            environment=dict(os.environ), timeout=10, stage='install')
            self.assertEqual(caught.exception.code, 7)
            self.assertEqual(caught.exception.stage, 'install')

    def test_timeout_terminates_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / 'descendant-alive'
            child = "import time,pathlib; time.sleep(3); pathlib.Path(" + repr(str(marker)) + ").write_text('alive')"
            parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," + repr(child) + "]); time.sleep(60)"
            with self.assertRaises(process.StageFailure) as caught:
                process.run([sys.executable, '-c', parent], root / 'log', environment=dict(os.environ),
                            timeout=1, heartbeat=0.2, stage='tool')
            self.assertEqual(caught.exception.kind, 'timeout')
            time.sleep(3.2)
            self.assertFalse(marker.exists(), 'grandchild survived process-tree termination')

    def test_remove_readonly_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'tree'
            root.mkdir()
            file = root / 'readonly'
            file.write_text('synthetic')
            file.chmod(stat.S_IREAD)
            process.remove_tree(root)
            self.assertFalse(root.exists())

    @unittest.skipIf(os.name == 'nt', 'symlink privilege is not assumed on Windows')
    def test_refuses_linked_cleanup_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'real').mkdir()
            (root / 'link').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(ValueError):
                process.remove_tree(root / 'link')
            self.assertTrue((root / 'real').exists())


if __name__ == '__main__':
    unittest.main()
