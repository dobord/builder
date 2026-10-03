"""ZIP regression for real vcpkg export epoch timestamps, with no private input."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from secure_release import safeio


class SdkMetadataTests(unittest.TestCase):
    def test_epoch_mtime_is_supported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root / 'sdk'; sdk.mkdir()
            header = sdk / 'fixture.hpp'; header.write_bytes(b'// public synthetic header\n')
            os.utime(header, (0, 0))
            safeio.sdk_zip(sdk, root / 'sdk.zip')
            with zipfile.ZipFile(root / 'sdk.zip') as z:
                self.assertEqual(z.getinfo('fixture.hpp').date_time, (1980, 1, 1, 0, 0, 0))
                self.assertEqual(z.read('fixture.hpp'), header.read_bytes())
                self.assertIsNone(z.testzip())

    def test_host_mtime_does_not_change_zip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); sdk = root / 'sdk'; sdk.mkdir()
            f = sdk / 'license.txt'; f.write_bytes(b'public synthetic license')
            os.utime(f, (0, 0)); safeio.sdk_zip(sdk, root / 'a.zip')
            os.utime(f, (1789600000, 1789600000)); safeio.sdk_zip(sdk, root / 'b.zip')
            self.assertEqual((root / 'a.zip').read_bytes(), (root / 'b.zip').read_bytes())

    @unittest.skipIf(os.name == 'nt', 'POSIX executable permission contract')
    def test_executable_mode_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); sdk = root / 'sdk'; sdk.mkdir()
            f = sdk / 'tool'; f.write_bytes(b'synthetic'); f.chmod(0o755)
            safeio.sdk_zip(sdk, root / 'a.zip')
            safeio.extract_zip(root / 'a.zip', root / 'out')
            self.assertEqual(stat.S_IMODE((root / 'out/tool').stat().st_mode), 0o755)

    def test_shared_target_payload_is_rejected_but_host_tools_are_not(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root / 'sdk'
            target_bin = sdk / 'installed/x64-windows-static-release/bin'
            target_bin.mkdir(parents=True)
            (target_bin / 'forbidden.dll').write_bytes(b'MZsynthetic')
            with self.assertRaisesRegex(ValueError, 'shared target payload'):
                safeio.sdk_zip(sdk, root / 'bad.zip')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root / 'sdk'
            tools = sdk / 'installed/x64-windows-static-release/tools/example'
            tools.mkdir(parents=True)
            (tools / 'host-helper.dll').write_bytes(b'MZsynthetic')
            safeio.sdk_zip(sdk, root / 'ok.zip')

    def test_versioned_linux_shared_target_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root / 'sdk'
            lib = sdk / 'installed/x64-linux-static-release/lib'
            lib.mkdir(parents=True)
            (lib / 'libforbidden.so.1').write_bytes(b'ELFsynthetic')
            with self.assertRaisesRegex(ValueError, 'shared target payload'):
                safeio.sdk_zip(sdk, root / 'bad.zip')

    def test_implementation_source_still_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); sdk = root / 'sdk'; sdk.mkdir()
            (sdk / 'not-an-sdk.cpp').write_text('int synthetic;')
            with self.assertRaises(ValueError):
                safeio.sdk_zip(sdk, root / 'a.zip')


if __name__ == '__main__':
    unittest.main()
