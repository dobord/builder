"""Pure source-validation tests; never start mstsc, QEMU or project binaries."""
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).parent
API = runpy.run_path(str(ROOT / 'native-arm-platform.py'))
VERIFY = API['verified_fixture']
CANONICAL = (ROOT / 'native.py').read_bytes().replace(b'\r\n', b'\n')


class FixtureGuardTests(unittest.TestCase):
    def test_reviewed_lf(self):
        text, info = VERIFY(CANONICAL)
        self.assertEqual(text.encode(), CANONICAL)
        self.assertEqual(info['canonical_blob'], API['EXPECTED_FIXTURE'])
        self.assertFalse(info['normalized_crlf'])

    def test_windows_checkout_crlf(self):
        text, info = VERIFY(CANONICAL.replace(b'\n', b'\r\n'))
        self.assertEqual(text.encode(), CANONICAL)
        self.assertTrue(info['normalized_crlf'])
        self.assertNotEqual(info['checkout_blob'], info['canonical_blob'])

    def test_source_change_rejected_even_with_crlf(self):
        for data in (CANONICAL + b'# unreviewed\n', CANONICAL.replace(b'\n', b'\r\n') + b'# unreviewed\r\n'):
            with self.subTest(size=len(data)), self.assertRaises(RuntimeError):
                VERIFY(data)

    def test_lone_carriage_return_rejected(self):
        with self.assertRaises(RuntimeError):
            VERIFY(CANONICAL.replace(b'\n', b'\r', 1))

    def test_whitespace_changes_rejected(self):
        with self.assertRaises(RuntimeError):
            VERIFY(b' ' + CANONICAL)

    def test_truncation_rejected(self):
        with self.assertRaises(RuntimeError):
            VERIFY(CANONICAL[:-1])


if __name__ == '__main__':
    unittest.main()
