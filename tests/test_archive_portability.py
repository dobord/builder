"""Regression tests use synthetic names and files only, on both hosted OSes."""
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile
from secure_release import safeio


class ArchivePortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def zip_named(self, names):
        path = self.root / 'sample.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name in names:
                archive.writestr(name, b'' if name.endswith('/') else b'synthetic')
        return path

    def test_zip_parent_case_alias(self):
        with self.assertRaises(ValueError):
            safeio.zip_files(self.zip_named(['Include/a.h', 'include/b.h']))

    def test_zip_file_as_parent(self):
        with self.assertRaises(ValueError):
            safeio.zip_files(self.zip_named(['include', 'include/a.h']))

    def test_zip_parent_as_file(self):
        with self.assertRaises(ValueError):
            safeio.zip_files(self.zip_named(['include/a.h', 'include']))

    def test_zip_directory_file_alias(self):
        with self.assertRaises(ValueError):
            safeio.zip_files(self.zip_named(['include/', 'include']))

    def test_zip_implicit_then_explicit_directory_allowed(self):
        path = self.zip_named(['include/a.h', 'include/', 'include/b.h'])
        safeio.extract_zip(path, self.root / 'out')
        self.assertEqual((self.root / 'out/include/a.h').read_bytes(), b'synthetic')

    def test_zip_special_types(self):
        for kind in (stat.S_IFSOCK, stat.S_IFIFO, stat.S_IFBLK, stat.S_IFCHR, stat.S_IFLNK):
            with self.subTest(kind=kind):
                path = self.root / 'special.zip'
                with zipfile.ZipFile(path, 'w') as archive:
                    entry = zipfile.ZipInfo('special')
                    entry.create_system = 3
                    entry.external_attr = (kind | 0o600) << 16
                    archive.writestr(entry, b'synthetic')
                with self.assertRaises(ValueError):
                    safeio.zip_files(path)

    def test_zip_reparse_attribute(self):
        path = self.root / 'reparse.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            entry = zipfile.ZipInfo('reparse')
            entry.external_attr = ((stat.S_IFREG | 0o600) << 16) | 0x400
            archive.writestr(entry, b'synthetic')
        with self.assertRaises(ValueError):
            safeio.zip_files(path)

    def test_tar_parent_case_alias(self):
        path = self.root / 'case.tar'
        with tarfile.open(path, 'w') as archive:
            for name in ('Include/a.h', 'include/b.h'):
                entry = tarfile.TarInfo(name)
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b'x'))
        with self.assertRaises(ValueError):
            safeio.extract_tar(path, self.root / 'out')

    def test_path_bounds(self):
        for path in ('a' * (safeio.MAX_PATH + 1), '/'.join(['a'] * (safeio.MAX_DEPTH + 1))):
            with self.subTest(path=path[:20]), self.assertRaises(ValueError):
                safeio.parts(path)

    def test_windows_forbidden_characters(self):
        for name in ('a*b', 'a?b', 'a|b', 'a<b', 'a>b', 'a"b', 'a\x7fb'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safeio.parts(name)

    def test_pack_and_extract_nested_files(self):
        source = self.root / 'source'
        (source / 'include').mkdir(parents=True)
        (source / 'include/a.hpp').write_text('// synthetic\n')
        (source / 'include/b.hpp').write_text('// synthetic\n')
        safeio.pack_tar(source, self.root / 'source.tgz')
        safeio.extract_tar(self.root / 'source.tgz', self.root / 'out')
        self.assertEqual((self.root / 'out/include/b.hpp').read_text(), '// synthetic\n')

    def test_directory_symlink_not_silently_skipped(self):
        source = self.root / 'source'
        source.mkdir()
        outside = self.root / 'outside'
        outside.mkdir()
        try:
            (source / 'link').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('creating a symlink requires privileges on this OS')
        with self.assertRaises(ValueError):
            safeio.pack_tar(source, self.root / 'source.tgz')


if __name__ == '__main__':
    unittest.main()
