"""Native compiler plus synthetic binary regressions; no CEF execution claim."""
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_release import static_audit as audit


def ar_record(data, name):
    if len(name) > 16:
        raise ValueError('ar member name must use a long-name table')
    fields = (name.ljust(16), b'0'.ljust(12), b'0'.ljust(6), b'0'.ljust(6),
              b'100644'.ljust(8), str(len(data)).encode().ljust(10), b'`\n')
    return b''.join(fields) + data + (b'\n' if len(data) & 1 else b'')


def ar(data, name=b'object.o/'):
    if len(name) <= 16:
        return b'!<arch>\n' + ar_record(data, name)
    longname = name if name.endswith(b'/') else name + b'/'
    table = longname + b'\n'
    return b'!<arch>\n' + ar_record(table, b'//') + ar_record(data, b'/0')


def elf(kind=1):
    return b'\x7fELF\x02\x01\x01' + b'\0' * 9 + struct.pack('<HHI', kind, 62, 1) + b'\0' * 40


def coff(section=b'.text', big=False):
    if big:
        header = struct.pack('<HHHHI', 0, 0xffff, 2, 0x8664, 0) + audit.BIGOBJ_CLASS + b'\0'*16 + struct.pack('<III', 1, 0, 0)
    else:
        header = struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 0, 0)
    return header + section.ljust(8, b'\0') + b'\0' * 32


class AuditTests(unittest.TestCase):
    def test_native_linux_archive_and_shared_detection(self):
        if sys.platform != 'linux' or not shutil.which('cc') or not shutil.which('ar'):
            self.skipTest('native Linux compiler/ar unavailable')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / 'a.c'
            source.write_text('int example(void) { return 7; }\n')
            subprocess.run(['cc', '-c', '-fPIC', str(source), '-o', str(root/'a.o')], check=True)
            subprocess.run(['ar', 'rcs', str(root/'a.a'), str(root/'a.o')], check=True)
            subprocess.run(['cc', '-shared', str(root/'a.o'), '-o', str(root/'a.so')], check=True)
            with (root/'a.a').open('rb') as f:
                self.assertTrue(audit.inspect_archive(f, (root/'a.a').stat().st_size, 'linux')['qualified_objects_only'])
            data = ar((root/'a.so').read_bytes())
            result = audit.inspect_archive(io.BytesIO(data), len(data), 'linux')
            self.assertFalse(result['qualified_objects_only'])
            self.assertEqual(result['kinds'], {'elf-image': 1})

    def test_native_windows_static_and_import_libraries(self):
        if sys.platform != 'win32':
            self.skipTest('native Windows host required')
        if not all(shutil.which(tool) for tool in ('cl', 'lib', 'link')):
            if os.environ.get('REQUIRE_NATIVE_ARCHIVE_AUDIT') == '1':
                self.fail('MSVC toolchain was not activated for archive audit')
            self.skipTest('MSVC environment not activated')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'a.c').write_text('__declspec(dllexport) int example(void) { return 7; }\n')
            for command in (['cl', '/nologo', '/c', '/MT', 'a.c'],
                            ['lib', '/nologo', '/out:a.lib', 'a.obj'],
                            ['link', '/nologo', '/dll', '/noentry', '/out:a.dll', '/implib:a-import.lib', 'a.obj']):
                subprocess.run(command, cwd=root, check=True, capture_output=True, timeout=60)
            for name, expected in (('a.lib', True), ('a-import.lib', False)):
                path = root/name
                with path.open('rb') as stream:
                    self.assertEqual(audit.inspect_archive(stream, path.stat().st_size, 'windows')['qualified_objects_only'], expected)

    def test_empty_archive_cannot_qualify_sdk(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sdk.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('installed/x64-linux-static-release/lib/empty.a', b'!<arch>\n')
            report = audit.inspect_sdk(path, 'linux')
            self.assertFalse(report['target_archives_static'])
            self.assertEqual(audit.summarize(report)['violation_count'], 1)

    def test_coff_long_section_names_are_inspected(self):
        section_name = b'.idata$123456789\0'
        symbols = 60
        header = struct.pack('<HHIIIHH', 0x8664, 1, 0, symbols, 0, 0, 0)
        data = header + b'/4\0\0\0\0\0\0' + b'\0'*32 + struct.pack('<I', 4+len(section_name)) + section_name
        self.assertEqual(audit.object_kind(data, 'a.obj', 'windows'), 'coff-import')

    def test_short_import_lib_is_not_static(self):
        data = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0, 9, 0, 4) + b'a\0bad.dll\0'
        self.assertEqual(audit.object_kind(data, 'a.obj', 'windows'), 'coff-import')

    def test_cef_generated_archive_allows_only_reviewed_windows_os_short_imports(self):
        def short(dll):
            body = b'symbol\0' + dll.encode('ascii') + b'\0'
            return struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0,
                               len(body), 0, 4) + body
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prefix = 'installed/x64-windows-static-release/'
            for dll, expected in (('kernel32.dll', True), ('api-ms-win-core-file-l1-1-0.dll', True),
                                  ('third-party.dll', False)):
                path = root / (dll.replace('.', '-') + '.zip')
                with zipfile.ZipFile(path, 'w') as z:
                    payload = ar(coff(), b'native.obj/') + ar(short(dll), b'import.obj/')[8:]
                    z.writestr(prefix+'lib/cef-static/cef_2181_7aff207fa4d8.lib', payload)
                report = audit.inspect_sdk(path, 'windows')
                self.assertEqual(report['target_archives_static'], expected, dll)
                archive = report['archives'][0]
                if expected:
                    self.assertEqual(archive['system_imports'], {dll: 1})
                    self.assertEqual(archive['kinds'], {'coff-os-import': 1})
                else:
                    self.assertEqual(archive['unqualified_samples'][0]['dll'], dll)

    def test_ordinary_import_library_stays_forbidden_even_for_system_dll(self):
        body = b'symbol\0kernel32.dll\0'
        member = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0,
                             len(body), 0, 4) + body
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'sdk.zip'
            prefix = 'installed/x64-windows-static-release/'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr(prefix+'lib/kernel32.lib', ar(member, b'import.obj/'))
            report = audit.inspect_sdk(path, 'windows')
            self.assertFalse(report['target_archives_static'])
            self.assertEqual(report['violations'][0]['reason'], 'unqualified-archive-members')

    def test_named_long_idata_member_can_prove_reviewed_os_import(self):
        payload = coff(b'.idata$2')
        data = ar(payload, b'bcryptprimitives.dll/')
        result = audit.inspect_archive(
            io.BytesIO(data), len(data), 'windows',
            allow_windows_os_imports=True)
        self.assertTrue(result['qualified_objects_only'])
        self.assertEqual(result['kinds'], {'coff-os-import': 1})
        self.assertEqual(result['system_imports'], {'bcryptprimitives.dll': 1})

    def test_long_idata_import_never_inherits_short_os_allowance(self):
        payload = coff(b'.idata$2')
        data = ar(payload)
        result = audit.inspect_archive(
            io.BytesIO(data), len(data), 'windows',
            allow_windows_os_imports=True)
        self.assertFalse(result['qualified_objects_only'])
        self.assertEqual(result['kinds'], {'coff-import': 1})

    def test_long_import_and_bigobj(self):
        for big in (False, True):
            self.assertEqual(audit.object_kind(coff(big=big), 'a.obj', 'windows'), 'coff-object')
            self.assertEqual(audit.object_kind(coff(b'.idata$2', big), 'a.obj', 'windows'), 'coff-import')

    def test_wrong_bigobj_guid_and_truncated_tables(self):
        for payload in (coff(big=True)[:20], coff()[:25], coff(big=True)[:12] + b'X'*16 + coff(big=True)[28:]):
            with self.assertRaises(ValueError):
                audit.object_kind(payload, 'a.obj', 'windows')

    def test_elf_image_and_wrong_platform(self):
        self.assertEqual(audit.object_kind(elf(3), 'a.o', 'linux'), 'elf-image')
        with self.assertRaises(ValueError):
            audit.object_kind(elf(), 'a.obj', 'windows')

    def test_thin_and_truncated_archive(self):
        for data in (b'!<thin>\n', ar(elf())[:-1], b'!<arch>\n'+b'x'*60):
            with self.assertRaises(ValueError):
                audit.inspect_archive(io.BytesIO(data), len(data), 'linux')

    def test_bsd_long_member_names(self):
        name = b'long/object.o'
        data = ar(name + elf(), b'#1/' + str(len(name)).encode())
        self.assertTrue(audit.inspect_archive(io.BytesIO(data), len(data), 'linux')['qualified_objects_only'])

    def test_bitcode_not_silently_qualified(self):
        data = ar(b'BC\xc0\xdeanything')
        self.assertFalse(audit.inspect_archive(io.BytesIO(data), len(data), 'linux')['qualified_objects_only'])

    def test_sdk_scope_and_versioned_so(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sdk.zip'
            prefix = 'installed/x64-linux-static-release/'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr(prefix+'lib/a.a', ar(elf()))
                z.writestr(prefix+'tools/compiler/helper.so', b'not a target library')
            result = audit.inspect_sdk(path, 'linux')
            self.assertTrue(result['target_archives_static'])
            self.assertFalse(result['runtime_dependencies_verified'])
            with zipfile.ZipFile(path, 'a') as z:
                z.writestr(prefix+'lib/b.so.1.2', elf(3))
            self.assertFalse(audit.inspect_sdk(path, 'linux')['target_archives_static'])

    def test_renamed_pe_and_import_archive(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sdk.zip'
            prefix = 'installed/x64-windows-static-release/'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr(prefix+'lib/a.lib', ar(coff()))
                z.writestr(prefix+'lib/b.lib', ar(coff(b'.idata$2')))
                z.writestr(prefix+'lib/renamed.data', b'MZbinary')
            result = audit.inspect_sdk(path, 'windows')
            self.assertEqual(len(result['violations']), 2)

    def test_zip_case_alias_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sdk.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('installed/x64-linux-static-release/lib/a.a', ar(elf()))
                z.writestr('installed/x64-linux-static-release/LIB/b.a', ar(elf()))
            with self.assertRaises(ValueError):
                audit.inspect_sdk(path, 'linux')

    def test_empty_sdk_is_not_static_proof(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'sdk.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('README', 'empty')
            with self.assertRaises(ValueError):
                audit.inspect_sdk(path, 'linux')


if __name__ == '__main__':
    unittest.main()
