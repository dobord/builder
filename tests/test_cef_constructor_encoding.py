"""Unknown input relocation encodings must never look like missing records."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from secure_release import cef_constructor_inputs as subject


class BudgetTests(unittest.TestCase):
    def test_archive_limit_precedes_hashing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            archive = root/'cef_0001_012345abcdef.a'
            with archive.open('wb') as stream:
                stream.write(b'!<arch>\n')
                stream.truncate(1024**3+1)
            slot = {'kind':'inside-input', 'input':{'owner':str(archive)+'(ctor.o)'}}
            with mock.patch.object(subject.hashlib, 'file_digest', side_effect=AssertionError('hash must not run')):
                with self.assertRaisesRegex(ValueError, 'size outside bounds'):
                    subject.inspect_inputs(root,[slot])


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc') and shutil.which('ar'), 'native Linux ELF tools')
class EncodingTests(unittest.TestCase):
    def test_unknown_relocation_format_is_not_called_missing(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, obj, archive = root/'ctor.s', root/'ctor.o', root/'cef_objects.a'
            source.write_text('''
.weak missing_constructor
.hidden missing_constructor
.section .init_array,"aw",@init_array
.p2align 3
.quad missing_constructor
''')
            subprocess.run(['gcc','-c',str(source),'-o',str(obj)],check=True,capture_output=True)
            raw = bytearray(obj.read_bytes())
            h = subject.HEADER.unpack_from(raw)
            changed = 0
            for i in range(h[12]):
                offset = h[6]+i*subject.SECTION.size
                section = subject.SECTION.unpack_from(raw,offset)
                if section[1] == 4:
                    struct.pack_into('<I',raw,offset+4,0x40000014)
                    changed += 1
            self.assertEqual(changed,1)
            obj.write_bytes(raw)
            subprocess.run(['ar','rcs',str(archive),str(obj)],check=True,capture_output=True)
            slot = {'kind':'inside-input','section':'.init_array','slot':0,'offset_in_input':0,
                    'input':{'owner':str(archive)+'(ctor.o)','section':'.init_array','size':8,'alignment':8}}
            result = subject.inspect_inputs(root,[slot])
            self.assertEqual(result['summary']['constructor_input_unknown_relocation_format_count'],1)
            self.assertEqual(result['summary']['constructor_input_multiple_relocations_count'],0)
            self.assertEqual(result['summary']['constructor_input_without_relocation_count'],0)
            self.assertIn('prefix_hex',result['details'][0]['candidates'][0]['relocation_sections'][0])
            self.assertNotIn('prefix_hex',str(result['summary']))
