from __future__ import annotations
import hashlib
import struct
import sys
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from secure_release import cef_constructor_inputs as subject


class PolicyTests(unittest.TestCase):
    def test_absent_relocated_sdk_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as name:
            result = subject.inspect_inputs(Path(name)/"absent", [])
        self.assertEqual(result, {"summary": {"constructor_input_relocations_available": False}, "details": []})

    def test_slot_inventory_is_bounded_before_reading(self):
        with self.assertRaises(ValueError):
            subject.inspect_inputs(Path("absent"), [{}]*(subject.MAX_SLOTS+1))


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc") and shutil.which("ar"), "native Linux ELF tools")
class InputEvidenceTests(unittest.TestCase):
    def build(self, root, source, *, name="constructor_member_with_long_name", append=False):
        base = root / "consumer-sdk/installed/x64-linux-static-release/lib/cef-static"
        base.mkdir(parents=True, exist_ok=True)
        text = root / (name + ".s")
        text.write_text(source)
        obj = root / (name + ".o")
        subprocess.run(["gcc", "-c", str(text), "-o", str(obj)], check=True, capture_output=True)
        archive = base / "cef_objects.a"
        subprocess.run(["ar", "qc" if append else "rcs", str(archive), str(obj)],
                       check=True, capture_output=True)
        slot = {"kind": "inside-input", "section": ".init_array", "slot": 2,
                "input": {"owner": str(archive)+"("+obj.name+")", "section": ".init_array",
                          "size": 8, "alignment": 8}, "offset_in_input": 0}
        return base, archive, slot

    def evidence(self, source):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            base, archive, slot = self.build(root, source)
            before = hashlib.sha256(archive.read_bytes()).hexdigest()
            result = subject.inspect_inputs(base, [slot])
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), before)
            self.assertEqual(result["summary"]["constructor_input_matched_count"], 1)
            return result

    def test_undefined_hidden_weak_relocation_is_not_lost(self):
        r = self.evidence('''
.weak missing_constructor
.hidden missing_constructor
.section .init_array,"aw",@init_array
.p2align 3
.quad missing_constructor
.section .note.GNU-stack,"",@progbits
''')
        self.assertEqual(r['summary']['constructor_input_undefined_weak_count'], 1)
        rel = r['details'][0]['candidates'][0]['relocations'][0]
        self.assertEqual((rel['type'], rel['binding'], rel['visibility'], rel['shndx']), (1,2,2,0))
        self.assertNotIn('missing_constructor', repr(r['summary']))

    def test_literal_null_is_distinct_from_a_weak_reference(self):
        r = self.evidence('.section .init_array,"aw",@init_array\n.p2align 3\n.quad 0\n')
        self.assertEqual(r['summary']['constructor_input_without_relocation_count'], 1)
        self.assertEqual(r['summary']['constructor_input_undefined_weak_count'], 0)

    def test_defined_local_executable_target_and_addend(self):
        r = self.evidence('''
.section .text.startup,"ax",@progbits
.local constructor
.type constructor,@function
constructor:
ret
.section .init_array,"aw",@init_array
.p2align 3
.quad constructor
.section .note.GNU-stack,"",@progbits
''')
        self.assertEqual(r['summary']['constructor_input_defined_target_count'], 1)
        self.assertEqual(r['summary']['constructor_input_nonexec_target_count'], 0)
        self.assertEqual(r['summary']['constructor_input_without_relocation_count'], 0)

    def test_duplicate_members_are_reported_not_silently_selected(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = '.section .init_array,"aw",@init_array\n.p2align 3\n.quad 0\n'
            base, archive, slot = self.build(root, source)
            self.build(root, source, append=True)
            result = subject.inspect_inputs(base, [slot])
            self.assertEqual(result['summary']['constructor_input_ambiguous_count'], 1)
            self.assertEqual(len(result['details'][0]['candidates']), 2)

    def test_redirect_escape_truncation_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            base, archive, slot = self.build(root, '.section .init_array,"aw",@init_array\n.p2align 3\n.quad 0\n')
            (base/'wrong').mkdir()
            with self.assertRaises(ValueError):
                subject.inspect_inputs(base/'wrong', [slot])
            raw = archive.read_bytes()
            archive.write_bytes(raw[:-3])
            with self.assertRaises(ValueError):
                subject.inspect_inputs(base, [slot])
            archive.unlink()
            real = root/'real.a'; real.write_bytes(raw)
            archive.symlink_to(real)
            with self.assertRaises(ValueError):
                subject.inspect_inputs(base, [slot])

    def test_comdat_target_signature_is_recorded(self):
        r = self.evidence('''
.section .text.ctor,"axG",@progbits,ctor,comdat
.weak ctor
.type ctor,@function
ctor:
ret
.section .init_array,"aw",@init_array
.p2align 3
.quad ctor
.section .note.GNU-stack,"",@progbits
''')
        rel = r['details'][0]['candidates'][0]['relocations'][0]
        self.assertEqual(rel['target_section']['groups'][0]['signature'], 'ctor')
        self.assertEqual(rel['target_section']['groups'][0]['flags'], 1)

    def test_dotdot_owner_does_not_escape_allowed_subtree(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            base, archive, slot = self.build(root, '.section .init_array,"aw",@init_array\n.p2align 3\n.quad 0\n')
            slot['input']['owner'] = str(base/'..'/archive.name) + '(ignored.o)'
            shutil.copy2(archive, base.parent/archive.name)
            with self.assertRaises(ValueError):
                subject.inspect_inputs(base,[slot])

    @unittest.skipUnless(shutil.which("ld.lld"), "LLD map integration")
    def test_actual_final_link_map_traces_hidden_weak_input_without_mutation(self):
        from secure_release import cef_constructor_map
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            base, archive, _ = self.build(root, '''
.weak missing_constructor
.hidden missing_constructor
.section .init_array,"aw",@init_array
.p2align 3
.quad missing_constructor
.section .note.GNU-stack,"",@progbits
''')
            build = root/'consumer-build'
            build.mkdir()
            main = build/'main.c'
            main.write_text('int main(void){return 0;}\n')
            executable, map_file = build/'probe', build/cef_constructor_map.MAP_NAME
            subprocess.run(['gcc','-no-pie','-fuse-ld=lld',str(main),'-Wl,--whole-archive',
                str(archive),'-Wl,--no-whole-archive','-Wl,-Map='+str(map_file),'-o',str(executable)],
                check=True,capture_output=True)
            raw = executable.read_bytes()
            h = subject.HEADER.unpack_from(raw)
            sh = [subject.SECTION.unpack_from(raw,h[6]+i*subject.SECTION.size) for i in range(h[12])]
            names = raw[sh[h[13]][4]:sh[h[13]][4]+sh[h[13]][5]]
            sections = [dict(name=names[item[0]:].split(b'\0',1)[0].decode(),
                             addr=item[3],size=item[5],align=item[8],offset=item[4]) for item in sh]
            init = next(item for item in sections if item['name']=='.init_array')
            bad = [dict(reason='zero-unrelocated',section='.init_array',slot=i)
                   for i in range(init['size']//8) if struct.unpack_from('<Q',raw,init['offset']+8*i)[0]==0]
            self.assertEqual(len(bad),1)
            result = cef_constructor_map.inspect_map(map_file,sections,{'bad':bad})
            self.assertEqual(result['summary']['constructor_input_undefined_weak_count'],1)
            self.assertEqual(result['summary']['constructor_zero_linker_padding_count'],0)
            self.assertEqual(raw,executable.read_bytes())

    def test_missing_member_is_explicit_and_geometry_not_guessed(self):
        with tempfile.TemporaryDirectory() as t:
            base, archive, slot = self.build(Path(t), '.section .init_array,"aw",@init_array\n.p2align 3\n.quad 0\n')
            slot['input']['size'] = 16
            result = subject.inspect_inputs(base,[slot])
            self.assertEqual(result['summary']['constructor_input_missing_count'],1)
            self.assertEqual(result['summary']['constructor_input_matched_count'],0)


if __name__ == '__main__':
    unittest.main()
