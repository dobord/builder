from __future__ import annotations
import copy
from pathlib import Path
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from secure_release import cef_crel_compat as subject


def leb(value, signed=False):
    """Independent fixture encoder (LLVM MCELFExtras.h encoding rules)."""
    data = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        stop = (value == 0 and not (byte & 64)) or (value == -1 and byte & 64) if signed else value == 0
        data.append(byte if stop else byte | 128)
        if stop:
            return bytes(data)


def crel(rows, shift=0):
    data = bytearray(leb((len(rows) << 3) | 4 | shift))
    offset = symbol = kind = addend = 0
    for new_offset, new_symbol, new_kind, new_addend in rows:
        assert new_offset % (1 << shift) == 0 and new_offset >> shift >= offset
        flags = int(new_symbol != symbol) | (int(new_kind != kind) << 1) | (int(new_addend != addend) << 2)
        data += leb(((new_offset >> shift) - offset) << 3 | flags)
        for new, old in ((new_symbol, symbol), (new_kind, kind), (new_addend, addend)):
            if new != old:
                data += leb(new - old, True)
        offset, symbol, kind, addend = new_offset >> shift, new_symbol, new_kind, new_addend
    return bytes(data)


def make_crel_object(data):
    """Test-only producer: encode real assembler RELA as explicit CREL.

    This is not imported by production or used to repair private SDK bytes.
    Section ordinals, symbols and code stay unchanged; append changed payloads.
    """
    h = list(subject.HEADER.unpack_from(data))
    sections = [list(subject.SECTION.unpack_from(data, h[6]+i*subject.SECTION.size))
                for i in range(h[12])]
    names = bytearray(data[sections[h[13]][4]:sections[h[13]][4]+sections[h[13]][5]])
    out = bytearray(data)
    for sec in sections:
        if sec[1] != 4:
            continue
        name = bytes(names[sec[0]:]).split(b'\0', 1)[0]
        assert name.startswith(b'.rela')
        rows = [(o, info >> 32, info & 0xffffffff, a)
                for o, info, a in subject.RELA.iter_unpack(data[sec[4]:sec[4]+sec[5]])]
        packed = crel(rows)
        sec[0] = len(names)
        names += b'.crel' + name[5:] + b'\0'
        sec[1], sec[4], sec[5], sec[8], sec[9] = subject.SHT_CREL, len(out), len(packed), 1, 1
        out += packed
    strings = sections[h[13]]
    strings[4], strings[5] = len(out), len(names)
    out += names
    out += b'\0' * (-len(out) % 8)
    h[6] = len(out)
    out += b''.join(subject.SECTION.pack(*s) for s in sections)
    subject.HEADER.pack_into(out, 0, *h)
    return bytes(out)


class CodecTests(unittest.TestCase):
    def test_explicit_reference_vector_and_empty(self):
        self.assertEqual(list(subject.decode(bytes([12, 3, 2, 1]))), [(0, 2, 1, 0)])
        self.assertEqual(list(subject.decode(bytes([4]))), [])

    def test_signed_deltas_shift_multibyte_and_repeated_offsets(self):
        rows = [(0, 100, 1, -9), (8, 3, 2, -10), (8, 5, 2, -10),
                (1 << 20, 4, 1, 512), ((1 << 20)+8, 4, 1, 513)]
        for shift in range(4):
            self.assertEqual(list(subject.decode(crel(rows, shift))), rows)

    def test_malformed_fails_closed(self):
        for data in (b'', b'\x80', b'\x08', b'\x0c', b'\x0c\x03',
                     b'\x04\x00', b'\xff'*11, b'\x0c\x03'+b'\xff'*11):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    list(subject.decode(data))

    def test_zero_count_uses_no_response_file(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with subject.options({'section_count': 0}, root) as args:
                self.assertEqual(args, [])
            self.assertEqual(list(root.iterdir()), [])

    def test_exact_response_options_and_cleanup(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with subject.options({'section_count': 2, 'names': ['.crel.init_array', '.crel.text.f']}, root) as args:
                self.assertEqual(len(args), 1)
                p = Path(args[0][1:])
                self.assertEqual(p.read_text(), '--set-section-type=.crel.init_array=4\n'
                    '--rename-section=.crel.init_array=.rela.init_array\n'
                    '--set-section-type=.crel.text.f=4\n--rename-section=.crel.text.f=.rela.text.f\n')
                if os.name != 'nt':
                    self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertFalse(p.exists())

    def test_untrusted_option_and_budget_fail_and_cleanup(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaises(ValueError):
                with subject.options({'section_count': 1, 'names': ['.crel.a\n--strip-all']}, root):
                    pass
            with mock.patch.object(subject, 'MAX_RSP_BYTES', 2):
                with self.assertRaises(ValueError):
                    with subject.options({'section_count': 1, 'names': ['.crel.init_array']}, root):
                        pass
            self.assertEqual(list(root.iterdir()), [])


    def test_receipt_rejects_missing_encoding_unknown_archive_and_bad_counters(self):
        names = {'lib/cef-static/cef_objects.a'}
        record = {'section_count': 1, 'relocation_count': 1, 'sha256': 'a' * 64}
        subject.validate_receipt(subject.ENCODING, {next(iter(names)): record}, names)
        subject.validate_receipt(subject.ENCODING, {}, names)
        for encoding, records in ((None, {}), (subject.ENCODING, None),
                (subject.ENCODING, {'foreign.a': record})):
            with self.assertRaises(ValueError):
                subject.validate_receipt(encoding, records, names)
        for key, value in [('section_count', 0), ('section_count', True),
                ('relocation_count', -1), ('relocation_count', True),
                ('sha256', 'bad'), ('section_count', subject.MAX_RELOCATIONS + 1)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                subject.validate_receipt(subject.ENCODING,
                    {next(iter(names)): {**record, key: value}}, names)

    def test_bounded_integer_wraparound_is_identical_to_llvm(self):
        rows = [(0, 0xffffffff, 0xffffffff, -(1 << 63)),
                (8, 0, 0, (1 << 63) - 1)]
        # Canonical emitter uses width-specific modular delta arithmetic.
        data = (leb((2 << 3) | 4) + leb(7) + leb(-1, True) + leb(-1, True)
                + leb(-(1 << 63), True) + leb((8 << 3) | 7)
                + leb(1, True) + leb(1, True) + leb(-1, True))
        self.assertEqual(list(subject.decode(data)), rows)


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('gcc'), 'native x86-64 ELF')
class NativeTests(unittest.TestCase):
    def make(self, root):
        source = root / 'constructor.s'
        source.write_text('''
.section .text.ctor,"ax",@progbits
.globl fixture_ctor
.type fixture_ctor,@function
fixture_ctor:
    movl $23, fixture_state(%rip)
    ret
.size fixture_ctor, .-fixture_ctor
.section .init_array,"aw",@init_array
.p2align 3
.quad fixture_ctor
.section .note.GNU-stack,"",@progbits
''')
        obj = root / 'original.o'
        subprocess.run(['gcc','-c',str(source),'-o',str(obj)], check=True,capture_output=True)
        original = obj.read_bytes()
        compressed = make_crel_object(original)
        plan = subject.inventory([(2, compressed)])
        return original, compressed, plan

    def test_all_sections_and_symbol_semantics_match_rela_reference(self):
        with tempfile.TemporaryDirectory() as t:
            a,b,p = self.make(Path(t))
            self.assertEqual(p['section_count'], 2)
            self.assertEqual(p['relocation_count'], 2)
            r = subject.inventory([(2,a)], plan=p)
            self.assertEqual(r['sha256'], p['sha256'])
            self.assertNotIn('fixture_ctor', p['sha256'])

    def test_unknown_format_and_retained_crel_fail(self):
        with tempfile.TemporaryDirectory() as t:
            a,b,p = self.make(Path(t))
            with self.assertRaisesRegex(ValueError,'retains CREL'):
                subject.inventory([(2,b)], plan=p)
            h=subject.HEADER.unpack_from(b); altered=bytearray(b)
            for i in range(h[12]):
                off=h[6]+i*subject.SECTION.size
                s=list(subject.SECTION.unpack_from(b,off))
                if s[1] == subject.SHT_CREL:
                    s[1]=0x40000020
                    subject.SECTION.pack_into(altered,off,*s)
            with self.assertRaisesRegex(ValueError,'Unknown experimental'):
                subject.inventory([(2,bytes(altered))])

    def test_changed_addend_target_code_or_member_fails(self):
        with tempfile.TemporaryDirectory() as t:
            a,b,p = self.make(Path(t))
            e=subject.ELF(a)
            for mode in ('code','relocation'):
                bad=bytearray(a)
                sec=next(s for n,s in zip(e.names,e.sections)
                         if n==('.text.ctor' if mode=='code' else '.rela.init_array'))
                bad[sec[4] + (0 if mode=='code' else 16)] ^= 1
                with self.assertRaises(ValueError):
                    subject.inventory([(2,bytes(bad))],plan=p)
            with self.assertRaises(ValueError):
                subject.inventory([(3,a)],plan=p)
            with self.assertRaises(ValueError):
                subject.inventory([],plan=p)

    def test_inverse_reviewed_namespace_mapping_only(self):
        objcopy=shutil.which('llvm-objcopy') or shutil.which('objcopy')
        if not objcopy:
            self.skipTest('objcopy unavailable')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);a,b,p=self.make(root)
            (root/'source.o').write_bytes(a)
            subprocess.run([objcopy,'--redefine-sym=fixture_ctor=PREFIX_fixture_ctor',
                            str(root/'source.o'),str(root/'renamed.o')],check=True,capture_output=True)
            renamed=(root/'renamed.o').read_bytes()
            with self.assertRaises(ValueError):
                subject.inventory([(2,renamed)],plan=p)
            subject.inventory([(2,renamed)],plan=p,reverse={'PREFIX_fixture_ctor':'fixture_ctor'})

    def test_old_lld_crel_crashes_but_original_rela_executes_constructor(self):
        pinned_lld = Path('/usr/lib/llvm-18/bin/ld.lld')
        lld = str(pinned_lld) if pinned_lld.is_file() else shutil.which('ld.lld')
        if not lld:
            self.skipTest('LLD unavailable')
        version=subprocess.check_output([lld,'--version'],text=True)
        m=re.search(r'LLD (\d+)',version)
        if not m or int(m[1]) >= 19:
            self.skipTest('Old LLD required for unsupported-format reproduction')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);a,b,p=self.make(root)
            main=root/'main.c';main.write_text('int fixture_state; int main(void){return fixture_state==23?0:7;}\n')
            results=[]
            for name,data in [('rela',a),('crel',b)]:
                obj=root/(name+'.o');obj.write_bytes(data);exe=root/name
                subprocess.run(['gcc','-B'+str(Path(lld).parent),'-fuse-ld=lld',str(main),str(obj),'-o',str(exe)],check=True,capture_output=True)
                results.append(subprocess.run([exe],capture_output=True,timeout=10).returncode)
            if results == [0, 0]:
                self.skipTest('Local LLD has backported CREL support despite its version string')
            self.assertEqual(results,[0,-11])

    def test_actual_llvm_crel_to_rela_conversion(self):
        objcopy=os.environ.get('CEF_CREL_OBJCOPY') or shutil.which('llvm-objcopy')
        if not objcopy:
            self.skipTest('CREL-capable llvm-objcopy unavailable')
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);a,b,p=self.make(root)
            source=root/'compressed.o';source.write_bytes(b);out=root/'converted.o'
            self._writer(root, p, source, out)
            subject.inventory([(2,out.read_bytes())],plan=p)
            main=root/'main.c';main.write_text('int fixture_state; int main(void){return fixture_state==23?0:7;}\n')
            exe=root/'probe'
            subprocess.run(['gcc',str(main),str(out),'-o',str(exe)],check=True,capture_output=True,timeout=30)
            self.assertEqual(subprocess.run([exe],capture_output=True,timeout=10).returncode,0)


    def _writer(self, root, plan, source, output, *additional):
        objcopy = os.environ.get('CEF_CREL_OBJCOPY') or shutil.which('llvm-objcopy')
        if not objcopy:
            self.skipTest('CREL-capable llvm-objcopy unavailable')
        # Probe the installed writer independently of subject.options. An
        # Ubuntu LLD18 *consumer* package need not include a CREL-aware writer;
        # production always uses the checkpoint's pinned Chromium writer.
        # Explicit CEF_CREL_OBJCOPY makes absent capability a hard failure.
        with tempfile.TemporaryDirectory(dir=root) as probe_dir:
            probe = Path(probe_dir)
            _, compressed, _ = self.make(probe)
            source_probe, output_probe = probe/'input.o', probe/'output.o'
            source_probe.write_bytes(compressed)
            check = subprocess.run([objcopy,
                '--set-section-type=.crel.init_array=4',
                '--rename-section=.crel.init_array=.rela.init_array',
                str(source_probe), str(output_probe)], capture_output=True,
                text=True, timeout=30)
            capable = False
            if check.returncode == 0:
                golden = subject.ELF(output_probe.read_bytes())
                index = golden.names.index('.rela.init_array')
                section = golden.sections[index]
                capable = (section[1], section[5], section[8], section[9]) == (4, 24, 8, 24)
            if not capable and not os.environ.get('CEF_CREL_OBJCOPY'):
                self.skipTest('Local objcopy lacks semantic CREL-to-RELA conversion')
            self.assertTrue(capable, 'Explicit producer llvm-objcopy cannot convert CREL')
        with subject.options(plan, root) as args:
            result = subprocess.run([objcopy, *args, *additional, str(source), str(output)],
                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return result

    @staticmethod
    def _ar_members(path):
        # Test-only regular ar reader. Production reuses its existing bounded
        # archive/ownership/path checks, not this small fixture reader.
        with path.open('rb') as stream:
            assert stream.read(8) == b'!<arch>\n'
            index = 0
            while header := stream.read(60):
                assert len(header) == 60 and header[58:] == b'`\n'
                index += 1
                size = int(header[48:58])
                data = stream.read(size)
                if size & 1:
                    assert stream.read(1) == b'\n'
                if data.startswith(b'\x7fELF'):
                    yield index, data

    def test_regular_archive_one_pass_namespace_encoding_and_relocated_runtime(self):
        ar = shutil.which('llvm-ar')
        if not ar:
            self.skipTest('LLVM archive writer unavailable')
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); original, compressed, _ = self.make(root)
            # Two copies have different archive member identities. One has
            # no CREL and must not be selected by the CREL-specific proof.
            one = root / 'ctor_long_member_name.o'; one.write_bytes(compressed)
            empty_src = root / 'empty.c'; empty_src.write_text('int unrelated(void){return 9;}\n')
            two = root / 'unrelated.o'
            subprocess.run(['gcc','-c',str(empty_src),'-o',str(two)], check=True, capture_output=True)
            source = root / 'cef_objects.a'
            subprocess.run([ar, 'rcs', str(source), str(one), str(two)], check=True, capture_output=True)
            original_bytes = source.read_bytes()
            plan = subject.inventory(self._ar_members(source))
            output = root / 'converted.a'
            self._writer(root, plan, source, output,
                '--redefine-sym=fixture_ctor=CEF_CHROMIUM_BSSL_fixture_ctor')
            subject.inventory(self._ar_members(output), plan=plan,
                reverse={'CEF_CHROMIUM_BSSL_fixture_ctor': 'fixture_ctor'})
            self.assertEqual(source.read_bytes(), original_bytes)
            self.assertEqual(subject.inventory(self._ar_members(output))['section_count'], 0)
            relocated = root / 'relocated'; relocated.mkdir()
            target = relocated / 'final.a'; shutil.copy2(output, target)
            subject.inventory(self._ar_members(target), plan=plan,
                reverse={'CEF_CHROMIUM_BSSL_fixture_ctor': 'fixture_ctor'})
            main = root / 'main.c'
            main.write_text('int fixture_state; int main(void){return fixture_state==23?0:7;}\n')
            exe = relocated / 'probe'
            subprocess.run(['gcc',str(main),'-Wl,--whole-archive',str(target),
                '-Wl,--no-whole-archive','-o',str(exe)], check=True, capture_output=True)
            self.assertEqual(subprocess.run([exe], timeout=10).returncode, 0)

    def test_existing_alignment_normalization_does_not_lose_relocations(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); original, compressed, _ = self.make(root)
            data = bytearray(compressed)
            h = subject.HEADER.unpack_from(data)
            elf = subject.ELF(data)
            index = elf.names.index('.init_array')
            section = list(elf.sections[index]); section[8] = 16
            subject.SECTION.pack_into(data, h[6]+index*subject.SECTION.size, *section)
            plan = subject.inventory([(2, bytes(data))])
            source = root / 'aligned.o'; source.write_bytes(data)
            output = root / 'normalized.o'
            self._writer(root, plan, source, output, '--set-section-alignment=.init_array=8')
            subject.inventory([(2, output.read_bytes())], plan=plan)
            elf = subject.ELF(output.read_bytes())
            self.assertEqual(elf.sections[elf.names.index('.init_array')][8], 8)

    def test_relabeling_crel_bytes_without_reencoding_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); original, compressed, plan=self.make(root)
            raw=bytearray(compressed); h=subject.HEADER.unpack_from(raw)
            for i in range(h[12]):
                off=h[6]+i*subject.SECTION.size
                values=list(subject.SECTION.unpack_from(raw,off))
                if values[1] == subject.SHT_CREL:
                    values[1]=4
                    subject.SECTION.pack_into(raw,off,*values)
            with self.assertRaises(ValueError):
                subject.inventory([(2, bytes(raw))], plan=plan)


if __name__=='__main__':
    unittest.main()
