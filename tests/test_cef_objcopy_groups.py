"""Preserve actual COMDAT deduplication, not merely symbol-table equality."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_cef_crel as encoding
from secure_release import cef_crel as elf, cef_objcopy_groups as groups
from secure_release import cef_crel_diagnostics as diagnostic

ASM = '''
.local group_signature
.section .text.boot,"axG",@progbits,group_signature,comdat
group_signature:
.local boot
.type boot,@function
boot:
  incl counter(%rip)
  ret
.section .init_array.01001,"awG",@init_array,group_signature,comdat
.p2align 3
.quad boot
.section .note.GNU-stack,"",@progbits
'''


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc') and shutil.which('ar'),
                     'native GNU ELF fixture')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tools.cleanup)
        cls.tool = encoding.pinned_tool(Path(cls.tools.name))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root/'groups.a'
        self.rela = self.root/'original.a'
        objects, originals = [], []
        for label in ('one', 'two'):
            folder = self.root/label
            folder.mkdir()
            src, obj, rel = folder/'same.s', folder/'same.o', folder/'rela.o'
            src.write_text(ASM)
            subprocess.run(['gcc', '-c', str(src), '-o', str(rel)], check=True, capture_output=True)
            obj.write_bytes(encoding.make_crel(rel.read_bytes())[0])
            originals.append(rel)
            objects.append(obj)
        subprocess.run(['ar', 'qcP', str(self.source), *map(str, objects)], check=True, capture_output=True)
        subprocess.run(['ar', 'qcP', str(self.rela), *map(str, originals)], check=True, capture_output=True)
        self.original = self.source.read_bytes()
        self.before = elf.archive_profile(self.source, limit=1024**3)

    def execute(self, archive, counter='counter'):
        c, exe = self.root/'consumer.c', self.root/'consumer'
        c.write_text(f'int {counter}; int main(void){{return {counter}!=1;}}\n')
        linker = Path('/usr/lib/llvm-18/bin/ld.lld')
        flags = []
        if linker.is_file():
            version = subprocess.check_output([str(linker),'--version'],text=True,timeout=30)
            self.assertRegex(version, r'LLD 18\.')
            flags = ['-B'+str(linker.parent), '-fuse-ld=lld']
        elif os.environ.get('REQUIRE_CEF_CONSUMER_LLD') == '1':
            self.fail('required LLD18 is missing')
        subprocess.run(['gcc', *flags, str(c), '-Wl,--whole-archive', str(archive),
                        '-Wl,--no-whole-archive', '-o', str(exe)], check=True, capture_output=True)
        return subprocess.run([str(exe)], timeout=10, capture_output=True).returncode

    def test_native_writer_demotes_existing_local_comdat_and_changes_execution(self):
        self.assertEqual(self.execute(self.rela),0)
        output = self.root/'raw.a'
        options = ['--set-section-type='+n+'=4' for n in self.before['names']]
        subprocess.run([str(self.tool),*options,str(self.source),str(output)],check=True,capture_output=True)
        self.assertNotEqual(elf.archive_profile(output,limit=1024**3)['sha256'],self.before['sha256'])
        self.assertEqual(len(groups.profile(output,1024**3)['patches']),0)
        self.assertEqual(self.execute(output),1)  # Both constructors run: semantics changed.
        self.assertEqual(self.source.read_bytes(),self.original)

    def test_complete_crel_and_namespace_passes_keep_deduplication_after_relocation(self):
        receipt=elf.install([('fixture',self.source)],self.tool)
        after=elf.archive_profile(self.source,limit=1024**3)
        self.assertEqual(after['sha256'],self.before['sha256'])
        self.assertEqual(after['crel_sections'],0)
        self.assertEqual(receipt['archives']['fixture']['source_sha256'],hashlib.sha256(self.original).hexdigest())
        self.assertEqual(len(groups.profile(self.source,1024**3)['patches']),2)
        self.assertEqual(self.execute(self.source),0)
        mapping=self.root/'mapping.txt'
        mapping.write_text('counter CEF_counter\ngroup_signature CEF_group_signature\n')
        out=self.root/'namespaced.a'
        proof=groups.run(self.tool,['--redefine-syms='+str(mapping)],self.source,out,
                         limit=1024**3,reverse={'CEF_group_signature':'group_signature'})
        self.assertEqual(proof['preserved_local_comdat'],2)
        moved=self.root/'relocated'
        moved.mkdir()
        shutil.move(out,moved/'sdk.a')
        for label in ('one','two'):shutil.rmtree(self.root/label)
        self.assertEqual(self.execute(moved/'sdk.a','CEF_counter'),0)
        print('CEF_LOCAL_COMDAT_PRESERVED',elf.TOOL_SHA256,2)

    def test_temporary_encoding_changes_only_reviewed_type_words(self):
        p=groups.profile(self.source,1024**3)
        with groups._input_copy(self.source,p) as (staged,options):
            payload=bytearray(self.original)
            for pos,_ in p['patches']:struct.pack_into('<I',payload,pos,1)
            self.assertEqual(staged.read_bytes(),bytes(payload))
            self.assertEqual(len(options),1)
            self.assertEqual(Path(options[0][1:]).read_text(),'--set-section-type=.group=17\n')
        self.assertFalse(staged.exists())
        self.assertEqual(self.source.read_bytes(),self.original)

    def test_wrong_tool_and_existing_output_are_not_written(self):
        out=self.root/'out.a'
        wrong=self.root/'wrong';wrong.write_bytes(b'not a converter')
        with self.assertRaisesRegex(ValueError,'Unreviewed'):
            groups.run(wrong,[],self.source,out,limit=1024**3)
        self.assertFalse(out.exists())
        out.write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError,'already exists'):
            groups.run(self.tool,[],self.source,out,limit=1024**3)
        self.assertEqual(out.read_bytes(),b'keep')
        self.assertEqual(self.source.read_bytes(),self.original)

    def test_group_signature_and_membership_changes_fail(self):
        raw=next(groups.members(self.source,1024**3))[1]
        h=elf.HEADER.unpack_from(raw)
        sections=[elf.SECTION.unpack_from(raw,h[6]+i*64) for i in range(h[12])]
        i=next(i for i,s in enumerate(sections) if s[1]==17)
        group=sections[i]
        for off,value in ((group[4]+4,len(sections)), (h[6]+i*64+44,0)):
            bad=bytearray(raw);struct.pack_into('<I',bad,off,value)
            with self.assertRaises(ValueError): groups._groups(bytes(bad),{})

    def test_unrelated_semantic_change_is_fatal_and_privately_explained(self):
        real_run=subprocess.run
        def mutate(argv,**kwargs):
            result=real_run(argv,**kwargs)
            output=Path(argv[-1])
            _,data,start=next(groups.members(output,1024**3))
            h=elf.HEADER.unpack_from(data)
            sections=[elf.SECTION.unpack_from(data,h[6]+i*64) for i in range(h[12])]
            code=next(s for s in sections if s[1]==1 and s[2]&4 and s[5]>0)
            with output.open('r+b') as stream:
                stream.seek(start+code[4]);old=stream.read(1)
                stream.seek(-1,1);stream.write(bytes([old[0]^1]))
            return result
        report=self.root/'private-mismatch.json'
        with mock.patch.object(groups.subprocess,'run',side_effect=mutate):
            with self.assertRaisesRegex(ValueError,'changed object semantics'):
                elf.install([('fixture',self.source)],self.tool,diagnostics=report)
        self.assertEqual(self.source.read_bytes(),self.original)
        self.assertEqual(report.stat().st_mode&0o777,0o600)
        value=json.loads(report.read_text())
        self.assertEqual(value['format'],'cef-crel-semantic-failure-v1')
        self.assertEqual(value['first_changed_member']['index'],0)
        self.assertIn('.text.boot',repr(value['difference']))
        self.assertEqual(value['difference']['group_changes'],[])
        self.assertFalse(list(self.root.glob('.cef-crel-*')))
        before=report.read_bytes()
        with self.assertRaises(ValueError):
            diagnostic.write_mismatch(self.source,self.source,report,self.before,self.before,limit=1024**3)
        self.assertEqual(report.read_bytes(),before)

    def test_budget_and_redirects_precede_reading(self):
        with mock.patch.object(Path,'open',side_effect=AssertionError('must not open')):
            with self.assertRaises(ValueError):groups.profile(self.source,elf.MAX_ARCHIVE+1)
        link=self.root/'redirect.a';link.symlink_to(self.source)
        with self.assertRaises(ValueError):groups.profile(link,1024**3)


def group_fixture():
    names=b'\0.strtab\0.symtab\0.group\0.text\0.init_array\0signature\0'
    sections=[(0,)*10]
    data=bytearray(b'\0'*64)
    def add(name,kind,payload,flags=0,link=0,info=0,align=1,entry=0):
        data.extend(b'\0'*((-len(data))%align))
        offset=len(data);data.extend(payload)
        sections.append((names.index(name.encode()+b'\0'),kind,flags,0,offset,len(payload),link,info,align,entry))
    add('.strtab',3,names)
    syms=bytes(24)+elf.SYMBOL.pack(names.index(b'signature\0'),0,0,4,0,1)
    add('.symtab',2,syms,link=1,info=2,align=8,entry=24)
    add('.group',17,struct.pack('<III',1,4,5),link=2,info=1,align=4,entry=4)
    add('.text',1,b'\xc3',flags=0x206)
    add('.init_array',14,bytes(8),flags=0x203,align=8,entry=8)
    data.extend(b'\0'*((-len(data))%8));table=len(data)
    data.extend(b''.join(elf.SECTION.pack(*s) for s in sections))
    elf.HEADER.pack_into(data,0,b'\x7fELF\x02\x01\x01'+bytes(9),1,62,1,0,0,table,0,64,0,0,64,len(sections),1)
    return bytes(data)


def fixture_archive(data):
    return (b'!<arch>\n'+b'member.o/'.ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)
            +b'0'.ljust(6)+b'644'.ljust(8)+str(len(data)).encode().ljust(10)+b'`\n'
            +data+(b'\n' if len(data)&1 else b''))


class PolicyTests(unittest.TestCase):
    def test_local_global_and_noncomdat_cases_are_not_conflated(self):
        raw=group_fixture()
        records,patches,_=groups._groups(raw,{})
        self.assertEqual(len(records),1);self.assertEqual(len(patches),1)
        h=elf.HEADER.unpack_from(raw);syms=elf.SECTION.unpack_from(raw,h[6]+2*64)
        global_=bytearray(raw);global_[syms[4]+24+4]=0x10
        self.assertEqual(groups._groups(bytes(global_),{})[1],[])
        group=elf.SECTION.unpack_from(raw,h[6]+3*64)
        noncomdat=bytearray(raw);struct.pack_into('<I',noncomdat,group[4],0)
        self.assertEqual(groups._groups(bytes(noncomdat),{})[1],[])
        self.assertNotEqual(records,groups._groups(bytes(noncomdat),{})[0])

    def test_bad_metadata_is_rejected_not_normalized(self):
        raw=group_fixture();h=elf.HEADER.unpack_from(raw)
        group=elf.SECTION.unpack_from(raw,h[6]+3*64)
        for offset,value in ((h[6]+3*64+40,0),(h[6]+3*64+44,0),(group[4],2),
                             (group[4]+4,6),(group[4]+8,4)):
            bad=bytearray(raw);struct.pack_into('<I',bad,offset,value)
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):
                groups._groups(bytes(bad),{})

    def test_archive_copy_is_exclusive_and_preserves_all_non_type_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();source=root/'source.a'
            original=fixture_archive(group_fixture());source.write_bytes(original)
            p=groups.profile(source,1024**3)
            with groups._input_copy(source,p) as (staged,options):
                expected=bytearray(original)
                for pos,_ in p['patches']:struct.pack_into('<I',expected,pos,1)
                self.assertEqual(staged.read_bytes(),expected)
                self.assertEqual(len(options),1)
                self.assertEqual(Path(options[0][1:]).read_text(),'--set-section-type=.group=17\n')
            self.assertFalse(staged.exists());self.assertEqual(source.read_bytes(),original)
            with mock.patch.object(groups.subprocess,'run',side_effect=AssertionError('must not execute')):
                wrong=root/'wrong';wrong.write_bytes(b'wrong')
                with self.assertRaisesRegex(ValueError,'Unreviewed'):
                    groups.run(wrong,[],source,root/'out.a',limit=1024**3)
            self.assertFalse((root/'out.a').exists())

    def test_complete_profile_and_diagnostic_callback_are_identical(self):
        data=group_fixture();events=[]
        self.assertEqual(elf.object_profile(data),elf.object_profile(data,record_callback=events.append))
        self.assertGreater(len(events),5)
        self.assertEqual(events[0][1:4],[1,62,1])

    def test_diagnostic_is_bounded_and_does_not_sanitize_semantics(self):
        self.assertEqual(diagnostic._bounded('short'),'short')
        large='x'*(diagnostic.MAX_VALUE+1)
        self.assertEqual(set(diagnostic._bounded(large)),{'omitted_bytes','sha256'})
        self.assertNotEqual(diagnostic._bounded(large)['sha256'],diagnostic._bounded(large+'y')['sha256'])
