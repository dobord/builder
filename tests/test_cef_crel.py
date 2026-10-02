"""Native regression for the diagnosed LLVM CREL / LLD18 format mismatch."""
from __future__ import annotations
import ast
import copy
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.request
from unittest import mock
from secure_release import cef_crel as subject

PACKAGE = 'clang-llvmorg-23-init-19482-g53d18800-1.tar.xz'
TOOL_URL = 'https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/' + PACKAGE


def leb(value, signed=False):
    out = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and (not signed or not byte & 64)) or (signed and value == -1 and byte & 64)
        out.append(byte if done else byte | 128)
        if done:
            return bytes(out)


def make_crel(data):
    """Independent fixture encoder, starting from real GCC-produced RELA."""
    data = bytearray(data)
    h = subject.HEADER.unpack_from(data)
    sections = [subject.SECTION.unpack_from(data, h[6]+i*64) for i in range(h[12])]
    names = sections[h[13]]
    total = 0
    for i, s in enumerate(sections):
        if s[1] != 4:
            continue
        original = list(subject.RELA.iter_unpack(data[s[4]:s[4]+s[5]]))
        encoded = bytearray(leb(len(original)*8+4))
        prev_offset = prev_sym = prev_type = prev_add = 0
        for offset, info, addend in original:
            symbol, kind = info >> 32, info & 0xffffffff
            flags = (symbol != prev_sym) | ((kind != prev_type) << 1) | ((addend != prev_add) << 2)
            encoded += leb((((offset-prev_offset) & subject.MASK64) << 3) | flags)
            if flags & 1: encoded += leb(symbol-prev_sym, True)
            if flags & 2: encoded += leb(kind-prev_type, True)
            if flags & 4: encoded += leb(addend-prev_add, True)
            prev_offset, prev_sym, prev_type, prev_add = offset, symbol, kind, addend
        if len(encoded) > s[5]:
            raise AssertionError('fixture unexpectedly expands CREL')
        data[s[4]:s[4]+len(encoded)] = encoded
        values = list(s)
        values[1], values[5], values[8], values[9] = subject.CREL, len(encoded), 1, 1
        subject.SECTION.pack_into(data, h[6]+i*64, *values)
        pos = names[4]+s[0]
        assert data[pos:pos+5] == b'.rela'
        data[pos:pos+5] = b'.crel'
        total += len(original)
    return bytes(data), total


def pinned_tool(folder):
    existing = os.environ.get('CEF_CREL_OBJCOPY')
    if existing:
        path = Path(existing)
        if subject.digest(path) != subject.TOOL_SHA256:
            raise AssertionError('unreviewed native CREL test tool')
        return path
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise unittest.SkipTest('official pinned LLVM23 executable requires the public CI network')
    # PUBLIC tool only. Verify the exact executable hash authenticated in #137;
    # no package is installed and no arbitrary tar member is extracted/run.
    package = folder/'tool.tar.xz'
    deadline = time.monotonic()+240
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(TOOL_URL, timeout=30) as response, package.open('xb') as out:
        if response.geturl() != TOOL_URL:
            raise AssertionError('pinned LLVM package was redirected')
        total = 0
        while chunk := response.read(1024**2):
            total += len(chunk)
            if total > 1024**3 or time.monotonic() > deadline:
                raise AssertionError('pinned LLVM test tool acquisition exceeded bound')
            out.write(chunk)
    tool = folder/'llvm-objcopy'
    seen = 0
    members = expanded = 0
    with tarfile.open(package, 'r:xz') as archive:
        for item in archive:
            members += 1
            expanded += item.size
            if members > 10000 or expanded > 4*1024**3 or time.monotonic() > deadline:
                raise AssertionError('pinned LLVM test package inventory exceeded bound')
            if item.name not in ('bin/llvm-objcopy', './bin/llvm-objcopy'):
                continue
            seen += 1
            if not item.isfile() or not 0 < item.size <= 128*1024**2:
                raise AssertionError('invalid pinned LLVM executable member')
            with archive.extractfile(item) as source, tool.open('xb') as dest:
                shutil.copyfileobj(source, dest)
    if seen != 1 or subject.digest(tool) != subject.TOOL_SHA256:
        raise AssertionError('pinned LLVM executable identity mismatch')
    tool.chmod(0o700)
    package.unlink()
    return tool


class DecoderTests(unittest.TestCase):
    def test_explicit_addends_and_negative_deltas(self):
        # count=2, explicit addends, shift=0. No dependency on production encoder.
        raw = bytes([20, 7, 5, 1, 0x7c, 0x43, 0x7e, 1])
        self.assertEqual(list(subject.decode_crel(raw)), [(0, 5, 1, -4), (8, 3, 2, -4)])

    def test_malformed_and_implicit_addends_are_fatal(self):
        for raw in (b'', b'\x08\x00', b'\x0c', b'\x0c\x03', b'\x04\x00', b'\x80'*11):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                list(subject.decode_crel(raw))

    def test_no_converter_without_ownership_installer_hook(self):
        source = (Path(__file__).resolve().parents[1]/'secure_release/cef_boringssl_isolation.py').read_text()
        # Check the actual call, not whitespace or the closing parenthesis:
        # private diagnostics are a keyword, not a different archive/tool input.
        tree = ast.parse(source)
        install = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'install')
        calls = [n for n in ast.walk(install) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == 'install'
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == 'cef_crel']
        self.assertEqual(len(calls), 1)
        call = calls[0]
        self.assertEqual([ast.dump(a) for a in call.args],
                         [ast.dump(ast.Name(id=n, ctx=ast.Load())) for n in ('cef', 'objcopy')])
        self.assertEqual([k.arg for k in call.keywords], ['diagnostics'])
        expected = ast.parse('diagnostics.with_name(diagnostics.name + "-crel-failure.json")',
                             mode='eval').body
        self.assertEqual(ast.dump(call.keywords[0].value), ast.dump(expected))
        self.assertLess(source.index('ownership_receipt = _ownership('),
                        source.index('relocation_receipt = cef_crel.install('))
        self.assertIn('cef_crel.verify_receipt(receipt)', source)
        self.assertIn('"relocation_compatibility": relocation_receipt', source)


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('gcc') and shutil.which('ar'), 'native Linux')
class NativeTests(unittest.TestCase):
    _tool = None

    @classmethod
    def real_tool(cls):
        if cls._tool is None:
            folder = tempfile.TemporaryDirectory(prefix='cef-pinned-crel-test-')
            cls.addClassCleanup(folder.cleanup)
            cls._tool = pinned_tool(Path(folder.name))
        return cls._tool

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        source = self.root/'ctor.s'
        source.write_text('''
.text
.type ctor,@function
ctor:
    movl $7, result(%rip)
    ret
.data
.globl result
result: .long 0
.section .init_array,"aw",@init_array
.p2align 3
.quad ctor
.section .note.GNU-stack,"",@progbits
''')
        self.rela = self.root/'ctor.o'
        subprocess.run(['gcc','-c',str(source),'-o',str(self.rela)], check=True,capture_output=True)
        self.crel = self.root/'compact.o'
        payload, self.count = make_crel(self.rela.read_bytes())
        self.crel.write_bytes(payload)

    def link(self, archive, name):
        linker = Path('/usr/lib/llvm-18/bin/ld.lld')
        if not linker.is_file():
            if os.environ.get('REQUIRE_CEF_CONSUMER_LLD') == '1':
                self.fail('mandatory LLD18 preflight is unavailable')
            found = shutil.which('ld.lld')
            if not found: self.skipTest('LLD unavailable')
            linker = Path(found)
        version = subprocess.check_output([str(linker),'--version'],text=True,timeout=15)
        if linker == Path('/usr/lib/llvm-18/bin/ld.lld'):
            self.assertIn('LLD 18.',version)
        main = self.root/'main.c'
        main.write_text('extern int result; int main(void){return result==7 ? 0 : 9;}\n')
        exe = self.root/name
        subprocess.run(['gcc','-B'+str(linker.parent),'-fuse-ld=lld',str(main),str(archive),'-o',str(exe)],check=True,capture_output=True)
        return subprocess.run([str(exe)],cwd=self.root,timeout=10,capture_output=True).returncode

    def archive(self, obj, name):
        path = self.root/name
        subprocess.run(['ar','rcs',str(path),str(obj)],check=True,capture_output=True)
        return path

    def test_original_rela_executes_and_crel_reproduces_null_call(self):
        self.assertEqual(self.link(self.archive(self.rela,'rela.a'),'good'),0)
        result = self.link(self.archive(self.crel,'crel.a'),'bad')
        if Path('/usr/lib/llvm-18/bin/ld.lld').is_file():
            self.assertEqual(result, -11)
        else:
            # Some downstream Swift LLD builds accept CREL even when their
            # version banner says 17. Only the exact required LLD18 proof may
            # assert the diagnosed incompatibility.
            self.assertIn(result, (0, -11))
        a,b=subject.object_profile(self.rela.read_bytes()),subject.object_profile(self.crel.read_bytes())
        self.assertEqual(a['relocations'],b['relocations'])
        self.assertGreater(b['crel_sections'],0)

    def test_real_pinned_objcopy_converts_and_preserves_every_relocation(self):
        tool = self.real_tool()
        archive = self.archive(self.crel,'cef_objects.a')
        before = subject.archive_profile(archive,limit=subject.MAX_ARCHIVE)
        proof = subject.install([('lib/cef-static/cef_objects.a',archive)],tool)
        after = subject.archive_profile(archive,limit=subject.MAX_ARCHIVE)
        self.assertEqual(before['sha256'],after['sha256'])
        self.assertEqual(after['crel_sections'],0)
        self.assertEqual(after['relocations'],self.count)
        self.assertEqual(self.link(archive,'fixed'),0)
        self.assertEqual(len(proof['archives']),1)
        self.assertFalse(list(self.root.glob('.cef-crel-*')))
        print('CEF_CREL_PINNED_RELA_VERIFIED',subject.TOOL_SHA256,after['relocations'])


    def test_conversion_preserves_duplicate_member_order(self):
        tool = self.real_tool()
        archive = self.archive(self.crel, 'cef_objects.a')
        subprocess.run(['ar','q',str(archive),str(self.crel)],check=True,capture_output=True)
        before = subject.archive_profile(archive,limit=subject.MAX_ARCHIVE)
        receipt = subject.install([('lib/cef-static/cef_objects.a',archive)],tool)
        after = subject.archive_profile(archive,limit=subject.MAX_ARCHIVE)
        self.assertEqual(before['members'], 2)
        self.assertEqual(before['sha256'], after['sha256'])
        self.assertEqual(after['relocations'], 2*self.count)
        self.assertEqual(receipt['archives']['lib/cef-static/cef_objects.a']['members'], 2)

    def test_path_members_and_comdat_keep_complete_semantics(self):
        tool = self.real_tool()
        directory = self.root/'objects'
        directory.mkdir()
        source = directory/'group.s'
        source.write_text("""
.section .text.ctor,"axG",@progbits,ctor,comdat
.weak ctor
.type ctor,@function
ctor:
  movl $7, result(%rip)
  ret
.data
.globl result
result: .long 0
.section .init_array,"aw",@init_array
.p2align 3
.quad ctor
.section .note.GNU-stack,"",@progbits
""")
        obj = directory/'constructor_comdat_member_with_long_name.o'
        subprocess.run(['gcc','-c',str(source),'-o',str(obj)],check=True,capture_output=True)
        obj.write_bytes(make_crel(obj.read_bytes())[0])
        archive = self.root/'cef_objects.a'
        subprocess.run(['ar','rcsP',str(archive),'objects/constructor_comdat_member_with_long_name.o'],cwd=self.root,check=True,capture_output=True)
        before = subject.archive_profile(archive,limit=subject.MAX_ARCHIVE)
        shutil.rmtree(directory)  # No thin-archive/external member lookup.
        subject.install([('lib/cef-static/cef_objects.a',archive)],tool)
        self.assertEqual(subject.archive_profile(archive,limit=subject.MAX_ARCHIVE)['sha256'],before['sha256'])
        self.assertEqual(self.link(archive,'group-fixed'),0)

    def test_relocation_target_addend_and_group_payload_are_authenticated(self):
        data = self.rela.read_bytes()
        base = subject.object_profile(data)['sha256']
        h = subject.HEADER.unpack_from(data)
        sections = [subject.SECTION.unpack_from(data,h[6]+i*64) for i in range(h[12])]
        rel = next(s for s in sections if s[1]==4 and s[5]>=24)
        for delta in (8,16):  # r_info and explicit addend, not unrelated padding.
            bad = bytearray(data)
            bad[rel[4]+delta] ^= 1
            self.assertNotEqual(subject.object_profile(bad)['sha256'],base)

    def test_failed_or_semantically_wrong_tool_output_leaves_archive_unchanged(self):
        tool = self.root/'mock-tool'
        tool.write_bytes(b'PUBLIC disposable unit-test tool identity')
        archive = self.archive(self.crel,'cef_objects.a')
        original = archive.read_bytes()
        def tamper(command, **kwargs):
            shutil.copyfile(command[-2],command[-1])
            return subprocess.CompletedProcess(command,0)
        with mock.patch.object(subject,'TOOL_SHA256',subject.digest(tool)):
            with mock.patch.object(subject.subprocess,'run',side_effect=tamper):
                with self.assertRaisesRegex(ValueError,'semantics'):
                    subject.install([('lib/cef-static/cef_objects.a',archive)],tool)
            self.assertEqual(archive.read_bytes(),original)
            with mock.patch.object(subject.subprocess,'run',side_effect=subprocess.TimeoutExpired('public-test',600)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    subject.install([('lib/cef-static/cef_objects.a',archive)],tool)
        self.assertEqual(archive.read_bytes(),original)
        self.assertFalse(list(self.root.glob('.cef-crel-*')))

    def test_transport_receipt_keeps_original_before_namespace_hash(self):
        item = dict(source_sha256='a'*64,sha256='b'*64,semantic_sha256='c'*64,
                    members=1,crel_sections=1,relocations=1)
        name = 'lib/cef-static/cef_objects.a'
        receipt = dict(objcopy_sha256=subject.TOOL_SHA256,cef_archives={name:'d'*64},
            affected={name:dict(source_sha256='a'*64,sha256='d'*64)},
            relocation_compatibility=dict(format=subject.FORMAT,tool_sha256=subject.TOOL_SHA256,
                                          archives={name:item}))
        subject.verify_receipt(receipt)
        for location in ('source_sha256','semantic_sha256','crel_sections','members','relocations'):
            bad = copy.deepcopy(receipt)
            bad['relocation_compatibility']['archives'][name][location] = -1 if location.endswith('s') else 'wrong'
            with self.assertRaises(ValueError):
                subject.verify_receipt(bad)

    def test_metadata_target_and_code_tampering_changes_semantic_profile(self):
        data = self.crel.read_bytes()
        h=subject.HEADER.unpack_from(data)
        baseline=subject.object_profile(data)['sha256']
        sections=[subject.SECTION.unpack_from(data,h[6]+i*64) for i in range(h[12])]
        # Flip a genuine machine-code byte, not a serialization offset/padding.
        code=next(s for s in sections if s[2]&4 and s[5])
        bad=bytearray(data); bad[code[4]] ^= 1
        self.assertNotEqual(subject.object_profile(bad)['sha256'],baseline)
        sym=next(s for s in sections if s[1]==2)
        bad=bytearray(data); bad[sym[4]+24+4] ^= 0x10
        self.assertNotEqual(subject.object_profile(bad)['sha256'],baseline)

    def test_wrong_tool_and_tampered_conversion_never_publish(self):
        archive=self.archive(self.crel,'cef_objects.a')
        original=archive.read_bytes()
        tool=self.root/'wrong-tool'; tool.write_bytes(b'not the pinned binary')
        with self.assertRaisesRegex(ValueError,'Unreviewed'):
            subject.install([('lib/cef-static/cef_objects.a',archive)],tool)
        self.assertEqual(archive.read_bytes(),original)

    def test_ordinary_rela_archive_is_byte_identical_and_needs_no_new_tool(self):
        archive=self.archive(self.rela,'normal.a')
        original=archive.read_bytes()
        tool=Path(shutil.which('objcopy'))
        with mock.patch.object(subject.subprocess,'run',side_effect=AssertionError('unexpected rewrite')):
            receipt=subject.install([('normal',archive)],tool)
        self.assertEqual(receipt['archives'],{})
        self.assertEqual(archive.read_bytes(),original)


if __name__=='__main__':
    unittest.main()
