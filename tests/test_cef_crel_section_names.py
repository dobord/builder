"""ELF relocation names are '.crel' + target name, not always '.crel.'.

Producer rule: llvm/lib/MC/ELFObjectWriter.cpp, createRelocationSection,
Chromium LLVM 53d18800. Names are exact ELF identifiers, not filesystem paths
or response-file syntax. Never infer the relocation target from a name alone.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_cef_crel as encoding
from secure_release import cef_crel as subject


def object_fixture(target="__llvm_prf_data", relocation=None, info=3):
    """Small explicit ELF64 ET_REL with one genuine pointer relocation."""
    if relocation is None:
        relocation = ".crel" + target
    labels = ["", ".shstrtab", ".text", target, relocation, ".symtab", ".strtab"]
    names = bytearray(b"\0")
    offsets = [0]
    for label in labels[1:]:
        offsets.append(len(names))
        names += label.encode("utf-8") + b"\0"
    symbols = bytes(subject.SYMBOL.size) + subject.SYMBOL.pack(1, 0x12, 0, 2, 0, 1)
    # count=1, explicit addend; delta offset=0, symbol=1, R_X86_64_64=1.
    payloads = [b"", bytes(names), b"\xc3", bytes(8), bytes([12, 3, 1, 1]),
                symbols, b"\0ctor\0"]
    metadata = [
        (0, 0, 0, 0, 0, 0),
        (3, 0, 0, 0, 1, 0),
        (1, 6, 0, 0, 1, 0),
        (1, 3, 0, 0, 8, 0),
        (subject.CREL, 0x40, 5, info, 1, 1),
        (2, 0, 6, 1, 8, subject.SYMBOL.size),
        (3, 0, 0, 0, 1, 0),
    ]
    raw = bytearray(subject.HEADER.size)
    sections = [bytes(subject.SECTION.size)]
    for index in range(1, len(labels)):
        kind, flags, link, section_info, align, entsize = metadata[index]
        raw += bytes((-len(raw)) % align)
        offset = len(raw)
        raw += payloads[index]
        sections.append(subject.SECTION.pack(
            offsets[index], kind, flags, 0, offset, len(payloads[index]),
            link, section_info, align, entsize,
        ))
    raw += bytes((-len(raw)) % 8)
    section_offset = len(raw)
    raw += b"".join(sections)
    subject.HEADER.pack_into(
        raw, 0, b"\x7fELF\x02\x01\x01" + bytes(9), 1, 62, 1,
        0, 0, section_offset, 0, subject.HEADER.size, 0, 0,
        subject.SECTION.size, len(sections), 1,
    )
    return bytes(raw)


def regular_archive(payload):
    name = b"member.o/".ljust(16)
    header = name + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
    header += b"100644".ljust(8) + str(len(payload)).encode().ljust(10) + b"`\n"
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) & 1 else b"")


class NamePolicyTests(unittest.TestCase):
    def test_dotted_and_undotted_targets_bind_the_exact_sh_info_name(self):
        for target in (".text", ".init_array", ".data.rel.ro._ZTV4Test",
                       "__llvm_prf_data", "__sancov_pcs", "fixture$part+1-2"):
            with self.subTest(target=target):
                result = subject.object_profile(object_fixture(target))
                self.assertEqual(result["names"], [".crel" + target])
                self.assertEqual(result["relocations"], 1)
                self.assertEqual(result["crel_sections"], 1)

    def test_added_dot_or_mismatched_target_is_not_accepted(self):
        for name in (".crel.__llvm_prf_data", ".crel.text", ".crel__llvm_prf_datb",
                     ".rela__llvm_prf_data", "__llvm_prf_data", ".crel"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "section name"):
                subject.object_profile(object_fixture(relocation=name))

    def test_target_index_is_checked_before_dereference(self):
        for index in (0, 7, 0xffffffff):
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "section links"):
                subject.object_profile(object_fixture(info=index))
        # Valid index, wrong target: do not trust a syntactically plausible name.
        with self.assertRaisesRegex(ValueError, "section name"):
            subject.object_profile(object_fixture(info=2))

    def test_response_file_metacharacters_still_rejected_without_conversion(self):
        targets = ("", "profile=4", "profile name", "profile\n--remove-section=.text",
                   "profile\rname", "profile\tname", "@options", "profile*", "profile?",
                   "profile[0]", 'profile"name', "profile'name", "profile\\name",
                   "profile/name", "profile;name", "profile:name", "pröfile", "profile\x7f")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            tool = root / "not-executed"
            tool.write_bytes(b"public disposable test identity")
            archive = root / "cef_objects.a"
            for target in targets:
                with self.subTest(target=target):
                    original = regular_archive(object_fixture(target))
                    archive.write_bytes(original)
                    with mock.patch.object(subject.subprocess, "run") as process:
                        with self.assertRaises(ValueError):
                            subject.install([("lib/cef-static/cef_objects.a", archive)], tool)
                        process.assert_not_called()
                    self.assertEqual(archive.read_bytes(), original)

    def test_change_in_target_identity_changes_the_full_semantic_profile(self):
        original = subject.object_profile(object_fixture("__llvm_prf_data"))
        other = subject.object_profile(object_fixture("__sancov_pcs"))
        self.assertNotEqual(original["sha256"], other["sha256"])


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("gcc")
                     and shutil.which("ar"), "native ELF assembler")
class NativeNamesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.source = self.root / "names.s"
        self.source.write_text('''
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
.section __llvm_prf_data,"aw",@progbits
.p2align 3
.quad ctor
.section __sancov_pcs,"aw",@progbits
.p2align 3
.quad ctor
.section .note.GNU-stack,"",@progbits
''', encoding="ascii")
        self.obj = self.root / "names.o"
        self.run_tool(["gcc", "-c", self.source, "-o", self.obj])
        self.rela = self.obj.read_bytes()
        self.crel, self.count = encoding.make_crel(self.rela)
        self.obj.write_bytes(self.crel)

    def run_tool(self, args):
        return subprocess.run(list(map(str, args)), cwd=self.root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)

    def test_real_assembler_names_reproduce_the_old_overstrict_regex(self):
        profile = subject.object_profile(self.crel)
        self.assertEqual(profile["relocations"], self.count)
        self.assertEqual(set(profile["names"]), {
            ".crel.text", ".crel.init_array", ".crel__llvm_prf_data", ".crel__sancov_pcs",
        })
        old = re.compile(r"\.crel\.[A-Za-z0-9_.$+\-]+")
        self.assertIsNone(old.fullmatch(".crel__llvm_prf_data"))
        self.assertIsNone(old.fullmatch(".crel__sancov_pcs"))

    def test_real_clang_crel_writer_uses_the_same_nondotted_names(self):
        clang = shutil.which("clang")
        if not clang:
            self.skipTest("optional local LLVM producer")
        help_text = self.run_tool([clang, "-cc1as", "--help"]).stdout.decode()
        if "--crel" not in help_text:
            self.skipTest("local LLVM producer predates CREL")
        obj = self.root / "llvm.o"
        self.run_tool([clang, "-cc1as", "-triple", "x86_64-unknown-linux-gnu",
                       "--crel", "-filetype", "obj", "-o", obj, self.source])
        profile = subject.object_profile(obj.read_bytes())
        self.assertIn(".crel__llvm_prf_data", profile["names"])
        self.assertIn(".crel__sancov_pcs", profile["names"])
        self.assertEqual(profile["relocations"], self.count)

    def test_pinned_conversion_preserves_semantics_and_relocated_startup(self):
        # Mandatory real converter in GitHub CI; no synthetic replacement or
        # tool-hash override. Offline local runs may explicitly skip this test.
        tool = encoding.pinned_tool(self.root)
        archive = self.root / "cef_objects.a"
        self.run_tool(["ar", "rcs", archive, self.obj])
        before = subject.archive_profile(archive, limit=subject.MAX_ARCHIVE)
        receipt = subject.install([("lib/cef-static/cef_objects.a", archive)], tool)
        after = subject.archive_profile(archive, limit=subject.MAX_ARCHIVE)
        self.assertEqual(before["sha256"], after["sha256"])
        self.assertEqual(after["crel_sections"], 0)
        self.assertEqual(after["relocations"], self.count)
        self.assertEqual(receipt["archives"]["lib/cef-static/cef_objects.a"]["crel_sections"], 4)
        self.assertFalse(list(self.root.glob(".cef-crel-*")))
        moved = self.root / "relocated"
        moved.mkdir()
        final_archive = moved / archive.name
        archive.rename(final_archive)
        self.source.unlink()
        self.obj.unlink()
        self.assertEqual(after, subject.archive_profile(final_archive, limit=subject.MAX_ARCHIVE))
        main = moved / "main.c"
        main.write_text("extern int result; int main(void){return result == 7 ? 0 : 9;}\n")
        lld = Path("/usr/lib/llvm-18/bin/ld.lld")
        if not lld.is_file():
            if os.environ.get("REQUIRE_CEF_CONSUMER_LLD") == "1":
                self.fail("required LLD18 consumer preflight is unavailable")
            other = shutil.which("ld.lld")
            if not other:
                self.skipTest("optional local LLD execution")
            lld = Path(other)
        else:
            version = self.run_tool([lld, "--version"]).stdout.decode()
            self.assertIn("LLD 18.", version)
        exe = moved / "probe"
        self.run_tool(["gcc", "-B" + str(lld.parent), "-fuse-ld=lld", main, final_archive,
                       "-o", exe])
        self.run_tool([exe])
        print("CEF_CREL_EXACT_SECTION_NAMES_VERIFIED", subject.TOOL_SHA256, self.count)


if __name__ == "__main__":
    unittest.main()
