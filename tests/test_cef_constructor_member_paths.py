"""Regular ar member identifiers are not extraction paths or basenames."""
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_constructor_inputs as subject
from secure_release import cef_constructor_map as maps


def slot(archive: Path, member: str, number: int = 0) -> dict:
    return {
        "kind": "inside-input", "section": ".init_array", "slot": number,
        "input": {"owner": str(archive) + "(" + member + ")",
                  "section": ".init_array", "size": 8, "alignment": 8},
        "offset_in_input": 0,
    }


class IdentifierTests(unittest.TestCase):
    def test_noncanonical_names_fail_before_reading_archive(self):
        # Only the fixed archive path is filesystem authority. Nevertheless,
        # malformed/ambiguous member spellings must not become name aliases.
        names = ("", "/unit.o", "//host/unit.o", "../unit.o", "dir/../unit.o",
                 "./unit.o", "dir/./unit.o", "dir//unit.o", "dir/", ".", "..",
                 "dir\\unit.o", "C:unit.o", "dir/\x00unit.o", "dir/\tunit.o",
                 "dir/\nunit.o", "dir/\runit.o", "dir/\x7funit.o", "x" * 4097)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            for name in names:
                with self.subTest(name=repr(name)[:60]), \
                     mock.patch.object(subject, "_regular") as regular, \
                     mock.patch.object(subject, "_members") as members:
                    with self.assertRaisesRegex(ValueError, "member identifier"):
                        subject.inspect_inputs(root, [slot(root / "cef_objects.a", name)])
                    regular.assert_not_called()
                    members.assert_not_called()

    def test_member_name_bound_is_utf8_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            name = "folder/" + "\u00e9" * 2048
            with mock.patch.object(subject, "_regular") as regular:
                with self.assertRaisesRegex(ValueError, "member identifier"):
                    subject.inspect_inputs(root, [slot(root / "cef_objects.a", name)])
                regular.assert_not_called()


@unittest.skipUnless(sys.platform.startswith("linux"), "native Linux ar/ELF")
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("gcc-14") or shutil.which("gcc")
        cls.ar = shutil.which("ar")
        if not cls.cc or not cls.ar:
            if os.environ.get("REQUIRE_CEF_CONSUMER_LLD") == "1":
                raise AssertionError("Required constructor archive tools missing")
            raise unittest.SkipTest("native GNU archive tools missing")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.base = self.root / "consumer-sdk/installed/x64-linux-static-release/lib/cef-static"
        self.base.mkdir(parents=True)
        self.archive = self.base / "cef_0001_0123456789ab.a"
        self.producer = self.root / "producer"
        self.producer.mkdir()
        self.names = ("left_directory_name/unit.o", "right_directory_name/unit.o")
        self.payloads = {}

    def command(self, args, *, cwd=None):
        return subprocess.run(args, cwd=cwd or self.producer, check=True,
                              capture_output=True, timeout=30)

    def build_archive(self, *, valid=False, llvm=False):
        for index, name in enumerate(self.names):
            obj = self.producer / name
            obj.parent.mkdir(parents=True)
            asm = obj.with_suffix(".s")
            prefix = ""
            if valid:
                prefix = ('.section .text.ctor,"ax",@progbits\n'
                          '.local fixture_ctor\n.type fixture_ctor,@function\n'
                          'fixture_ctor:\n'
                          f'movl ${index + 7}, fixture_result_{index}(%rip)\nret\n')
                target = "fixture_ctor"
            elif index:
                prefix = '.weak fixture_missing\n.hidden fixture_missing\n'
                target = "fixture_missing"
            else:
                target = "0"
            asm.write_text(prefix + '.section .init_array,"aw",@init_array\n'
                           '.p2align 3\n.quad ' + target + '\n'
                           '.section .note.GNU-stack,"",@progbits\n', encoding="utf-8")
            self.command([self.cc, "-c", str(asm), "-o", str(obj)])
            self.payloads[name] = obj.read_bytes()
        if llvm:
            ar = shutil.which("llvm-ar")
            if ar is None:
                self.skipTest("optional LLVM archive conversion fixture")
            self.command([ar, "crsT", "thin.a", *self.names])
            self.command([ar, "qcsDL", str(self.archive), "thin.a"])
        else:
            self.command([self.ar, "rcsP", str(self.archive), *self.names])
        self.assertTrue(self.archive.read_bytes().startswith(b"!<arch>\n"))
        listing = self.command([self.ar, "t", str(self.archive)]).stdout.decode().splitlines()
        self.assertEqual(listing, list(self.names))
        return [slot(self.archive, name, index) for index, name in enumerate(self.names)]

    def inspect_unchanged(self, slots):
        before = self.archive.stat()
        sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        result = subject.inspect_inputs(self.base, slots)
        after = self.archive.stat()
        self.assertEqual((before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        self.assertEqual(sha, hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertNotIn("constructor_integrity_verified", result["summary"])
        self.assertNotIn("unit.o", repr(result["summary"]))
        self.assertNotIn("fixture_missing", repr(result["summary"]))
        return result

    def test_regular_path_members_match_exactly_after_producer_removal(self):
        slots = self.build_archive()
        shutil.rmtree(self.producer)
        before = set(self.root.rglob("*"))
        # Poisoned paths with the same spellings are never opened/extracted.
        for name in self.names:
            path = self.base / name
            path.parent.mkdir(parents=True)
            path.write_bytes(b"not an ELF; never read")
        after_poison = set(self.root.rglob("*"))
        result = self.inspect_unchanged(slots)
        self.assertEqual(set(self.root.rglob("*")), after_poison)
        self.assertLess(len(before), len(after_poison))
        self.assertEqual(result["summary"]["constructor_input_matched_count"], 2)
        self.assertEqual(result["summary"]["constructor_input_without_relocation_count"], 1)
        self.assertEqual(result["summary"]["constructor_input_undefined_weak_count"], 1)
        for record in result["details"]:
            self.assertEqual(record["candidates"][0]["member_sha256"],
                             hashlib.sha256(self.payloads[record["member"]]).hexdigest())

    def test_llvm_thin_to_regular_keeps_path_identifiers_without_external_reads(self):
        slots = self.build_archive(llvm=True)
        shutil.rmtree(self.producer)
        result = self.inspect_unchanged(slots)
        self.assertEqual(result["summary"]["constructor_input_matched_count"], 2)
        self.assertEqual(result["summary"]["constructor_input_undefined_weak_count"], 1)

    def test_basename_case_and_other_directory_are_not_aliases(self):
        slots = self.build_archive()
        for member in ("unit.o", "other_directory_name/unit.o", "LEFT_directory_name/unit.o"):
            with self.subTest(member=member):
                result = self.inspect_unchanged([slot(self.archive, member)])
                self.assertEqual(result["summary"]["constructor_input_missing_count"], 1)
                self.assertEqual(result["summary"]["constructor_input_matched_count"], 0)

    def test_duplicate_full_member_name_remains_ambiguous(self):
        slots = self.build_archive()
        self.command([self.ar, "qcP", str(self.archive), self.names[0]])
        result = self.inspect_unchanged([slots[0]])
        self.assertEqual(result["summary"]["constructor_input_ambiguous_count"], 1)
        candidates = result["details"][0]["candidates"]
        self.assertEqual(len(candidates), 2)
        self.assertNotEqual(candidates[0]["member_index"], candidates[1]["member_index"])

    def test_path_members_do_not_authorize_thin_archives(self):
        slots = self.build_archive()
        self.archive.unlink()
        self.command([self.ar, "crsT", str(self.archive), *self.names])
        with self.assertRaisesRegex(ValueError, "regular constructor archive"):
            subject.inspect_inputs(self.base, slots)

    def test_archive_root_and_symlink_guards_still_apply(self):
        slots = self.build_archive()
        other = self.root / self.archive.name
        shutil.copyfile(self.archive, other)
        altered = copy.deepcopy(slots[0])
        altered["input"]["owner"] = str(other) + "(" + self.names[0] + ")"
        with self.assertRaises(ValueError):
            subject.inspect_inputs(self.base, [altered])
        self.archive.unlink()
        self.archive.symlink_to(other)
        with self.assertRaises(ValueError):
            subject.inspect_inputs(self.base, slots)

    def linker_flags(self):
        if os.environ.get("REQUIRE_CEF_CONSUMER_LLD") == "1":
            linker = Path("/usr/lib/llvm-18/bin/ld.lld")
            self.assertTrue(linker.is_file(), "Mandatory LLD18 missing")
            version = self.command([str(linker), "--version"]).stdout.decode()
            self.assertRegex(version, r"(?:Ubuntu )?LLD 18\.")
        else:
            found = shutil.which("ld.lld")
            if found is None:
                self.skipTest("LLD differential fixture")
            linker = Path(found)
        return ["-B" + str(linker.parent), "-fuse-ld=lld"]

    def final_map(self, *, valid):
        self.build_archive(valid=valid)
        build = self.root / "consumer-build"
        build.mkdir()
        source = build / "main.c"
        source.write_text('int fixture_result_0, fixture_result_1;\n'
                          'int main(void){return fixture_result_0 == 7 && '
                          'fixture_result_1 == 8 ? 0 : 2;}\n', encoding="utf-8")
        exe, mapping = build / "probe", build / maps.MAP_NAME
        self.command([self.cc, *self.linker_flags(), "-no-pie", str(source),
                      "-Wl,--whole-archive", str(self.archive), "-Wl,--no-whole-archive",
                      "-Wl,-Map=" + str(mapping), "-o", str(exe)])
        shutil.rmtree(self.producer)
        raw = exe.read_bytes()
        h = subject.HEADER.unpack_from(raw)
        table = [subject.SECTION.unpack_from(raw, h[6] + i * subject.SECTION.size)
                 for i in range(h[12])]
        names = raw[table[h[13]][4]:table[h[13]][4] + table[h[13]][5]]
        sections = [dict(name=names[s[0]:].split(b"\0", 1)[0].decode(),
                         addr=s[3], size=s[5], align=s[8], offset=s[4]) for s in table]
        init = next(s for s in sections if s["name"] == ".init_array")
        bad = [dict(reason="zero-unrelocated", section=".init_array", slot=i)
               for i in range(init["size"] // 8)
               if struct.unpack_from("<Q", raw, init["offset"] + 8 * i)[0] == 0]
        archive_before = self.archive.read_bytes()
        result = maps.inspect_map(mapping, sections, {"bad": bad})
        self.assertEqual(raw, exe.read_bytes())
        self.assertEqual(archive_before, self.archive.read_bytes())
        self.assertNotIn("constructor_integrity_verified", result["summary"])
        self.assertNotIn("unit.o", repr(result["summary"]))
        return result, exe, bad

    def test_real_lld_map_reaches_both_input_relocations_not_padding(self):
        result, _, bad = self.final_map(valid=False)
        self.assertEqual(len(bad), 2)
        self.assertEqual(result["summary"]["constructor_zero_inside_input_count"], 2)
        self.assertEqual(result["summary"]["constructor_zero_linker_padding_count"], 0)
        self.assertEqual(result["summary"]["constructor_input_matched_count"], 2)
        self.assertEqual(result["summary"]["constructor_input_without_relocation_count"], 1)
        self.assertEqual(result["summary"]["constructor_input_undefined_weak_count"], 1)
        self.assertEqual(len(result["details"]["input_relocations"]), 2)

    def test_valid_path_named_constructors_execute_after_producer_removal(self):
        result, exe, bad = self.final_map(valid=True)
        self.assertEqual(bad, [])
        self.assertEqual(result["summary"]["constructor_zero_inside_input_count"], 0)
        self.assertEqual(subprocess.run([str(exe)], timeout=10).returncode, 0)


if __name__ == "__main__":
    unittest.main()
