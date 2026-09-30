"""Native LLD provenance, distinguish embedded NULLs from alignment padding."""
from __future__ import annotations

import hashlib
import json
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_constructor_map as subject, cef_elf_init


@unittest.skipUnless(sys.platform == "linux", "native Linux linker map")
class NativeTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("cc") or not shutil.which("ld.lld"):
            self.skipTest("native compiler and LLD required")
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)

    def build(self, alignment=8, null_slot=False):
        source = self.root / "constructor.c"
        source.write_text(
            "static void init(void){}\n"
            '__attribute__((used,section(".init_array"),aligned('
            + str(alignment) + '))) static void(*const array[])(void)={'
            + ("0," if null_slot else "") + "init};\n"
            "int main(void){return 0;}\n",
            encoding="utf-8",
        )
        obj = self.root / "constructor.o"
        lib = self.root / "provider.a"
        exe = self.root / "consumer"
        map_path = self.root / subject.MAP_NAME
        subprocess.run(["cc", "-c", source, "-o", obj], check=True, capture_output=True)
        subprocess.run(["ar", "rcs", lib, obj], check=True, capture_output=True)
        command = ["cc", "-fuse-ld=lld", "-Wl,--whole-archive", lib,
                   "-Wl,--no-whole-archive", "-o", exe]
        subprocess.run(command, check=True, capture_output=True)
        before = exe.read_bytes()
        subprocess.run(command + ["-Wl,-Map=" + str(map_path)], check=True, capture_output=True)
        self.assertEqual(before, exe.read_bytes(), "map diagnostics changed ELF bytes")
        return exe, map_path

    def inspect(self, exe, map_path):
        with exe.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            _, sections = cef_elf_init._section_table(data)
            bad = []
            for s in sections:
                if s["name"] != ".init_array":
                    continue
                # Native fixture with -no-pie is not needed here: get NULL
                # slots from audit for align8, synthesize known padding only
                # in the separate over-alignment fixture below.
                if s["align"] == 8:
                    bad = cef_elf_init.audit(exe)["details"]["bad"]
                else:
                    # In this minimal PIE both real constructor pointers have
                    # RELA; the alignment gap has no relocation.
                    rela_offsets = set()
                    for r in sections:
                        if r["type"] == cef_elf_init.SHT_RELA:
                            for off in range(r["offset"], r["offset"] + r["size"], 24):
                                rela_offsets.add(struct.unpack_from("<Q", data, off)[0])
                    for i in range(s["size"] // 8):
                        if (s["addr"] + 8*i not in rela_offsets
                                and struct.unpack_from("<Q", data, s["offset"] + 8*i)[0] == 0):
                            bad.append({"reason": "zero-unrelocated", "section": ".init_array", "slot": i})
            return subject.inspect_map(map_path, sections, {"bad": bad})

    def test_null_inside_archive_input_is_not_linker_padding(self):
        exe, path = self.build(null_slot=True)
        result = self.inspect(exe, path)
        self.assertEqual(result["summary"]["constructor_zero_inside_input_count"], 1)
        self.assertEqual(result["summary"]["constructor_zero_linker_padding_count"], 0)
        self.assertIn("provider.a(constructor.o)", result["details"]["zero_slots"][0]["input"]["owner"])
        self.assertNotIn("provider", json.dumps(result["summary"]))
        self.assertFalse(cef_elf_init.audit(exe)["summary"]["constructor_integrity_verified"])

    def test_overalignment_gap_is_not_blamed_on_archive_bytes(self):
        exe, path = self.build(alignment=16)
        result = self.inspect(exe, path)
        self.assertEqual(result["summary"]["constructor_zero_linker_padding_count"], 1)
        self.assertEqual(result["summary"]["constructor_zero_inside_input_count"], 0)

    def test_success_retains_strict_elf_proof_and_empty_bad_slots(self):
        exe, path = self.build()
        result = cef_elf_init.audit(exe)
        self.assertTrue(result["summary"]["constructor_integrity_verified"])
        self.assertTrue(result["summary"]["constructor_source_map_available"])
        self.assertEqual(result["details"]["source_map"]["zero_slots"], [])
        self.assertEqual(result["summary"]["constructor_source_map_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(subprocess.run([exe], timeout=10).returncode, 0)

    def test_missing_redirected_and_oversized_maps_are_not_evidence(self):
        exe, path = self.build()
        text = path.read_bytes()
        path.unlink()
        self.assertFalse(cef_elf_init.audit(exe)["summary"]["constructor_source_map_available"])
        other = self.root / "outside.map"
        other.write_bytes(text)
        path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "redirected"):
            cef_elf_init.audit(exe)
        path.unlink()
        path.write_bytes(text)
        with mock.patch.object(subject, "MAX_MAP_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "bounds"):
                cef_elf_init.audit(exe)

    def test_stale_range_and_malformed_rows_are_rejected(self):
        exe, path = self.build()
        text = path.read_text()
        path.write_text(text.replace("VMA", "OLD", 1))
        with self.assertRaisesRegex(ValueError, "header"):
            cef_elf_init.audit(exe)
        lines = text.splitlines(keepends=True)
        for i, line in enumerate(lines):
            if line.rstrip().endswith(" .init_array"):
                parts = line.split()
                parts[2] = "ffff"
                lines[i] = " ".join(parts) + "\n"
                break
        path.write_text("".join(lines))
        with self.assertRaisesRegex(ValueError, "disagrees"):
            cef_elf_init.audit(exe)
        path.write_text(text + "invalid row\n")
        with self.assertRaisesRegex(ValueError, "malformed"):
            cef_elf_init.audit(exe)


if __name__ == "__main__":
    unittest.main()
