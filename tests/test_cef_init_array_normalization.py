"""Native regressions for binary archive framing and startup alignment transport."""
from __future__ import annotations

import ast
import hashlib
import inspect
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from secure_release import cef_boringssl_isolation as isolation


def ar_member(name: bytes, data: bytes) -> bytes:
    header = (name.ljust(16) + b"0".ljust(12) + b"0".ljust(6)
              + b"0".ljust(6) + b"100644".ljust(8)
              + str(len(data)).encode().ljust(10) + b"`\n")
    assert len(header) == 60
    return header + data + (b"\n" if len(data) & 1 else b"")


class PolicyTests(unittest.TestCase):
    def test_profile_uses_real_delimiters(self):
        records = [(1, ".init_array", 8, 16), (2, ".init_array.101", 8, 8)]
        expected = b"1\t.init_array\t8\t16\n2\t.init_array.101\t8\t8\n"
        self.assertEqual(isolation._profile_sha256(records),
                         hashlib.sha256(expected).hexdigest())

    def test_temporary_profile_uses_source_archive_budget(self):
        tree = ast.parse(inspect.getsource(isolation.install))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == "_init_array_profile"
                 and node.args and isinstance(node.args[0], ast.Name)
                 and node.args[0].id == "temporary"]
        self.assertEqual(len(calls), 1)
        limits = [item.value for item in calls[0].keywords
                  if item.arg == "archive_limit"]
        self.assertEqual(len(limits), 1)
        self.assertEqual(ast.unparse(limits[0]), "_archive_limit(path)")

    def test_binary_archive_framing_and_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "framing.a"
            good = b"!<arch>\n" + ar_member(b"note/", b"x")
            path.write_bytes(good)
            self.assertEqual(list(isolation._ar_elf_payloads(path)), [])
            bad_trailer = bytearray(good)
            bad_trailer[66:68] = b"xx"
            bad_size = bytearray(good)
            bad_size[56:66] = b"9999999999"
            for raw in (b"!<arch>\\n", b"!<thin>\n", good[:-1],
                        good[:-1] + b"x", bytes(bad_trailer),
                        bytes(bad_size), b"!<arch>\n" + b"x"):
                with self.subTest(raw_size=len(raw)):
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        list(isolation._ar_elf_payloads(path))

    def test_sparse_archive_keeps_source_budget_without_large_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "cef_objects.a"
            size = isolation.MAX_SOURCE_ARCHIVE_BYTES + 2
            # Valid sparse non-ELF ar member; no allocation of its large body.
            header = ar_member(b"//", b"")[:60]
            header = header[:48] + str(size).encode().ljust(10) + header[58:]
            with source.open("wb") as stream:
                stream.write(b"!<arch>\n" + header)
                stream.seek(size - 1, os.SEEK_CUR)
                stream.write(b"\0")
            self.assertEqual(isolation._init_array_profile(source), [])
            derived = root / ".cef-bssl-derived.a"
            source.rename(derived)
            with self.assertRaises(ValueError):
                isolation._init_array_profile(derived)
            self.assertEqual(isolation._init_array_profile(
                derived, archive_limit=isolation._archive_limit(source)), [])
            for limit in (True, 1, isolation.safeio.MAX_BYTES + 1):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    isolation._init_array_profile(derived, archive_limit=limit)


@unittest.skipUnless(sys.platform == "linux", "native ELF normalization proof")
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.cc = shutil.which("cc")
        self.ar = shutil.which("ar")
        self.objcopy = shutil.which("llvm-objcopy") or shutil.which("objcopy")
        if not all((self.cc, self.ar, self.objcopy)):
            self.skipTest("native compiler/ar/objcopy required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_tool(self, args):
        return subprocess.run(list(map(str, args)), cwd=self.root, check=True,
                              capture_output=True, timeout=60)

    def object(self, index, alignment, section=".init_array"):
        path = self.root / ("long_constructor_object_name_" + str(index) + ".c")
        path.write_text(
            "extern int seen;\n"
            f"static void ctor_{index}(void){{seen += {index};}}\n"
            f'__attribute__((used,section("{section}"),aligned({alignment})))\n'
            f"static void (*const ptr_{index})(void)=ctor_{index};\n",
            encoding="utf-8",
        )
        obj = path.with_suffix(".o")
        self.run_tool([self.cc, "-c", path, "-o", obj])
        return obj

    def archive(self, objects):
        path = self.root / "cef_objects.a"
        self.run_tool([self.ar, "rcs", path, *objects])
        return path

    def normalize(self, path):
        before = isolation._init_array_profile(path)
        names = sorted({name for _, name, _, align in before if align > 8})
        output = self.root / ".cef-bssl-normalized.a"
        self.run_tool([self.objcopy, *[
            "--set-section-alignment=" + name + "=8" for name in names
        ], path, output])
        after = isolation._init_array_profile(
            output, archive_limit=isolation._archive_limit(path))
        self.assertEqual(after, isolation._normalized_init_array_profile(before))
        return output, before, after

    def test_real_elf_and_long_archive_names_round_trip(self):
        path = self.archive([self.object(1, 16), self.object(2, 8),
                             self.object(3, 16, ".init_array.101")])
        output, before, after = self.normalize(path)
        self.assertEqual([r[3] for r in before], [16, 8, 16])
        self.assertEqual([r[3] for r in after], [8, 8, 8])
        self.assertEqual([r[:3] for r in before], [r[:3] for r in after])
        self.assertNotEqual(isolation.digest(path), isolation.digest(output))
        # Real binary string-table termination, not text escape sequences.
        for _, payload in isolation._ar_elf_payloads(output):
            self.assertTrue(payload.startswith(b"\x7fELF"))
            self.assertTrue(list(isolation._elf_init_array_sections(payload)))

    def test_lld_crash_then_both_constructors_run_after_normalization(self):
        if not shutil.which("ld.lld"):
            self.skipTest("LLD required for alignment-padding reproduction")
        path = self.archive([self.object(1, 16), self.object(2, 16)])
        main = self.root / "main.c"
        main.write_text("int seen; int main(void){return seen == 3 ? 0 : 7;}\n")
        bad = self.root / "bad"
        self.run_tool([self.cc, "-fuse-ld=lld", main, "-Wl,--whole-archive", path,
                       "-Wl,--no-whole-archive", "-o", bad])
        import resource
        def no_core():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = subprocess.run([bad], cwd=self.root, capture_output=True,
                                timeout=10, preexec_fn=no_core)
        self.assertEqual(result.returncode, -11)
        output, _, _ = self.normalize(path)
        good = self.root / "good"
        self.run_tool([self.cc, "-fuse-ld=lld", main, "-Wl,--whole-archive", output,
                       "-Wl,--no-whole-archive", "-o", good])
        self.run_tool([good])

    def test_truncated_or_wrong_elf_magic_rejected(self):
        obj = self.object(1, 16)
        data = obj.read_bytes()
        for bad in (data[:20], b"\\x7fELF" + data[4:]):
            with self.assertRaises(ValueError):
                list(isolation._elf_init_array_sections(bad))


if __name__ == "__main__":
    unittest.main()
