from __future__ import annotations

import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from secure_release import cef_elf_init as subject


class PolicyTests(unittest.TestCase):
    def test_constants_are_exact_for_supported_linux_profile(self):
        self.assertEqual(subject.ET_DYN, 3)
        self.assertEqual(subject.R_X86_64_RELATIVE, 8)
        self.assertEqual(subject.R_X86_64_IRELATIVE, 37)
        self.assertEqual(subject.DT_INIT_ARRAY, 25)
        self.assertEqual(subject.DT_PREINIT_ARRAY, 32)


@unittest.skipUnless(sys.platform.startswith("linux"), "native ELF regression")
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cxx = shutil.which("g++") or shutil.which("c++")
        if cls.cxx is None:
            raise unittest.SkipTest("native C++ compiler unavailable")

    def build(self, root: Path) -> Path:
        source = root / "main.cpp"
        source.write_text(
            """
struct Startup {
  Startup() noexcept { value = 7; }
  static volatile int value;
};
volatile int Startup::value = 0;
Startup startup;
int main() { return Startup::value == 7 ? 0 : 3; }
""",
            encoding="utf-8",
        )
        output = root / "probe"
        subprocess.run(
            [self.cxx, "-std=c++17", "-O0", "-no-pie", source, "-o", output],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        return output

    def test_real_executable_constructor_table_is_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            executable = self.build(Path(folder))
            result = subject.audit(executable)
            summary = result["summary"]
            self.assertTrue(summary["constructor_integrity_verified"])
            self.assertGreater(summary["constructor_entry_count"], 0)
            self.assertEqual(summary["constructor_zero_unrelocated_count"], 0)
            self.assertEqual(subprocess.run([executable], timeout=10).returncode, 0)

    def test_zero_constructor_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = self.build(root)
            broken = root / "broken"
            shutil.copy2(executable, broken)
            with broken.open("r+b") as stream, mmap.mmap(stream.fileno(), 0) as data:
                _, sections = subject._section_table(data)
                init = next(item for item in sections if item["name"] == ".init_array")
                self.assertGreaterEqual(init["size"], 8)
                data[init["offset"]:init["offset"] + 8] = struct.pack("<Q", 0)
                data.flush()
            result = subject.audit(broken)
            self.assertFalse(result["summary"]["constructor_integrity_verified"])
            self.assertGreater(
                result["summary"]["constructor_zero_unrelocated_count"], 0
            )


if __name__ == "__main__":
    unittest.main()
