"""Independent ELF CLI checks do not confuse static libraries with static tools."""
import hashlib
from pathlib import Path
import struct
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from secure_release import multimedia_tools as tools


def elf(segment=1, dynamic_tag=0):
    data = bytearray(144)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 2, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<I", data, 64, segment)
    struct.pack_into("<Q", data, 72, 128)
    struct.pack_into("<Q", data, 96, 16)
    struct.pack_into("<q", data, 128, dynamic_tag)
    return bytes(data)


class StaticToolsTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux" and shutil.which("cc"), "Native ELF compiler required")
    def test_real_static_executable_passes_and_dynamic_executable_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "main.c"
            source.write_text("int main(void){return 0;}\n")
            static = root / "static"
            result = subprocess.run(["cc", "-static", str(source), "-o", str(static)], capture_output=True)
            if result.returncode:
                self.skipTest("System static C runtime unavailable")
            tools.static_elf(static.read_bytes())
            dynamic = root / "dynamic"
            subprocess.run(["cc", str(source), "-o", str(dynamic)], check=True, capture_output=True)
            with self.assertRaises(ValueError):
                tools.static_elf(dynamic.read_bytes())

    def test_static_and_static_pie_tables_without_needed_are_allowed(self):
        tools.static_elf(elf())
        tools.static_elf(elf(segment=2))

    def test_interpreter_needed_wrong_architecture_and_truncation_are_fatal(self):
        for data in (elf(segment=3), elf(segment=2, dynamic_tag=1), elf()[:80], b"MZ" + elf()[2:]):
            with self.assertRaises(ValueError):
                tools.static_elf(data)

    def test_publisher_binds_both_actual_tool_bytes_and_runtime_result(self):
        data = elf()
        record = {"sha256": hashlib.sha256(data).hexdigest(), "dt_needed": 0, "interpreter": False}
        proof = {"tools": {"ffmpeg": dict(record), "ffprobe": dict(record)}, "h264_roundtrip": True}
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / "sdk.zip"
            with zipfile.ZipFile(archive, "w") as sdk:
                for name in proof["tools"]:
                    sdk.writestr("installed/x64-linux-static-release/tools/ffmpeg/" + name, data)
            tools.validate_archive(archive, proof)
            proof["tools"]["ffprobe"]["sha256"] = "a" * 64
            with self.assertRaises(ValueError):
                tools.validate_archive(archive, proof)


if __name__ == "__main__":
    unittest.main()
