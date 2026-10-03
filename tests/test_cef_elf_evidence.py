"""Bounded public evidence tests; not CEF runtime qualification."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from secure_release import cef_elf_evidence as evidence


class NativeElfEvidenceTests(unittest.TestCase):
    def test_exact_basenames_and_fixed_families(self):
        text = "\n".join((
            " 0x1 (NEEDED) Shared library: [libc.so.6]",
            " 0x1 (NEEDED) Shared library: [libm.so.6]",
            " 0x1 (NEEDED) Shared library: [libX11.so.6]",
            " 0x1 (NEEDED) Shared library: [libstdc++.so.6]",
        ))
        result = evidence.classify_readelf(text)
        self.assertEqual(result["runtime_native_elf_unexpected_names"],
                         ["libX11.so.6", "libstdc++.so.6"])
        self.assertEqual(result["runtime_native_elf_unexpected_x11_count"], 1)
        self.assertEqual(result["runtime_native_elf_unexpected_cxx_count"], 1)
        self.assertEqual(result["runtime_native_elf_unexpected_other_count"], 0)

    def test_path_like_and_unbounded_names_are_rejected(self):
        for name in ("/tmp/libX11.so.6", "../libX11.so.6", "x" * 97):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.classify_readelf(
                    f" 0x1 (NEEDED) Shared library: [{name}]\n")

    def test_inspect_cross_checks_authoritative_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            exe = source / "out/CEF_Static_Platform_Release_x64/cef_static_smoke"
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"fixture")
            text = (" 0x1 (NEEDED) Shared library: [libc.so.6]\n"
                    " 0x1 (NEEDED) Shared library: [libgbm.so.1]\n")
            completed = subprocess.CompletedProcess([], 0, text, "")
            with patch.object(evidence.subprocess, "run", return_value=completed):
                result = evidence.inspect(source, expected_needed=2, expected_unexpected=1)
                self.assertEqual(result["runtime_native_elf_unexpected_names"], ["libgbm.so.1"])
                with self.assertRaises(RuntimeError):
                    evidence.inspect(source, expected_needed=3, expected_unexpected=1)
                with self.assertRaises(RuntimeError):
                    evidence.inspect(source, expected_needed=2, expected_unexpected=2)


if __name__ == "__main__":
    unittest.main()
