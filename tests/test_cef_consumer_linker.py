from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from secure_release import cef_consumer_linker as subject

ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def test_pinned_ubuntu_lld_profile_and_cmake_flag(self):
        self.assertEqual(subject.GXX, Path("/usr/bin/g++-14"))
        self.assertEqual(subject.LLD_DIR, Path("/usr/lib/llvm-18/bin"))
        self.assertEqual(subject.LLD_MAJOR, 18)
        self.assertEqual(
            subject.CXX_RUNTIME_FLAGS,
            ("-static-libstdc++", "-static-libgcc"),
        )
        self.assertEqual(
            subject.cmake_flag(),
            "-DCMAKE_EXE_LINKER_FLAGS=-B/usr/lib/llvm-18/bin -fuse-ld=lld "
            "-static-libstdc++ -static-libgcc",
        )

    def test_workflow_installs_and_preflights_lld_before_restore(self):
        flow = (ROOT / ".github/workflows/cef-strict-combined.yml").read_text()
        self.assertIn("g++-14 lld-18 autoconf", flow)
        self.assertIn("REQUIRE_CEF_CONSUMER_LLD: '1'", flow)
        self.assertLess(
            flow.index("test_cef_consumer_linker.py -v"),
            flow.index("Run checkpoint-resumed final combined SDK qualification"),
        )

    def test_combined_uses_same_verified_lld_for_both_final_consumers(self):
        from secure_release import cef_strict_combined as combined
        import inspect
        source = inspect.getsource(combined.main)
        self.assertLess(
            source.index("cef_consumer_linker.verify(root)"),
            source.index('stage = "checkpoint-restore"'),
        )
        self.assertEqual(source.count("cef_consumer_linker.cmake_flag()"), 2)
        self.assertLess(
            source.index("configure.append(cef_consumer_linker.cmake_flag())"),
            source.index('stage = "combined-consumer-sdk-build"'),
        )
        self.assertLess(
            source.index("proxy_configure.append(cef_consumer_linker.cmake_flag())"),
            source.index("lfc-ui-freerdp-cef-build.log"),
        )
        for field in (
            'summary["consumer_linker_kind"]',
            'summary["consumer_linker_version"]',
            'summary["consumer_linker_sha256"]',
        ):
            self.assertIn(field, source)


@unittest.skipUnless(sys.platform == "linux", "Linux LLD proof")
class NativeTests(unittest.TestCase):
    def test_available_lld_is_selected_by_gcc_driver_and_links(self):
        found = shutil.which("ld.lld")
        gxx = shutil.which("g++-14")
        if not found or not gxx:
            self.skipTest("Local GCC14/LLD pair is unavailable")
        linker = Path(found)
        version = subprocess.check_output(
            [str(linker), "--version"], text=True, timeout=30
        ).strip()
        match = re.search(r"(?:Ubuntu )?LLD (\d+)\.", version)
        if match is None:
            self.skipTest("Local linker is not GNU-compatible LLD")
        with tempfile.TemporaryDirectory() as name:
            receipt = subject._verify(
                Path(name), gxx=Path(gxx), lld_dir=linker.parent,
                major=int(match.group(1)),
            )
        self.assertEqual(receipt["kind"], "lld")
        self.assertEqual(receipt["version"], version)
        self.assertTrue(receipt["cxx_runtime_static"])
        self.assertNotIn("libstdc++.so.6", receipt["probe_needed"])
        self.assertNotIn("libgcc_s.so.1", receipt["probe_needed"])

    def test_required_ubuntu_lld18_profile(self):
        if os.environ.get("REQUIRE_CEF_CONSUMER_LLD") != "1":
            self.skipTest("Exact Ubuntu LLD18 is a combined-CI requirement")
        with tempfile.TemporaryDirectory() as name:
            receipt = subject.verify(Path(name))
        self.assertEqual(receipt["major"], 18)
        self.assertRegex(receipt["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(receipt["cxx_runtime_static"])
        self.assertTrue(receipt["probe_needed"])
        self.assertFalse(
            {"libstdc++.so.6", "libgcc_s.so.1"} & set(receipt["probe_needed"])
        )


if __name__ == "__main__":
    unittest.main()
