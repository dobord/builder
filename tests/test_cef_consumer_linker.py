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

from secure_release import cef_consumer_linker as subject

ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def test_constructor_map_keeps_input_metadata_private(self):
        from secure_release import cef_constructor_map as maps
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            build = root / 'consumer-build'
            build.mkdir()
            mapping = build / maps.MAP_NAME
            def row(tail):
                return f'{0x1000:x} {0x1000:x} 8 8 {tail}\n'
            mapping.write_text('VMA LMA Size Align Out In Symbol\n'
                + row('.init_array') + row('        example.a(ctor.o):(.init_array)'),
                encoding='utf-8')
            sections = [dict(name='.init_array', addr=0x1000, size=8, align=8)]
            details = {'bad': [dict(reason='zero-unrelocated', section='.init_array', slot=0)]}
            evidence = {'summary': {'constructor_input_matched_count': 1},
                        'details': [{'symbol': 'private-fixture-constructor'}]}
            with mock.patch.object(maps.cef_constructor_inputs, 'inspect_inputs', return_value=evidence) as inspect_inputs:
                result = maps.inspect_map(mapping, sections, details)
            inspect_inputs.assert_called_once_with(
                root / 'consumer-sdk/installed/x64-linux-static-release/lib/cef-static',
                result['details']['zero_slots'])
            self.assertEqual(result['summary']['constructor_input_matched_count'], 1)
            self.assertEqual(result['summary']['constructor_zero_inside_input_count'], 1)
            self.assertEqual(result['details']['input_relocations'], evidence['details'])
            self.assertNotIn('private-fixture-constructor', repr(result['summary']))
            self.assertNotIn('constructor_integrity_verified', result['summary'])

    def test_pinned_ubuntu_lld_profile_and_cmake_flag(self):
        self.assertEqual(subject.GXX, Path("/usr/bin/g++-14"))
        self.assertEqual(subject.LLD_DIR, Path("/usr/lib/llvm-18/bin"))
        self.assertEqual(subject.LLD_MAJOR, 18)
        self.assertEqual(
            subject.cmake_flag(),
            "-DCMAKE_EXE_LINKER_FLAGS=-B/usr/lib/llvm-18/bin -fuse-ld=lld -static-libstdc++ -static-libgcc -Wl,-Map=cef-consumer-link.map",
        )

    def test_workflow_installs_and_preflights_lld_before_restore(self):
        flow = (ROOT / ".github/workflows/cef-strict-combined.yml").read_text()
        self.assertIn("g++-14", flow)
        self.assertIn("lld-18", flow)
        self.assertIn("gdb", flow)
        self.assertIn("autoconf", flow)
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
            'summary["consumer_linker_static_gcc_runtime"]',
            'summary["consumer_linker_os_needed_count"]',
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
        self.assertTrue(receipt["static_gcc_runtime"])
        self.assertNotIn("libstdc++.so.6", receipt["needed"])
        self.assertNotIn("libgcc_s.so.1", receipt["needed"])
        self.assertFalse(set(receipt["needed"]) - subject.cef_x11_static.OS_NEEDED)

    def test_required_ubuntu_lld18_profile(self):
        if os.environ.get("REQUIRE_CEF_CONSUMER_LLD") != "1":
            self.skipTest("Exact Ubuntu LLD18 is a combined-CI requirement")
        with tempfile.TemporaryDirectory() as name:
            receipt = subject.verify(Path(name))
        self.assertEqual(receipt["major"], 18)
        self.assertRegex(receipt["sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(receipt["static_gcc_runtime"])
        self.assertFalse(set(receipt["needed"]) - subject.cef_x11_static.OS_NEEDED)


def load_tests(loader, standard_tests, pattern):
    # The Strict workflow invokes this exact preflight before restore. Full
    # discovery already loads the new module, so do not run it twice there.
    if pattern == "test_cef_consumer_linker.py":
        import test_cef_constructor_member_paths as regression
        import test_cef_crel as crel
        import test_cef_crel_transport as transport
        import test_cef_crel_section_names as section_names
        import test_cef_objcopy_groups as groups
        import test_cef_runtime_symbols as runtime_symbols
        import test_cef_constructor_map_scale as map_scale
        standard_tests.addTests(loader.loadTestsFromModule(regression))
        standard_tests.addTests(loader.loadTestsFromModule(crel))
        standard_tests.addTests(loader.loadTestsFromModule(transport))
        standard_tests.addTests(loader.loadTestsFromModule(section_names))
        standard_tests.addTests(loader.loadTestsFromModule(groups))
        standard_tests.addTests(loader.loadTestsFromModule(runtime_symbols))
        standard_tests.addTests(loader.loadTestsFromModule(map_scale))
    return standard_tests


if __name__ == "__main__":
    unittest.main()
