"""Evaluate public triplets in fresh CMake processes; no sources, keys or network."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = r'''
cmake_minimum_required(VERSION 3.25)
include("${TRIPLET_FILE}")
if(NOT DEFINED VCPKG_CRT_LINKAGE OR
   NOT VCPKG_CRT_LINKAGE MATCHES "^(static|dynamic)$")
    message(FATAL_ERROR "TRIPLET_CRT_INVALID")
endif()
if(NOT "${VCPKG_CRT_LINKAGE}" STREQUAL "${EXPECTED_CRT}")
    message(FATAL_ERROR "TRIPLET_CRT_MISMATCH")
endif()
if(NOT "${VCPKG_LIBRARY_LINKAGE}" STREQUAL "static")
    message(FATAL_ERROR "TRIPLET_LIBRARIES_NOT_STATIC")
endif()
if(NOT "${VCPKG_TARGET_ARCHITECTURE}" STREQUAL "x64")
    message(FATAL_ERROR "TRIPLET_ARCHITECTURE_MISMATCH")
endif()
if(NOT "${VCPKG_BUILD_TYPE}" STREQUAL "release")
    message(FATAL_ERROR "TRIPLET_BUILD_TYPE_MISMATCH")
endif()
if(NOT "${VCPKG_CMAKE_SYSTEM_NAME}" STREQUAL "${EXPECTED_SYSTEM}")
    message(FATAL_ERROR "TRIPLET_SYSTEM_MISMATCH")
endif()
'''


class TripletContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = shutil.which("cmake")
        if cls.cmake is None:
            raise RuntimeError("CMake is required for triplet contract tests")

    def evaluate(self, triplet: Path, crt: str, system: str):
        # A new process has no inherited CMake variables which could hide a
        # missing assignment in the triplet under test.
        with tempfile.TemporaryDirectory(prefix="public-triplet-check-") as d:
            root = Path(d)
            script = root / "check.cmake"
            script.write_text(CHECK, encoding="utf-8")
            return subprocess.run(
                [self.cmake, "-DTRIPLET_FILE=" + triplet.resolve().as_posix(),
                 "-DEXPECTED_CRT=" + crt, "-DEXPECTED_SYSTEM=" + system,
                 "-P", str(script)],
                cwd=root, capture_output=True, text=True, timeout=30,
                check=False,
            )

    def test_linux_static_release_contract(self):
        result = self.evaluate(
            ROOT / "triplets/x64-linux-static-release.cmake", "dynamic", "Linux")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_windows_static_release_contract(self):
        result = self.evaluate(
            ROOT / "triplets/x64-windows-static-release.cmake", "static", "")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_crt_is_rejected(self):
        self.check_invalid_crt(None)

    def test_empty_crt_is_rejected(self):
        self.check_invalid_crt("")

    def check_invalid_crt(self, value):
        with tempfile.TemporaryDirectory(prefix="public-invalid-triplet-") as d:
            triplet = Path(d) / "invalid.cmake"
            text = (
                "set(VCPKG_TARGET_ARCHITECTURE x64)\n"
                "set(VCPKG_CMAKE_SYSTEM_NAME Linux)\n"
                "set(VCPKG_LIBRARY_LINKAGE static)\n"
                "set(VCPKG_BUILD_TYPE release)\n"
            )
            if value is not None:
                text += 'set(VCPKG_CRT_LINKAGE "' + value + '")\n'
            triplet.write_text(text, encoding="utf-8")
            result = self.evaluate(triplet, "dynamic", "Linux")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TRIPLET_CRT_INVALID", result.stderr)


if __name__ == "__main__":
    unittest.main()
