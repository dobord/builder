"""Reproduce ambient VAAPI discovery with pinned CMake and disposable providers.

Unrelated SIMD/aggregation code is stubbed. The exact upstream FFmpeg option
block and complete codec-discovery file execute unchanged. The option block is
from cmake/ConfigOptions.cmake blob 1660d2ef80ac2a32f2797f2956ee0f6c9ddf4387
at FreeRDP commit 63b948ca5cb94307fd5444ee6e73927a41ccdab4. No unrelated
platform/fuzzer options are copied. This is not full FreeRDP/CEF proof.
"""
from __future__ import annotations

import hashlib
import inspect
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from secure_release import cef_freerdp_profile as profile
from secure_release import cef_strict_combined as combined

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/freerdp-host-isolation"
TRIPLET = ROOT / "triplets/x64-linux-static-release.cmake"
BLOBS = {"ffmpeg-options.cmake": "d72372f4cfe879aab83546be86462800b800ec2b",
         "codec.cmake": "fdbbe3a0913c6d816eb7ea2c3e799ad4bf68bc3a"}


def run(command, cwd, env=None, ok=True):
    result = subprocess.run(list(map(str, command)), cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=120)
    if ok and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result


def triplet_options(root: Path, port: str) -> list[str]:
    script = root / "triplet.cmake"
    script.write_text('include("' + TRIPLET.as_posix() + '")\n'
                      'file(WRITE "' + (root / 'options.txt').as_posix()
                      + '" "${VCPKG_CMAKE_CONFIGURE_OPTIONS}")\n')
    run(["cmake", "-DPORT=" + port, "-P", script], root)
    return [v for v in (root / "options.txt").read_text().split(";") if v]


class ProfileTests(unittest.TestCase):
    def test_pinned_codec_and_exact_ffmpeg_option_inputs(self):
        for name, sha in BLOBS.items():
            data = (FIXTURE / name).read_bytes()
            self.assertEqual(hashlib.sha1(b"blob " + str(len(data)).encode()
                                         + b"\0" + data).hexdigest(), sha)

    def test_triplet_changes_only_undeclared_vaapi_for_freerdp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(triplet_options(root, "freerdp"),
                             ["-DWITH_VAAPI=OFF", "-DWITH_VAAPI_H264_ENCODING=OFF"])
            for name in ("cef-static", "ffmpeg", "lfc-ui", "gtk3", ""):
                self.assertEqual(triplet_options(root, name), [])
        self.assertNotIn("WITH_FFMPEG=OFF", TRIPLET.read_text())

    def test_workflow_and_actual_main_keep_both_package_boundaries(self):
        source = inspect.getsource(combined.main)
        install = source.index('stage = "vcpkg-install"')
        verify = source.index('summary.update(cef_freerdp_profile.verify(installed / TRIPLET))')
        export = source.index('stage = "vcpkg-export"')
        relocated = source.index('cef_freerdp_profile.verify(consumer_sdk / "installed" / TRIPLET)')
        consumer = source.index('stage = "combined-consumer"')
        self.assertLess(install, verify)
        self.assertLess(verify, export)
        self.assertLess(export, relocated)
        self.assertLess(relocated, consumer)
        workflow = (ROOT / ".github/workflows/cef-strict-combined.yml").read_text()
        self.assertIn('- triplets/x64-linux-static-release.cmake', workflow)
        self.assertLess(workflow.index('test_cef_freerdp_profile.py -v'),
                        workflow.index('- name: Run checkpoint-resumed final'))
        self.assertNotIn('write_text', inspect.getsource(profile.verify))

    def fixture(self, root):
        header = root / "include/freerdp3/freerdp/buildflags.h"
        pc = root / "lib/pkgconfig/freerdp3.pc"
        header.parent.mkdir(parents=True)
        pc.parent.mkdir(parents=True)
        flags = " ".join(f"{v}=ON" for v in sorted(profile.REQUIRED_ON))
        flags += " " + " ".join(f"{v}=OFF" for v in sorted(profile.REQUIRED_OFF))
        header.write_text('#define FREERDP_BUILD_CONFIG "' + flags + '"\n')
        pc.write_text('Name: freerdp3\nVersion: 3.31.1\n'
                      'Requires.private: libavcodec libavutil libswscale libswresample\n')
        return header, pc

    def test_installed_and_relocated_proof_preserves_ffmpeg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root / "installed")
            before = profile.verify(root / "installed")
            shutil.move(root / "installed", root / "relocated")
            self.assertEqual(before, profile.verify(root / "relocated"))
            self.assertTrue(before["freerdp_ffmpeg_features_verified"])

    def test_feature_missing_disabled_or_ambiguous_fails(self):
        for name in sorted(profile.REQUIRED_ON | profile.REQUIRED_OFF):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                header, _ = self.fixture(root)
                text = header.read_text()
                old = f"{name}=" + ("ON" if name in profile.REQUIRED_ON else "OFF")
                for replacement in ("", name + "=MAYBE", old + " " + old):
                    header.write_text(text.replace(old, replacement))
                    with self.assertRaises(RuntimeError):
                        profile.verify(root)

    def test_pkgconfig_typo_alias_and_missing_ffmpeg_closure_rejected(self):
        for suffix in (" va", " libva", " libva-drm", " -lva"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, pc = self.fixture(root)
                pc.write_text(pc.read_text().rstrip() + suffix + "\n")
                with self.assertRaisesRegex(RuntimeError, "VAAPI"):
                    profile.verify(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, pc = self.fixture(root)
            pc.write_text(pc.read_text().replace("libavcodec", "unrelated"))
            with self.assertRaisesRegex(RuntimeError, "FFmpeg closure"):
                profile.verify(root)

    def test_missing_duplicate_macro_and_oversized_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header, pc = self.fixture(root)
            text = header.read_text()
            for value in ("", text + text):
                header.write_text(value)
                with self.assertRaises(RuntimeError):
                    profile.verify(root)
            header.write_text(text)
            pc.write_bytes(b" " * (1024**2 + 1))
            with self.assertRaises(ValueError):
                profile.verify(root)


@unittest.skipUnless(sys.platform == "linux", "Native Linux pkg-config/ELF regression")
class NativeDiscoveryTests(unittest.TestCase):
    def test_missing_and_host_libva_cannot_change_requested_codec_graph(self):
        for tool in ("cmake", "cc", "ar", "pkg-config", "readelf"):
            self.assertIsNotNone(shutil.which(tool), tool + " required by native regression")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sdk, host = root / "sdk", root / "host"
            for prefix in (sdk, host):
                (prefix / "lib/pkgconfig").mkdir(parents=True)
                (prefix / "include").mkdir()
            (root / "av.c").write_text("int fixture_avcodec(void) { return 42; }\n")
            run(["cc", "-c", root / "av.c", "-o", root / "av.o"], root)
            run(["ar", "rcs", sdk / "lib/libavcodec.a", root / "av.o"], root)
            (root / "va.c").write_text("int vaInitialize(void *p, int *a, int *b) { return 9; }\n")
            run(["cc", "-shared", "-fPIC", root / "va.c", "-Wl,-soname,libva.so.1",
                 "-o", host / "lib/libva.so.1"], root)
            (host / "lib/libva.so").symlink_to("libva.so.1")
            for name in ("libavcodec", "libavutil", "libavformat", "libavfilter",
                         "libswscale", "libswresample"):
                (sdk / "lib/pkgconfig" / f"{name}.pc").write_text(
                    f"prefix={sdk}\nName: {name}\nDescription: disposable codec fixture\nVersion: 1.0\n"
                    "Libs: -L${prefix}/lib -lavcodec\n")
            (host / "lib/pkgconfig/libva.pc").write_text(
                f"prefix={host}\nName: libva\nDescription: hostile host-only fixture\nVersion: 1.0\n"
                "Libs: -L${prefix}/lib -lva\nCflags: -I${prefix}/include\n")
            project = root / "project"
            (project / "codec").mkdir(parents=True)
            (project / "modules").mkdir()
            shutil.copyfile(FIXTURE / "ffmpeg-options.cmake", project / "ConfigOptions.cmake")
            shutil.copyfile(FIXTURE / "codec.cmake", project / "codec/CMakeLists.txt")
            for token in set(re.findall(r"\b([a-zA-Z0-9_/]+\.(?:c|h))\b",
                                        (FIXTURE / "codec.cmake").read_text())):
                file = project / "codec" / token
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("/* Unrelated implementation omitted in dependency fixture. */\n")
            (project / "codec/h264_ffmpeg.c").write_text('''extern int fixture_avcodec(void);
#ifdef HAVE_LIBVA
extern int vaInitialize(void*, int*, int*);
#endif
int fixture_decode(void) {
 int value = fixture_avcodec();
#ifdef HAVE_LIBVA
 value += vaInitialize(0,0,0);
#endif
 return value;
}
''')
            for module in ("CompilerDetect", "DetectIntrinsicSupport"):
                (project / "modules" / f"{module}.cmake").write_text(
                    "# Unrelated architecture detection excluded from dependency fixture.\n")
            (project / "modules/WarnExperimental.cmake").write_text(
                "function(warn_experimental)\nendfunction()\n")
            (project / "main.c").write_text(
                '#include <stdio.h>\nextern int fixture_decode(void);\n'
                'int main(void){printf("%d\\n", fixture_decode());return 0;}\n')
            (project / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.25)
project(FreeRDPDependencyFixture C)
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/modules")
foreach(name ALSA PulseAudio OSS SNDIO)
 set(CMAKE_DISABLE_FIND_PACKAGE_${name} TRUE)
endforeach()
include(CMakeDependentOption)
include(ConfigOptions.cmake)
function(freerdp_pc_add_requires_private)
 set_property(GLOBAL APPEND PROPERTY required_pc ${ARGN})
endfunction()
function(freerdp_pc_add_library_private)
endfunction()
function(freerdp_library_add)
 set_property(GLOBAL PROPERTY codec_libraries ${ARGN})
endfunction()
function(freerdp_object_library_add)
endfunction()
add_subdirectory(codec)
get_property(libs GLOBAL PROPERTY codec_libraries)
add_library(freerdp_fixture STATIC $<TARGET_OBJECTS:freerdp-codecs>)
target_link_libraries(freerdp_fixture PRIVATE ${libs} "${FIXTURE_FFMPEG}")
add_executable(probe main.c)
target_link_libraries(probe PRIVATE freerdp_fixture)
get_property(pc GLOBAL PROPERTY required_pc)
list(JOIN pc " " pc)
file(WRITE "${CMAKE_BINARY_DIR}/freerdp3.pc" "Name: freerdp3\nDescription: discovery regression\nVersion: 3.31.1\nRequires.private: ${pc}\n")
file(WRITE "${CMAKE_BINARY_DIR}/flags.txt" "ffmpeg=${WITH_FFMPEG}\naudio=${WITH_DSP_FFMPEG}\nvideo=${WITH_VIDEO_FFMPEG}\nscale=${WITH_SWSCALE}\nvaapi=${WITH_VAAPI}\nvaapi_h264=${WITH_VAAPI_H264_ENCODING}\n")
''')
            fixed_options = triplet_options(root, "freerdp")
            for fixed, ambient in ((False, False), (False, True), (True, False), (True, True)):
                with self.subTest(fixed=fixed, ambient=ambient):
                    build = root / f"build-{fixed}-{ambient}"
                    env = dict(os.environ)
                    env.update(PKG_CONFIG_PATH="", PKG_CONFIG_LIBDIR=os.pathsep.join(
                        [str(sdk / "lib/pkgconfig")] + ([str(host / "lib/pkgconfig")] if ambient else [])),
                        LD_LIBRARY_PATH=str(host / "lib"))
                    run(["cmake", "-S", project, "-B", build,
                         "-DFIXTURE_FFMPEG=" + str(sdk / "lib/libavcodec.a"),
                         "-DWITH_FFMPEG=ON", "-DWITH_SWSCALE=ON",
                         *(fixed_options if fixed else [])], root, env)
                    flags = (build / "flags.txt").read_text()
                    for field in ("ffmpeg", "audio", "video", "scale"):
                        self.assertIn(field + "=ON", flags)
                    run(["cmake", "--build", build, "--parallel", "2"], root, env)
                    value = run([build / "probe"], root, env).stdout.strip()
                    self.assertEqual(value, "51" if ambient and not fixed else "42")
                    elf = run(["readelf", "-d", build / "probe"], root).stdout
                    self.assertEqual("Shared library: [libva.so.1]" in elf, ambient and not fixed)
                    env["PKG_CONFIG_PATH"] = str(build)
                    result = run(["pkg-config", "--static", "--libs", "freerdp3"], root, env, ok=False)
                    self.assertEqual(result.returncode == 0, fixed or not ambient)
                    if fixed:
                        self.assertIn("vaapi=OFF", flags)
                        self.assertIn("vaapi_h264=OFF", flags)
                        self.assertNotIn(" va", (build / "freerdp3.pc").read_text())
                    elif ambient:
                        self.assertIn("vaapi_h264=ON", flags)
                        self.assertIn("Package 'va'", result.stderr)

    def test_parent_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").mkdir()
            (root / "alias").symlink_to(root / "outside", target_is_directory=True)
            with self.assertRaises(ValueError):
                profile.verify(root / "alias")


if __name__ == "__main__":
    unittest.main()
