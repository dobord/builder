"""Bounded x64 COFF transport and Windows-only FFmpeg source policy."""
import copy
import hashlib
from pathlib import Path
import struct
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import (cef_sdk_objects as objects, cef_sdk_source_interfaces as interfaces,
                            cef_sdk_xz as xz, safeio, static_audit, windows_multimedia as subject)

T = subject.TRIPLET


def coff(section=b".text", machine=0x8664):
    return (struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, 0, 0) +
            struct.pack("<8sIIIIIIHHI", section, 0, 0, 4, 60, 0, 0, 0, 0, 0x60000020) + b"\xc3\x90\x90\x90")


class WindowsMultimediaTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.sdk = self.root / "sdk"
        self.prefix = self.sdk / "installed" / T
        self.names = []
        for target, export in zip(("drdynvc-client", "rdpdr-server"), objects.EXPORTS):
            relative = objects.OBJECT_ROOT + "/" + target + "/main.c.obj"
            path = self.prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(coff())
            path.chmod(0o644)
            self.names.append(relative)
            declarations = self.prefix / (export + ".cmake")
            declarations.parent.mkdir(parents=True, exist_ok=True)
            declarations.write_text(f"add_library({target} OBJECT IMPORTED)\n")
            config = self.prefix / (export + "-release.cmake")
            config.write_text(f'set_target_properties({target} PROPERTIES\n'
                              f'  IMPORTED_OBJECTS_RELEASE "${{_IMPORT_PREFIX}}/{relative}"\n)\n'
                              f'list(APPEND _cmake_import_check_files_for_{target} "${{_IMPORT_PREFIX}}/{relative}")\n')
            self.names += [export + ".cmake", export + "-release.cmake"]
        info = self.sdk / "installed/vcpkg/info"
        info.mkdir(parents=True)
        (info / ("freerdp_3.32.2_" + T + ".list")).write_text("".join(T + "/" + n + "\n" for n in self.names))
        data = coff()
        header = f"{'fixture.obj/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        (self.prefix / "lib/fixture.lib").write_bytes(b"!<arch>\n" + header + data)

    def test_objects_preserved_after_zip_relocation_and_native_static_audit(self):
        receipt = objects.capture(self.sdk / "installed", triplet=T)
        review = objects.verify(self.sdk / "installed", receipt, triplet=T)
        archive = self.root / "sdk.zip"
        safeio.sdk_zip(self.sdk, archive, reviewed_objects=review)
        moved = self.root / "moved"
        safeio.extract_zip(archive, moved)
        self.assertEqual(objects.verify(moved / "installed", receipt, triplet=T), review)
        report = static_audit.inspect_sdk(archive, "windows", reviewed_objects=review)
        self.assertEqual(report["violations"], [])
        with self.assertRaises(ValueError):
            static_audit.inspect_sdk(archive, "linux", reviewed_objects=review)
        (moved / "installed" / T / self.names[0]).write_bytes(coff() + b"tamper")
        with self.assertRaises(ValueError):
            objects.verify(moved / "installed", receipt, triplet=T)

    def test_no_default_object_exemption_or_cross_platform_payload(self):
        with self.assertRaises(ValueError):
            safeio._source_review({"installed": {"size": 64, "sha256": "a" * 64}}, shared_interfaces=True)
        with self.assertRaises(ValueError):
            safeio.sdk_zip(self.sdk, self.root / "unreviewed.zip")
        for data in (coff(b".idata"), coff(machine=0x14c), b"BC\xc0\xde" + b"\0" * 64, b"MZ" + b"\0" * 64):
            with self.subTest(header=data[:4]), self.assertRaises(ValueError):
                safeio._object_payload(data, platform="windows")
        with self.assertRaises(ValueError):
            safeio._object_payload(coff(), platform="linux")

    def test_crlf_exports_parse_without_rewriting_the_bound_bytes(self):
        for relative in self.names:
            if relative.endswith(".cmake"):
                path = self.prefix / relative
                path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        receipt = objects.capture(self.sdk / "installed", triplet=T)
        path = self.prefix / (objects.EXPORTS[0] + ".cmake")
        before = path.read_bytes()
        objects.verify(self.sdk / "installed", receipt, triplet=T)
        self.assertEqual(path.read_bytes(), before)
        path.write_bytes(before.replace(b"\r\n", b"\n"))
        with self.assertRaises(ValueError):
            objects.verify(self.sdk / "installed", receipt, triplet=T)

    @unittest.skipUnless(shutil.which("clang"), "A native COFF-producing Clang is required")
    def test_real_compiler_coff_survives_bound_transport(self):
        source = self.root / "native.c"
        source.write_text("int fixture(void) { return 42; }\n")
        output = self.prefix / self.names[0]
        subprocess.run([shutil.which("clang"), "--target=x86_64-pc-windows-msvc",
                        "-c", str(source), "-o", str(output)], check=True, capture_output=True)
        output.chmod(0o644)
        receipt = objects.capture(self.sdk / "installed", triplet=T)
        archive = self.root / "native.zip"
        safeio.sdk_zip(self.sdk, archive, reviewed_objects=receipt["objects"])
        self.assertEqual(static_audit.inspect_sdk(archive, "windows", reviewed_objects=receipt["objects"])["violations"], [])

    def test_windows_samples_are_byte_bound_without_xtrans_exemption(self):
        policy = copy.deepcopy(interfaces.policy())
        spec = policy["packages"]["ffmpeg"]
        listed = []
        for name, entry in spec["files"].items():
            data = ("/* synthetic sample " + name + " */\n").encode()
            path = self.prefix / spec["directory"] / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            entry.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                         blob=hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest())
            listed.append(T + "/" + spec["directory"] + "/" + name)
        info = self.sdk / "installed/vcpkg/info"
        (info / ("ffmpeg_9.0.2_" + T + ".list")).write_text("\n".join(listed) + "\n")
        docs_policy = {}
        docs_owner = []
        for name in xz.FILES:
            data = ("/* synthetic XZ companion " + name + " */\n").encode()
            path = self.prefix / xz.DIRECTORY / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            docs_policy[name] = (len(data), hashlib.sha256(data).hexdigest(),
                hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest())
            docs_owner.append(T + "/" + xz.DIRECTORY + "/" + name)
        (info / ("liblzma_5.8.3_" + T + ".list")).write_text("\n".join(docs_owner) + "\n")
        with mock.patch.object(interfaces, "policy", return_value=policy), mock.patch.object(xz, "FILES", docs_policy):
            source_review = interfaces.verify(self.sdk, triplet=T)
            self.assertEqual(len(source_review), 24)
            receipt = objects.capture(self.sdk / "installed", triplet=T)
            archive = self.root / "complete.zip"
            # Reproduce the missing Windows doc review before granting it.
            with self.assertRaisesRegex(ValueError, "implementation source"):
                safeio.sdk_zip(self.sdk, archive, reviewed_interface_sources=source_review,
                               reviewed_objects=receipt["objects"])
            review = subject.package(self.sdk, archive, receipt)
            self.assertEqual(review["interfaces"], source_review)
            self.assertEqual(len(review["docs"]), 5)
            self.assertEqual(subject.validate_archive_sources(archive, review), set(source_review) | set(review["docs"]))
            wrong = copy.deepcopy(review)
            wrong["docs"].pop(next(iter(wrong["docs"])))
            with self.assertRaises(ValueError):
                subject.validate_archive_sources(archive, wrong)
            moved = self.root / "complete-moved"
            safeio.extract_zip(archive, moved)
            subject.relocated(moved, receipt, review)
            (moved / "installed" / T / xz.DIRECTORY / "00_README.txt").write_text("tampered companion")
            with self.assertRaises(ValueError):
                subject.relocated(moved, receipt, review)
            listing = info / ("liblzma_5.8.3_" + T + ".list")
            before = listing.read_bytes()
            listing.write_text("")
            with self.assertRaises(ValueError):
                xz.verify(self.sdk, triplet=T)
            listing.write_bytes(before)
            foreign = self.prefix / "share/doc/foreign/examples/foreign.c"
            foreign.parent.mkdir(parents=True)
            foreign.write_text("int arbitrary_source;\n")
            with self.assertRaisesRegex(ValueError, "unreviewed sources"):
                subject.package(self.sdk, self.root / "refused.zip", receipt)


if __name__ == "__main__":
    unittest.main()
