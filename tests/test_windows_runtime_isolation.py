import copy
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
import zipfile

from secure_release import crypto, windows_runtime_isolation as subject


class WindowsCoffIsolationTests(unittest.TestCase):
    def test_real_coff_duplicate_providers_are_separated_without_changing_sections(self):
        def tool(*names):
            return next((Path(p) for n in names if (p := shutil.which(n))), None)
        clang = tool("clang-cl-18", "clang-cl")
        librarian = tool("llvm-lib-18", "llvm-lib")
        nm = tool("llvm-nm-18", "llvm-nm")
        objcopy = tool("llvm-objcopy-18", "llvm-objcopy")
        linker = tool("lld-link-18", "lld-link")
        if not all((clang, librarian, nm, objcopy, linker)):
            self.skipTest("Native LLVM COFF tools unavailable")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            installed = root / "installed"
            prefix = installed / subject.TRIPLET
            (prefix / "lib/cef-static").mkdir(parents=True)
            (prefix / "share/cef-static").mkdir(parents=True)
            info = installed / "vcpkg/info"
            info.mkdir(parents=True)
            sources = {
                "engine": "int OPENSSL_state[16]; int SSL_new(void){return 17+OPENSSL_state[0];} int SSL_use_certificate(void){return 3;} int PEM_read_PrivateKey(void){return 5;}",
                "caller": "extern int SSL_new(void); int cef_engine_probe(void){return SSL_new();}",
                "openssl": "int OPENSSL_state[16]; int SSL_new(void){return 29+OPENSSL_state[0];} int SSL_use_certificate(void){return 7;} int vcpkg_tls_probe(void){return SSL_new();}",
                "crypto": "int PEM_read_PrivateKey(void){return 11;}",
                "os_fixture": "int PUBLIC_OS_FUNCTION(void){return 0;}",
                "app": "extern int cef_engine_probe(void); extern int vcpkg_tls_probe(void); int mainCRTStartup(void){return cef_engine_probe()+vcpkg_tls_probe()-46;}"}
            for name, text in sources.items():
                (root / (name + ".c")).write_text(text)
                result = subprocess.run([str(clang), "/nologo", "/c", "/GS-", "/Fo" + str(root / (name + ".obj")),
                                         str(root / (name + ".c"))], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            subprocess.run([str(linker), "/dll", "/noentry", "/nodefaultlib", "/export:PUBLIC_OS_FUNCTION",
                            "/out:" + str(root / "PUBLIC_FIXTURE.dll"),
                            "/implib:" + str(root / "PUBLIC_FIXTURE.lib"), str(root / "os_fixture.obj")], check=True)
            imported = subject.symbols(nm, root / "PUBLIC_FIXTURE.lib")
            self.assertIn(("PUBLIC_OS_FUNCTION", "T"), imported)
            engine = prefix / "lib/cef-static/cef_0000_aaaaaaaaaaaa.lib"
            ssl, crypt = prefix / "lib/libssl.lib", prefix / "lib/libcrypto.lib"
            for target, members in ((engine, ("engine", "caller", "PUBLIC_FIXTURE.lib")), (ssl, ("openssl",)), (crypt, ("crypto",))):
                subprocess.run([str(librarian), "/out:" + str(target),
                                *[str(root / (n if n.endswith(".lib") else n + ".obj")) for n in members]], check=True)
            for package, members in (("cef-static", (engine,)), ("openssl", (ssl, crypt))):
                (info / f"{package}_1_{subject.TRIPLET}.list").write_text("".join(
                    subject.TRIPLET + "/" + p.relative_to(prefix).as_posix() + "\n" for p in members))
            command = [str(linker), "/entry:mainCRTStartup", "/subsystem:console", "/nodefaultlib",
                       "/out:" + str(root / "consumer.exe"), str(root / "app.obj"), str(engine), str(ssl), str(crypt)]
            failed = subprocess.run(command, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn(b"duplicate symbol", failed.stderr)
            section_hash = subject._sections(engine)
            provider_hashes = {p: crypto.digest(p) for p in (ssl, crypt)}
            receipt = subject.install(installed, root, root / "diagnostics", tools=(nm, objcopy, linker))
            self.assertEqual(subject._sections(engine), section_hash)
            self.assertTrue(all(crypto.digest(p) == h for p, h in provider_hashes.items()))
            succeeded = subprocess.run(command, capture_output=True)
            self.assertEqual(succeeded.returncode, 0, succeeded.stderr.decode(errors="replace"))
            if sys.platform == "win32":
                self.assertEqual(subprocess.run([str(root / "consumer.exe")], timeout=30).returncode, 0)
            symbols = subject.symbols(nm, engine)
            self.assertIn((subject.NAMESPACE + "SSL_new", "T"), symbols)
            self.assertIn((subject.NAMESPACE + "SSL_new", "U"), symbols)
            self.assertNotIn(("SSL_new", "U"), symbols)
            raw = bytearray(engine.read_bytes())
            cursor, corrupted = 8, False
            while cursor < len(raw) and not corrupted:
                header = raw[cursor:cursor + 60]
                size = int(header[48:58].strip())
                start = cursor + 60
                payload = raw[start:start + size]
                if header[:16].rstrip(b" ") not in (b"/", b"//") and payload[:2] == b"\x64\x86":
                    for index in range(struct.unpack_from("<H", payload, 2)[0]):
                        offset = 20 + 40 * index
                        flags = struct.unpack_from("<I", payload, offset + 36)[0]
                        length, pointer = struct.unpack_from("<II", payload, offset + 16)
                        if flags & 0x80 and length and pointer:
                            raw[start + pointer] = 1
                            corrupted = True
                            break
                cursor = start + size + (size & 1)
            self.assertTrue(corrupted, "LLVM must materialize the fixture's zero BSS")
            (root / "corrupt.lib").write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "BSS unexpectedly"):
                subject._sections(root / "corrupt.lib")
            sdk = root / "sdk.zip"
            with zipfile.ZipFile(sdk, "w") as archive:
                for path in prefix.rglob("*"):
                    if path.is_file():
                        archive.write(path, "installed/" + subject.TRIPLET + "/" + path.relative_to(prefix).as_posix())
            subject.validate_archive(sdk, receipt)
            for field in ("mapping_sha256", "namespace", "archives"):
                wrong = copy.deepcopy(receipt)
                wrong[field] = "0" * 64 if field != "archives" else {}
                with self.assertRaises(ValueError):
                    subject.validate_archive(sdk, wrong)
            with zipfile.ZipFile(sdk, "a") as archive:
                archive.writestr("installed/" + subject.TRIPLET + "/lib/cef-static/cef_0001_bbbbbbbbbbbb.lib", b"!<arch>\n")
            with self.assertRaises(ValueError):
                subject.validate_archive(sdk, receipt)


if __name__ == "__main__":
    unittest.main()
