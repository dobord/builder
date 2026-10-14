import copy
from pathlib import Path
import shutil
import subprocess
import struct
import sys
import tempfile
import unittest
import zipfile

from secure_release import crypto, static_audit, windows_runtime_isolation as subject


class WindowsCoffIsolationTests(unittest.TestCase):
    def test_native_stl_ownership_is_distinct_from_std_parameter_types(self):
        self.assertTrue(subject._shared_msvc_stl("?probe@std@@YAHXZ"))
        self.assertTrue(subject._shared_msvc_stl("??_E?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAAPEAXI@Z"))
        self.assertFalse(subject._shared_msvc_stl("?probe@google@@YAHPEAVBox@std@@@Z"))
        self.assertFalse(subject._shared_msvc_stl("SSL_new"))

    def test_real_coff_duplicate_providers_are_separated_without_changing_sections(self):
        def tool(*names):
            return next((Path(p) for n in names if (p := shutil.which(n))), None)
        clang = tool("clang-cl-18", "clang-cl")
        librarian = tool("llvm-lib-18", "llvm-lib")
        nm = tool("llvm-nm-18", "llvm-nm")
        objcopy = tool("llvm-objcopy-18", "llvm-objcopy")
        linker = tool("lld-link-18", "lld-link")
        nasm = tool("nasm")
        if not all((clang, librarian, nm, objcopy, linker, nasm)):
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
                "engine": "extern int SSL_ASM_PROBE(void); int OPENSSL_state[16]; int SSL_new(void){return 17+OPENSSL_state[0]+SSL_ASM_PROBE();} int SSL_use_certificate(void){return 3;} int PEM_read_PrivateKey(void){return 5;}",
                "caller": "extern int SSL_new(void); int cef_engine_probe(void){return SSL_new();}",
                "openssl": "int OPENSSL_state[16]; int SSL_ASM_PROBE(void){return 99;} int SSL_new(void){return 29+OPENSSL_state[0];} int SSL_use_certificate(void){return 7;} int vcpkg_tls_probe(void){return SSL_new();}",
                "crypto": "int PEM_read_PrivateKey(void){return 11;}",
                "os_fixture": "int PUBLIC_OS_FUNCTION(void){return 0;}",
                "app": "extern int cef_engine_probe(void); extern int vcpkg_tls_probe(void); extern int cef_stl_probe(void); extern int vcpkg_stl_probe(void); int mainCRTStartup(void){return cef_engine_probe()+vcpkg_tls_probe()+cef_stl_probe()+vcpkg_stl_probe()-89;}"}
            weak = '__asm__(".weak SSL_weak_probe\\n.set SSL_weak_probe, SSL_new");'
            sources["engine"] += weak
            sources["app"] += weak
            for name, text in sources.items():
                (root / (name + ".c")).write_text(text)
                result = subprocess.run([str(clang), "/nologo", "/c", "/GS-", "/Fo" + str(root / (name + ".obj")),
                                         str(root / (name + ".c"))], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            for name, wrapper in (("engine_stl", "cef_stl_probe"), ("sdk_stl", "vcpkg_stl_probe")):
                (root / (name + ".cpp")).write_text('namespace std { inline int PUBLIC_STL_probe(){return 6;} } '
                    'extern "C" int ' + wrapper + '(){return std::PUBLIC_STL_probe();}')
                subprocess.run([str(clang), "/nologo", "/c", "/GS-", "/Fo" + str(root / (name + ".obj")),
                                str(root / (name + ".cpp"))], check=True)
            (root / "assembly.asm").write_text("bits 64\nsection .text\nglobal SSL_ASM_PROBE\nSSL_ASM_PROBE:\nmov eax,31\nret\n")
            subprocess.run([str(nasm), "-f", "win64", "-o", str(root / "assembly.obj"), str(root / "assembly.asm")], check=True)
            subprocess.run([str(linker), "/dll", "/noentry", "/nodefaultlib", "/export:PUBLIC_OS_FUNCTION",
                            "/out:" + str(root / "bcryptprimitives.dll"),
                            "/implib:" + str(root / "PUBLIC_FIXTURE.lib"), str(root / "os_fixture.obj")], check=True)
            imported = subject.symbols(nm, root / "PUBLIC_FIXTURE.lib")
            self.assertIn(("PUBLIC_OS_FUNCTION", "T"), imported)
            engine = prefix / "lib/cef-static/cef_0000_aaaaaaaaaaaa.lib"
            ssl, crypt = prefix / "lib/libssl.lib", prefix / "lib/libcrypto.lib"
            for target, members in ((engine, ("engine", "caller", "assembly", "engine_stl", "PUBLIC_FIXTURE.lib")),
                                    (ssl, ("openssl", "sdk_stl")), (crypt, ("crypto",))):
                subprocess.run([str(librarian), "/out:" + str(target),
                                *[str(root / (n if n.endswith(".lib") else n + ".obj")) for n in members]], check=True)
            # Model Rust's native OS import members: their original archive
            # identities are DLL basenames, including the long .idata objects.
            original_names = []
            with engine.open("rb") as stream:
                stream.read(8)
                while header := stream.read(60):
                    size = int(header[48:58].strip())
                    payload = stream.read(size)
                    if header[:16].rstrip(b" ") not in (b"/", b"//", b"/SYM64/"):
                        original_names.append(b"bcryptprimitives.dll" if static_audit.coff_kind(payload) == "coff-import"
                                              else f"public{len(original_names)}.obj".encode())
                    if size & 1:
                        stream.read(1)
            subject._restore_import_member_names(engine, original_names)
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
            receipt = subject.install(installed, root, root / "diagnostics", tools=(nm, linker))
            self.assertEqual(subject._sections(engine), section_hash)
            with engine.open("rb") as stream:
                audit = static_audit.inspect_archive(stream, engine.stat().st_size, "windows", allow_windows_os_imports=True)
            self.assertTrue(audit["qualified_objects_only"], audit)
            self.assertIn("bcryptprimitives.dll", audit["system_imports"])
            self.assertTrue(all(crypto.digest(p) == h for p, h in provider_hashes.items()))
            succeeded = subprocess.run(command, capture_output=True)
            self.assertEqual(succeeded.returncode, 0, succeeded.stderr.decode(errors="replace"))
            if sys.platform == "win32":
                self.assertEqual(subprocess.run([str(root / "consumer.exe")], timeout=30).returncode, 0)
            symbols = subject.symbols(nm, engine)
            self.assertIn((subject.NAMESPACE + "SSL_new", "T"), symbols)
            self.assertIn((subject.NAMESPACE + "SSL_new", "U"), symbols)
            self.assertNotIn(("SSL_new", "U"), symbols)
            self.assertIn("SSL_weak_probe", receipt["collisions"])
            self.assertNotIn("SSL_weak_probe", {name for name, kind in symbols})
            self.assertIn(subject.NAMESPACE + "SSL_weak_probe", {name for name, kind in symbols})
            self.assertIn("?PUBLIC_STL_probe@std@@YAHXZ", {name for name, kind in symbols})
            self.assertNotIn("?PUBLIC_STL_probe@std@@YAHXZ", receipt["collisions"])
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
                        if flags & 0x80 and length and not pointer:
                            struct.pack_into("<I", raw, start + offset + 36, flags & ~0x80 | 0x40)
                            corrupted = True
                            break
                cursor = start + size + (size & 1)
            self.assertTrue(corrupted, "Symbol-only rewriting must retain virtual zero BSS")
            (root / "corrupt.lib").write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "Initialized COFF section"):
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
