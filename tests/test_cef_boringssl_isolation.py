"""Native proof for CEF Chromium/BoringSSL vs vcpkg OpenSSL isolation."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_boringssl_isolation as isolation

T = isolation.TRIPLET


def run(args, cwd, *, ok=True):
    result = subprocess.run(
        list(map(str, args)), cwd=cwd, capture_output=True, text=True, timeout=180
    )
    if ok and result.returncode:
        raise AssertionError(result.stdout[-4000:] + result.stderr[-4000:])
    return result


def archive(root: Path, name: str, source: str) -> Path:
    c = root / (name + ".c")
    o = root / (name + ".o")
    a = root / (name + ".a")
    c.write_text(source, encoding="utf-8")
    run(["cc", "-O2", "-c", c, "-o", o], root)
    run(["ar", "rcs", a, o], root)
    return a


def tools(source: Path) -> None:
    root = source / "third_party/llvm-build/Release+Asserts/bin"
    root.mkdir(parents=True)
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    objcopy = shutil.which("llvm-objcopy") or shutil.which("objcopy")
    if not nm or not objcopy:
        raise unittest.SkipTest("nm/objcopy required")
    shutil.copy2(nm, root / "llvm-nm")
    shutil.copy2(objcopy, root / "llvm-objcopy")


def fixture(root: Path):
    installed = root / "installed"
    prefix = installed / T
    (installed / "vcpkg/info").mkdir(parents=True)
    (installed / "vcpkg/status").write_text(
        "Package: cef-static\n"
        "Version: 152.0.6#15\n"
        "Architecture: " + T + "\n"
        "Status: install ok installed\n\n"
        "Package: openssl\n"
        "Version: 3.6.3\n"
        "Architecture: " + T + "\n"
        "Status: install ok installed\n",
        encoding="utf-8",
    )
    (prefix / "lib/cef-static").mkdir(parents=True)
    (prefix / "share/cef-static").mkdir(parents=True)
    source = root / "chromium"
    tools(source)

    provider = archive(root, "cef_provider",
        "int SSL_new(void){return 7;}\n"
        "int SSL_use_certificate(void){return 11;}\n"
        "int PEM_read_PrivateKey(void){return 13;}\n"
        "int cxx_typeinfo(void) __asm__(\"_ZNSt9type_infoD0Ev\");\n"
        "int cxx_class(void) __asm__(\"_ZN10__cxxabiv117__class_type_infoD0Ev\");\n"
        "int cxx_exception(void) __asm__(\"_ZNSt9exceptionD0Ev\");\n"
        "int cxx_typeinfo(void){return 29;}\n"
        "int cxx_class(void){return 31;}\n"
        "int cxx_exception(void){return 37;}\n")
    user = archive(root, "cef_user",
        "int SSL_new(void); int SSL_use_certificate(void); int PEM_read_PrivateKey(void);\n"
        "int cxx_typeinfo(void) __asm__(\"_ZNSt9type_infoD0Ev\");\n"
        "int cxx_class(void) __asm__(\"_ZN10__cxxabiv117__class_type_infoD0Ev\");\n"
        "int cxx_exception(void) __asm__(\"_ZNSt9exceptionD0Ev\");\n"
        "int cef_value(void){return SSL_new()+SSL_use_certificate()+PEM_read_PrivateKey()"
        "+cxx_typeinfo()+cxx_class()+cxx_exception();}\n")
    ssl = archive(root, "openssl_ssl",
        "int SSL_new(void){return 17;} int SSL_use_certificate(void){return 19;}\n"
        "int openssl_ssl_value(void){return SSL_new()+SSL_use_certificate();}\n")
    crypto = archive(root, "openssl_crypto",
        "int PEM_read_PrivateKey(void){return 23;}\n"
        "int openssl_crypto_value(void){return PEM_read_PrivateKey();}\n")

    names = [
        "lib/cef-static/cef_0000_aaaaaaaaaaaa.a",
        "lib/cef-static/cef_0001_bbbbbbbbbbbb.a",
    ]
    shutil.copy2(provider, prefix / names[0])
    shutil.copy2(user, prefix / names[1])
    shutil.copy2(ssl, prefix / "lib/libssl.a")
    shutil.copy2(crypto, prefix / "lib/libcrypto.a")
    config = (
        'set_property(TARGET CEF::static PROPERTY INTERFACE_LINK_LIBRARIES\n'
        '  "${_cef_static_prefix}/' + names[0] + '"\n'
        '  "${_cef_static_prefix}/' + names[1] + '"\n'
        ')\n'
    )
    (prefix / isolation.CEF_CONFIG).write_text(config, encoding="utf-8")

    # vcpkg info-list filenames are an ownership transport detail; the
    # authoritative version/port-version identity comes from vcpkg/status.
    cef_list = installed / "vcpkg/info" / (
        "cef-static_152.0.6_" + T + ".list"
    )
    cef_list.write_text(
        "".join(T + "/" + name + "\n" for name in names)
        + T + "/" + isolation.CEF_CONFIG + "\n",
        encoding="utf-8",
    )
    openssl_list = installed / "vcpkg/info" / (
        "openssl_3.6.3_" + T + ".list"
    )
    openssl_list.write_text(
        T + "/lib/libssl.a\n" + T + "/lib/libcrypto.a\n",
        encoding="utf-8",
    )

    gcc_root = root / "gcc-runtime"
    gcc_root.mkdir()
    stdcxx = archive(root, "fixture_libstdcxx",
        "int cxx_typeinfo(void) __asm__(\"_ZNSt9type_infoD0Ev\");\n"
        "int cxx_class(void) __asm__(\"_ZN10__cxxabiv117__class_type_infoD0Ev\");\n"
        "int cxx_exception(void) __asm__(\"_ZNSt9exceptionD0Ev\");\n"
        "int cxx_typeinfo(void){return 41;}\n"
        "int cxx_class(void){return 43;}\n"
        "int cxx_exception(void){return 47;}\n")
    libgcc = archive(root, "fixture_libgcc", "int fixture_libgcc(void){return 1;}\n")
    libgcc_eh = archive(root, "fixture_libgcc_eh", "int fixture_libgcc_eh(void){return 2;}\n")
    runtime_paths = {}
    providers = []
    for name, source_archive in (
        ("libstdc++.a", stdcxx),
        ("libgcc.a", libgcc),
        ("libgcc_eh.a", libgcc_eh),
    ):
        target = gcc_root / name
        shutil.copy2(source_archive, target)
        providers.append((name, target))
        runtime_paths[name] = {
            "path": target.as_posix(),
            "sha256": isolation.digest(target),
        }
    runtime = {
        "driver": "/fixture/g++-14",
        "driver_sha256": "d" * 64,
        "version": "14.2.0",
        "root": gcc_root.as_posix(),
        "archives": runtime_paths,
    }
    return installed, source, names, runtime, providers


def consumer(
    root: Path,
    prefix: Path,
    names: list[str],
    runtime_providers: list[tuple[str, Path]],
    label: str,
    *,
    ok=True,
):
    main = root / (label + ".c")
    obj = root / (label + ".o")
    exe = root / label
    main.write_text(
        "int cef_value(void); int openssl_ssl_value(void); int openssl_crypto_value(void);\n"
        "int main(void){return cef_value()!=128 || openssl_ssl_value()!=36 || "
        "openssl_crypto_value()!=23;}\n",
        encoding="utf-8",
    )
    run(["cc", "-c", main, "-o", obj], root)
    command = [
        "cc", obj, "-Wl,--whole-archive",
        *(prefix / name for name in names),
        prefix / "lib/libssl.a", prefix / "lib/libcrypto.a",
        *(path for _, path in runtime_providers),
        "-Wl,--no-whole-archive", "-o", exe,
    ]
    result = run(command, root, ok=ok)
    if ok:
        run([exe], root)
    return result


@unittest.skipUnless(sys.platform == "linux", "native ELF isolation fixture")
class NativeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (
            self.installed,
            self.source,
            self.names,
            self.runtime_receipt,
            self.runtime_providers,
        ) = fixture(self.root)
        self.prefix = self.installed / T
        patcher = mock.patch.object(
            isolation,
            "_gcc_runtime",
            return_value=(self.runtime_receipt, self.runtime_providers),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_duplicate_ssl_providers_fail_then_namespaced_cef_links_and_relocates(self):
        failed = consumer(
            self.root, self.prefix, self.names, self.runtime_providers,
            "before", ok=False
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("multiple definition", failed.stderr + failed.stdout)

        openssl = {
            name: isolation.digest(self.prefix / name)
            for name in isolation.OPENSSL_ARCHIVES
        }
        receipt = isolation.install(
            self.installed, self.source, self.root / "diagnostics"
        )
        proof = isolation.verify(self.installed, self.source, receipt)
        self.assertTrue(proof["cef_boringssl_isolation_verified"])
        self.assertEqual(proof["cef_boringssl_collision_count"], 3)
        self.assertEqual(set(receipt["symbols"]), isolation.ANCHORS)
        self.assertTrue(proof["cef_cxx_runtime_isolation_verified"])
        self.assertEqual(proof["cef_cxx_runtime_collision_count"], 3)
        self.assertEqual(set(receipt["cxx_symbols"]), isolation.CXX_ANCHORS)
        self.assertEqual(receipt["gcc_runtime"], self.runtime_receipt)
        self.assertEqual(set(receipt["ownership"]), {"cef-static", "openssl"})
        for owner in receipt["ownership"].values():
            self.assertRegex(owner["owner_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(owner["required_count"], 0)
        self.assertGreaterEqual(proof["cef_boringssl_affected_archive_count"], 2)
        self.assertGreaterEqual(proof["cef_cxx_runtime_affected_archive_count"], 1)
        self.assertTrue(receipt["boringssl_affected_archives"])
        self.assertTrue(receipt["cxx_affected_archives"])
        for record in receipt["affected"].values():
            self.assertGreater(record["global_symbol_count"], 0)
            self.assertRegex(record["global_symbol_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            openssl,
            {name: isolation.digest(self.prefix / name)
             for name in isolation.OPENSSL_ARCHIVES},
        )
        consumer(
            self.root, self.prefix, self.names, self.runtime_providers, "after"
        )

        moved = self.root / "relocated"
        shutil.copytree(self.installed, moved)
        # vcpkg --raw export preserves package owner lists but does not promise
        # the mutable install status database. Transport proof must therefore
        # use the immutable owner receipt captured before export.
        (moved / "vcpkg/status").unlink()
        self.assertEqual(
            isolation.verify(moved, self.source, receipt), proof
        )
        consumer(
            self.root, moved / T, self.names, self.runtime_providers,
            "relocated-consumer"
        )

    def test_tamper_unknown_namespace_and_owner_changes_fail_closed(self):
        receipt = isolation.install(
            self.installed, self.source, self.root / "diagnostics"
        )
        target = self.prefix / next(iter(receipt["affected"]))
        raw = target.read_bytes()
        target.write_bytes(raw + b"x")
        with self.assertRaisesRegex(ValueError, "changed in transport"):
            isolation.verify(self.installed, self.source, receipt)
        target.write_bytes(raw)

        owner = self.installed / "vcpkg/info" / (
            "openssl_3.6.3_" + T + ".list"
        )
        data = owner.read_text()
        owner.write_text(data.replace(T + "/lib/libssl.a\n", ""))
        with self.assertRaisesRegex(ValueError, "unique vcpkg package owner"):
            isolation.verify(self.installed, self.source, receipt)
        owner.write_text(data)

        runtime = self.runtime_providers[0][1]
        saved = runtime.read_bytes()
        runtime.write_bytes(saved + b"x")
        with self.assertRaisesRegex(ValueError, "GCC static runtime provider changed"):
            isolation.verify(self.installed, self.source, receipt)
        runtime.write_bytes(saved)

    def test_transport_without_status_still_requires_exact_owner_receipt(self):
        receipt = isolation.install(
            self.installed, self.source, self.root / "diagnostics"
        )
        (self.installed / "vcpkg/status").unlink()
        proof = isolation.verify(self.installed, self.source, receipt)
        self.assertTrue(proof["cef_boringssl_isolation_verified"])

        owner = self.installed / "vcpkg/info" / (
            "cef-static_152.0.6_" + T + ".list"
        )
        owner.write_text(owner.read_text() + T + "/unexpected\n")
        with self.assertRaisesRegex(ValueError, "ownership receipt changed"):
            isolation.verify(self.installed, self.source, receipt)

    def test_status_version_duplicate_owner_and_wrong_package_fail_closed(self):
        receipt = isolation.install(
            self.installed, self.source, self.root / "diagnostics"
        )
        status = self.installed / "vcpkg/status"
        original = status.read_text()
        status.write_text(original.replace("Version: 152.0.6#15", "Version: 152.0.6#14"))
        with self.assertRaisesRegex(ValueError, "version changed"):
            isolation.verify(self.installed, self.source, receipt)
        status.write_text(original)

        cef_owner = self.installed / "vcpkg/info" / (
            "cef-static_152.0.6_" + T + ".list"
        )
        duplicate = cef_owner.with_name("cef-static_stale_" + T + ".list")
        duplicate.write_text(cef_owner.read_text())
        with self.assertRaisesRegex(ValueError, "unique vcpkg package owner"):
            isolation.verify(self.installed, self.source, receipt)
        duplicate.unlink()

        renamed = cef_owner.with_name("other_152.0.6_" + T + ".list")
        cef_owner.rename(renamed)
        with self.assertRaisesRegex(ValueError, "owner package changed"):
            isolation.verify(self.installed, self.source, receipt)

    def test_cef_objects_uses_existing_sdk_budget_but_source_archives_keep_cap(self):
        huge = self.root / "cef_objects.a"
        with huge.open("wb") as stream:
            stream.write(b"!<arch>\n")
            stream.seek(isolation.MAX_SOURCE_ARCHIVE_BYTES + 4096 - 1)
            stream.write(b"\0")
        self.assertEqual(
            isolation._archive_size(huge),
            isolation.MAX_SOURCE_ARCHIVE_BYTES + 4096,
        )

        chunk = self.root / "cef_0000_aaaaaaaaaaaa.a"
        chunk.write_bytes(b"!<arch>\n")
        with chunk.open("r+b") as stream:
            stream.seek(isolation.MAX_SOURCE_ARCHIVE_BYTES + 4096 - 1)
            stream.write(b"\0")
        with self.assertRaisesRegex(ValueError, "Invalid static archive"):
            isolation._archive_size(chunk)

        derived = self.root / ".cef-bssl-derived.a"
        derived.write_bytes(b"!<arch>\n")
        with derived.open("r+b") as stream:
            stream.seek(isolation.MAX_SOURCE_ARCHIVE_BYTES + 4096 - 1)
            stream.write(b"\0")
        with self.assertRaisesRegex(ValueError, "Invalid static archive"):
            isolation._archive_size(derived)
        self.assertEqual(
            isolation._archive_size(
                derived, limit=isolation._archive_limit(huge)
            ),
            isolation.MAX_SOURCE_ARCHIVE_BYTES + 4096,
        )
        with self.assertRaisesRegex(ValueError, "byte budget"):
            isolation._archive_size(derived, limit=isolation.safeio.MAX_BYTES + 1)

    def test_config_duplicate_archive_reference_is_rejected(self):
        config = self.prefix / isolation.CEF_CONFIG
        config.write_text(
            config.read_text() +
            '"${_cef_static_prefix}/' + self.names[0] + '"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            isolation.install(
                self.installed, self.source, self.root / "diagnostics"
            )


class PolicyTests(unittest.TestCase):
    def test_pinned_openssl_source_manifest(self):
        raw = os.environ.get("CEF_BORINGSSL_UPSTREAM")
        if not raw:
            if os.environ.get("REQUIRE_CEF_BORINGSSL_ISOLATION") == "1":
                self.fail("Pinned upstream checkout required")
            self.skipTest("Pinned upstream checkout supplied in CI")
        isolation.validate_sources(Path(raw))

    def test_canonical_profile_is_order_independent_but_type_and_count_exact(self):
        original = [
            ("AAA", "T"),
            ("SSL_new", "T"),
            ("SSL_new", "U"),
            ("ZZZ", "W"),
        ]
        rewritten = [
            ("CEF_CHROMIUM_BSSL_SSL_new", "U"),
            ("ZZZ", "W"),
            ("AAA", "T"),
            ("CEF_CHROMIUM_BSSL_SSL_new", "T"),
        ]
        before, before_hits = isolation._profile_records(
            iter(original), watch={"SSL_new"}
        )
        after, after_hits = isolation._profile_records(
            iter(rewritten),
            watch={"CEF_CHROMIUM_BSSL_SSL_new"},
            reverse={"CEF_CHROMIUM_BSSL_SSL_new": "SSL_new"},
        )
        self.assertEqual(before, after)
        self.assertEqual(before_hits[("SSL_new", "T")], 1)
        self.assertEqual(after_hits[("CEF_CHROMIUM_BSSL_SSL_new", "T")], 1)

        changed_type, _ = isolation._profile_records(
            iter([
                ("AAA", "T"),
                ("SSL_new", "W"),
                ("SSL_new", "U"),
                ("ZZZ", "W"),
            ]),
            watch=set(),
        )
        self.assertNotEqual(before, changed_type)

        changed_count, _ = isolation._profile_records(
            iter(original + [("AAA", "T")]), watch=set()
        )
        self.assertNotEqual(before, changed_count)

    def test_nm_inventory_is_streamed_and_bounded(self):
        import inspect
        text = inspect.getsource(isolation._symbol_records)
        self.assertIn("stdout=out", text)
        self.assertIn("stderr=err", text)
        self.assertNotIn("capture_output=True", text)
        self.assertGreater(isolation.MAX_NM_OUTPUT_BYTES, 128 * 1024**2)
        self.assertLessEqual(isolation.MAX_NM_OUTPUT_BYTES, isolation.safeio.MAX_BYTES)
        self.assertGreater(isolation.MAX_NM_RECORDS, 1_000_000)
        profile_text = inspect.getsource(isolation._profile_records)
        self.assertIn("heapq.merge", profile_text)
        self.assertIn("pending.sort()", profile_text)
        self.assertLess(isolation.PROFILE_CHUNK_RECORDS, isolation.MAX_NM_RECORDS)

    def test_policy_is_collision_derived_and_never_suppresses_linker_errors(self):
        import inspect
        text = inspect.getsource(isolation)
        self.assertIn('"--redefine-syms="', text)
        self.assertIn("watch = openssl_defined | gcc_defined", text)
        self.assertIn('kind in {"U", "w", "v"}', text)
        self.assertIn("CXX_NAMESPACE", text)
        self.assertIn("GCC_RUNTIME_ARCHIVES", text)
        self.assertNotIn("--allow-multiple-definition", text)
        self.assertNotIn("--unresolved-symbols", text)
        self.assertNotIn("--exclude-libs", text)
        self.assertEqual(isolation.OPENSSL_VERSION, "3.6.3")


if __name__ == "__main__":
    unittest.main()
