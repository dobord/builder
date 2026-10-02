"""Full LLD maps are larger than ELF files; no constructor gate may be skipped."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock

from secure_release import cef_constructor_map as subject, cef_elf_init

ROOT = Path(__file__).resolve().parents[1]
HEADER = b"VMA LMA Size Align Out In Symbol\n"


def row(tail, address=0x1000, size=8, align=8):
    return f"{address:x} {address:x} {size:x} {align} {tail}\n".encode()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / subject.MAP_NAME
        self.sections = [dict(name=".init_array", addr=0x1000, size=16, align=8)]
        self.data = (HEADER + row(".init_array", size=16)
                     + row("        private-provider.a(ctor.o):(.init_array)")
                     + row("                private-constructor", size=0)
                     + row(".unrelated", address=0x3000, size=0))
        self.path.write_bytes(self.data)

    def audit(self, bad=None):
        return subject.inspect_map(self.path, self.sections, {"bad": bad or []})

    def test_exact_boundary_complete_hash_privacy_and_unchanged_inputs(self):
        with mock.patch.object(subject, "MAX_MAP_BYTES", len(self.data)):
            result = self.audit()
        public = result["summary"]
        self.assertEqual(public["constructor_source_map_bytes"], len(self.data))
        self.assertEqual(public["constructor_source_map_rows"], 4)
        self.assertEqual(public["constructor_source_map_sha256"], hashlib.sha256(self.data).hexdigest())
        self.assertTrue(public["constructor_source_map_scan_complete"])
        self.assertNotIn("private-", json.dumps(public))
        self.assertNotIn("constructor_integrity_verified", public)
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertEqual(self.sections, [dict(name=".init_array", addr=0x1000, size=16, align=8)])

    def test_null_attribution_and_relocated_input_inspector_remain_mandatory(self):
        bad = [dict(reason="zero-unrelocated", section=".init_array", slot=i) for i in (0, 1)]
        evidence = dict(summary={"constructor_input_matched_count": 1}, details=[{"symbol": "private-target"}])
        with mock.patch.object(subject.cef_constructor_inputs, "inspect_inputs", return_value=evidence) as inputs:
            result = self.audit(bad)
        inputs.assert_called_once_with(
            self.path.parent.parent / "consumer-sdk/installed/x64-linux-static-release/lib/cef-static",
            result["details"]["zero_slots"],
        )
        self.assertEqual(result["summary"]["constructor_zero_inside_input_count"], 1)
        self.assertEqual(result["summary"]["constructor_zero_linker_padding_count"], 1)
        self.assertEqual(result["details"]["input_relocations"], evidence["details"])
        self.assertNotIn("private-", json.dumps(result["summary"]))

    def test_late_malformed_duplicate_missing_and_stale_rows_are_fatal(self):
        for data, message in (
            (self.data + b"invalid private-row\n", "malformed"),
            (self.data + row(".init_array", size=16), "duplicate"),
            (self.data.replace(b".init_array\n", b".not_init\n", 1), "missing"),
            (self.data.replace(row(".init_array", size=16), row(".init_array", size=24)), "disagrees"),
        ):
            with self.subTest(message=message):
                self.path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, message):
                    self.audit()

    def test_header_and_last_row_must_be_complete_even_after_all_matches(self):
        for data, message in ((b"VMA LMA Size Align Out In Symbol", "header"),
                              (b" " * (subject.MAX_MAP_LINE_BYTES + 1) + HEADER, "header"),
                              (self.data[:-1], "incomplete")):
            self.path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, message):
                self.audit()

    def test_size_rows_line_and_retained_input_budgets_are_independent(self):
        for name, limit, message in (("MAX_MAP_BYTES", len(self.data) - 1, "bounds"),
                                     ("MAX_MAP_ROWS", 3, "bounded inventory"),
                                     ("MAX_MAP_LINE_BYTES", len(HEADER), "bounded inventory"),
                                     ("MAX_INPUT_BYTES", 8, "byte budget"),
                                     ("MAX_INPUTS", 0, "oversized")):
            with self.subTest(name=name), mock.patch.object(subject, name, limit):
                with self.assertRaisesRegex(ValueError, message):
                    self.audit()
        self.path.write_bytes(self.data + row("                " + "x" * subject.MAX_MAP_LINE_BYTES))
        with self.assertRaisesRegex(ValueError, "bounded inventory"):
            self.audit()

    def test_oversized_sparse_map_and_nonregular_input_fail_before_open(self):
        # POSIX truncate is sparse. Avoid allocating 2 GiB on a Windows
        # filesystem that does not expose sparse extension through truncate.
        limit = subject.MAX_MAP_BYTES if os.name == "posix" else 4096
        with self.path.open("wb") as stream:
            stream.truncate(limit + 1)
        with mock.patch.object(subject, "MAX_MAP_BYTES", limit), \
             mock.patch.object(subject.os, "open", side_effect=AssertionError("must not read oversized map")):
            with self.assertRaisesRegex(ValueError, f"bytes={limit + 1} maximum={limit}"):
                self.audit()
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaisesRegex(ValueError, "regular"):
            self.audit()
        self.path.rmdir()
        self.path.touch()
        with self.assertRaisesRegex(ValueError, "bytes=0"):
            self.audit()

    def test_numeric_fields_and_input_geometry_stay_bounded(self):
        for tail, message in ((b"1" * 17 + b" 0 0 0 .extra\n", "numeric"),
                              (b"0 0 0 " + b"1" * 21 + b" .extra\n", "numeric"),
                              (row("        a.o:(.init_array)", address=0x1010), "escapes"),
                              (row("        a.o:(.init_array)", address=0x1001), "pointer-aligned"),
                              (row("        a.o:(.init_array)"), "overlapping")):
            with self.subTest(message=message):
                # Insert before the .unrelated output declaration.
                self.path.write_bytes(self.data[:self.data.rindex(row(".unrelated", address=0x3000, size=0))] + tail)
                with self.assertRaisesRegex(ValueError, message):
                    self.audit()

    def test_replaced_truncated_or_inplace_mutated_map_is_never_published(self):
        original_fdopen = os.fdopen
        actions = ("truncate", "mutate") if os.name == "nt" else ("replace", "truncate", "mutate")
        for action in actions:
            with self.subTest(action=action):
                self.path.write_bytes(self.data)
                path, data = self.path, self.data
                class ChangingStream:
                    def __init__(self, stream):
                        self.stream, self.done = stream, False
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        self.stream.close()
                    def fileno(self):
                        return self.stream.fileno()
                    def readline(self, count):
                        line = self.stream.readline(count)
                        if not self.done:
                            self.done = True
                            if action == "replace":
                                other = path.with_suffix(".replacement")
                                other.write_bytes(data)
                                os.replace(other, path)
                            elif action == "truncate":
                                with path.open("r+b") as stream:
                                    stream.truncate(len(HEADER))
                            else:
                                with path.open("r+b") as stream:
                                    stream.seek(data.index(b"private-constructor"))
                                    stream.write(b"changed-constructor")
                        return line
                # Deliberately freeze metadata observations: Windows exposed
                # that a same-size write can leave the compared times intact.
                # The real byte change must fail without sleeps/forced mtimes,
                # even when the first read buffered the entire original map.
                with mock.patch.object(subject, "_identity", **(
                        {"wraps": subject._identity} if action == "replace" else {"return_value": (1,)})), \
                     mock.patch.object(subject.os, "fdopen", side_effect=lambda *a: ChangingStream(original_fdopen(*a))):
                    with self.assertRaises(ValueError):
                        self.audit()

    def test_absent_map_is_distinct_from_redirect_or_failed_scan(self):
        self.path.unlink()
        self.assertEqual(self.audit(), {"summary": {"constructor_source_map_available": False}, "details": {}})
        other = self.root / "other.map"
        other.write_bytes(self.data)
        try:
            self.path.symlink_to(other)
        except OSError:
            self.skipTest("symlinks unavailable on this host")
        with self.assertRaisesRegex(ValueError, "redirected"):
            self.audit()

    @unittest.skipUnless(os.name == "posix", "O_NOFOLLOW/nonblocking FIFO protection")
    def test_open_race_cannot_redirect_to_regular_file_or_fifo(self):
        original_open = os.open
        for kind in ("link", "fifo"):
            self.path.unlink(missing_ok=True)
            self.path.write_bytes(self.data)
            other = self.root / "other.map"
            other.write_bytes(self.data)
            def swap(path, flags):
                self.path.unlink()
                if kind == "link":
                    self.path.symlink_to(other)
                else:
                    os.mkfifo(self.path)
                return original_open(path, flags)
            with self.subTest(kind=kind), mock.patch.object(subject.os, "open", side_effect=swap):
                with self.assertRaisesRegex(ValueError, "open failed|changed before"):
                    self.audit()


@unittest.skipUnless(sys.platform == "linux", "native ELF/LLD volume regression")
class NativeScaleTests(unittest.TestCase):
    def test_real_large_map_full_elf_audit_null_rejection_and_relocated_startup(self):
        required = os.environ.get("REQUIRE_CEF_CONSUMER_LLD") == "1"
        pinned = Path("/usr/lib/llvm-18/bin/ld.lld")
        if pinned.is_file():
            linker, cxx, cc = pinned, "/usr/bin/g++-14", "/usr/bin/gcc-14"
        else:
            if required:
                self.fail("required pinned LLD18 unavailable")
            found, cxx = shutil.which("ld.lld"), shutil.which("g++")
            linker = Path(found) if found else None
            cc = shutil.which("cc")
        tools = (cxx, cc, shutil.which("ar"), shutil.which("nm"))
        if linker is None or not all(tool and Path(tool).is_file() for tool in tools):
            if required:
                self.fail("required native map fixture tools unavailable")
            self.skipTest("native LLD/compiler tools unavailable")
        cxx, cc, ar, nm = tools
        flags = ["-B" + str(linker.parent), "-fuse-ld=lld", "-static-libstdc++", "-static-libgcc"]
        version = subprocess.check_output([linker, "--version"], text=True, timeout=30).strip()
        if pinned.is_file() or required:
            self.assertRegex(version, r"(?:Ubuntu )?LLD 18\.")
        driver_version = subprocess.check_output([cxx, *flags, "-Wl,--version"], stderr=subprocess.PIPE, text=True, timeout=30)
        self.assertIn(version, driver_version)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            producer = root / "producer"
            producer.mkdir()
            cpp = producer / "types.cpp"
            cpp.write_text("template<class,class> struct Pair {};\nusing T0=int;\n"
                           + "".join(f"using T{i}=Pair<T{i-1},T{i-1}>;\n" for i in range(1, 13))
                           + "void fixture(T12) {}\n", encoding="utf-8")
            subprocess.run([cxx, "-c", cpp, "-o", producer / "types.o"], check=True, capture_output=True, timeout=60)
            symbol = subprocess.check_output([nm, "--defined-only", "--format=just-symbols", producer / "types.o"], text=True, timeout=30).strip()
            self.assertRegex(symbol, r"^_Z7fixture[A-Za-z0-9_]+$")
            tail = symbol[len("_Z7fixture"):]
            # Compact valid mangled aliases expand only in the real LLD map.
            # Do not store a huge synthetic map or huge source file in Git.
            asm = producer / "volume.s"
            with asm.open("w", encoding="ascii") as stream:
                stream.write(".text\n.type target,@function\ntarget:\nret\n")
                for i in range(12000):
                    name = f"volume_{i:05d}"
                    mangled = f"_Z{len(name)}{name}{tail}"
                    stream.write(f".globl {mangled}\n.type {mangled},@function\n.set {mangled},target\n")
                stream.write('.section .note.GNU-stack,"",@progbits\n')
            subprocess.run([cc, "-c", asm, "-o", producer / "volume.o"], check=True, capture_output=True, timeout=60)
            main = producer / "main.c"
            main.write_text("int calls; int main(void){return calls != 1;}\n", encoding="ascii")
            subprocess.run([cc, "-c", main, "-o", producer / "main.o"], check=True, capture_output=True, timeout=60)
            for null in (False, True):
                bundle = root / ("null" if null else "valid")
                build = bundle / "smoke-build"
                archives = bundle / "consumer-sdk/installed/x64-linux-static-release/lib/cef-static"
                build.mkdir(parents=True)
                archives.mkdir(parents=True)
                ctor = producer / "ctor.c"
                ctor.write_text('extern int calls; static void init(void){calls++;}\n'
                                '__attribute__((used,section(".init_array"),aligned(8))) '
                                'static void(*const slots[])(void)={' + ('0,' if null else '') + 'init};\n', encoding="ascii")
                subprocess.run([cc, "-c", ctor, "-o", producer / "ctor.o"], check=True, capture_output=True, timeout=60)
                archive = archives / "cef_objects.a"
                subprocess.run([ar, "rcs", archive, producer / "ctor.o", producer / "volume.o"], check=True, capture_output=True, timeout=60)
                executable = build / "consumer"
                mapping = build / subject.MAP_NAME
                command = [cxx, *flags, producer / "main.o", "-Wl,--whole-archive", archive,
                           "-Wl,--no-whole-archive", "-o", executable]
                subprocess.run(command, check=True, capture_output=True, timeout=90)
                original_elf, original_archive = digest(executable), digest(archive)
                subprocess.run(command + ["-Wl,-Map=" + str(mapping)], check=True, capture_output=True, timeout=90)
                self.assertEqual(digest(executable), original_elf, "map generation changed executable")
                size = mapping.stat().st_size
                self.assertGreater(size, 512 * 1024**2)
                self.assertLess(size, subject.MAX_MAP_BYTES)
                with mock.patch.object(subject, "MAX_MAP_BYTES", 512 * 1024**2):
                    with self.assertRaisesRegex(ValueError, "size outside bounds"):
                        cef_elf_init.audit(executable)
                tracemalloc.start()
                try:
                    with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("bulk map read")), \
                         mock.patch.object(Path, "read_text", side_effect=AssertionError("bulk map read")):
                        proof = cef_elf_init.audit(executable)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 32 * 1024**2)
                summary = proof["summary"]
                self.assertEqual(summary["constructor_source_map_bytes"], size)
                self.assertEqual(summary["constructor_source_map_sha256"], digest(mapping))
                self.assertTrue(summary["constructor_source_map_scan_complete"])
                self.assertGreater(summary["constructor_source_map_rows"], 12000)
                self.assertEqual(summary["constructor_integrity_verified"], not null)
                self.assertEqual(summary["constructor_zero_unrelocated_count"], int(null))
                self.assertEqual(summary["constructor_zero_inside_input_count"], int(null))
                self.assertEqual(summary["constructor_zero_linker_padding_count"], 0)
                if null:
                    self.assertEqual(summary["constructor_input_matched_count"], 1)
                    self.assertEqual(summary["constructor_input_without_relocation_count"], 1)
                else:
                    self.assertEqual(subprocess.run([executable], timeout=10).returncode, 0)
                # An invalid tail must fail even after every expected range was
                # matched in a map larger than the old total-size limit.
                with mapping.open("ab") as stream:
                    stream.write(b"invalid late private-row\n")
                with self.assertRaisesRegex(ValueError, "malformed"):
                    cef_elf_init.audit(executable)
                with mapping.open("r+b") as stream:
                    stream.truncate(size)
                self.assertEqual(digest(executable), original_elf)
                self.assertEqual(digest(archive), original_archive)
                self.assertNotIn("volume_", json.dumps(summary))
                if not null:
                    valid_build, valid_sha = build, original_elf
                print("CEF_CONSTRUCTOR_LARGE_MAP_VERIFIED", size,
                      summary["constructor_source_map_rows"], "null=" + str(int(null)), version)
            shutil.rmtree(producer)
            relocated = valid_build.with_name("relocated-build")
            valid_build.rename(relocated)
            self.assertEqual(digest(relocated / "consumer"), valid_sha)
            self.assertTrue(cef_elf_init.audit(relocated / "consumer")["summary"]["constructor_integrity_verified"])
            self.assertEqual(subprocess.run([relocated / "consumer"], cwd=relocated, timeout=10).returncode, 0)


class WiringTests(unittest.TestCase):
    def test_required_preflight_loads_scale_regression_once_and_audit_stays_strict(self):
        source = (ROOT / "tests/test_cef_consumer_linker.py").read_text(encoding="utf-8")
        self.assertIn('if pattern == "test_cef_consumer_linker.py":', source)
        self.assertEqual(source.count("import test_cef_constructor_map_scale as map_scale"), 1)
        self.assertEqual(source.count("loader.loadTestsFromModule(map_scale)"), 1)
        audit = inspect.getsource(cef_elf_init.audit)
        self.assertIn("cef_constructor_map.inspect_map(", audit)
        self.assertIn('"constructor_integrity_verified": verified', audit)
        self.assertIn('"zero_unrelocated",', audit)
        self.assertIn('"undefined_weak",', audit)
        self.assertEqual(subject.MAX_MAP_BYTES, 2 * 1024**3)
        self.assertEqual(subject.MAX_MAP_ROWS, 20_000_000)
        self.assertEqual(subject.MAX_MAP_LINE_BYTES, 1024**2)
        self.assertEqual(subject.MAX_INPUTS, 1_000_000)


if __name__ == "__main__":
    unittest.main()
