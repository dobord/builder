"""Native collision regressions use disposable public C/assembly sources only."""
from collections import Counter
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from secure_release import cef_gtk_codecs as codecs


class NinjaPathTests(unittest.TestCase):
    def test_exact_path_tokens_and_arbitrary_bytes(self):
        pairs = [(b"/prefix/lib/libjpeg.a", b".derived/jpeg.a")]
        raw = (b"libs = /prefix/lib/libjpeg.a\n"
               b"build /prefix/lib/libjpeg.a: phony\n"
               b" /prefix/lib/libjpeg.a.backup /other/prefix/lib/libjpeg.a\n#\xff\xfe\n")
        actual, used = codecs.rewrite_graph(raw, pairs)
        self.assertEqual(used, {0})
        self.assertIn(b"libs = .derived/jpeg.a\n", actual)
        self.assertIn(b"build .derived/jpeg.a: phony\n", actual)
        self.assertIn(b"/prefix/lib/libjpeg.a.backup", actual)
        self.assertIn(b"/other/prefix/lib/libjpeg.a", actual)
        self.assertTrue(actual.endswith(b"#\xff\xfe\n"))
        self.assertEqual(codecs.rewrite_graph(actual, pairs), (actual, {0}))

    def test_weak_undefined_is_not_a_provider(self):
        table = Counter({("weak_ref", "w"): 1, ("weak_data", "v"): 1,
                         ("strong_ref", "U"): 1, ("weak_def", "W"): 1,
                         ("data", "D"): 1})
        self.assertEqual(codecs.defined(table), {"weak_def", "data"})

    def test_source_has_no_error_suppression_or_codec_feature_disable(self):
        text = Path(codecs.__file__).read_text()
        for forbidden in ("allow-multiple-definition", "muldefs", "use_gtk = false",
                          "ignore-all", "strip-all"):
            self.assertNotIn(forbidden, text)
        wrapper = (Path(codecs.__file__).parent / "cef_nss_isolation.py").read_text()
        self.assertIn("cef_gtk_codecs.attach(", wrapper)
        self.assertIn("cef_gtk_codecs.record_receipt(", wrapper)


@unittest.skipUnless(sys.platform == "linux" and all(shutil.which(x) for x in
                    ("cc", "ar", "nm", "objcopy", "ninja", "readelf")),
                    "Native Linux archive tools required")
class CodecNativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / "prefix"
        (self.prefix / "lib").mkdir(parents=True)
        self.out = self.root / "out"
        self.out.mkdir()
        self.nm = Path(shutil.which("nm")).resolve()
        self.objcopy = Path(shutil.which("objcopy")).resolve()
        self.manifest = self.root / "platform.json"
        self.sources = {}
        self.archive("lib/libjpeg.a", {
            "jpeg": "int jpeg_natural_order=3; int jpeg_std_error(void){return 11;} "
                    "int jpeg_only(void){return 97;} "
                    "__attribute__((weak)) int jpeg_weak(void){return 9;}",
            "simd": '.text\n.globl jsimd_h2v1_downsample\n'
                    'jsimd_h2v1_downsample:\n mov $13, %eax\n ret\n'
                    '.section .note.GNU-stack,"",@progbits\n',
        })
        self.archive("lib/libtiff.a", {"tiff":
            "extern int jpeg_std_error(void); extern int jpeg_natural_order; "
            "int TIFFOpen(void){return 100+jpeg_std_error()+jpeg_natural_order;} "
            "int TIFFOnly(void){return 199;}"})
        self.archive("lib/libgdk_pixbuf-2.0.a", {"pixbuf":
            "extern int TIFFOpen(void), TIFFOnly(void), jpeg_only(void), jsimd_h2v1_downsample(void); "
            "int gtk_image_probe(void){return TIFFOpen()+TIFFOnly()+jpeg_only()+jsimd_h2v1_downsample();}"})
        self.archive("lib/libcairo.a", {"cairo":
            "extern int jpeg_natural_order; int cairo_image_probe(void){return jpeg_natural_order;}"})
        self.archive("lib/libglib-2.0.a", {"glib":
            "int single_registry=5; int registry_probe(void){return single_registry;}"})
        self.refresh_manifest()
        app = self.object("app", "extern int gtk_image_probe(void), cairo_image_probe(void), registry_probe(void); "
            "extern int jpeg_std_error(void), TIFFOpen(void), jsimd_h2v1_downsample(void); "
            "extern int jpeg_natural_order; int main(void){return !(gtk_image_probe()==423 "
            "&& cairo_image_probe()==3 && registry_probe()==5 && jpeg_std_error()==31 "
            "&& TIFFOpen()==301 && jsimd_h2v1_downsample()==47 && jpeg_natural_order==7);}")
        engine = self.object("engine", "int jpeg_natural_order=7; int jpeg_std_error(void){return 31;} "
            "int TIFFOpen(void){return 301;} int jsimd_h2v1_downsample(void){return 47;}")
        inputs = [str(app), str(engine)] + [str(self.prefix/n) for n in self.sources]
        (self.out/"build.ninja").write_text(
            "rule link\n  command = cc -Wl,--start-group $in -Wl,--end-group -o $out\n"
            "build codec-probe: link " + " ".join(inputs) + "\n")

    def command(self, command, **kwargs):
        return subprocess.run(list(map(str, command)), capture_output=True, text=True,
                              timeout=30, **kwargs)

    def object(self, name, content, asm=False):
        src = self.root / (name + (".S" if asm else ".c"))
        src.write_text(content)
        obj = self.root / (name + ".o")
        result = self.command(["cc", "-O0", "-fPIC", "-c", src, "-o", obj])
        self.assertEqual(result.returncode, 0, result.stderr)
        return obj

    def archive(self, name, contents):
        objects = [self.object(Path(name).stem+"_"+n, s, n == "simd") for n,s in contents.items()]
        archive = self.prefix / name
        archive.unlink(missing_ok=True)
        result = self.command(["ar", "rcs", archive, *objects])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.sources[name] = len(objects)

    def refresh_manifest(self):
        value = {"schema": 1, "kind": "linux-x64-static-platform-build-inputs",
                 "runtime_verified": False,
                 "modules": {"gtk+-3.0": {"libraries": list(self.sources)}},
                 "archive_objects": dict(self.sources),
                 "files": {n: {"size": (self.prefix/n).stat().st_size,
                               "sha256": codecs.digest(self.prefix/n)} for n in self.sources}}
        self.manifest.write_bytes(codecs.canonical(value))
        self.sha = codecs.digest(self.manifest)

    def repair(self):
        return codecs.repair(self.out, self.manifest, self.prefix, self.sha, self.nm, self.objcopy)

    def test_native_duplicate_then_coherent_namespace_link_and_run(self):
        before = {n: (codecs.digest(self.prefix/n), (self.prefix/n).stat().st_mtime_ns)
                  for n in self.sources}
        bad = self.command(["ninja", "-C", self.out])
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("multiple definition", bad.stdout)
        status = self.repair()
        self.assertEqual(status["status"], "success")
        good = self.command(["ninja", "-C", self.out])
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        self.assertEqual(self.command([self.out/"codec-probe"]).returncode, 0)
        imports = self.command(["readelf", "-d", self.out/"codec-probe"]).stdout
        for unwanted in ("libjpeg.so", "libtiff.so", "libgobject", "libglib"):
            self.assertNotIn(unwanted, imports)
        self.assertEqual(before, {n: (codecs.digest(self.prefix/n), (self.prefix/n).stat().st_mtime_ns)
                                 for n in self.sources})
        derived = self.out / codecs.DIRECTORY
        receipt = json.loads((derived/"receipt.json").read_bytes())
        self.assertEqual(set(receipt["archives"]), set(self.sources)-{"lib/libglib-2.0.a"})
        for name in ("lib/libtiff.a", "lib/libgdk_pixbuf-2.0.a", "lib/libcairo.a"):
            table = codecs.symbols(self.nm, derived/receipt["archives"][name]["file"])
            self.assertTrue(any(n.startswith(codecs.NAMESPACE) and k == "U" for n,k in table))
        clocks = {p: p.stat().st_mtime_ns for p in derived.iterdir()}
        graph_clock = (self.out/"build.ninja").stat().st_mtime_ns
        self.assertEqual(self.repair(), status)
        self.assertEqual(clocks, {p: p.stat().st_mtime_ns for p in derived.iterdir()})
        self.assertEqual(graph_clock, (self.out/"build.ninja").stat().st_mtime_ns)

    def test_llvm_objcopy_uses_the_same_namespace_and_archive_index(self):
        llvm = shutil.which("llvm-objcopy")
        if not llvm:
            self.skipTest("LLVM objcopy not installed")
        self.objcopy = Path(llvm).resolve()
        self.repair()
        result = self.command(["ninja", "-C", self.out])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.command([self.out/"codec-probe"]).returncode, 0)

    def test_provider_only_rename_would_be_wrong(self):
        self.repair()
        graph = self.out / "build.ninja"
        receipt = json.loads((self.out/codecs.DIRECTORY/"receipt.json").read_bytes())
        # Deliberately undo consumer rewriting: the link either fails or binds
        # image callers to the wrong engine codec. It must never qualify.
        s = graph.read_text()
        for name, item in receipt["archives"].items():
            if name not in codecs.OWNERS:
                s = s.replace(str(self.out/codecs.DIRECTORY/item["file"]), str(self.prefix/name))
        graph.write_text(s)
        result = self.command(["ninja", "-C", self.out])
        if result.returncode == 0:
            self.assertNotEqual(self.command([self.out/"codec-probe"]).returncode, 0)

    def test_frozen_tamper_rejected_even_with_cached_derivation(self):
        self.repair()
        with (self.prefix/"lib/libjpeg.a").open("ab") as f:
            f.write(b"corrupt")
        with self.assertRaisesRegex(ValueError, "Frozen codec closure changed"):
            self.repair()

    def test_derived_tamper_rejected(self):
        self.repair()
        p = next((self.out/codecs.DIRECTORY).glob("*.a"))
        with p.open("ab") as f:
            f.write(b"corrupt")
        with self.assertRaisesRegex(ValueError, "Derived codec archive changed"):
            self.repair()

    def test_mapping_tamper_rejected(self):
        self.repair()
        (self.out/codecs.DIRECTORY/"redefine-syms.txt").write_text("wrong\n")
        with self.assertRaisesRegex(ValueError, "Codec mapping changed"):
            self.repair()

    def test_missing_consumer_record_rejected(self):
        value = json.loads(self.manifest.read_bytes())
        del value["files"]["lib/libgdk_pixbuf-2.0.a"]
        self.manifest.write_bytes(codecs.canonical(value)); self.sha = codecs.digest(self.manifest)
        with self.assertRaises(ValueError):
            self.repair()

    def test_foreign_definition_and_namespace_collision_rejected(self):
        self.archive("lib/libforeign.a", {"foreign": "int jpeg_std_error(void){return 0;}"})
        self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, "outside its providers"):
            self.repair()
        self.archive("lib/libforeign.a", {"foreign": "int CEF_GTK_CODEC_jpeg_std_error(void){return 0;}"})
        self.refresh_manifest()
        with self.assertRaisesRegex(ValueError, "namespace already exists"):
            self.repair()

    def test_symlink_inputs_and_outputs_rejected(self):
        original = self.prefix/"lib/libjpeg.a"
        saved = original.with_suffix(".saved")
        original.rename(saved); original.symlink_to(saved.name)
        with self.assertRaisesRegex(ValueError, "Redirected"):
            self.repair()
        original.unlink(); saved.rename(original)
        elsewhere = self.root/"elsewhere"; elsewhere.mkdir()
        (self.out/codecs.DIRECTORY).symlink_to(elsewhere)
        with self.assertRaisesRegex(ValueError, "Redirected"):
            self.repair()

    def test_missing_native_codec_edge_rejected(self):
        (self.out/"build.ninja").write_text("# no codec link here\n")
        with self.assertRaisesRegex(ValueError, "does not link both"):
            self.repair()

    def test_cli_receipt_and_nss_hook(self):
        wrapper = "import os,sys,subprocess\nout = None\nREAL_NINJA = None\n" + codecs.ANCHOR
        summary = {}
        hooked = codecs.attach(wrapper, self.root, self.manifest, self.prefix, self.sha, summary)
        compile(hooked, "<synthetic-nss-hook>", "exec")
        self.assertTrue(summary["gtk_codec_namespace_installed"])
        with self.assertRaisesRegex(ValueError, "exec boundary changed"):
            codecs.attach(wrapper+codecs.ANCHOR, self.root, self.manifest, self.prefix, self.sha, {})
        run = self.command([sys.executable, codecs.__file__, "--out", self.out,
                            "--manifest", self.manifest, "--prefix", self.prefix,
                            "--sha256", self.sha, "--nm", self.nm, "--objcopy", self.objcopy])
        self.assertEqual(run.returncode, 0, run.stderr)
        source = self.root/"source"
        (source/"out").mkdir(parents=True)
        self.out.rename(source/"out/CEF_Static_Platform_Release_x64")
        self.assertTrue(codecs.record_receipt(source, summary, required=True))
        self.assertTrue(summary["gtk_codec_namespace_verified"])
        self.assertEqual(summary["gtk_codec_namespace_archives"], 4)


if __name__ == "__main__":
    unittest.main()
