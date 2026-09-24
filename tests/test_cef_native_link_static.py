"""Regression guards for the strict static Expat/unwind link repair."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import cef_native_link_static as native


class NativeLinkTransformTests(unittest.TestCase):
    def test_recipe_selects_chromium_libunwind_without_allowlist_escape(self):
        original = "prefix\n" + native._RECIPE_OLD + "suffix\n"
        patched = native.patch_recipe(original)
        self.assertIn("result['use_custom_libunwind'] = True", patched)
        self.assertIn(native.MARKER, patched)
        self.assertNotIn("static-libgcc", patched)
        self.assertNotIn("libgcc_s.so", patched)
        self.assertEqual(native.unpatch_recipe(patched), original)

    def test_expat_uses_frozen_pkg_config_only_for_static_target(self):
        original = (
            native._EXPAT_IMPORT_OLD
            + "other import\n"
            + native._EXPAT_OLD
        )
        patched = native.patch_expat(original)
        self.assertIn('import("//build/config/linux/pkg_config.gni")', patched)
        self.assertIn('cef_static_platform_manifest != ""', patched)
        self.assertIn("current_toolchain == default_toolchain", patched)
        self.assertIn('pkg_config("expat_config")', patched)
        self.assertIn('packages = [ "expat" ]', patched)
        # The ordinary/host fallback remains exactly Chromium's bare-library path.
        self.assertIn('libs = [ "expat" ]', patched)
        self.assertEqual(native.unpatch_expat(patched), original)

    def test_partial_states_fail_closed(self):
        with self.assertRaises(ValueError):
            native.patch_recipe(native.MARKER + "\n" + native._RECIPE_OLD)
        with self.assertRaises(ValueError):
            native.unpatch_expat(native._EXPAT_IMPORT_NEW + native._EXPAT_OLD)

    def test_reviewed_output_accepts_original_and_exact_migration_only(self):
        original = ("prefix\n" + native._RECIPE_OLD + "suffix\n").encode()
        expected = native.git_blob(original)
        output = native.reviewed_output(
            original, expected, native.patch_recipe, native.unpatch_recipe, "test recipe"
        )
        self.assertEqual(
            native.reviewed_output(
                output, expected, native.patch_recipe, native.unpatch_recipe, "test recipe"
            ),
            output,
        )
        tampered = output.replace(b"use_custom_libunwind", b"use_custom_libunwinX")
        with self.assertRaises(ValueError):
            native.reviewed_output(
                tampered, expected, native.patch_recipe, native.unpatch_recipe, "test recipe"
            )


class NativeLinkInstallTests(unittest.TestCase):
    def test_install_validates_both_files_before_writing_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipe_repo = root / "cef"
            recipe = recipe_repo / "vcpkg/ports/cef-static/source_build.py"
            source = root / "chromium"
            expat = source / "third_party/expat/BUILD.gn"
            recipe.parent.mkdir(parents=True)
            expat.parent.mkdir(parents=True)
            recipe_original = ("prefix\n" + native._RECIPE_OLD + "suffix\n").encode()
            expat_original = (
                native._EXPAT_IMPORT_OLD + "other import\n" + native._EXPAT_OLD
            ).encode()
            recipe.write_bytes(recipe_original)
            expat.write_bytes(expat_original)

            def head(path):
                return native.CEF_RECIPE if Path(path) == recipe_repo else native.CHROMIUM

            with mock.patch.object(native, "RECIPE_BLOB", native.git_blob(recipe_original)), \
                 mock.patch.object(native, "EXPAT_BLOB", native.git_blob(expat_original)), \
                 mock.patch.object(native, "_head", side_effect=head):
                first = native.install(recipe, source)
                recipe_mtime = recipe.stat().st_mtime_ns
                expat_mtime = expat.stat().st_mtime_ns
                second = native.install(recipe, source)

            self.assertEqual(first["changed_files"], 2)
            self.assertEqual(second["changed_files"], 0)
            self.assertEqual(recipe.stat().st_mtime_ns, recipe_mtime)
            self.assertEqual(expat.stat().st_mtime_ns, expat_mtime)
            self.assertIn("use_custom_libunwind", recipe.read_text())
            self.assertIn('pkg_config("expat_config")', expat.read_text())

    def test_unknown_expat_fails_before_recipe_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipe_repo = root / "cef"
            recipe = recipe_repo / "vcpkg/ports/cef-static/source_build.py"
            source = root / "chromium"
            expat = source / "third_party/expat/BUILD.gn"
            recipe.parent.mkdir(parents=True)
            expat.parent.mkdir(parents=True)
            recipe_original = ("prefix\n" + native._RECIPE_OLD + "suffix\n").encode()
            recipe.write_bytes(recipe_original)
            expat.write_text("unknown\n")

            def head(path):
                return native.CEF_RECIPE if Path(path) == recipe_repo else native.CHROMIUM

            with mock.patch.object(native, "RECIPE_BLOB", native.git_blob(recipe_original)), \
                 mock.patch.object(native, "EXPAT_BLOB", "0" * 40), \
                 mock.patch.object(native, "_head", side_effect=head):
                with self.assertRaises(ValueError):
                    native.install(recipe, source)
            self.assertEqual(recipe.read_bytes(), recipe_original)


if __name__ == "__main__":
    unittest.main()
