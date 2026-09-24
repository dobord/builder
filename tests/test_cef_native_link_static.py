"""Regression guards for the strict static Expat/unwind link repair."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_native_link_static as native

def _pinned_checkpoint_roundtrip(snapshot: Path) -> None:
    """Child-process regression using the real, immutable Linux checkpoint codec."""
    import shutil

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repo = root / "recipe"
        shutil.copytree(snapshot / "vcpkg", repo / "vcpkg")
        sys.path.insert(0, str(repo / "vcpkg/static"))
        import linux_checkpoint as checkpoint

        recipe = repo / "vcpkg/ports/cef-static/source_build.py"
        original = recipe.read_bytes()
        assert native.git_blob(original) == native.RECIPE_BLOB
        policy = repo / "vcpkg/static/linux_checkpoint.py"
        assert native.git_blob(policy.read_bytes()) == native.CHECKPOINT_POLICY_BLOB
        patched = native.reviewed_output(
            original, native.RECIPE_BLOB, native.patch_recipe,
            native.unpatch_recipe, "CEF recipe"
        )
        os.environ.update(
            ImageVersion="fixture-image", GITHUB_REPOSITORY="dobord/builder",
            GITHUB_REF="refs/heads/feature/cef-static-integration"
        )
        work, package = root / "work", root / "package"
        work.mkdir()
        (work / "preserved.o").write_bytes(b"synthetic-compiled-progress")
        clock = 1700000000000000123
        os.utime(work / "preserved.o", ns=(clock, clock))
        recipe.write_bytes(patched)
        identity = checkpoint.ci_identity(work)
        checkpoint.save(work, package, identity)
        shutil.rmtree(work)
        manifest_before = (package / "checkpoint.json").read_bytes()
        recipe.write_bytes(original)
        mismatch = checkpoint.ci_identity(work)
        assert identity != mismatch
        try:
            checkpoint.restore(package, work, mismatch)
        except ValueError as error:
            assert "identity/schema mismatch" in str(error)
        else:
            raise AssertionError("Pristine recipe incorrectly restored changed recipe identity")
        assert not work.exists()
        # Public source archives have no .git metadata. Only this metadata call
        # is mocked; complete recipe bytes and the upstream codec are real.
        with mock.patch.object(native, "_head", return_value=native.CEF_RECIPE):
            report = native.prepare_restore(recipe, package)
        assert report["profile"] == "native-link-v1"
        assert checkpoint.ci_identity(work) == identity
        assert (package / "checkpoint.json").read_bytes() == manifest_before
        checkpoint.restore(package, work, checkpoint.ci_identity(work))
        assert (work / "preserved.o").read_bytes() == b"synthetic-compiled-progress"
        assert (work / "preserved.o").stat().st_mtime_ns == clock
        shutil.rmtree(work)
        try:
            checkpoint.restore(package, work, dict(identity, image="wrong-image"))
        except ValueError as error:
            assert "identity/schema mismatch" in str(error)
        else:
            raise AssertionError("Full checkpoint identity was not enforced")
        assert not work.exists()



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
            # Windows TEMP can use an 8.3 alias; install() resolves repository roots.
            root = Path(directory).resolve(strict=True)
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

            # An unexpected repository must fail the test, not receive Chromium's pin.
            heads = {recipe_repo.resolve(strict=True): native.CEF_RECIPE,
                     source.resolve(strict=True): native.CHROMIUM}

            with mock.patch.object(native, "RECIPE_BLOB", native.git_blob(recipe_original)), \
                 mock.patch.object(native, "EXPAT_BLOB", native.git_blob(expat_original)), \
                 mock.patch.object(native, "_head", side_effect=heads.__getitem__):
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
            # Windows TEMP can use an 8.3 alias; install() resolves repository roots.
            root = Path(directory).resolve(strict=True)
            recipe_repo = root / "cef"
            recipe = recipe_repo / "vcpkg/ports/cef-static/source_build.py"
            source = root / "chromium"
            expat = source / "third_party/expat/BUILD.gn"
            recipe.parent.mkdir(parents=True)
            expat.parent.mkdir(parents=True)
            recipe_original = ("prefix\n" + native._RECIPE_OLD + "suffix\n").encode()
            recipe.write_bytes(recipe_original)
            expat.write_text("unknown\n")

            # An unexpected repository must fail the test, not receive Chromium's pin.
            heads = {recipe_repo.resolve(strict=True): native.CEF_RECIPE,
                     source.resolve(strict=True): native.CHROMIUM}

            with mock.patch.object(native, "RECIPE_BLOB", native.git_blob(recipe_original)), \
                 mock.patch.object(native, "EXPAT_BLOB", "0" * 40), \
                 mock.patch.object(native, "_head", side_effect=heads.__getitem__):
                with self.assertRaisesRegex(
                    ValueError, "Unreviewed or partially patched Chromium Expat source"
                ):
                    native.install(recipe, source)
            self.assertEqual(recipe.read_bytes(), recipe_original)


    def test_noncanonical_temp_path_reproduces_old_mock_error(self):
        # Unlike a symlink/junction, this spelling requires no Windows privilege.
        # It recreates the distinction between a TEMP alias and install's resolved
        # repository path on every OS; real Windows CI additionally covers 8.3 TEMP.
        with tempfile.TemporaryDirectory() as directory:
            canonical = Path(directory).resolve(strict=True)
            traversal = canonical / "path-spelling"
            traversal.mkdir()
            root = traversal / ".."
            recipe_repo = root / "cef"
            recipe = recipe_repo / "vcpkg/ports/cef-static/source_build.py"
            source = root / "chromium"
            expat = source / "third_party/expat/BUILD.gn"
            recipe.parent.mkdir(parents=True)
            expat.parent.mkdir(parents=True)
            recipe_original = ("prefix\n" + native._RECIPE_OLD + "suffix\n").encode()
            expat_original = (native._EXPAT_IMPORT_OLD + native._EXPAT_OLD).encode()
            recipe.write_bytes(recipe_original)
            expat.write_bytes(expat_original)
            self.assertNotEqual(recipe_repo, recipe_repo.resolve(strict=True))

            def old_head(path):
                return native.CEF_RECIPE if Path(path) == recipe_repo else native.CHROMIUM

            heads = {recipe_repo.resolve(strict=True): native.CEF_RECIPE,
                     source.resolve(strict=True): native.CHROMIUM}
            with mock.patch.object(native, "RECIPE_BLOB", native.git_blob(recipe_original)), \
                 mock.patch.object(native, "EXPAT_BLOB", native.git_blob(expat_original)):
                with mock.patch.object(native, "_head", side_effect=old_head):
                    with self.assertRaisesRegex(ValueError, "source revision changed"):
                        native.install(recipe, source)
                self.assertEqual(recipe.read_bytes(), recipe_original)
                self.assertEqual(expat.read_bytes(), expat_original)

                with mock.patch.object(native, "_head", side_effect=heads.__getitem__) as head:
                    result = native.install(recipe, source)
                self.assertEqual(head.call_args_list, [
                    mock.call(recipe_repo.resolve(strict=True)),
                    mock.call(source.resolve(strict=True)),
                ])
                self.assertEqual(result["changed_files"], 2)
                self.assertFalse(result["runtime_verified"])

                # Correcting test path spelling must not bypass revision checks.
                wrong_heads = dict(heads)
                wrong_heads[recipe_repo.resolve(strict=True)] = "0" * 40
                with mock.patch.object(native, "_head", side_effect=wrong_heads.__getitem__):
                    with self.assertRaisesRegex(ValueError, "source revision changed"):
                        native.install(recipe, source)

class CheckpointRecipeTests(unittest.TestCase):
    # Independent reference for the pinned linux_checkpoint.ci_identity recipe
    # algorithm (blob 8e04c160c33a808602aa3cdb727fc2fb8bedad29).
    @staticmethod
    def reference_fingerprint(repo):
        import hashlib
        digest = hashlib.sha256()
        paths = list((repo / "vcpkg/ports/cef-static").rglob("*")) + [
            repo / "vcpkg/static/ci.py", repo / "vcpkg/static/checkpoint.py",
            repo / "vcpkg/static/windows_slice.py", repo / "vcpkg/static/linux_checkpoint.py",
            repo / "vcpkg/static/linux_slice.py",
            repo / "vcpkg/static/triplets/x64-linux.cmake",
        ]
        for path in sorted(paths):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                digest.update(path.relative_to(repo).as_posix().encode() + b"\0")
                digest.update(path.read_bytes())
        return digest.hexdigest()

    def setUp(self):
        import json
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve(strict=True)
        self.repo = self.root / "cef"
        self.recipe = self.repo / "vcpkg/ports/cef-static/source_build.py"
        self.recipe.parent.mkdir(parents=True)
        self.original = ("prefix\n" + native._RECIPE_OLD + "suffix\n").encode()
        self.patched = native.patch_recipe(self.original.decode()).encode()
        self.recipe.write_bytes(self.original)
        self.policy = self.repo / "vcpkg/static/linux_checkpoint.py"
        for relative in ("ci.py", "checkpoint.py", "windows_slice.py",
                         "linux_checkpoint.py", "linux_slice.py", "triplets/x64-linux.cmake"):
            path = self.repo / "vcpkg/static" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode())
        # Nested recipe files, including ignored Python cache files, participate
        # according to the original algorithm, not a source_build-only hash.
        support = self.recipe.parent / "cpp_support/config.cmake"
        support.parent.mkdir()
        support.write_bytes(b"set(FIXTURE ON)\n")
        (self.recipe.parent / "unused.pyc").write_bytes(b"ignored cache")
        self.old_hash = self.reference_fingerprint(self.repo)
        self.recipe.write_bytes(self.patched)
        self.new_hash = self.reference_fingerprint(self.repo)
        self.assertNotEqual(self.old_hash, self.new_hash)
        self.recipe.write_bytes(self.original)
        self.package = self.root / "authenticated-package"
        self.package.mkdir()
        self.record = self.package / "checkpoint.json"
        self.value = {"schema": 3, "kind": "build-checkpoint-not-sdk",
                      "engine_runtime_verified": False,
                      "identity": {"recipe": self.new_hash, "image": "fixture-image"}}
        self.record.write_text(json.dumps(self.value), encoding="utf-8")
        for patch in (
            mock.patch.object(native, "RECIPE_BLOB", native.git_blob(self.original)),
            mock.patch.object(native, "CHECKPOINT_POLICY_BLOB",
                              native.git_blob(self.policy.read_bytes())),
            mock.patch.object(native, "_head", return_value=native.CEF_RECIPE),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_new_checkpoint_requires_and_recreates_exact_native_recipe(self):
        before_record = self.record.read_bytes()
        # This is the old consumer failure: restoring a native-link checkpoint
        # with the pristine checkout gives a different recipe identity.
        self.assertNotEqual(self.reference_fingerprint(self.repo), self.new_hash)
        report = native.prepare_restore(self.recipe, self.package)
        self.assertEqual(report["profile"], "native-link-v1")
        self.assertTrue(report["changed"])
        self.assertEqual(self.recipe.read_bytes(), self.patched)
        self.assertEqual(self.reference_fingerprint(self.repo), self.new_hash)
        self.assertEqual(self.record.read_bytes(), before_record)
        stamp = self.recipe.stat().st_mtime_ns
        self.assertFalse(native.prepare_restore(self.recipe, self.package)["changed"])
        self.assertEqual(self.recipe.stat().st_mtime_ns, stamp)
        self.assertFalse(report["runtime_verified"])

    def test_old_checkpoint_remains_usable_without_identity_rewrite(self):
        import json
        self.value["identity"]["recipe"] = self.old_hash
        self.record.write_text(json.dumps(self.value), encoding="utf-8")
        before = self.record.read_bytes()
        stamp = self.recipe.stat().st_mtime_ns
        self.assertFalse(native.prepare_restore(self.recipe, self.package)["changed"])
        self.assertEqual(self.recipe.stat().st_mtime_ns, stamp)
        self.recipe.write_bytes(self.patched)
        report = native.prepare_restore(self.recipe, self.package)
        self.assertEqual(report["profile"], "pinned-recipe")
        self.assertEqual(self.recipe.read_bytes(), self.original)
        self.assertEqual(self.reference_fingerprint(self.repo), self.old_hash)
        self.assertEqual(self.record.read_bytes(), before)

    def test_unknown_recorded_identity_rejected_before_any_write(self):
        import json
        self.value["identity"]["recipe"] = "0" * 64
        self.record.write_text(json.dumps(self.value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unreviewed recipe state"):
            native.prepare_restore(self.recipe, self.package)
        self.assertEqual(self.recipe.read_bytes(), self.original)

    def test_unrelated_recipe_change_cannot_be_hidden_by_variant_selection(self):
        (self.recipe.parent / "cpp_support/config.cmake").write_bytes(b"changed\n")
        with self.assertRaisesRegex(ValueError, "unreviewed recipe state"):
            native.prepare_restore(self.recipe, self.package)
        self.assertEqual(self.recipe.read_bytes(), self.original)

    def test_unknown_recipe_bytes_and_hashing_policy_are_not_blessed(self):
        self.recipe.write_bytes(self.patched + b"# unknown edit\n")
        with self.assertRaisesRegex(ValueError, "partially patched"):
            native.prepare_restore(self.recipe, self.package)
        self.recipe.write_bytes(self.original)
        self.policy.write_bytes(b"unknown hashing algorithm\n")
        with self.assertRaisesRegex(ValueError, "hashing policy changed"):
            native.prepare_restore(self.recipe, self.package)
        self.assertEqual(self.recipe.read_bytes(), self.original)

    def test_invalid_manifest_and_revision_rejected(self):
        import json
        self.value["engine_runtime_verified"] = True
        self.record.write_text(json.dumps(self.value), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Invalid checkpoint recipe manifest"):
            native.prepare_restore(self.recipe, self.package)
        with mock.patch.object(native, "_head", return_value="0" * 40):
            with self.assertRaisesRegex(ValueError, "revision changed"):
                native.prepare_restore(self.recipe, self.package)
        self.assertEqual(self.recipe.read_bytes(), self.original)

    def test_other_identity_fields_are_never_rewritten(self):
        import json
        self.value["identity"]["image"] = "another-image-the-driver-must-reject"
        self.record.write_text(json.dumps(self.value), encoding="utf-8")
        before = self.record.read_bytes()
        native.prepare_restore(self.recipe, self.package)
        self.assertEqual(self.record.read_bytes(), before)
        self.assertEqual(json.loads(before)["identity"]["image"],
                         "another-image-the-driver-must-reject")

    def test_atomic_replace_failure_preserves_recipe_and_cleans_staging(self):
        with mock.patch.object(native.os, "replace", side_effect=OSError("test failure")):
            with self.assertRaises(OSError):
                native.prepare_restore(self.recipe, self.package)
        self.assertEqual(self.recipe.read_bytes(), self.original)
        self.assertEqual(list(self.recipe.parent.glob(".cef-native-link-*")), [])


class PinnedCheckpointRoundtripTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Pinned checkpoint codec is Linux-only")
    def test_real_pinned_codec_rejects_old_recipe_and_restores_exact_variant(self):
        builder = Path(__file__).resolve().parents[1]
        snapshot = Path(os.environ.get(
            "CEF_NATIVE_LINK_RECIPE_FIXTURE", builder / "private-vcpkg/.full-cef"
        )).resolve()
        if not (snapshot / "vcpkg/static/linux_checkpoint.py").is_file():
            self.skipTest("The engine preflight supplies the pinned CEF recipe checkout")
        # Run isolated: the real codec imports sibling modules named checkpoint.
        # Copy public recipe inputs; never modify the runner's actual recipe.
        script = (
            "import runpy, sys; from pathlib import Path; "
            "sys.path.insert(0, sys.argv[1]); "
            "runpy.run_path(sys.argv[2])['_pinned_checkpoint_roundtrip'](Path(sys.argv[3]))"
        )
        subprocess.run(
            [sys.executable, "-I", "-c", script, str(builder), __file__, str(snapshot)],
            check=True, capture_output=True, text=True, timeout=60
        )

class RestoreAdapterTests(unittest.TestCase):
    def test_prepare_precedes_unchanged_restore_command(self):
        from types import SimpleNamespace
        from secure_release import cef_strict_iteration_runtime as runtime

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            workspace, temp = root / "workspace", root / "temp"
            recipe = workspace / "private-vcpkg/.full-cef/vcpkg/ports/cef-static"
            package = temp / "cef-strict-restored-checkpoint"
            command = ["python", recipe.parents[1] / "integration/driver.py", "restore",
                       "--checkpoint", package, "--contract", "fixture-contract"]
            events = []

            def prepare(*args):
                events.append(("prepare", args))

            def run(*args, **kwargs):
                events.append(("restore", args, kwargs))
                return SimpleNamespace(returncode=0)

            module = SimpleNamespace(run=run, classify_engine_runtime=lambda _: {})
            with mock.patch.object(native, "prepare_restore", side_effect=prepare), \
                 mock.patch.object(native, "install") as install:
                with runtime.observed_runtime(module, workspace, temp):
                    module.run(command, timeout=37)
            self.assertEqual(events, [
                ("prepare", (recipe / "source_build.py", package)),
                ("restore", (command,), {"timeout": 37}),
            ])
            install.assert_not_called()
            self.assertIs(module.run, run)

    def test_unexpected_restore_package_never_prepares_or_restores(self):
        from types import SimpleNamespace
        from secure_release import cef_strict_iteration_runtime as runtime

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            workspace, temp = root / "workspace", root / "temp"
            driver = workspace / "private-vcpkg/.full-cef/vcpkg/integration/driver.py"
            base = ["python", driver, "restore"]
            run = mock.Mock()
            module = SimpleNamespace(run=run, classify_engine_runtime=lambda _: {})
            with mock.patch.object(native, "prepare_restore") as prepare:
                with runtime.observed_runtime(module, workspace, temp):
                    for tail in ([], ["--checkpoint"], ["--checkpoint", "wrong"],
                                 ["--checkpoint", "a", "--checkpoint", "b"]):
                        with self.subTest(tail=tail), self.assertRaisesRegex(
                            ValueError, "Unexpected native restore package"
                        ):
                            module.run(base + tail)
            prepare.assert_not_called()
            run.assert_not_called()

    def test_original_restore_validation_failure_remains_fatal(self):
        from types import SimpleNamespace
        from secure_release import cef_strict_iteration_runtime as runtime

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(strict=True)
            workspace, temp = root / "workspace", root / "temp"
            driver = workspace / "private-vcpkg/.full-cef/vcpkg/integration/driver.py"
            package = temp / "cef-strict-restored-checkpoint"
            command = ["python", driver, "restore", "--checkpoint", package]
            failure = ValueError("upstream identity mismatch")
            run = mock.Mock(side_effect=failure)
            module = SimpleNamespace(run=run, classify_engine_runtime=lambda _: {})
            with mock.patch.object(native, "prepare_restore") as prepare:
                with runtime.observed_runtime(module, workspace, temp):
                    with self.assertRaises(ValueError) as observed:
                        module.run(command)
            self.assertIs(observed.exception, failure)
            self.assertEqual(prepare.call_count, 1)
            run.assert_called_once_with(command)


if __name__ == "__main__":
    unittest.main()
