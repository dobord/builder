"""ABI-visible acquisition patch and real native exporter regressions.

The native fixture uses disposable public archives and synthetic receipt fields.
It tests the exporter, not actual CEF rendering or final SDK qualification.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from secure_release import cef_combined_port as port
from secure_release import cef_qualified_export as export
from secure_release import cef_native_link_static as native
from secure_release import cef_strict_combined as combined
from secure_release import cef_build

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/cef-qualified-export"


def recipe_fixture(test: unittest.TestCase) -> Path:
    path = Path(os.environ.get("CEF_NATIVE_LINK_RECIPE_FIXTURE",
                               ROOT / "private-vcpkg/.full-cef")).resolve()
    if not (path / port.SOURCE_BUILD).is_file():
        if os.environ.get("REQUIRE_CEF_COMBINED_PORT_FIXTURE") == "1":
            test.fail("Required pinned CEF recipe fixture is absent")
        test.skipTest("Full pinned CEF recipe supplied by combined preflight")
    return path


def sample_spec():
    records = {}
    for index, name in enumerate(sorted(export.EXPECTED_INPUTS), 1):
        relative = (".cef-nss-isolation/libcef_nss_isolated.a" if name.startswith("lib/cef-nss/")
                    else ".cef-gtk-codecs-v1/" + hashlib.sha256(name.encode()).hexdigest()[:16] + ".a")
        records[name] = {"native": relative, "source_sha256": str(index)*64,
                         "sha256": str(index+4)*64}
    return {"schema": 1, "kind": "cef-qualified-native-platform-bindings",
            "platform_sha256": "a"*64, "bindings": records}


def run(command, cwd, success=True):
    result = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True, text=True, timeout=90)
    if success and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    if not success and not result.returncode:
        raise AssertionError("Expected native regression failure")
    return result


def load(path):
    spec = importlib.util.spec_from_file_location("recipe_fixture_"+hashlib.sha256(str(path).encode()).hexdigest(), path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class AcquisitionSourceTests(unittest.TestCase):
    def test_whole_port_is_pinned_and_all_payload_hashes_precede_installer(self):
        raw = (FIXTURES/"portfile.cmake").read_bytes()
        self.assertEqual(native.git_blob(raw), port.PORT_BLOB)
        files = {"vcpkg/ports/cef-static/source_build.py": b"a", "vcpkg/static/policy.py": b"b"}
        output = port.patch_port(raw, files).decode()
        self.assertIn('PATCHES "qualified-native-profile.patch"', output)
        self.assertLess(output.index("PATCHES"), output.index("file(SHA256"))
        self.assertLess(output.index("file(SHA256"), output.index('include("${CEF_RECIPE_SOURCE}'))
        self.assertNotIn("SKIP_PATCH_CHECK", output)
        for content in files.values():
            self.assertIn(hashlib.sha256(content).hexdigest(), output)
        with self.assertRaisesRegex(ValueError, "acquisition port changed"):
            port.patch_port(raw+b"# unexpected\n", files)

    def test_orchestration_materializes_before_abi_and_uses_canonical_consumer(self):
        text = inspect.getsource(combined.main)
        self.assertLess(text.index("cef_combined_port.materialize("), text.index("protect_source_archives("))
        self.assertLess(text.index("cef_combined_port.materialize("), text.index('stage = "vcpkg-install"'))
        self.assertIn('rglob("cef_static_combined_smoke")', text)
        self.assertNotIn('rglob("cef_static_smoke")', text)
        self.assertIn("recipe_root=recipe", text)
        self.assertEqual(text.count("cef_combined_port.verify_packaged_isolation("), 2)
        workflow = (ROOT/".github/workflows/cef-strict-combined.yml").read_text()
        self.assertIn("REQUIRE_CEF_COMBINED_PORT_FIXTURE: '1'", workflow)
        self.assertLess(workflow.index("test_cef_combined_port.py -v"),
                        workflow.index("- name: Run checkpoint-resumed final"))
        self.assertIn("--binarysource=clear", inspect.getsource(combined.source_fresh_binary_args))

    def test_required_fixture_does_not_silently_skip(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(os.environ, {
            "CEF_NATIVE_LINK_RECIPE_FIXTURE": folder, "REQUIRE_CEF_COMBINED_PORT_FIXTURE": "1"
        }):
            with self.assertRaisesRegex(AssertionError, "fixture is absent"):
                recipe_fixture(self)


class FullRecipeTests(unittest.TestCase):
    def test_exact_patch_reproduces_and_fixes_real_static_profile_reset(self):
        recipe = recipe_fixture(self)
        before, after = port.recipe_payload(recipe, sample_spec())
        self.assertEqual(native.git_blob(before[port.SOURCE_BUILD]), native.RECIPE_BLOB)
        self.assertEqual(native.git_blob(before[port.EXPORT]), port.EXPORT_BLOB)
        self.assertEqual(after[port.SOURCE_BUILD], native.reviewed_output(
            before[port.SOURCE_BUILD], native.RECIPE_BLOB, native.patch_recipe, native.unpatch_recipe, "recipe"
        ))
        original = load(recipe/port.SOURCE_BUILD)
        args = {"use_custom_libunwind": False, "enable_linux_installer": True}
        self.assertFalse(original.static_profile(args, False)["use_custom_libunwind"])
        with tempfile.TemporaryDirectory() as folder:
            acquired = Path(folder)/"acquired"; acquired.mkdir()
            for name,data in before.items():
                if data:
                    target=acquired/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
            patch=Path(folder)/port.PATCH_NAME; patch.write_bytes(port.make_patch(before,after))
            run(["git","-c","core.autocrlf=false","-c","core.eol=lf","apply","--check",patch],acquired)
            run(["git","-c","core.autocrlf=false","-c","core.eol=lf","apply",patch],acquired)
            for name,data in after.items():
                self.assertEqual((acquired/name).read_bytes(),data)
            selected=load(acquired/port.SOURCE_BUILD)
            self.assertTrue(selected.static_profile(args,False)["use_custom_libunwind"])
            self.assertEqual(selected.static_profile(args,True),original.static_profile(args,True))
            guards=port.patch_port((FIXTURES/"portfile.cmake").read_bytes(),after).decode()
            guards=guards[guards.index("# "+port.MARKER):guards.index('set(CEF_BUILD_CONTRACT_FILE')]
            script=Path(folder)/"check.cmake"
            script.write_text('set(CEF_RECIPE_SOURCE "'+acquired.as_posix()+'")\n'+guards)
            run(["cmake","-P",script],acquired)
            for name in after:
                saved=(acquired/name).read_bytes();(acquired/name).write_bytes(saved+b"tamper")
                result=run(["cmake","-P",script],acquired,success=False)
                self.assertIn("CEF_QUALIFIED_RECIPE_MISMATCH",result.stdout+result.stderr)
                (acquired/name).write_bytes(saved)
        self.assertEqual((recipe/port.SOURCE_BUILD).read_bytes(),before[port.SOURCE_BUILD])

    def test_payload_rejects_unreviewed_exporter_and_partial_native_recipe(self):
        recipe=recipe_fixture(self)
        with tempfile.TemporaryDirectory() as folder:
            copied=Path(folder)/"recipe";shutil.copytree(recipe/"vcpkg",copied/"vcpkg")
            for name in (port.EXPORT,port.SOURCE_BUILD,"vcpkg/static/platform_export.py","vcpkg/integration/install.cmake"):
                path=copied/name; saved=path.read_bytes();path.write_bytes(saved+b"# unreviewed\n")
                with self.assertRaises(ValueError): port.recipe_payload(copied,sample_spec())
                path.write_bytes(saved)

    def test_materialization_preserves_recipe_objects_and_stages_before_write(self):
        recipe=recipe_fixture(self)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); acquired=root/"port";acquired.mkdir()
            (acquired/"portfile.cmake").write_bytes((FIXTURES/"portfile.cmake").read_bytes())
            before=(recipe/port.SOURCE_BUILD).read_bytes(),(recipe/port.SOURCE_BUILD).stat().st_mtime_ns
            frozen=root/"frozen-object.o";frozen.write_bytes(b"do not change accumulated checkpoint")
            clock=frozen.stat().st_mtime_ns
            with mock.patch.object(native,"_head",return_value=native.CEF_RECIPE), \
                 mock.patch.object(port,"collect_bindings",return_value=sample_spec()):
                report=port.materialize(acquired,recipe,root,root,root,"a"*64)
            self.assertTrue(report["abi_tracked"])
            self.assertEqual(report["isolated_archives"],4)
            self.assertEqual(before,((recipe/port.SOURCE_BUILD).read_bytes(),(recipe/port.SOURCE_BUILD).stat().st_mtime_ns))
            self.assertEqual(frozen.stat().st_mtime_ns,clock)
            self.assertEqual(frozen.read_bytes(),b"do not change accumulated checkpoint")
            self.assertEqual(hashlib.sha256((acquired/port.PATCH_NAME).read_bytes()).hexdigest(), report["patch_sha256"])
            (acquired/port.PATCH_NAME).unlink()
            raw=(FIXTURES/"portfile.cmake").read_bytes();(acquired/"portfile.cmake").write_bytes(raw)
            stage=port._stage; count=0
            def fail_second(path,data):
                nonlocal count
                count+=1
                if count==2: raise OSError("fixture second staging failure")
                return stage(path,data)
            with mock.patch.object(native,"_head",return_value=native.CEF_RECIPE), \
                 mock.patch.object(port,"collect_bindings",return_value=sample_spec()), \
                 mock.patch.object(port,"_stage",side_effect=fail_second):
                with self.assertRaises(OSError): port.materialize(acquired,recipe,root,root,root,"a"*64)
            self.assertEqual((acquired/"portfile.cmake").read_bytes(),raw)
            self.assertEqual(sorted(p.name for p in acquired.iterdir()),["portfile.cmake"])


@unittest.skipUnless(sys.platform=="linux", "ELF/archive/export regression runs natively on Linux")
class NativeExportTests(unittest.TestCase):
    def test_full_exporter_relinks_exact_isolated_bytes_with_all_roots_hidden(self):
        recipe=recipe_fixture(self)
        self.assertTrue(all(shutil.which(x) for x in ("cc","ar","git","cmake","ninja","pkg-config")))
        result=run([sys.executable,FIXTURES/"native.py",recipe,ROOT],ROOT)
        self.assertIn("QUALIFIED_EXPORT_NATIVE_RELOCATION_VERIFIED",result.stdout)


class ConsumerRecipeTests(unittest.TestCase):
    def test_explicit_recipe_driver_preserves_canonical_target_and_hide_boundary(self):
        from test_cef_contract import config
        class StopFixture(Exception): pass
        for explicit in (False,True):
            with self.subTest(explicit=explicit), tempfile.TemporaryDirectory() as folder:
                root=Path(folder)/"root";root.mkdir()
                for name in ("smoke-build","consumer-sdk","cef-work","installed","export/sdk"):
                    (root/name).mkdir(parents=True)
                recipe=Path(folder)/"pinned-recipe-checkout"
                driver=recipe/"vcpkg/integration/driver.py";driver.parent.mkdir(parents=True);driver.write_text("# fixture\n")
                (root/"smoke-build/cef_static_combined_smoke").write_bytes(b"not executed")
                (root/"smoke-build/icudtl.dat").write_bytes(b"fixture")
                def execute(command,**options):
                    selected=recipe if explicit else root/"cef-recipe"
                    self.assertEqual(command[1],str(selected/"vcpkg/integration/driver.py"))
                    self.assertEqual(options["cwd"],selected)
                    hidden={Path(command[i+1]) for i,v in enumerate(command) if v=="--hide"}
                    self.assertEqual(hidden,{root/n for n in ("smoke-build","consumer-sdk","cef-work","installed","export/sdk")})
                    raise StopFixture
                with self.assertRaises(StopFixture):
                    cef_build.verify_consumer(root,config(),"linux",execute,**({"recipe_root":recipe} if explicit else {}))

    def test_missing_explicit_recipe_is_rejected_before_runtime(self):
        from test_cef_contract import config
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError,"recipe is missing"):
                cef_build.verify_consumer(Path(folder),config(),"linux",mock.Mock(),recipe_root=Path(folder)/"absent")


if __name__=="__main__":
    unittest.main()
