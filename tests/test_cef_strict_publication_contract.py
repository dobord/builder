"""Strict publication ABI binding tests; no network or native build required."""
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from secure_release import cef_build, cef_strict_combined
from test_cef_contract import config


def proof(platform: str) -> dict:
    count = 3 if platform == "windows" else 1
    value = {
        "schema": 1,
        "kind": "consumer-verification",
        "engine_linkage": "static",
        "capi_only": True,
        "third_party_libraries_static": True,
        "system_libraries_static": False,
        "sandbox_verified": False,
        "executable_sha256": "a" * 64,
        "target_archive_audit": {
            "kind": "target-archive-audit-summary",
            "target_archives_static": True,
            "violation_count": 0,
        },
        "smoke": {
            "cef": "152.0.6+g708dc14+chromium-152.0.7977.83",
            "engine": "static",
            "interface": "capi",
            "javascript": True,
            "paint": True,
            "browser_modules_clean": True,
            "renderer_modules_clean": True,
            "third_party_modules_static": True,
            "browser_pid": 10,
            "renderer_pid": 20,
        },
        "smoke_runs": {
            "status": "success",
            "executable_sha256": "a" * 64,
            "engine_runtime_verified": True,
            "no_retry_on_failure": True,
            "required_runs": count,
            "passed_runs": count,
            "runs": [
                {
                    "number": i,
                    "status": "success",
                    "engine_runtime_verified": True,
                    "cwd": f"fresh-{i}",
                }
                for i in range(1, count + 1)
            ],
        },
    }
    value["platform_closure"] = (
        {
            "kind": "linux-frozen-vcpkg",
            "manifest_sha256": "b" * 64,
            "inventory_sha256": "c" * 64,
            "qualification_sha256": "e" * 64,
            "full_platform_graph_qualified": True,
            "archive_count": 36,
        }
        if platform == "linux"
        else {"kind": "windows-native-os-abi", "manifest_sha256": None}
    )
    return value


def write_registry_fixture(root: Path, lfc_port_version: int, minimal: bool) -> None:
    freerdp_dependency = {
        "name": "freerdp",
        "default-features": False,
        "features": ["ffmpeg", "proxy", "x11"] if minimal else ["full"],
    }
    lfc_manifest = {
        "name": "lfc-ui",
        "version": "0.3.0",
        "port-version": lfc_port_version,
        "features": {
            "freerdp": {
                "description": "minimal" if minimal else "full",
                "supports": "linux",
                "dependencies": [freerdp_dependency],
            },
            "cef": {"description": "unchanged"},
        },
    }
    old_freerdp_overlay = """            freerdp-shadow)
        target_link_libraries(lfc-ui ${_lfc_ui_usage_scope} freerdp-shadow freerdp-server freerdp)
            freerdp-server-proxy freerdp-client freerdp-server freerdp)
"""
    new_freerdp_overlay = """            freerdp-shadow
            ainput-server
            cliprdr-server
            disp-server
            rdpgfx-server)
        target_link_libraries(lfc-ui ${_lfc_ui_usage_scope}
            freerdp-shadow freerdp-server freerdp
            ainput-server cliprdr-server disp-server rdpgfx-server)
        target_link_libraries(lfc-ui INTERFACE "$<TARGET_OBJECTS:disp-server>")
            freerdp-server-proxy freerdp-client freerdp-server freerdp
            disp-server rdpgfx-server)
        target_link_libraries(lfc-ui INTERFACE "$<TARGET_OBJECTS:rdpgfx-server>")
"""
    files = {
        "ports/freerdp/vcpkg.json": json.dumps({
            "name": "freerdp",
            "version": "3.31.1",
            "port-version": 25 if minimal else 23,
            "features": {"proxy": {"description": "unchanged"}},
        }, sort_keys=True) + "\n",
        "ports/freerdp/portfile.cmake": (
            "PATCHES\n        static-libusb-client.patch\n"
            + ("        static-shadow-winpr-tools-dependency.patch\n" if minimal else "")
            + "        install-layout.patch\n"
            + "if (NOT HAS_SHADOW_SUBSYSTEM)\n"
            + "    list(APPEND FEATURE_OPTIONS -DWITH_SHADOW_SUBSYSTEM=OFF -DWITH_SERVER_SHADOW_CLI=OFF)\n"
            + "endif()\n\n"
            + (
                "# Installed static channel OBJECT libraries are part of the exported SDK link\n"
                "# interface. GCC LTO objects are discoverable by nm through liblto_plugin but\n"
                "# cannot be consumed by the qualified LLD linker used by the final CEF SDK.\n"
                "# Keep Linux static FreeRDP link inputs as native ELF relocatables.\n"
                "if(VCPKG_TARGET_IS_LINUX AND VCPKG_LIBRARY_LINKAGE STREQUAL \"static\")\n"
                "    list(APPEND FEATURE_OPTIONS -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF)\n"
                "endif()\n\n"
                if minimal else ""
            )
            + "vcpkg_find_acquire_program(PKGCONFIG)\n"
        ),
        "ports/freerdp/static-shadow-winpr-tools-dependency.patch": (
            """diff --git a/server/shadow/FreeRDP-ShadowConfig.cmake.in b/server/shadow/FreeRDP-ShadowConfig.cmake.in
index 3a7f5aa..4bc04cf 100644
--- a/server/shadow/FreeRDP-ShadowConfig.cmake.in
+++ b/server/shadow/FreeRDP-ShadowConfig.cmake.in
@@ -1,5 +1,8 @@
 include(CMakeFindDependencyMacro)
 find_dependency(WinPR @FREERDP_VERSION@)
+if("@WITH_WINPR_TOOLS@" AND NOT "@BUILD_SHARED_LIBS@")
+  find_dependency(WinPR-tools @FREERDP_VERSION@)
+endif()
 find_dependency(FreeRDP @FREERDP_VERSION@)
 find_dependency(FreeRDP-Server @FREERDP_VERSION@)
 
""" if minimal else None
        ),
        "ports/lfc-ui/vcpkg.json": json.dumps(lfc_manifest, sort_keys=True) + "\n",
        "ports/lfc-ui/use-installed-freerdp.cmake": (
            new_freerdp_overlay if minimal else old_freerdp_overlay
        ),
        "ports/lfc-ui/use-installed-lockfreecoro.patch": (
            """@@ -1,7 +1,11 @@
 @PACKAGE_INIT@
 
 include(CMakeFindDependencyMacro)
+if(@LFC_UI_PACKAGE_HAS_LOCKFREECORO@)
+    find_dependency(lockfreecoro CONFIG COMPONENTS core)
+endif()
+
 include("${CMAKE_CURRENT_LIST_DIR}/lfc_ui_compiler_requirements.cmake")
 include("${CMAKE_CURRENT_LIST_DIR}/lfc_ui_pkgconfig_runtime.cmake")
 lfc_ui_require_supported_compiler("${CMAKE_CXX_COMPILER_ID}" "${CMAKE_CXX_COMPILER_VERSION}")
"""
            if minimal else
            """@@ -1,6 +1,10 @@
 @PACKAGE_INIT@
 
 include(CMakeFindDependencyMacro)
+if(@LFC_UI_PACKAGE_HAS_LOCKFREECORO@)
+    find_dependency(lockfreecoro CONFIG COMPONENTS core)
+endif()
+
 include("${CMAKE_CURRENT_LIST_DIR}/lfc_ui_compiler_requirements.cmake")
 lfc_ui_require_supported_compiler("${CMAKE_CXX_COMPILER_ID}" "${CMAKE_CXX_COMPILER_VERSION}")
"""
        ),
        "ports/lfc-ui/usage": ("ffmpeg-minimal\n" if minimal else "full\n"),
        "ports/lfc-ui/portfile.cmake": (
            'REF "307afeab287b283514e036aa82ea1bd331dbac2a"\n'
            if minimal else
            'REF "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5"\n'
        ),
        "ci/release-plan.json": json.dumps({
            "ports": [{
                "name": "lfc-ui",
                "sha": (
                    "307afeab287b283514e036aa82ea1bd331dbac2a"
                    if minimal else
                    "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5"
                ),
            }]
        }, sort_keys=True) + "\n",
        "versions/baseline.json": json.dumps({
            "default": {
                "lfc-ui": {"baseline": "0.3.0", "port-version": lfc_port_version},
                "freerdp": {"baseline": "3.31.1", "port-version": 25 if minimal else 23},
                "cef-static": {"baseline": "152.0.6", "port-version": 15},
            }
        }, sort_keys=True) + "\n",
        "versions/f-/freerdp.json": json.dumps({
            "versions": (
                [{
                    "git-tree": "2c8bdcad32d778ff2ff280db0efe3e1eefabf162",
                    "version": "3.31.1",
                    "port-version": 25,
                }, {
                    "git-tree": "aceadca1288983390522864e4d6c42b38ae84a6a",
                    "version": "3.31.1",
                    "port-version": 24,
                }, {
                    "git-tree": "old-tree",
                    "version": "3.31.1",
                    "port-version": 23,
                }]
                if minimal else
                [{
                    "git-tree": "old-tree",
                    "version": "3.31.1",
                    "port-version": 23,
                }]
            )
        }, sort_keys=True) + "\n",
        "versions/l-/lfc-ui.json": json.dumps({
            "versions": (
                [{
                    "git-tree": "bbc00cc70e557268570db3e08714d26171c8f06e",
                    "version": "0.3.0",
                    "port-version": 15,
                }, {
                    "git-tree": "cb1a947459fe788d6d697e9e62bb87edec24f3e2",
                    "version": "0.3.0",
                    "port-version": 14,
                }, {
                    "git-tree": "456adaca80fe88da3f23fb7c103f20fab2003fd7",
                    "version": "0.3.0",
                    "port-version": 13,
                }, {
                    "git-tree": "700498a2d6c2a33f652146e804eaeed359247a2d",
                    "version": "0.3.0",
                    "port-version": 12,
                }, {
                    "git-tree": "d635813c8ca3903f7300987e3d24d1c8c6cdea9a",
                    "version": "0.3.0",
                    "port-version": 11,
                }, {
                    "git-tree": "9cc7498e3dd005babec671f17cc7dcea26797c45",
                    "version": "0.3.0",
                    "port-version": 10,
                }, {
                    "git-tree": "cf9f360b1433c1aec5c8eabb4a2fcd3b551627bf",
                    "version": "0.3.0",
                    "port-version": 9,
                }, {
                    "git-tree": "old-lfc-tree",
                    "version": "0.3.0",
                    "port-version": 8,
                }]
                if minimal else
                [{
                    "git-tree": "old-lfc-tree",
                    "version": "0.3.0",
                    "port-version": 8,
                }]
            )
        }, sort_keys=True) + "\n",
        "ports/cef-static/vcpkg.json": "unchanged-engine-port\n",
    }
    for relative, content in files.items():
        if content is None:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class StrictPublicationContractTests(unittest.TestCase):
    def strict(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        return cfg

    def test_reviewed_lfc_ui_and_freerdp_registry_delta_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine, sdk = root / "engine", root / "sdk"
            write_registry_fixture(engine, 8, False)
            write_registry_fixture(sdk, 15, True)
            engine_sha, sdk_sha = "1" * 40, "2" * 40

            def fake_head(path):
                return engine_sha if Path(path) == engine else sdk_sha

            with patch.object(cef_strict_combined, "ENGINE_VCPKG", engine_sha), \
                 patch.object(cef_strict_combined, "SDK_VCPKG", sdk_sha), \
                 patch.object(cef_strict_combined, "git_head", side_effect=fake_head):
                cef_strict_combined.verify_engine_registry_delta(engine, sdk)

    def test_registry_delta_rejects_non_lfc_ui_change(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine, sdk = root / "engine", root / "sdk"
            write_registry_fixture(engine, 8, False)
            write_registry_fixture(sdk, 15, True)
            (sdk / "ports/cef-static/vcpkg.json").write_text(
                "changed-engine-port\n", encoding="utf-8"
            )
            engine_sha, sdk_sha = "1" * 40, "2" * 40

            def fake_head(path):
                return engine_sha if Path(path) == engine else sdk_sha

            with patch.object(cef_strict_combined, "ENGINE_VCPKG", engine_sha), \
                 patch.object(cef_strict_combined, "SDK_VCPKG", sdk_sha), \
                 patch.object(cef_strict_combined, "git_head", side_effect=fake_head):
                with self.assertRaisesRegex(ValueError, "outside the reviewed lfc-ui/FreeRDP dependency delta"):
                    cef_strict_combined.verify_engine_registry_delta(engine, sdk)

    def test_reviewed_sdk_registry_child_tree_replay_is_exact(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            native_anchor = (
                "if (NOT HAS_SHADOW_SUBSYSTEM)\n"
                "    list(APPEND FEATURE_OPTIONS -DWITH_SHADOW_SUBSYSTEM=OFF -DWITH_SERVER_SHADOW_CLI=OFF)\n"
                "endif()\n\n"
                "vcpkg_find_acquire_program(PKGCONFIG)\n"
            )
            files = {
                "ports/freerdp/portfile.cmake": native_anchor,
                "ports/freerdp/vcpkg.json": (
                    '{\n  "name": "freerdp",\n  "port-version": 24\n}\n'
                ),
                "versions/baseline.json": (
                    '{\n  "default": {\n'
                    '    "freerdp": {\n'
                    '      "baseline": "3.31.1",\n'
                    '      "port-version": 24\n'
                    '    },\n'
                    '    "other": {"baseline": "1"}\n'
                    '  }\n}\n'
                ),
                "versions/f-/freerdp.json": (
                    '{\n'
                    '  "versions": [\n'
                    '    {\n'
                    '      "git-tree": "aceadca1288983390522864e4d6c42b38ae84a6a",\n'
                    '      "version": "3.31.1",\n'
                    '      "port-version": 24\n'
                    '    },\n'
                    '    {"git-tree": "old", "version": "3.31.1", "port-version": 23}\n'
                    '  ]\n}\n'
                ),
            }
            for relative, data in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("w", encoding="utf-8", newline="") as stream:
                    stream.write(data)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "fixture"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "parent"], cwd=root, check=True)
            parent = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            parent_tree = subprocess.check_output(
                ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
            ).strip()

            native_policy = (
                "if (NOT HAS_SHADOW_SUBSYSTEM)\n"
                "    list(APPEND FEATURE_OPTIONS -DWITH_SHADOW_SUBSYSTEM=OFF -DWITH_SERVER_SHADOW_CLI=OFF)\n"
                "endif()\n\n"
                "# Installed static channel OBJECT libraries are part of the exported SDK link\n"
                "# interface. GCC LTO objects are discoverable by nm through liblto_plugin but\n"
                "# cannot be consumed by the qualified LLD linker used by the final CEF SDK.\n"
                "# Keep Linux static FreeRDP link inputs as native ELF relocatables.\n"
                "if(VCPKG_TARGET_IS_LINUX AND VCPKG_LIBRARY_LINKAGE STREQUAL \"static\")\n"
                "    list(APPEND FEATURE_OPTIONS -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF)\n"
                "endif()\n\n"
                "vcpkg_find_acquire_program(PKGCONFIG)\n"
            )
            replacements = {
                "ports/freerdp/portfile.cmake": (native_anchor, native_policy),
                "ports/freerdp/vcpkg.json": (
                    '  "port-version": 24\n}\n',
                    '  "port-version": 25\n}\n',
                ),
                "versions/baseline.json": (
                    '    "freerdp": {\n'
                    '      "baseline": "3.31.1",\n'
                    '      "port-version": 24\n'
                    '    },\n',
                    '    "freerdp": {\n'
                    '      "baseline": "3.31.1",\n'
                    '      "port-version": 25\n'
                    '    },\n',
                ),
                "versions/f-/freerdp.json": (
                    '  "versions": [\n'
                    '    {\n'
                    '      "git-tree": "aceadca1288983390522864e4d6c42b38ae84a6a",\n'
                    '      "version": "3.31.1",\n'
                    '      "port-version": 24\n'
                    '    },\n',
                    '  "versions": [\n'
                    '    {\n'
                    '      "git-tree": "2c8bdcad32d778ff2ff280db0efe3e1eefabf162",\n'
                    '      "version": "3.31.1",\n'
                    '      "port-version": 25\n'
                    '    },\n'
                    '    {\n'
                    '      "git-tree": "aceadca1288983390522864e4d6c42b38ae84a6a",\n'
                    '      "version": "3.31.1",\n'
                    '      "port-version": 24\n'
                    '    },\n',
                ),
            }
            for relative, (before, after) in replacements.items():
                path = root / relative
                data = path.read_text(encoding="utf-8")
                self.assertEqual(data.count(before), 1)
                with path.open("w", encoding="utf-8", newline="") as stream:
                    stream.write(data.replace(before, after, 1))
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            expected_tree = subprocess.check_output(
                ["git", "write-tree"], cwd=root, text=True
            ).strip()
            subprocess.run(["git", "reset", "--hard", "-q", parent], cwd=root, check=True)

            with patch.object(cef_strict_combined, "SDK_VCPKG_CHECKOUT", parent), \
                 patch.object(cef_strict_combined, "SDK_VCPKG_CHECKOUT_TREE", parent_tree), \
                 patch.object(cef_strict_combined, "SDK_VCPKG", "f" * 40), \
                 patch.object(cef_strict_combined, "SDK_VCPKG_TREE", expected_tree):
                result = cef_strict_combined.materialize_sdk_registry(root)

            self.assertEqual(result["mode"], "reviewed-child-tree-replay")
            self.assertEqual(result["checkout_commit"], parent)
            self.assertEqual(result["tree"], expected_tree)
            self.assertEqual(
                subprocess.check_output(
                    ["git", "write-tree"], cwd=root, text=True
                ).strip(),
                expected_tree,
            )
            self.assertIn(
                "-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF",
                (root / "ports/freerdp/portfile.cmake").read_text(),
            )

    def test_strict_linux_capture_requires_complete_signed_preflight(self):
        cfg = self.strict()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "workspace/ci/cef-full").mkdir(parents=True)
            (root / "workspace/ci/cef-full/verify_prefix.py").write_text("# signed fixture\n")
            (root / "cef-recipe").mkdir()
            calls = []

            def execute(command, **options):
                calls.append((list(map(str, command)), options))
                if len(calls) == 2:
                    receipt = root / "cef-platform-probe/qualification.json"
                    receipt.write_text(json.dumps({
                        "schema": 1,
                        "kind": "cef-static-platform-preflight",
                        "status": "success",
                        "full_platform_graph_qualified": True,
                        "cef_runtime_verified": False,
                        "gpu_runtime_qualified": False,
                        "module_count": 37,
                        "manifest_sha256": "b" * 64,
                    }, sort_keys=True, separators=(",", ":")) + "\n")

            with patch.object(cef_build.shutil, "which", return_value="/usr/bin/pkg-config"), \
                 patch.object(cef_build.build_support, "install_command",
                              return_value=["vcpkg", "install", "cef-platform-deps"]):
                result = cef_build.capture_platform_dependencies(
                    root, cfg, "linux", execute, "vcpkg", [], None)

            self.assertEqual(len(calls), 2)
            self.assertIn(str(root / "workspace/ci/cef-full/verify_prefix.py"), calls[1][0])
            self.assertEqual(result["sha256"], "b" * 64)
            self.assertTrue(result["qualification"].is_file())
            self.assertEqual(len(result["qualification_sha256"]), 64)

    def test_linux_contract_contains_qualified_platform_digest(self):
        key, contract = cef_build.qualified_contract(proof("linux"), self.strict(), "linux")
        self.assertEqual(contract["platform_sha256"], "b" * 64)
        self.assertEqual(len(key), 64)

    def test_windows_contract_has_no_external_platform_digest(self):
        key, contract = cef_build.qualified_contract(proof("windows"), self.strict(), "windows")
        self.assertIsNone(contract["platform_sha256"])
        self.assertEqual(len(key), 64)

    def test_changed_linux_platform_digest_changes_abi_contract(self):
        cfg = self.strict()
        first = proof("linux")
        second = proof("linux")
        second["platform_closure"]["manifest_sha256"] = "d" * 64
        first_key, first_contract = cef_build.qualified_contract(first, cfg, "linux")
        second_key, second_contract = cef_build.qualified_contract(second, cfg, "linux")
        self.assertNotEqual(first_key, second_key)
        self.assertNotEqual(first_contract, second_contract)

    def test_embedded_platform_preflight_is_hash_bound(self):
        cfg = self.strict()
        value = proof("linux")
        record = {
            "schema": 1,
            "kind": "cef-static-platform-preflight",
            "status": "success",
            "full_platform_graph_qualified": True,
            "cef_runtime_verified": False,
            "gpu_runtime_qualified": False,
            "module_count": 37,
            "manifest_sha256": value["platform_closure"]["manifest_sha256"],
        }
        value["platform_closure"]["qualification_sha256"] = cef_build.platform_preflight_digest(record)
        cef_build.validate_platform_preflight(record, value, cfg, "linux")
        record["manifest_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            cef_build.validate_platform_preflight(record, value, cfg, "linux")

    def test_platform_preflight_is_linux_strict_only(self):
        with self.assertRaises(ValueError):
            cef_build.validate_platform_preflight(
                {"schema": 1}, proof("windows"), self.strict(), "windows")

    def test_invalid_platform_digest_is_rejected_before_publication(self):
        value = proof("linux")
        value["platform_closure"]["manifest_sha256"] = "latest"
        with self.assertRaises(ValueError):
            cef_build.qualified_contract(value, self.strict(), "linux")


if __name__ == "__main__":
    unittest.main()
