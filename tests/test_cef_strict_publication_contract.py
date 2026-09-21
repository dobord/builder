"""Strict publication ABI binding tests; no network or native build required."""
import json
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
        "features": ["proxy", "x11"] if minimal else ["full"],
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
    files = {
        "ports/lfc-ui/vcpkg.json": json.dumps(lfc_manifest, sort_keys=True) + "\n",
        "ports/lfc-ui/usage": ("minimal\n" if minimal else "full\n"),
        "versions/baseline.json": json.dumps({
            "default": {
                "lfc-ui": {"baseline": "0.3.0", "port-version": lfc_port_version},
                "freerdp": {"baseline": "3.31.1", "port-version": 23},
                "cef-static": {"baseline": "152.0.6", "port-version": 15},
            }
        }, sort_keys=True) + "\n",
        "versions/l-/lfc-ui.json": ("registry-minimal\n" if minimal else "registry-full\n"),
        "ports/cef-static/vcpkg.json": "unchanged-engine-port\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


class StrictPublicationContractTests(unittest.TestCase):
    def strict(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        return cfg

    def test_reviewed_lfc_ui_v8_to_v9_registry_delta_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            engine, sdk = root / "engine", root / "sdk"
            write_registry_fixture(engine, 8, False)
            write_registry_fixture(sdk, 9, True)
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
            write_registry_fixture(sdk, 9, True)
            (sdk / "ports/cef-static/vcpkg.json").write_text(
                "changed-engine-port\n", encoding="utf-8"
            )
            engine_sha, sdk_sha = "1" * 40, "2" * 40

            def fake_head(path):
                return engine_sha if Path(path) == engine else sdk_sha

            with patch.object(cef_strict_combined, "ENGINE_VCPKG", engine_sha), \
                 patch.object(cef_strict_combined, "SDK_VCPKG", sdk_sha), \
                 patch.object(cef_strict_combined, "git_head", side_effect=fake_head):
                with self.assertRaisesRegex(ValueError, "outside the reviewed lfc-ui dependency delta"):
                    cef_strict_combined.verify_engine_registry_delta(engine, sdk)

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
