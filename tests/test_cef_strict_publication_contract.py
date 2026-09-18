"""Strict publication ABI binding tests; no network or native build required."""
import unittest
from secure_release import cef_build
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


class StrictPublicationContractTests(unittest.TestCase):
    def strict(self):
        cfg = config()
        cfg["profile"] = "static-third-party"
        return cfg

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
            "module_count": 36,
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
