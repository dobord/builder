"""Bind the reviewed example installation recipe to each source release."""
from pathlib import Path
import unittest
from unittest import mock

from secure_release import linux_sdk as subject


class ExampleVersionTests(unittest.TestCase):
    def test_exact_version_specific_source_and_recipe_pairs(self):
        for sha, proxy, port in (
            (subject.LFC_UI_050, subject.PROXY_050_BLOB, subject.PORT_050_BLOB),
            (subject.LFC_UI_061, subject.PROXY_050_BLOB, subject.PORT_061_BLOB),
            ("0" * 40, subject.PROXY_BLOB, subject.PORT_BLOB),
        ):
            plan = {"cef": {"profile": "static-third-party",
                            "recipe_commit": subject.cef_native_link_static.CPP_RECIPE},
                    "ports": [{"name": "lfc-ui", "sha": sha}]}
            root = Path("/synthetic")
            with self.subTest(sha=sha), \
                 mock.patch.object(subject.safeio, "extract_tar"), \
                 mock.patch.object(subject.safeio, "regular", return_value=True), \
                 mock.patch.object(subject.cef_sdk_objects, "validate_sources"), \
                 mock.patch.object(subject.cef_sdk_example, "capture", return_value={}) as capture:
                subject.capture_sources(root, plan)
                capture.assert_called_once_with(
                    root / "linux-publication-lfc-ui", root / "workspace",
                    proxy_blob=proxy, port_blob=port)

    def test_version_upgrade_does_not_broaden_accepted_example_bytes(self):
        self.assertNotEqual(subject.PORT_061_BLOB, subject.PORT_050_BLOB)
        self.assertEqual(subject.PROXY_050_BLOB, "20ccbf6778308a844fc39b01a780b15815077399")


if __name__ == "__main__":
    unittest.main()
