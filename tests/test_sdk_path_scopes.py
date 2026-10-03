"""Package configuration roots differ from legal public header/license paths."""
from pathlib import Path
import tempfile
import unittest
from secure_release import safeio

class SDKPathTests(unittest.TestCase):
    def test_nested_debug_headers_and_licenses_survive_packaging(self):
        names = ["installed/x64-linux-static-release/include/example/debug/api.h",
                 "installed/x64-linux-static-release/share/cef-static/licenses/example/debug/LICENSE"]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sdk = root / "sdk"
            for name in names:
                path = sdk / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic")
                self.assertFalse(safeio.forbidden_sdk_tree(name))
            archive = root / "sdk.zip"
            safeio.sdk_zip(sdk, archive)
            self.assertEqual({i.filename for i in safeio.zip_files(archive)}, set(names))

    def test_debug_configuration_still_fails(self):
        for name in ("debug/include/api.h", "installed/x64-linux/debug/lib/example.a",
                     "installed/x64-linux/share/cef-static/buildtrees/data"):
            self.assertTrue(safeio.forbidden_sdk_tree(name))

if __name__ == "__main__":
    unittest.main()
