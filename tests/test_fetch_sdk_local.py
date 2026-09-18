import tempfile
from pathlib import Path
import unittest
import zipfile

from secure_release.fetch_sdk_local import _artifact, _validate_sdk


class LocalSdkRetrievalTests(unittest.TestCase):
    def test_artifact_requires_exact_provenance_and_digest(self):
        good = {
            "id": 91,
            "name": "sdk-windows-42-3",
            "expired": False,
            "digest": "sha256:" + "a" * 64,
            "workflow_run": {"id": 42, "head_sha": "b" * 40},
        }
        self.assertIs(_artifact([good], 42, 3, "b" * 40, "windows"), good)

        bad_digest = dict(good, digest=None)
        with self.assertRaisesRegex(ValueError, "digest"):
            _artifact([bad_digest], 42, 3, "b" * 40, "windows")

        wrong_source = dict(
            good, workflow_run={"id": 42, "head_sha": "c" * 40}
        )
        with self.assertRaisesRegex(ValueError, "provenance"):
            _artifact([wrong_source], 42, 3, "b" * 40, "windows")

    def test_sdk_layout_requires_toolchain_and_static_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = root / "valid.zip"
            with zipfile.ZipFile(valid, "w") as archive:
                archive.writestr(
                    "scripts/buildsystems/vcpkg.cmake", "set(VCPKG 1)\n"
                )
                archive.writestr(
                    "installed/x64-windows-static-release/lib/example.lib",
                    b"archive",
                )
            _validate_sdk(valid, "x64-windows-static-release")

            invalid = root / "invalid.zip"
            with zipfile.ZipFile(invalid, "w") as archive:
                archive.writestr(
                    "scripts/buildsystems/vcpkg.cmake", "set(VCPKG 1)\n"
                )
            with self.assertRaisesRegex(ValueError, "static libraries"):
                _validate_sdk(invalid, "x64-windows-static-release")


if __name__ == "__main__":
    unittest.main()
