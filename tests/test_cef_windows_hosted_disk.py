"""Bound cleanup to the approved unused SDK, never a self-hosted machine."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import cef_windows_hosted_disk as worker


class HostedDiskTests(unittest.TestCase):
    def usage(self, free):
        return mock.Mock(free=free)

    def test_only_fixed_sdk_is_removed_when_capacity_is_low(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sdk = root / "android-sdk"
            sdk.mkdir()
            (sdk / "unused.bin").write_bytes(b"unused")
            retained = root / "checkpoint"
            retained.write_bytes(b"keep")
            worker.validate_tree(sdk)
            with mock.patch.object(worker.sys, "platform", "win32"), \
                 mock.patch.dict(worker.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows"}), \
                 mock.patch.object(worker, "Path", return_value=sdk) as path, \
                 mock.patch.object(worker, "validate_tree") as validate, \
                 mock.patch.object(worker.shutil, "disk_usage", side_effect=[self.usage(1), self.usage(worker.MINIMUM_FREE)]):
                report = worker.cleanup()
            path.assert_called_with(worker.ANDROID_SDK)
            validate.assert_called_once_with(sdk)
            self.assertTrue(report["android_sdk_removed"])
            self.assertFalse(sdk.exists())
            self.assertEqual(retained.read_bytes(), b"keep")

    def test_sufficient_capacity_performs_no_deletion(self):
        with mock.patch.object(worker.sys, "platform", "win32"), \
             mock.patch.dict(worker.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows"}), \
             mock.patch.object(worker.shutil, "disk_usage", return_value=self.usage(worker.MINIMUM_FREE)), \
             mock.patch.object(worker.shutil, "rmtree") as remove:
            self.assertFalse(worker.cleanup()["android_sdk_removed"])
            remove.assert_not_called()

    def test_other_platforms_and_self_hosted_runners_are_rejected_before_access(self):
        for platform, environment, runner_os in (("linux", "github-hosted", "Linux"),
                                                  ("win32", "self-hosted", "Windows"),
                                                  ("win32", "", "Windows")):
            with self.subTest(environment=environment), \
                 mock.patch.object(worker.sys, "platform", platform), \
                 mock.patch.dict(worker.os.environ, {"RUNNER_ENVIRONMENT": environment, "RUNNER_OS": runner_os}), \
                 mock.patch.object(worker, "Path") as path, self.assertRaises(ValueError):
                worker.cleanup()
            path.assert_not_called()

    def test_redirected_entries_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sdk = root / "android-sdk"
            sdk.mkdir()
            outside = root / "keep"
            outside.write_bytes(b"keep")
            try:
                (sdk / "redirect").symlink_to(outside)
            except OSError:
                self.skipTest("Symlink creation unavailable")
            with self.assertRaises(ValueError):
                worker.validate_tree(sdk)
            self.assertEqual(outside.read_bytes(), b"keep")

    def test_only_reviewed_sdk_alias_destination_is_removed(self):
        for admitted in (True, False):
            with self.subTest(admitted=admitted), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                physical = root / "physical-sdk"
                physical.mkdir()
                (physical / "unused.bin").write_bytes(b"unused")
                other = root / "keep"
                other.mkdir()
                alias = root / "sdk-alias"
                try:
                    alias.symlink_to(physical if admitted else other, target_is_directory=True)
                except OSError:
                    self.skipTest("Symlink creation unavailable")
                worker.validate_tree(physical)
                def fixed_path(value):
                    if value == worker.ANDROID_SDK:
                        return alias
                    if value == worker.ANDROID_SDK_PHYSICAL:
                        return physical
                    raise AssertionError("Unapproved cleanup path")
                with mock.patch.object(worker.sys, "platform", "win32"), \
                     mock.patch.dict(worker.os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Windows"}), \
                     mock.patch.object(worker, "Path", side_effect=fixed_path), \
                     mock.patch.object(worker, "validate_tree"), \
                     mock.patch.object(worker.shutil, "disk_usage", return_value=self.usage(1)):
                    if admitted:
                        self.assertTrue(worker.cleanup()["android_sdk_removed"])
                        self.assertFalse(physical.exists())
                    else:
                        with self.assertRaisesRegex(ValueError, "alias destination"):
                            worker.cleanup()
                        self.assertTrue(physical.exists())
                self.assertTrue(other.is_dir())


if __name__ == "__main__":
    unittest.main()
