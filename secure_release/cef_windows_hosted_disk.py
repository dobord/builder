"""Operator-approved removal of unused Android SDK on disposable hosted runners."""
import os
from pathlib import Path
import shutil
import stat
import sys

MINIMUM_FREE = 84825604096
ANDROID_SDK = r"C:\Android\android-sdk"


def plain(path: Path) -> None:
    info = path.lstat()
    if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Redirected Android SDK cleanup path")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise ValueError("Special Android SDK cleanup entry")


def validate_tree(root: Path) -> None:
    for parent in (root, *root.parents):
        plain(parent)
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            plain(Path(directory) / name)


def cleanup() -> dict:
    if (sys.platform != "win32"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Windows"):
        raise ValueError("Android SDK cleanup requires disposable GitHub-hosted Windows")
    target = Path(ANDROID_SDK)
    before = shutil.disk_usage(target.anchor).free
    report = {"free_before": before, "free_after": before, "android_sdk_removed": False}
    if before >= MINIMUM_FREE:
        return report
    # Fixed path only: no user-controlled path, glob, toolcache or workspace root.
    if target.is_symlink():
        raise ValueError("Refusing redirected fixed Android SDK cleanup path; "
                         f"link_target={os.readlink(target)!r}; resolved={str(target.resolve())!r}")
    if target.exists():
        validate_tree(target)
        shutil.rmtree(target)
        report["android_sdk_removed"] = True
    report["free_after"] = shutil.disk_usage(target.anchor).free
    return report


if __name__ == "__main__":
    import json
    print(json.dumps(cleanup(), sort_keys=True))
