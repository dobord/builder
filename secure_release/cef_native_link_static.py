"""Bind the strict Linux CEF root to frozen Expat and in-tree unwind.

Run 76 proved that the fully linked GTK-enabled reference executable still had
exactly two non-OS DT_NEEDED entries: libexpat.so.1 and libgcc_s.so.1. Both
come from reviewed Chromium defaults rather than from a missing archive in the
frozen platform graph.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

CEF_RECIPE = "2aff22e09daaa5c28780c5766a70ee13e61c93b6"
CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
RECIPE_BLOB = "b23ac3604fb2021f2fd5f91f311f5b233605185d"
EXPAT_BLOB = "9ad36d41f159d817fa932e632f23205709265e37"
MARKER = "CEF_STATIC_NATIVE_LINK_V1"
CHECKPOINT_POLICY_BLOB = "8e04c160c33a808602aa3cdb727fc2fb8bedad29"

_RECIPE_OLD = """        result['enable_remoting'] = False
    return result
"""
_RECIPE_NEW = """        result['enable_remoting'] = False
        # CEF_STATIC_NATIVE_LINK_V1: use Chromium's pinned in-tree unwinder.
        # The compiler driver must not add the host libgcc_s runtime.
        result['use_custom_libunwind'] = True
    return result
"""

_EXPAT_IMPORT_OLD = 'import("//build/config/cast.gni")\n'
_EXPAT_IMPORT_NEW = '''import("//build/config/cast.gni")
import("//build/config/linux/pkg_config.gni")  # CEF_STATIC_NATIVE_LINK_V1
'''
_EXPAT_OLD = '''  config("expat_config") {
    libs = [ "expat" ]
  }
'''
_EXPAT_NEW = '''  if (is_linux && cef_static_platform_manifest != "" &&
      current_toolchain == default_toolchain) {
    # CEF_STATIC_NATIVE_LINK_V1: make the linker consume the exact captured
    # libexpat.a instead of resolving a bare -lexpat against a host .so.
    pkg_config("expat_config") {
      packages = [ "expat" ]
    }
  } else {
    config("expat_config") {
      libs = [ "expat" ]
    }
  }
'''


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _one(text: str, before: str, after: str, label: str) -> str:
    if text.count(before) != 1:
        raise ValueError(f"Pinned native-link {label} anchor changed")
    return text.replace(before, after, 1)


def patch_recipe(text: str) -> str:
    if MARKER in text:
        raise ValueError("Native-link recipe is already or partially patched")
    return _one(text, _RECIPE_OLD, _RECIPE_NEW, "recipe")


def unpatch_recipe(text: str) -> str:
    if text.count(MARKER) != 1:
        raise ValueError("Unreviewed native-link recipe state")
    return _one(text, _RECIPE_NEW, _RECIPE_OLD, "recipe migration")


def patch_expat(text: str) -> str:
    if MARKER in text:
        raise ValueError("Native-link Expat source is already or partially patched")
    text = _one(text, _EXPAT_IMPORT_OLD, _EXPAT_IMPORT_NEW, "Expat import")
    return _one(text, _EXPAT_OLD, _EXPAT_NEW, "Expat library")


def unpatch_expat(text: str) -> str:
    if text.count(MARKER) != 2:
        raise ValueError("Unreviewed native-link Expat state")
    text = _one(text, _EXPAT_NEW, _EXPAT_OLD, "Expat migration")
    return _one(text, _EXPAT_IMPORT_NEW, _EXPAT_IMPORT_OLD, "Expat import migration")


def reviewed_output(
    raw: bytes,
    expected_blob: str,
    patcher,
    unpatcher,
    label: str,
) -> bytes:
    if git_blob(raw) == expected_blob:
        original = raw
    else:
        try:
            original = unpatcher(raw.decode("utf-8")).encode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"Unreviewed or partially patched {label}") from error
        if git_blob(original) != expected_blob:
            raise ValueError(f"Unreviewed or partially patched {label}")
    try:
        output = patcher(original.decode("utf-8")).encode("utf-8")
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"Pinned {label} transform changed") from error
    if raw != original and raw != output:
        raise ValueError(f"Unreviewed or partially patched {label}")
    return output


def _regular(path: Path, root: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or redirected native-link input")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root.resolve(strict=True)):
        raise ValueError("Native-link input escaped its reviewed repository")
    return path


def _head(repository: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        text=True,
        timeout=30,
    ).strip()


def _stage(path: Path, data: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix=".cef-native-link-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(path.stat().st_mode & 0o777)
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise



def prepare_restore(recipe_file: Path, package: Path) -> dict:
    """Recreate one of two reviewed recipe states, never rewrite an identity.

    Call only AFTER the existing transport has authenticated the checkpoint.
    linux_checkpoint.ci_identity hashes source_build.py along with the complete
    recipe tree. A native-link producer therefore cannot be restored using a
    pristine recipe checkout. Match that *recorded* hash against the original
    pin or our exact native-link transformation, then let the unchanged driver
    verify the complete identity, archive parts and workspace before restoring.
    """
    recipe_file = recipe_file.absolute()
    repo = recipe_file.parents[3].resolve(strict=True)
    if _head(repo) != CEF_RECIPE:
        raise ValueError("Restore recipe revision changed")
    recipe_file = _regular(recipe_file, repo)
    raw = recipe_file.read_bytes()
    patched = reviewed_output(raw, RECIPE_BLOB, patch_recipe, unpatch_recipe, "CEF recipe")
    original = unpatch_recipe(patched.decode("utf-8")).encode("utf-8")

    if package.is_symlink() or not package.is_dir():
        raise ValueError("Redirected or missing checkpoint recipe package")
    record = _regular(package / "checkpoint.json", package)
    if record.stat().st_size > 64 * 1024**2:
        raise ValueError("Oversized checkpoint recipe manifest")
    value = json.loads(record.read_bytes())
    if (not isinstance(value, dict) or value.get("schema") != 3
            or value.get("kind") != "build-checkpoint-not-sdk"
            or value.get("engine_runtime_verified") is not False
            or not isinstance(value.get("identity"), dict)):
        raise ValueError("Invalid checkpoint recipe manifest")
    recorded = value["identity"].get("recipe")
    if not isinstance(recorded, str) or re.fullmatch(r"[0-9a-f]{64}", recorded) is None:
        raise ValueError("Invalid checkpoint recipe fingerprint")

    # This layout is exactly the pinned ci_identity algorithm. Bind its source
    # before reproducing it, so an upstream algorithm change cannot be ignored.
    policy = _regular(repo / "vcpkg/static/linux_checkpoint.py", repo)
    if git_blob(policy.read_bytes()) != CHECKPOINT_POLICY_BLOB:
        raise ValueError("Checkpoint recipe hashing policy changed")
    paths = list((repo / "vcpkg/ports/cef-static").rglob("*")) + [
        repo / "vcpkg/static/ci.py", repo / "vcpkg/static/checkpoint.py",
        repo / "vcpkg/static/windows_slice.py", policy,
        repo / "vcpkg/static/linux_slice.py",
        repo / "vcpkg/static/triplets/x64-linux.cmake",
    ]
    original_hash, patched_hash = hashlib.sha256(), hashlib.sha256()
    recipe_seen = False
    for path in sorted(paths):
        # Refuse redirected inputs rather than hashing their destinations.
        if path.is_symlink():
            raise ValueError("Redirected checkpoint recipe input")
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        _regular(path, repo)
        name = path.relative_to(repo).as_posix().encode() + b"\0"
        is_recipe = path.resolve(strict=True) == recipe_file.resolve(strict=True)
        data = path.read_bytes()
        recipe_seen |= is_recipe
        original_hash.update(name)
        original_hash.update(original if is_recipe else data)
        patched_hash.update(name)
        patched_hash.update(patched if is_recipe else data)
    if not recipe_seen:
        raise ValueError("Restore recipe is outside the checkpoint hashing layout")

    if recorded == original_hash.hexdigest():
        selected, profile = original, "pinned-recipe"
    elif recorded == patched_hash.hexdigest():
        selected, profile = patched, "native-link-v1"
    else:
        raise ValueError("Checkpoint requires an unreviewed recipe state")
    if raw != selected:
        temporary = _stage(recipe_file, selected)
        try:
            os.replace(temporary, recipe_file)
        finally:
            temporary.unlink(missing_ok=True)
    return {"schema": 1, "profile": profile, "changed": raw != selected,
            "recorded_recipe_matched": True, "runtime_verified": False}


def install(recipe_file: Path, source: Path) -> dict:
    """Validate both complete inputs before atomically replacing either one."""
    recipe_file = recipe_file.absolute()
    source = source.resolve(strict=True)
    recipe_repo = recipe_file.parents[3].resolve(strict=True)
    if recipe_repo.is_symlink() or source.is_symlink():
        raise ValueError("Redirected native-link repository")
    if _head(recipe_repo) != CEF_RECIPE or _head(source) != CHROMIUM:
        raise ValueError("Native-link source revision changed")

    recipe_file = _regular(recipe_file, recipe_repo)
    expat = _regular(source / "third_party/expat/BUILD.gn", source)
    raw_recipe = recipe_file.read_bytes()
    raw_expat = expat.read_bytes()
    out_recipe = reviewed_output(
        raw_recipe, RECIPE_BLOB, patch_recipe, unpatch_recipe, "CEF recipe"
    )
    out_expat = reviewed_output(
        raw_expat, EXPAT_BLOB, patch_expat, unpatch_expat, "Chromium Expat source"
    )

    staged: list[tuple[Path, Path]] = []
    try:
        for path, raw, output in (
            (recipe_file, raw_recipe, out_recipe),
            (expat, raw_expat, out_expat),
        ):
            if raw != output:
                staged.append((path, _stage(path, output)))
        for path, temporary in staged:
            os.replace(temporary, path)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)

    return {
        "schema": 1,
        "status": "success",
        "kind": "cef-static-native-link",
        "changed_files": len(staged),
        "verified_files": 2,
        "expat_backend": "frozen-static-expat",
        "unwind_backend": "chromium-libunwind",
        "runtime_verified": False,
    }


def check_recipe(path: Path) -> dict:
    path = path.resolve(strict=True)
    output = reviewed_output(
        path.read_bytes(), RECIPE_BLOB, patch_recipe, unpatch_recipe, "CEF recipe"
    )
    if MARKER not in output.decode("utf-8"):
        raise ValueError("Native-link recipe marker missing")
    return {
        "schema": 1,
        "status": "verified",
        "patched_sha256": hashlib.sha256(output).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-recipe", type=Path)
    args = parser.parse_args()
    if args.check_recipe is None:
        parser.error("--check-recipe is required")
    check_recipe(args.check_recipe)
    print("CEF_STATIC_NATIVE_LINK_RECIPE_VERIFIED")


if __name__ == "__main__":
    main()
