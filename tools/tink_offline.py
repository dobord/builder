#!/usr/bin/env python3
"""Offline launcher for the repository's Tink 1.16.1 diagnostic decryptor.

The launcher never contacts a package index. It creates a local virtual
environment from vendor/wheels using requirements.lock with --require-hashes,
then delegates to secure_release.decrypt_local.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
WHEELHOUSE = ROOT / "vendor" / "wheels"
LOCK = ROOT / "requirements.lock"
CACHE_ROOT = ROOT / ".offline-tink"
SUPPORTED_PYTHON = {(3, 12), (3, 13)}


def _supported_host() -> None:
    if sys.version_info[:2] not in SUPPORTED_PYTHON:
        raise SystemExit("Use CPython 3.12 or 3.13.")
    system = platform.system()
    machine = platform.machine().lower()
    if system not in {"Linux", "Windows"}:
        raise SystemExit("Offline Tink bundle supports Linux x86-64 and Windows x64 only.")
    if machine not in {"x86_64", "amd64"}:
        raise SystemExit("Offline Tink bundle supports x86-64/AMD64 only.")


def _verify_wheelhouse() -> None:
    spec = importlib.util.spec_from_file_location("verify_wheelhouse", TOOLS / "verify_wheelhouse.py")
    if spec is None or spec.loader is None:
        raise SystemExit("Cannot load wheelhouse verifier.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if module.main() != 0:
        raise SystemExit("Offline wheelhouse verification failed.")


def _venv_python(folder: Path) -> Path:
    return folder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _environment_path() -> Path:
    tag = f"py{sys.version_info.major}{sys.version_info.minor}-{platform.system().lower()}-x86_64"
    return CACHE_ROOT / tag


def _lock_digest() -> str:
    return hashlib.sha256(LOCK.read_bytes()).hexdigest()


def _bootstrap() -> Path:
    _supported_host()
    _verify_wheelhouse()

    env_dir = _environment_path()
    python = _venv_python(env_dir)
    marker = env_dir / ".requirements.sha256"
    digest = _lock_digest()

    if not python.is_file() or not marker.is_file() or marker.read_text("ascii").strip() != digest:
        if env_dir.exists():
            shutil.rmtree(env_dir)
        env_dir.parent.mkdir(parents=True, exist_ok=True)
        venv.EnvBuilder(with_pip=True, clear=True).create(env_dir)
        python = _venv_python(env_dir)
        child_env = os.environ.copy()
        child_env.update({
            "PIP_NO_INDEX": "1",
            "PIP_REQUIRE_HASHES": "1",
            "PIP_FIND_LINKS": str(WHEELHOUSE),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        })
        subprocess.run([
            str(python), "-m", "pip", "install",
            "--no-index",
            f"--find-links={WHEELHOUSE}",
            "--require-hashes",
            "--only-binary=:all:",
            "-r", str(LOCK),
        ], cwd=ROOT, env=child_env, check=True)
        subprocess.run([
            str(python), "-c",
            "import importlib.metadata as m; "
            "assert m.version('tink') == '1.16.1'; "
            "assert m.version('protobuf') == '6.33.5'; "
            "print('Tink', m.version('tink'))",
        ], cwd=ROOT, env=child_env, check=True)
        marker.write_text(digest + "\n", encoding="ascii")

    return python


def main() -> int:
    python = _bootstrap()
    if sys.argv[1:] == ["--version"]:
        return subprocess.run([
            str(python), "-c",
            "import importlib.metadata as m; print('tink', m.version('tink'))",
        ], cwd=ROOT, check=False).returncode

    return subprocess.run(
        [str(python), "-m", "secure_release.decrypt_local", *sys.argv[1:]],
        cwd=ROOT,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
