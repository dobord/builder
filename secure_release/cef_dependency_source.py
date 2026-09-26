"""Fetch the exact minigbm source before expensive combined qualification.

Combined #67 stopped at package 62/107: vcpkg_from_git received HTTP 502 from
Googlesource. Retry only recognized 502/503/504 transport errors, not a build,
TLS, identity, checksum or ref failure. Populate the unchanged pinned vcpkg
helper's normal source archive using Git's verified commit, never a mirror,
branch, binary cache or replacement dependency. Raw output remains local.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from . import build_support

URL = "https://chromium.googlesource.com/chromiumos/platform/minigbm.git"
REVISION = "9d21b5cb5896c0cde186b54d430131f9f537104c"
PORT_BLOB = "4d7d2dd0f041a164dd5c7e4cfb6e3a2dfc546838"
HELPER_BLOB = "318de4e5e170880d1c75a6895defdb44cf0174ea"
PORT_FILE = "ports/cef-gbm/portfile.cmake"
HELPER_FILE = "scripts/cmake/vcpkg_from_git.cmake"
ARCHIVE_NAME = "cef-gbm-" + REVISION + ".tar.gz"
ATTEMPTS = 4
BACKOFF = (2, 5, 10)
FETCH_TIMEOUT = 120
MAX_OUTPUT = 2 * 1024**2
MAX_ARCHIVE = 64 * 1024**2


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _directory(path: Path) -> Path:
    path = path.absolute()
    for ancestor in (path, *path.parents):
        _require(not ancestor.is_symlink(), "Redirected dependency source directory")
    _require(path.is_dir(), "Missing dependency source directory")
    return path.resolve(strict=True)


def _pinned(root: Path, relative: str, expected: str) -> None:
    path = root / relative
    _directory(path.parent)
    _require(path.is_file() and not path.is_symlink()
             and _blob(path.read_bytes()) == expected,
             "Dependency source acquisition policy changed")


def transient_http_status(output: str) -> int | None:
    """Only Git's explicit transient HTTP server status permits another fetch."""
    if len(output) > MAX_OUTPUT or re.search(
        r"certificate|SSL peer|TLS|hash mismatch|object corrupt|bad object|"
        r"invalid object|not our ref|couldn't find remote ref|authentication failed",
        output, re.I,
    ):
        return None
    codes = {int(code) for code in re.findall(
        r"(?:\bHTTP\s+|requested URL returned error:\s*)([0-9]{3})\b", output, re.I
    )}
    if len(codes) == 1 and codes <= {502, 503, 504}:
        return next(iter(codes))
    return None


def _environment(base: dict[str, str]) -> dict[str, str]:
    env = {
        name: value for name, value in base.items()
        if not name.upper().startswith(("GIT_", "SSH_"))
        and not any(word in name.upper() for word in ("TOKEN", "KEY", "SECRET"))
    }
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https",
        "LC_ALL": "C",
    })
    return env


def _git(executable: str, arguments: list[str], cwd: Path, env: dict[str, str],
         log: Path, *, timeout: int = 60) -> subprocess.CompletedProcess:
    command = [executable, "-c", "core.autocrlf=false",
               "-c", "core.hooksPath=" + os.devnull,
               "-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true",
               *arguments]
    try:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        # Do not turn an unclassified timeout into an automatic build retry.
        raise RuntimeError("Pinned dependency source subprocess timed out") from error
    _require(len(result.stdout) <= MAX_OUTPUT, "Oversized dependency source response")
    with log.open("ab") as stream:
        stream.write(result.stdout)
    return result


def prefetch(registry: Path, upstream: Path, root: Path, env: dict[str, str],
             summary: dict) -> dict:
    """Acquire the exact port revision and publish its regular cached archive.

    Invoked after the host/producer gate but before the large engine restore.
    The complete acquisition policy is pinned. Source bytes and the vcpkg
    helper stay unchanged; the port receives only the existing archive guard.
    Each retry has an empty Git object database. Only FETCH receives retries.
    Every other failure is terminal and no unverified archive is published.
    """
    registry, upstream, root = map(_directory, (registry, upstream, root))
    _pinned(registry, PORT_FILE, PORT_BLOB)
    _pinned(upstream, HELPER_FILE, HELPER_BLOB)
    git = shutil.which("git")
    _require(git is not None, "Git is required for pinned dependency acquisition")
    downloads = upstream / "downloads"
    _require(not downloads.is_symlink(), "Redirected dependency download cache")
    downloads.mkdir(exist_ok=True)
    _directory(downloads)
    target = downloads / ARCHIVE_NAME
    _require(not target.exists() and not target.is_symlink(),
             "Unreviewed dependency source cache already exists")
    log = root / "dependency-source-fetch.log"
    _require(not log.exists() and not log.is_symlink(), "Dependency fetch log already exists")
    log.touch(mode=0o600, exist_ok=False)
    child_env = _environment(env)
    summary.update({"dependency_source_prefetch_verified": False,
                    "dependency_source_package": "cef-gbm",
                    "dependency_source_revision": REVISION,
                    "dependency_source_fetch_attempts": 0})
    for attempt in range(1, ATTEMPTS + 1):
        summary["dependency_source_fetch_attempts"] = attempt
        with tempfile.TemporaryDirectory(prefix=".cef-gbm-source-", dir=downloads) as name:
            stage = Path(name)
            repo = stage / "repo"
            initialized = _git(git, ["init", "--quiet", "--template=", "--object-format=sha1", str(repo)],
                               stage, child_env, log)
            if initialized.returncode:
                raise RuntimeError("Cannot initialize pinned dependency source repository")
            fetched = _git(git, ["fetch", "--no-tags", "--no-recurse-submodules", "--depth=1",
                                URL, REVISION], repo, child_env, log, timeout=FETCH_TIMEOUT)
            if fetched.returncode:
                status = transient_http_status(fetched.stdout.decode("utf-8", errors="replace"))
                if status is None:
                    raise RuntimeError("Pinned dependency fetch failed without a retryable HTTP status")
                summary["dependency_source_last_http_status"] = status
                if attempt == ATTEMPTS:
                    raise RuntimeError("Pinned dependency fetch exhausted bounded HTTP retries")
                time.sleep(BACKOFF[attempt - 1])
                continue
            head = _git(git, ["rev-parse", "--verify", "FETCH_HEAD^{commit}"], repo, child_env, log)
            _require(head.returncode == 0 and head.stdout.decode("ascii").strip() == REVISION,
                     "Fetched dependency commit differs from the pinned revision")
            checked = _git(git, ["fsck", "--strict", "--no-reflogs", "--no-dangling",
                                 "--no-progress", REVISION], repo, child_env, log)
            if checked.returncode:
                raise RuntimeError("Pinned dependency Git objects failed integrity validation")
            archive = stage / ARCHIVE_NAME
            archived = _git(git, ["archive", "--format=tar.gz", REVISION, "-o", str(archive)],
                            repo, child_env, log)
            _require(archived.returncode == 0 and archive.is_file() and not archive.is_symlink()
                     and 0 < archive.stat().st_size <= MAX_ARCHIVE,
                     "Pinned dependency source archive is invalid")
            with archive.open("rb") as stream:
                sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
                os.fsync(stream.fileno())
            receipt = {"schema": 1, "kind": "cef-pinned-dependency-source", "package": "cef-gbm",
                       "url": URL, "revision": REVISION, "archive": ARCHIVE_NAME,
                       "sha256": sha256, "size": archive.stat().st_size, "attempts": attempt}
            receipt_path = root / "dependency-source-receipt.json"
            with receipt_path.open("x", encoding="utf-8") as stream:
                json.dump(receipt, stream, sort_keys=True); stream.write("\n")
            # Publish without replacing even a concurrently-created cache entry.
            # The staging file and destination are guaranteed to share a device.
            os.link(archive, target)
            # Existing source-integrity guard becomes part of the port ABI and
            # rejects disappearance/tampering instead of silently refetching.
            build_support.protect_source_archives(
                registry, downloads, [{"name": "cef-gbm", "sha": REVISION}]
            )
            summary.update({"dependency_source_prefetch_verified": True,
                            "dependency_source_archive_sha256": sha256})
            return receipt
    raise AssertionError("Unreachable pinned dependency fetch state")
