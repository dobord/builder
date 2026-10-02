"""Read one reviewed ENGINE83 backup without changing its original identity.

The new Actions artifact is only a transport of the two ORIGINAL ZIPs. Both
original SHA-256 values remain mandatory. The normal summary qualification,
producer checks, checkpoint envelope/context and payload validation still run.
No private key, decryption, artifact discovery, re-upload or fresh-build fallback
belongs here. Only the exact selector below opts into this reviewed transport.
"""
from __future__ import annotations

import atexit
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import urllib.error
import zipfile

from . import crypto
from .protocol import BUILDER, check_run

ORIGINAL = {
    "run": 36069973563,
    "attempt": 1,
    "producer_sha": "4f0d60f6b83244fbcc0ef268b0914cb7cd820354",
    "artifact_id": 10839464034,
    "artifact_sha256": "90950cf0792a7f644ba5e40c73edc1793cf2f8cc6483bac306d3af566dbd8df3",
    "summary_artifact_id": 10839723709,
    "summary_artifact_sha256": "fc003422a66b6997f3e78c8953a03cfcb85aefd1e18e6bca4f0d50eabfdaadb3",
    "build_key": "a60c3359bb8fa8df9207f5895729d7bda7c7b1f72ae2ecf0f767a1a1cf719f53",
    "platform_sha256": "351272996be93d25308681ca051e34827b4f07375eff2d0f25de40164cdd206e",
}
BACKUP_RUN = 36975195624
BACKUP_ATTEMPT = 1
BACKUP_SHA = "49f5d947f1c40f98e75369ee0b66ec1aa6fdc5e7"
BACKUP_BRANCH = "temporary/checkpoint-reupload-20261002"
BACKUP_WORKFLOW = "local-checkpoint-reupload.yml"
BACKUP_ID = 11213402934
BACKUP_NAME = "cef-strict-checkpoint-backup-linux-36069973563-1-36975195624"
BACKUP_DIGEST = "9b1fbbcc022ec1b70b738b333674533ace3c3368cf60a168d3b61ec4d1a28bc9"
BACKUP_BYTES = 16753710075
SUMMARY_LIMIT = 4 * 1024**2
RECEIPT_LIMIT = 65536
MIN_REMAINING = timedelta(hours=6)
BLOCK = 1024**2
_cache: tempfile.TemporaryDirectory | None = None


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("CEF_CHECKPOINT_BACKUP_" + message)


def applies(selected: object) -> bool:
    # Canonical JSON also distinguishes bool/int and rejects nonfinite values.
    return isinstance(selected, dict) and crypto.canonical(selected) == crypto.canonical(ORIGINAL)


def _get(api, path: str):
    try:
        return api.get(path)
    except (urllib.error.HTTPError, urllib.error.URLError):
        raise ValueError("CEF_CHECKPOINT_BACKUP_API_UNAVAILABLE") from None


def _run(api, run: int, attempt: int, revision: str, workflow: str, branch: str) -> None:
    root = f"/repos/{BUILDER}/actions/runs/{run}"
    for suffix in (f"/attempts/{attempt}", ""):
        value = _get(api, root + suffix)
        _require(isinstance(value, dict) and type(value.get("id")) is int
                 and value["id"] == run and type(value.get("run_attempt")) is int
                 and value.get("head_branch") == branch,
                 "RUN_IDENTITY_CHANGED")
        try:
            check_run(value, BUILDER, workflow, revision, attempt, "push", success=True)
        except (KeyError, TypeError, ValueError):
            raise ValueError("CEF_CHECKPOINT_BACKUP_RUN_PROVENANCE_CHANGED") from None


def verify_available(selected: object, api, *, now: datetime | None = None) -> dict:
    """Metadata only: qualify neither the nested archive bytes nor the SDK."""
    _require(applies(selected), "SELECTOR_NOT_REVIEWED")
    now = datetime.now(timezone.utc) if now is None else now
    _require(now.tzinfo is not None and now.utcoffset() == timedelta(0), "CLOCK_INVALID")
    _run(api, ORIGINAL["run"], ORIGINAL["attempt"], ORIGINAL["producer_sha"],
         "cef-strict-engine-iteration.yml", "feature/cef-static-integration")
    _run(api, BACKUP_RUN, BACKUP_ATTEMPT, BACKUP_SHA, BACKUP_WORKFLOW, BACKUP_BRANCH)
    value = _get(api, f"/repos/{BUILDER}/actions/artifacts/{BACKUP_ID}")
    _require(isinstance(value, dict), "ARTIFACT_INVALID")
    origin = value.get("workflow_run")
    _require(value.get("id") == BACKUP_ID and value.get("name") == BACKUP_NAME
             and value.get("digest") == "sha256:" + BACKUP_DIGEST
             and type(value.get("size_in_bytes")) is int
             and value["size_in_bytes"] == BACKUP_BYTES and value.get("expired") is False
             and isinstance(origin, dict) and origin.get("id") == BACKUP_RUN
             and origin.get("head_sha") == BACKUP_SHA
             and origin.get("head_branch") == BACKUP_BRANCH,
             "ARTIFACT_IDENTITY_CHANGED")
    expires = value.get("expires_at")
    _require(isinstance(expires, str) and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", expires) is not None,
        "EXPIRY_INVALID")
    try:
        remaining = datetime.fromisoformat(expires.replace("Z", "+00:00")) - now
    except ValueError:
        raise ValueError("CEF_CHECKPOINT_BACKUP_EXPIRY_INVALID") from None
    _require(remaining >= MIN_REMAINING, "RETENTION_TOO_SHORT")
    return {"checkpoint_artifacts_available": True, "run": ORIGINAL["run"],
            "attempt": ORIGINAL["attempt"], "artifact_count": 1,
            "contained_original_archive_count": 2, "backup_run": BACKUP_RUN,
            "backup_artifact_id": BACKUP_ID,
            "min_remaining_seconds": int(remaining.total_seconds())}


def _regular(path: Path, limit: int) -> int:
    _require(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)),
             "REDIRECTED_PATH")
    value = path.lstat()
    _require(stat.S_ISREG(value.st_mode) and 0 < value.st_size <= limit, "FILE_BOUNDS")
    return value.st_size


def _hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _copy(source, target: Path, size: int, expected: str | None = None) -> None:
    """Write exclusively into our private staging directory, with a hard bound."""
    digest = hashlib.sha256()
    total = 0
    with target.open("xb") as output:
        while block := source.read(BLOCK):
            total += len(block)
            _require(total <= size, "MEMBER_OVERSIZE")
            output.write(block)
            digest.update(block)
    _require(total == size and (expected is None or digest.hexdigest() == expected),
             "ORIGINAL_ZIP_HASH_MISMATCH")


def _receipt(path: Path, selected: dict, sizes: dict[str, int]) -> None:
    value = crypto.parse(path.read_bytes())
    _require(isinstance(value, dict), "RECEIPT_INVALID")
    original = {"repository": BUILDER, "run": selected["run"],
                "attempt": selected["attempt"], "sha": selected["producer_sha"]}
    _require(type(value.get("schema")) is int and value["schema"] == 1
             and value.get("kind") == "strict-cef-exact-ciphertext-backup"
             and value.get("sdk_qualified") is False
             and value.get("original_producer") == original
             and value.get("backup_run") == BACKUP_RUN
             and value.get("backup_attempt") == BACKUP_ATTEMPT
             and value.get("original_zip_hashes_verified") is True
             and value.get("not_for_direct_lock_substitution") is True, "RECEIPT_IDENTITY_CHANGED")
    for role, id_key, hash_key in (("checkpoint", "artifact_id", "artifact_sha256"),
                                 ("summary", "summary_artifact_id", "summary_artifact_sha256")):
        item = value.get(role)
        _require(isinstance(item, dict) and item.get("original_artifact_id") == selected[id_key]
                 and item.get("sha256") == selected[hash_key]
                 and type(item.get("size")) is int and item["size"] == sizes[role + ".zip"],
                 "RECEIPT_ORIGINAL_CHANGED")
    # The receipt is not an authority: even a self-consistent one cannot replace
    # either original hash, and its historical chunk list is never followed.


def _extract(archive: Path, output: Path, selected: dict) -> None:
    _require(_regular(archive, BACKUP_BYTES) == BACKUP_BYTES
             and _hash(archive) == BACKUP_DIGEST, "TRANSPORT_HASH_MISMATCH")
    limits = {"checkpoint.zip": BACKUP_BYTES, "summary.zip": SUMMARY_LIMIT,
              "transport-receipt.json": RECEIPT_LIMIT}
    hashes = {"checkpoint.zip": selected["artifact_sha256"],
              "summary.zip": selected["summary_artifact_sha256"]}
    with zipfile.ZipFile(archive) as stream:
        infos = stream.infolist()
        _require(len(infos) == 3 and {i.filename for i in infos} == set(limits), "MEMBER_SET")
        for info in infos:
            _require(not info.is_dir() and not (info.flag_bits & 1)
                     and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                     and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                     and 0 < info.file_size <= limits[info.filename]
                     and 0 < info.compress_size <= BACKUP_BYTES
                     and (info.compress_type != zipfile.ZIP_STORED
                          or info.compress_size == info.file_size), "MEMBER_BOUNDS_OR_TYPE")
        sizes = {i.filename: i.file_size for i in infos}
        _require(sum(sizes.values()) <= BACKUP_BYTES, "TOTAL_BOUNDS")
        _require(shutil.disk_usage(output.parent).free > sum(sizes.values()) + BLOCK, "DISK_SPACE")
        output.mkdir(mode=0o700)  # Never merge into an existing or redirected tree.
        for info in infos:
            with stream.open(info) as source:
                _copy(source, output / info.filename, info.file_size, hashes.get(info.filename))
    _receipt(output / "transport-receipt.json", selected, sizes)


def cleanup() -> None:
    global _cache
    cached, _cache = _cache, None
    if cached is not None:
        cached.cleanup()


atexit.register(cleanup)


def _materialize(selected: dict, api) -> Path:
    global _cache
    verify_available(selected, api)
    if _cache is None:
        directory = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
        parent = Path(directory).absolute()
        _require(parent.is_dir() and all(not p.is_symlink() for p in (parent, *parent.parents)),
                 "TEMP_ROOT_INVALID")
        _require(shutil.disk_usage(parent).free > 2 * BACKUP_BYTES + BLOCK, "DISK_SPACE")
        staging = tempfile.TemporaryDirectory(prefix=".cef-engine83-backup-", dir=parent)
        try:
            root = Path(staging.name)
            archive = root / "transport.zip"
            api.download(f"/repos/{BUILDER}/actions/artifacts/{BACKUP_ID}/zip", archive,
                         BACKUP_DIGEST, max_size=BACKUP_BYTES)
            _extract(archive, root / "original", selected)
            verify_available(selected, api)
            archive.unlink()  # Do not retain the extra 16GB wrapper during restore.
            _cache = staging
        except BaseException:
            staging.cleanup()
            raise
    return Path(_cache.name) / "original"


def copy_original(api, selected: dict, role: str, target: Path) -> None:
    """Supply exact original ZIP bytes to the unchanged downstream validators.

    Fetch once per process (host review then restore), not once per API client.
    Nothing is published until BOTH original archive hashes and both run
    provenances have passed. No on-disk cache is accepted from a previous run.
    """
    _require(applies(selected) and role in ("summary", "checkpoint"), "REQUEST_NOT_REVIEWED")
    _require(target.is_absolute() and target.parent.is_dir()
             and all(not p.is_symlink() for p in target.parents), "REDIRECTED_PATH")
    _require(not target.exists() and not target.is_symlink(), "OUTPUT_EXISTS")
    try:
        root = _materialize(selected, api)
        source = root / (role + ".zip")
        limit = SUMMARY_LIMIT if role == "summary" else BACKUP_BYTES
        expected = selected["summary_artifact_sha256" if role == "summary" else "artifact_sha256"]
        size = _regular(source, limit)
        _require(shutil.disk_usage(target.parent).free > size + BLOCK, "DISK_SPACE")
        with tempfile.TemporaryDirectory(prefix=".backup-copy-", dir=target.parent) as folder:
            staged = Path(folder) / "archive.zip"
            with source.open("rb") as stream:
                _copy(stream, staged, size, expected)
            verify_available(selected, api)
            # Exclusive publication, including under a concurrent path creator.
            os.link(staged, target)
    except BaseException:
        cleanup()
        raise
    if role == "checkpoint":
        cleanup()  # Restore now owns the ciphertext ZIP; no extra copy needed.
