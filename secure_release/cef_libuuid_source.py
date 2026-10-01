"""Cache the unchanged libuuid 1.0.3 distfile before expensive CEF restore.

#135 got the same wrong SHA512 from every SourceForge redirector URL. Use one
fixed distribution mirror for the *identical* upstream-pinned distfile, not a
new release, rebuilt tarball or binary package. A mismatch remains fatal and
is never retried or allowed to replace an existing cache entry. The unchanged
vcpkg port performs its own SHA512 check again when consuming this cache.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

URL = "https://distfiles.macports.org/libuuid/libuuid-1.0.3.tar.gz"
ARCHIVE_NAME = "libuuid-1.0.3.tar.gz"
SHA512 = (
    "77488caccc66503f6f2ded7bdfc4d3bc2c20b24a8dc95b2051633c695e99ec27876"
    "ffbafe38269b939826e1fdb06eea328f07b796c9e0aaca12331a787175507"
)
PORT_FILE = "ports/libuuid/portfile.cmake"
PORT_BLOB = "c37a7a7957d733a15182808c959751df9c5a7b4c"
MAX_ARCHIVE = 2 * 1024**2
MAX_LOG = 64 * 1024


def _directory(path: Path) -> Path:
    path = path.absolute()
    if any(item.is_symlink() for item in (path, *path.parents)) or not path.is_dir():
        raise ValueError("Invalid libuuid source directory")
    return path.resolve(strict=True)


def _validate_policy(upstream: Path) -> None:
    path = upstream / PORT_FILE
    _directory(path.parent)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_LOG:
        raise ValueError("Invalid libuuid source policy file")
    raw = path.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if blob != PORT_BLOB:
        raise ValueError("Pinned libuuid source policy changed")


def _validate_archive(path: Path) -> int:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Invalid libuuid source archive")
    size = path.stat().st_size
    if not 0 < size <= MAX_ARCHIVE:
        raise ValueError("libuuid source archive size outside bounds")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha512").hexdigest()
    if actual != SHA512:
        raise ValueError("libuuid source SHA512 mismatch")
    return size


def _download(archive: Path, log: Path) -> None:
    curl = shutil.which("curl")
    if curl is None:
        raise RuntimeError("curl is required for pinned libuuid acquisition")
    # Ignore curlrc, proxy, CA overrides and all credentials from the caller.
    env = {name: value for name, value in os.environ.items()
           if name.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"}}
    env.update({"LC_ALL": "C", "LANG": "C"})
    try:
        result = subprocess.run(
            [curl, "--disable", "--fail", "--silent", "--show-error",
             "--location", "--max-redirs", "2", "--proto", "=https",
             "--proto-redir", "=https", "--connect-timeout", "20",
             "--max-time", "60", "--max-filesize", str(MAX_ARCHIVE),
             "--output", str(archive), URL],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env, timeout=70,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("Pinned libuuid source download timed out") from error
    if len(result.stdout) > MAX_LOG:
        raise ValueError("Oversized libuuid source download diagnostic")
    log.write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError("Pinned libuuid source download failed")


def prefetch(upstream: Path, root: Path, summary: dict) -> dict:
    """Publish only checksum-verified bytes at vcpkg's existing downloads path."""
    upstream, root = map(_directory, (upstream, root))
    _validate_policy(upstream)
    summary["libuuid_source_prefetch_verified"] = False
    downloads = upstream / "downloads"
    if downloads.is_symlink():
        raise ValueError("Redirected libuuid download cache")
    downloads.mkdir(exist_ok=True)
    downloads = _directory(downloads)
    target = downloads / ARCHIVE_NAME
    receipt_path = root / "libuuid-source-receipt.json"
    log = root / "libuuid-source-fetch.log"
    if any(path.exists() or path.is_symlink() for path in (receipt_path, log)):
        raise ValueError("libuuid source evidence already exists")
    if target.exists() or target.is_symlink():
        size = _validate_archive(target)  # Never overwrite or retry bad cache.
        cached = True
    else:
        log.touch(mode=0o600, exist_ok=False)
        with tempfile.TemporaryDirectory(prefix=".libuuid-source-", dir=downloads) as name:
            archive = Path(name) / ARCHIVE_NAME
            _download(archive, log)
            size = _validate_archive(archive)
            # Same filesystem; a concurrent cache creator is not overwritten.
            os.link(archive, target)
        cached = False
    receipt = {
        "schema": 1, "kind": "cef-pinned-libuuid-source", "version": "1.0.3",
        "url": URL, "archive": ARCHIVE_NAME, "sha512": SHA512,
        "size": size, "existing_cache": cached, "port_blob": PORT_BLOB,
    }
    with receipt_path.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
    summary.update({"libuuid_source_prefetch_verified": True,
                    "libuuid_source_archive_sha512": SHA512,
                    "libuuid_source_archive_bytes": size})
    return receipt
