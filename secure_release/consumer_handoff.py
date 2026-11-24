"""Re-encrypt exact approved archive bytes, without exporting the log private key.

This is transport, not publication authority. Callers must independently resolve
and authenticate approval with consumer_publication before invoking this module.
The official Tink envelope/context checks are unchanged. No archive is unpacked,
executed, rebuilt or signed here, and no signing/log private key is accepted.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile

from . import consumer_ci, consumer_publication, crypto, safeio

_MAX = consumer_ci.MAX_PREPARED


def _context(expected):
    raw = crypto.canonical(expected)
    consumer_publication.check_approval(raw, expected)
    return {"schema": 1, "purpose": "consumer-release-archive",
            "approval_sha256": hashlib.sha256(raw).hexdigest()}


def _destination(target):
    if target.exists() or target.is_symlink():
        raise ValueError("consumer handoff destination must be new")
    info = target.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or target.parent.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400
            or os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise ValueError("consumer handoff requires private destination staging")


def _snapshot(source, target, limit):
    """Read bounded regular input into private staging before checking its hash."""
    if not safeio.regular(source):
        raise ValueError("consumer handoff requires a regular source")
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(descriptor, "rb") as src:
        info = os.fstat(src.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError("consumer handoff source exceeds bounds")
        with target.open("xb") as dst:
            target.chmod(0o600)
            while block := src.read(1024 * 1024):
                count += len(block)
                if count > limit:
                    raise ValueError("consumer handoff source exceeds bounds")
                digest.update(block)
                dst.write(block)
    if not count:
        raise ValueError("consumer handoff source is empty")
    return digest.hexdigest()


def _publish(source, target):
    # Same-filesystem link is atomic and cannot overwrite a racing destination.
    # No fallback to replace(): interruption leaves either no output or complete
    # authenticated bytes. Private temporary staging is removed on every exit.
    try:
        os.link(source, target)
    except OSError:
        raise ValueError("consumer handoff output could not be published") from None


def seal_archive(source: Path, target: Path, recipient: str, expected: dict):
    """Use only the builder input PUBLIC recipient, never the local log key."""
    context = _context(expected)
    _destination(target)
    if source.name != expected["archive"]["name"]:
        raise ValueError("consumer archive name mismatch")
    with tempfile.TemporaryDirectory(prefix=".consumer-handoff-", dir=target.parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        snapshot = root / "archive"
        if _snapshot(source, snapshot, _MAX) != expected["archive"]["sha256"]:
            raise ValueError("consumer archive digest mismatch")
        cipher = root / "archive.enc"
        try:
            crypto.encrypt_file(snapshot, cipher, recipient, context)
        except Exception:
            raise ValueError("consumer archive encryption failed") from None
        cipher.chmod(0o600)
        _publish(cipher, target)


def open_archive(source: Path, target: Path, recipient_private: str, expected: dict):
    """Decrypt only in trusted builder staging, then verify exact approved bytes."""
    context = _context(expected)
    _destination(target)
    if target.name != expected["archive"]["name"]:
        raise ValueError("consumer archive name mismatch")
    with tempfile.TemporaryDirectory(prefix=".consumer-handoff-", dir=target.parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        cipher = root / "archive.enc"
        _snapshot(source, cipher, _MAX + 1024**2)
        plain = root / "archive"
        try:
            crypto.decrypt_file(cipher, plain, recipient_private, context)
        except Exception:
            raise ValueError("consumer archive decryption failed") from None
        if (not 0 < plain.stat().st_size <= _MAX
                or crypto.digest(plain) != expected["archive"]["sha256"]):
            raise ValueError("consumer archive digest mismatch")
        plain.chmod(0o600)
        _publish(plain, target)
