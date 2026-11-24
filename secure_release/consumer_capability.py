"""Explicit one-artifact delegation; never export the operator log master key.

The original VCPKGSE1 envelope, header, recipient, context and every Streaming
AEAD tag remain unchanged. A signed, builder-encrypted capability carries only
that envelope's random file key. Its entire independently resolved artifact and
approval identity is authenticated. Existing crypto.decrypt_file is not relaxed.
This is decryption authority for one file, NOT release/publication authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from . import consumer_ci as consumer, consumer_handoff, crypto, safeio

_FIELDS = {"schema", "purpose", "approval_sha256", "request_id", "builder_sha", "run",
           "attempt", "request_digest", "lane", "artifact_id", "artifact_sha256",
           "cipher_sha256", "recipient"}


def _validate(binding):
    if (not isinstance(binding, dict) or set(binding) != _FIELDS
            or type(binding["schema"]) is not int or binding["schema"] != 1
            or binding["purpose"] != "consumer-result-capability" or binding["lane"] != "static"
            or type(binding["attempt"]) is not int or binding["attempt"] != 1
            or any(type(binding[key]) is not int or not 0 < binding[key] <= 2**63 - 1
                   for key in ("run", "artifact_id"))
            or not isinstance(binding["request_id"], str)
            or str(uuid.UUID(binding["request_id"])) != binding["request_id"]
            or not isinstance(binding["builder_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", binding["builder_sha"]) is None
            or any(not isinstance(binding[key], str) or re.fullmatch(r"[0-9a-f]{64}", binding[key]) is None
                   for key in ("approval_sha256", "request_digest", "artifact_sha256", "cipher_sha256", "recipient"))):
        raise ValueError("invalid one-artifact capability binding")


def _header(stream, binding):
    header = crypto.read_header(stream)
    context = consumer.context("results", binding)
    context.update(run=binding["run"], attempt=1, request_digest=binding["request_digest"], lane="static")
    if header["recipient"] != binding["recipient"] or header["context"] != context:
        raise ValueError("original artifact recipient or context mismatch")
    return header


def _secret_file(path):
    info = path.lstat()
    if (not safeio.regular(path) or not 0 < info.st_size <= 65536
            or os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise ValueError("local private key file must be protected")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= 65536
                or os.name == "posix" and (opened.st_uid != os.getuid() or opened.st_mode & 0o077)):
            raise ValueError("invalid local private key file")
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("local private key file exceeds bounds")
    text = raw.decode("utf-8")
    return text if text.lstrip().startswith("{") else crypto.unb64(text.strip()).decode("utf-8")


def _stream(source, streaming_key, binding, destination=None):
    _, _, _, streaming_aead = crypto._tink()
    primitive = crypto.key(streaming_key).primitive(streaming_aead.StreamingAead)
    count = 0
    with source.open("rb") as encrypted:
        header = _header(encrypted, binding)
        with primitive.new_decrypting_stream(encrypted, crypto._aad(header)) as plain:
            while block := plain.read(1024 * 1024):
                count += len(block)
                if count > consumer.MAX_PREPARED:
                    raise ValueError("delegated result exceeds bounds")
                if destination is not None:
                    destination.write(block)
    if not count:
        raise ValueError("delegated result is empty")


def create(source: Path, log_private_path: Path, signing_private_path: Path,
           builder_public: str, binding: dict) -> str:
    """Local operator only; return encrypted delegation, never a plaintext key."""
    if os.environ.get("GITHUB_ACTIONS") == "true" or os.name != "posix":
        raise ValueError("one-artifact delegation creation requires a POSIX-local operator")
    try:
        _validate(binding)
        with tempfile.TemporaryDirectory(prefix=".consumer-capability-", dir=source.parent) as directory:
            root = Path(directory)
            root.chmod(0o700)
            snapshot = root / "original.enc"
            if consumer_handoff._snapshot(source, snapshot, consumer.MAX_PREPARED + 1024**2) != binding["cipher_sha256"]:
                raise ValueError("original artifact ciphertext digest mismatch")
            private = _secret_file(log_private_path)
            if crypto.fingerprint(crypto.public_text(private)) != binding["recipient"]:
                raise ValueError("wrong local artifact recipient")
            with snapshot.open("rb") as stream:
                header = _header(stream, binding)
            _, hybrid, _, _ = crypto._tink()
            streaming_key = crypto.key(private).primitive(hybrid.HybridDecrypt).decrypt(
                crypto.unb64(header["wrapped"]), b"vcpkg-file-key-v1\x00" + crypto.canonical(header["context"])).decode("utf-8")
            if not 0 < len(streaming_key) <= 8192:
                raise ValueError("invalid delegated file key")
            # Consume to authenticated EOF without retaining any plaintext.
            _stream(snapshot, streaming_key, binding)
            payload = {"schema": 1, "binding": binding, "streaming_key": streaming_key}
            signed = crypto.sign(payload, _secret_file(signing_private_path))
            return crypto.seal_message(crypto.canonical(signed), builder_public, binding)
    except Exception:
        # Backend diagnostics must never expose any keyset, capsule or input.
        raise ValueError("one-artifact capability creation failed") from None


def open_result(source: Path, capsule: str, target: Path, builder_private: str,
                operator_public: str, binding: dict):
    """Trusted stage: use only independently API/artifact-resolved binding values."""
    _validate(binding)
    consumer_handoff._destination(target)
    if not isinstance(capsule, str) or not 0 < len(capsule) <= 49152:
        raise ValueError("invalid encrypted one-artifact capability")
    with tempfile.TemporaryDirectory(prefix=".consumer-capability-", dir=target.parent) as directory:
        root = Path(directory)
        root.chmod(0o700)
        snapshot = root / "original.enc"
        try:
            if consumer_handoff._snapshot(source, snapshot, consumer.MAX_PREPARED + 1024**2) != binding["cipher_sha256"]:
                raise ValueError("original artifact ciphertext digest mismatch")
            document = crypto.parse(crypto.open_message(capsule, builder_private, binding))
            payload = crypto.verify(document, operator_public)
            if (not isinstance(payload, dict) or set(payload) != {"schema", "binding", "streaming_key"}
                    or type(payload["schema"]) is not int or payload["schema"] != 1
                    or crypto.canonical(payload["binding"]) != crypto.canonical(binding)
                    or not isinstance(payload["streaming_key"], str) or not 0 < len(payload["streaming_key"]) <= 8192):
                raise ValueError("delegated capability payload mismatch")
            plain = root / "result"
            with plain.open("xb") as stream:
                plain.chmod(0o600)
                _stream(snapshot, payload["streaming_key"], binding, stream)
        except Exception:
            raise ValueError("one-artifact capability authentication failed") from None
        consumer_handoff._publish(plain, target)
