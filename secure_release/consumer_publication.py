"""Validate the signed approval payload for an independent consumer publisher.

Validate exact approval identity and its detached release signature. This
module does not claim that acceptance reports passed, grant credentials,
or publish assets.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile

from . import crypto

_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
_FIELDS = frozenset({
    "schema", "purpose", "repository_id", "tag", "tag_object", "source_sha",
    "base_sha", "builder_sha", "run", "attempt", "request_digest", "archive", "acceptance",
})
_REPORTS = frozenset({"dataplane", "client", "supplier"})


def _matches(value, expression):
    return isinstance(value, str) and expression.fullmatch(value) is not None


def _positive_id(value):
    return type(value) is int and 0 < value <= 2**63 - 1


def check_approval(raw: bytes, expected: dict) -> dict:
    """Compare canonical approval bytes with independently resolved expectations.

    The caller must authenticate these exact bytes and resolve the expected
    values from trusted policy, Git refs, builder evidence and lab receipts,
    never by echoing fields from the untrusted approval back as expectations.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 8192:
        raise ValueError("consumer publication approval exceeds bounds")
    value = crypto.parse(raw)
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["purpose"] != "consumer-release-publication"
            or not _positive_id(value["repository_id"]) or not _positive_id(value["run"])
            or type(value["attempt"]) is not int or value["attempt"] != 1
            or not _matches(value["tag"], _TAG)
            or not all(_matches(value[field], _SHA) for field in ("tag_object", "source_sha", "base_sha", "builder_sha"))
            or not _matches(value["request_digest"], _DIGEST)):
        raise ValueError("invalid consumer publication approval identity")
    archive = value["archive"]
    suffix = "-" + value["tag"] + "-linux-x86_64-static.tar.gz"
    if (not isinstance(archive, dict) or set(archive) != {"name", "sha256"}
            or not _matches(archive["name"], re.compile(r"[a-z0-9][a-z0-9-]{0,62}" + re.escape(suffix)))
            or not _matches(archive["sha256"], _DIGEST)):
        raise ValueError("invalid consumer publication archive")
    acceptance = value["acceptance"]
    if (not isinstance(acceptance, dict) or set(acceptance) != _REPORTS
            or not all(_matches(item, _DIGEST) for item in acceptance.values())):
        raise ValueError("invalid consumer publication acceptance inventory")
    if not isinstance(expected, dict) or crypto.canonical(value) != raw or crypto.canonical(expected) != raw:
        raise ValueError("consumer publication approval does not match trusted evidence")
    return value


def verify_signed_approval(raw: bytes, signature: bytes, public_key: bytes,
                           fingerprint: str, expected: dict) -> dict:
    """Verify one detached Ed25519 OpenPGP signature in an isolated keyring.

    Public key and fingerprint are independently provisioned trust inputs,
    never fields selected by the untrusted approval. No signing private key,
    ambient keyring, keyserver, trust database or consumer executable is used.
    """
    value = check_approval(raw, expected)
    if (not isinstance(fingerprint, str) or re.fullmatch(r"[0-9A-F]{40}", fingerprint) is None
            or not isinstance(signature, bytes) or not 0 < len(signature) <= 65536
            or not isinstance(public_key, bytes) or not 0 < len(public_key) <= 65536
            or signature.splitlines()[0] != b"-----BEGIN PGP SIGNATURE-----"
            or public_key.splitlines()[0] != b"-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        raise ValueError("invalid consumer approval signature inputs")
    env = {name: item for name, item in os.environ.items()
           if name in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"}}
    env.update(LC_ALL="C", LANG="C")
    try:
        with tempfile.TemporaryDirectory(prefix="consumer-approval-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            for name, content in (("approval.json", raw), ("signature.asc", signature)):
                path = root / name
                path.write_bytes(content)
                path.chmod(0o600)
            keyring = root / "trusted.gpg"
            subprocess.run(["gpg", "--no-options", "--batch", "--homedir", str(root),
                            "--dearmor", "--output", str(keyring)], input=public_key, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
            keyring.chmod(0o600)
            result = subprocess.run(["gpgv", "--homedir", str(root), "--keyring", str(keyring),
                                     "--status-fd", "1", str(root / "signature.asc"),
                                     str(root / "approval.json")], env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True)
        records = [line.split() for line in result.stdout.decode("ascii").splitlines()
                   if line.startswith("[GNUPG:] ")]
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise ValueError("consumer approval signature verification failed") from None
    denied = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED",
              "SIGEXPIRED", "NODATA", "ERROR", "FAILURE"}
    valid = [row for row in records if len(row) > 1 and row[1] == "VALIDSIG"]
    if (any(len(row) > 1 and row[1] in denied for row in records) or len(valid) != 1
            or len(valid[0]) != 12 or valid[0][2] != fingerprint or valid[0][11] != fingerprint
            or valid[0][8] not in {"22", "27"} or valid[0][9] not in {"8", "9", "10"}
            or valid[0][10] != "00"):
        raise ValueError("consumer approval signature is not from the pinned release signer")
    return value
