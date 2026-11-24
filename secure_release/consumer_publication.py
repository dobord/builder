"""Validate the signed approval payload for an independent consumer publisher.

Validate exact approval identity and its detached release signature. This
module does not claim that acceptance reports passed, grant credentials,
or publish assets.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from . import consumer_ci as consumer, crypto

_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
_FIELDS = frozenset({
    "schema", "purpose", "repository_id", "tag", "tag_object", "source_sha",
    "base_sha", "builder_sha", "run", "attempt", "request_digest", "archive", "acceptance",
})
_REPORTS = frozenset({"dataplane", "client", "supplier"})
_CHECK = re.compile(r"[a-z][a-z0-9_-]{0,63}")


def _tool_home(path, env, *, windows=None):
    """Use the path namespace of the installed GnuPG, not the Python host."""
    if windows is None:
        windows = os.name == "nt"
    if windows:
        executable = shutil.which("gpg", path=env.get("PATH"))
        if not executable:
            raise OSError("GnuPG unavailable")
        translator = Path(executable).with_name("cygpath.exe")
        if translator.is_file():
            result = subprocess.run([str(translator), "-u", path.as_posix()], env=env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=10, check=True)
            home = result.stdout.decode("utf-8").strip()
            if (not home.startswith("/") or len(home) > 4096
                    or any(char in home for char in "\r\n\0")):
                raise ValueError("invalid GnuPG tool home")
            return home
    return path.as_posix()


def _matches(value, expression):
    return isinstance(value, str) and expression.fullmatch(value) is not None


def _positive_id(value):
    return type(value) is int and 0 < value <= 2**63 - 1


def resolve_qualification(sealed: str, request_id: str, builder_sha: str, run_id: int,
                          selected: dict, input_private: str, verify_public: str,
                          token: str) -> dict:
    """Resolve one complete historical qualification without executing its code.

    The builder SHA and source policy are independent protected configuration.
    The old request is decrypted and authenticated, not trusted from approval
    fields. Expiry is checked at API-resolved admission time, not waived for old
    builds. Fresh dispatches still use current-clock validation.
    """
    if (not isinstance(sealed, str) or not 0 < len(sealed) <= 65536
            or not _matches(request_id, re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"))
            or not _matches(builder_sha, _SHA) or not _positive_id(run_id)):
        raise ValueError("invalid consumer qualification reference")
    consumer.validate_policy(selected)
    digest = hashlib.sha256(sealed.encode("ascii")).hexdigest()
    reference = {"request_id": request_id, "builder_sha": builder_sha}
    try:
        document = crypto.parse(crypto.open_message(
            sealed, input_private, consumer.context("request", reference)))
        value = crypto.verify(document, verify_public)
    except Exception:
        # Backend exceptions must not disclose ciphertext, request data or keys.
        raise ValueError("consumer qualification request authentication failed") from None
    prefix = f"repos/{consumer.ci.BUILDER}/actions"
    run = consumer.ci.api_json(f"{prefix}/runs/{run_id}", token)
    stamp = run.get("created_at")
    if (not isinstance(stamp, str)
            or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", stamp) is None):
        raise ValueError("invalid consumer run admission timestamp")
    admitted = int(datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    consumer.validate_request(value, admitted_at=admitted)
    if (value["request_id"] != request_id or value["builder_sha"] != builder_sha
            or value["source"] != selected["repository"] or value["source_id"] != selected["repository_id"]
            or value["operator_id"] != selected["operator_id"] or run.get("id") != run_id):
        raise ValueError("consumer qualification policy mismatch")
    consumer.validate_execution(value, digest, run)
    runs = consumer.ci.pages(
        f"{prefix}/workflows/{consumer.WORKFLOW}/runs?head_sha={builder_sha}", token, "workflow_runs")
    matches = [item for item in runs if item.get("display_title") == "Encrypted consumer " + digest]
    if len(matches) != 1 or matches[0].get("id") != run_id:
        raise ValueError("consumer qualification request replay")
    jobs = consumer.ci.pages(f"{prefix}/runs/{run_id}/attempts/1/jobs", token, "jobs")
    consumer.validate_result(value, digest, run, jobs)
    current = consumer.ci.api_json(f"{prefix}/runs/{run_id}", token)
    consumer.validate_result(value, digest, current, jobs)
    if current.get("id") != run_id or current.get("created_at") != stamp:
        raise ValueError("consumer qualification changed during verification")
    return value


def check_acceptance_receipt(raw: bytes, kind: str, identity: dict,
                             required_checks: tuple) -> str:
    """Digest a complete receipt bound to independently qualified artifact data.

    The required check inventory is protected publisher policy, never selected by
    a receipt. This validates assertions, not packet paths: the operator must
    independently review their evidence before signing the publication approval
    that binds these receipt digests. Raw operational evidence stays private.
    """
    fields = {"source_sha", "builder_sha", "run", "attempt", "archive_sha256"}
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 32768
            or not isinstance(kind, str) or kind not in _REPORTS or not isinstance(identity, dict)
            or set(identity) != fields
            or not all(_matches(identity[key], _SHA) for key in ("source_sha", "builder_sha"))
            or not _matches(identity["archive_sha256"], _DIGEST)
            or not _positive_id(identity["run"])
            or type(identity["attempt"]) is not int or identity["attempt"] != 1
            or not isinstance(required_checks, tuple) or not 1 <= len(required_checks) <= 128
            or any(not _matches(name, _CHECK) for name in required_checks)
            or len(set(required_checks)) != len(required_checks)):
        raise ValueError("invalid consumer acceptance requirements")
    value = crypto.parse(raw)
    if (not isinstance(value, dict)
            or set(value) != fields | {"schema", "purpose", "kind", "checks"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["purpose"] != "consumer-release-acceptance" or value["kind"] != kind
            or any(type(value[key]) is not type(identity[key]) or value[key] != identity[key]
                   for key in fields)
            or not isinstance(value["checks"], dict) or set(value["checks"]) != set(required_checks)
            or any(result != "pass" for result in value["checks"].values())
            or crypto.canonical(value) != raw):
        raise ValueError("consumer acceptance incomplete or mismatched")
    return hashlib.sha256(raw).hexdigest()


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
    _verify_release_signature(raw, signature, public_key, fingerprint)
    return value


def verify_source_tag(raw: bytes, tag: str, source_sha: str, object_sha: str,
                      public_key: bytes, fingerprint: str) -> str:
    """Authenticate an annotated Git tag, not GitHub's generic verified flag.

    The caller resolves the tag ref and supplies its raw Git object bytes without
    checking out or executing consumer code. Expected version/source and signer
    come from independent publication policy and authenticated qualification.
    """
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 65536
            or not _matches(tag, _TAG) or not _matches(source_sha, _SHA)
            or not _matches(object_sha, _SHA)):
        raise ValueError("invalid consumer release tag inputs")
    actual = hashlib.sha1(b"tag " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if actual != object_sha:
        raise ValueError("consumer release tag object mismatch")
    marker = b"-----BEGIN PGP SIGNATURE-----"
    payload, found, armor = raw.partition(marker)
    header, separator, message = payload.partition(b"\n\n")
    lines = header.split(b"\n")
    if (not found or not separator or len(lines) != 4
            or lines[:3] != [b"object " + source_sha.encode("ascii"), b"type commit",
                             b"tag " + tag.encode("ascii")]
            or re.fullmatch(rb"tagger [^\x00-\x1f\x7f]{1,512} <[^\s<>]{1,254}> [0-9]{1,12} [+-][0-9]{4}",
                            lines[3]) is None
            or not message or not payload.endswith(b"\n")
            or marker in armor or armor.count(b"-----END PGP SIGNATURE-----") != 1
            or not armor.endswith((b"-----END PGP SIGNATURE-----\n",
                                    b"-----END PGP SIGNATURE-----\r\n"))):
        raise ValueError("invalid annotated consumer release tag")
    _verify_release_signature(payload, found + armor, public_key, fingerprint)
    return actual


def _verify_release_signature(raw, signature, public_key, fingerprint):
    """Share the isolated pinned-primary-key verifier for approvals and tags."""
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
            tool_home = _tool_home(root, env)
            for name, content in (("approval.json", raw), ("signature.asc", signature)):
                path = root / name
                path.write_bytes(content)
                path.chmod(0o600)
            keyring = root / "trusted.gpg"
            subprocess.run(["gpg", "--no-options", "--batch", "--homedir", tool_home,
                            "--dearmor", "--output", tool_home + "/trusted.gpg"], input=public_key, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
            keyring.chmod(0o600)
            result = subprocess.run(["gpgv", "--homedir", tool_home, "--keyring", tool_home + "/trusted.gpg",
                                     "--status-fd", "1", tool_home + "/signature.asc",
                                     tool_home + "/approval.json"], env=env, stdin=subprocess.DEVNULL,
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
