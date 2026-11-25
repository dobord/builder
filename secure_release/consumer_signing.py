"""Isolated release-signing core. Never execute a consumer executable or source."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from . import consumer_ci as consumer, consumer_publisher as publisher
from . import consumer_publication as approval, consumer_presentation as presentation
from . import crypto, safeio


def protocol_context(kind, producer_run, builder_sha, signer_sha, policy):
    if (kind not in {"input", "request", "result"} or not consumer.integer(producer_run)
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
                   for value in (builder_sha, signer_sha))):
        raise ValueError("invalid isolated signing context")
    publisher.validate_policy(policy)
    return {"schema": 1, "purpose": "consumer-isolated-signing-" + kind,
            "producer_run": producer_run, "producer_attempt": 1,
            "builder_sha": builder_sha, "signer_sha": signer_sha,
            "repository_id": policy["repository_id"], "source_sha": policy["source_sha"],
            "archive_sha256": policy["archive_sha256"],
            "policy_sha256": hashlib.sha256(crypto.canonical(policy)).hexdigest()}


def validate_plan(plan, policy, selected, archive):
    """Validate non-secret signing inputs before a caller reads a signing key.

    Hosted callers must additionally authenticate the producer, original signed
    request and live qualification. This pure contract cannot establish API
    authority from a self-reported plan.
    """
    publisher.validate_policy(policy)
    consumer.validate_policy(selected)
    fields = {"schema", "qualified", "qualification_request", "qualification_request_id",
              "artifact", "receipts", "notes", "existing", "tag_time"}
    if (not isinstance(plan, dict) or set(plan) != fields or type(plan["schema"]) is not int
            or plan["schema"] != 1 or not isinstance(plan["qualified"], dict)
            or not isinstance(plan["receipts"], dict)
            or set(plan["receipts"]) != set(policy["acceptance"])
            or not isinstance(plan["qualification_request"], str)
            or not 0 < len(plan["qualification_request"]) <= 65536
            or not consumer.integer(plan["tag_time"], 0)
            or not isinstance(plan["artifact"], dict) or set(plan["artifact"]) != {"id", "sha256"}
            or not consumer.integer(plan["artifact"]["id"])
            or not isinstance(plan["artifact"]["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", plan["artifact"]["sha256"])):
        raise ValueError("invalid isolated signing plan")
    qualified = plan["qualified"]
    if (qualified.get("source") != policy["repository"] or qualified.get("source_id") != policy["repository_id"]
            or qualified.get("operator_id") != policy["operator_id"]
            or qualified.get("source_sha") != policy["source_sha"]
            or qualified.get("base_sha") != policy["base_sha"]
            or qualified.get("builder_sha") != policy["qualifier_sha"]
            or qualified.get("request_id") != plan["qualification_request_id"]
            or hashlib.sha256(crypto.canonical(selected)).hexdigest() != policy["consumer_policy_sha256"]
            or not safeio.regular(archive) or not 0 < archive.stat().st_size <= consumer.MAX_PREPARED
            or crypto.digest(archive) != policy["archive_sha256"]):
        raise ValueError("isolated signing identity or archive mismatch")
    receipts = {kind: crypto.unb64(value) for kind, value in plan["receipts"].items()}
    receipt_hashes = publisher.receipt_digests(policy, receipts)
    if "automation" in policy and receipt_hashes != policy["automation"]["receipt_sha256"]:
        raise ValueError("isolated signing acceptance is not independently approved")
    if "presentation" in policy:
        presentation.validate_notes(plan["notes"])
        if hashlib.sha256(plan["notes"].encode("utf-8")).hexdigest() != policy["presentation"]["notes_sha256"]:
            raise ValueError("isolated signing notes policy mismatch")
    elif plan["notes"] is not None:
        raise ValueError("unapproved isolated signing notes")
    if plan["existing"] is not None:
        if (not isinstance(plan["existing"], dict)
                or set(plan["existing"]) != {"approval", "approval_signature", "tag", "signatures"}):
            raise ValueError("invalid existing signed release selection")
    return receipts


def sign_bundle(plan, policy, selected, archive, output, signer, public, *, sign_presentation=True):
    """Build the exact publisher bundle; preserve existing signature bytes.

    `signer` accepts bounded bytes or a Path and is supplied only after hosted
    producer/qualification authority is verified. It never receives source code.
    """
    receipts = validate_plan(plan, policy, selected, archive)
    output.mkdir(mode=0o700)
    target = output / policy["archive_name"]
    shutil.copyfile(archive, target)
    target.chmod(0o600)
    digest = hashlib.sha256(plan["qualification_request"].encode("ascii")).hexdigest()
    existing = plan["existing"]
    if existing is None:
        payload = (f"object {policy['source_sha']}\ntype commit\ntag {policy['tag']}\n"
                   f"tagger Consumer Release Signer <releases@users.noreply.github.com> {plan['tag_time']} +0000\n\n"
                   f"Native consumer {policy['tag']}\n").encode("utf-8")
        tag = payload + signer(payload)
    else:
        tag = crypto.unb64(existing["tag"])
    receipt_hashes = publisher.receipt_digests(policy, receipts)
    expected = publisher.expected_approval(policy, plan["qualified"], digest,
                                          publisher.tag_object(tag), receipt_hashes)
    approval.verify_source_tag(tag, policy["tag"], policy["source_sha"],
                               expected["tag_object"], public, policy["signer_fingerprint"])
    publisher.tag_payload(tag, expected)
    provenance = publisher.provenance(policy, plan["qualified"], plan["artifact"], receipt_hashes,
                                     selected, digest, expected["tag_object"])
    raw_approval = crypto.canonical(expected)
    for name, data in (("release-approval.json", raw_approval), ("provenance.json", provenance)):
        (output / name).write_bytes(data)
    (output / "SHA256SUMS").write_bytes(publisher.checksum_bytes(output, expected))
    if existing is None:
        signatures = {kind: signer(output / name) for kind, name in
                      (("archive", policy["archive_name"]), ("provenance", "provenance.json"),
                       ("checksums", "SHA256SUMS"))}
        approval_signature = signer(raw_approval)
    else:
        approval.verify_signed_approval(crypto.unb64(existing["approval"]),
                                        crypto.unb64(existing["approval_signature"]), public,
                                        policy["signer_fingerprint"], expected)
        signatures = {kind: crypto.unb64(raw) for kind, raw in existing["signatures"].items()}
        if set(signatures) != {"archive", "provenance", "checksums"}:
            raise ValueError("existing release signature inventory mismatch")
        approval_signature = crypto.unb64(existing["approval_signature"])
    for name, data in (("release-approval.json.asc", approval_signature),
                       (policy["archive_name"] + ".asc", signatures["archive"]),
                       ("provenance.json.asc", signatures["provenance"]),
                       ("SHA256SUMS.asc", signatures["checksums"])):
        (output / name).write_bytes(data)
    for path in output.iterdir():
        path.chmod(0o600)
    manifest = publisher.verify_assets(output, expected, public, policy["signer_fingerprint"], provenance)
    result = {"qualification_request": plan["qualification_request"],
              "qualification_request_id": plan["qualification_request_id"],
              "approval": crypto.b64(raw_approval), "approval_signature": crypto.b64(approval_signature),
              "tag": crypto.b64(tag), "receipts": plan["receipts"],
              "signatures": {kind: crypto.b64(value) for kind, value in signatures.items()}}
    if "presentation" in policy and sign_presentation:
        raw = presentation.intent(policy["presentation"], expected, manifest, plan["notes"])
        signature = signer(raw)
        presentation.verify(policy["presentation"], expected, manifest, plan["notes"], signature,
                            public, policy["signer_fingerprint"])
        result["presentation"] = {"notes": plan["notes"], "signature": crypto.b64(signature)}
    publisher.decode_bundle(result)
    return result


def verify_existing_bundle(plan, policy, selected, archive, output, public):
    """Authenticate existing tag/assets before opening any private signing key.

    Preverification omits only creation of a new presentation signature. All
    original signatures, receipt pins and notes policy still must validate.
    The incomplete presentation result cannot pass the publisher policy gate.
    """
    if plan.get("existing") is None:
        raise ValueError("existing release preverification requires an original bundle")
    def forbid_signing(value):
        raise ValueError("private signing is forbidden during existing release preverification")
    return sign_bundle(plan, policy, selected, archive, output, forbid_signing, public,
                       sign_presentation=False)


@contextmanager
def isolated_signer(private, passphrase, fingerprint):
    """Import one approved key into an ephemeral owner-only GnuPG home.

    No ambient keyring, credential environment, passphrase argv or tool output
    is forwarded. Key files and agent state are retired on every exit path.
    """
    if (not isinstance(private, bytes) or not 0 < len(private) <= 65536
            or not private.startswith(b"-----BEGIN PGP PRIVATE KEY BLOCK-----")
            or not isinstance(passphrase, bytes) or not 0 < len(passphrase) <= 1024
            or any(c in passphrase.rstrip(b"\n") for c in b"\r\n\0")
            or not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9A-F]{40}", fingerprint)):
        raise ValueError("invalid isolated signer inputs")
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"}}
    env.update(LC_ALL="C", LANG="C")
    with tempfile.TemporaryDirectory(prefix="consumer-isolated-signer-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        home = approval._tool_home(root, env)
        phrase = root / "passphrase"
        phrase.write_bytes(passphrase)
        phrase.chmod(0o600)
        base = ["gpg", "--no-options", "--batch", "--homedir", home]
        def command(args, *, data=None):
            result = subprocess.run([*base, *args], input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=env, timeout=120, check=True)
            return result.stdout
        try:
            command(["--import-options", "import-minimal", "--import"], data=private)
            listing = command(["--with-colons", "--list-secret-keys"]).decode("ascii")
            primary = [line for line in listing.splitlines() if line.startswith("sec:")]
            fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
            if len(primary) != 1 or not fingerprints or fingerprints[0] != fingerprint:
                raise ValueError("isolated private signer identity mismatch")
            def sign(value):
                args = ["--pinentry-mode", "loopback", "--passphrase-file", home + "/passphrase",
                        "--local-user", fingerprint + "!", "--digest-algo", "SHA256",
                        "--armor", "--detach-sign", "--output", "-"]
                if isinstance(value, Path):
                    if not safeio.regular(value) or not 0 < value.stat().st_size <= consumer.MAX_PREPARED:
                        raise ValueError("unsafe isolated signing file")
                    return command([*args, value.as_posix()])
                if not isinstance(value, bytes) or not 0 < len(value) <= 65536:
                    raise ValueError("isolated signing message exceeds bounds")
                return command(args, data=value)
            yield sign
        finally:
            failed = sys.exc_info()[0] is not None
            try:
                subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10, check=True)
            except (OSError, subprocess.SubprocessError):
                if not failed:
                    raise
