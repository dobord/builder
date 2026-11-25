"""Trusted consumer-only publisher. Never execute consumer source or archives."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from . import consumer_ci as consumer, consumer_publication as approval
from . import consumer_upload, crypto, safeio, encrypted_logs
from .github import Client, NoRedirect

WORKFLOW = "publish-consumer-release.yml"
_POLICY = {"schema", "repository", "repository_id", "operator_id", "source_sha", "base_sha",
           "qualifier_sha", "run", "tag", "archive_name", "archive_sha256",
           "consumer_policy_sha256", "signer_fingerprint", "acceptance"}
_KINDS = {"dataplane", "client", "supplier"}
_SHA = re.compile(r"[0-9a-f]{40}")
_HASH = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")


def validate_policy(value):
    if (not isinstance(value, dict) or set(value) != _POLICY
            or type(value["schema"]) is not int or value["schema"] != 1
            or not consumer.repository(value["repository"])
            or not consumer.integer(value["repository_id"])
            or type(value["operator_id"]) is not int or value["operator_id"] != 5323024
            or not consumer.integer(value["run"])
            or any(not isinstance(value[k], str) or not _SHA.fullmatch(value[k])
                   for k in ("source_sha", "base_sha", "qualifier_sha"))
            or not isinstance(value["tag"], str) or not _TAG.fullmatch(value["tag"])
            or any(not isinstance(value[k], str) or not _HASH.fullmatch(value[k])
                   for k in ("archive_sha256", "consumer_policy_sha256"))
            or not isinstance(value["signer_fingerprint"], str)
            or not re.fullmatch(r"[0-9A-F]{40}", value["signer_fingerprint"])
            or not isinstance(value["archive_name"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}-" + re.escape(value["tag"])
                                + r"-linux-x86_64-static\.tar\.gz", value["archive_name"])
            or not isinstance(value["acceptance"], dict) or set(value["acceptance"]) != _KINDS):
        raise ValueError("invalid protected consumer publication policy")
    for checks in value["acceptance"].values():
        if (not isinstance(checks, list) or not 1 <= len(checks) <= 128
                or any(not isinstance(x, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", x)
                       for x in checks) or len(set(checks)) != len(checks)):
            raise ValueError("invalid protected consumer acceptance inventory")


def expected_approval(policy, qualified, digest, tag_object, receipts):
    validate_policy(policy)
    if (qualified.get("source") != policy["repository"]
            or qualified.get("source_id") != policy["repository_id"]
            or qualified.get("operator_id") != policy["operator_id"]
            or qualified.get("source_sha") != policy["source_sha"]
            or qualified.get("base_sha") != policy["base_sha"]
            or qualified.get("builder_sha") != policy["qualifier_sha"]):
        raise ValueError("qualified consumer does not match publication policy")
    result = {"schema": 1, "purpose": "consumer-release-publication",
              "repository_id": policy["repository_id"], "tag": policy["tag"],
              "tag_object": tag_object, "source_sha": qualified["source_sha"],
              "base_sha": qualified["base_sha"], "builder_sha": qualified["builder_sha"],
              "run": policy["run"], "attempt": 1, "request_digest": digest,
              "archive": {"name": policy["archive_name"], "sha256": policy["archive_sha256"]},
              "acceptance": receipts}
    approval.check_approval(crypto.canonical(result), result)
    return result


def raw_tag(value):
    record = value.get("verification", {}) if isinstance(value, dict) else {}
    parts = [record.get("payload"), record.get("signature")] if isinstance(record, dict) else []
    if parts and all(isinstance(item, str) and 0 < len(item.encode("utf-8")) <= 65536 for item in parts):
        result = "".join(parts).encode("utf-8")
    else:
        # An independently approved key need not be registered with GitHub.
        # Reconstruct only UTC metadata; every caller still requires the exact
        # Git object hash AND the pinned OpenPGP signature, never "verified".
        try:
            tagger, obj = value["tagger"], value["object"]
            stamp = int(datetime.strptime(tagger["date"], "%Y-%m-%dT%H:%M:%SZ")
                        .replace(tzinfo=timezone.utc).timestamp())
            result = (f"object {obj['sha']}\ntype {obj['type']}\ntag {value['tag']}\n"
                      f"tagger {tagger['name']} <{tagger['email']}> {stamp} +0000\n\n"
                      + value["message"]).encode("utf-8")
        except (KeyError, TypeError, ValueError, OverflowError):
            raise ValueError("raw signed Git tag unavailable") from None
    if len(result) > 65536:
        raise ValueError("raw signed Git tag exceeds bounds")
    return result


def tag_payload(raw, expected):
    """Convert an already verified exact tag into GitHub's creation fields.

    Only UTC taggers are accepted: API date normalization must never silently
    change the signed bytes. The created object's raw bytes and ID are checked
    before its ref is published. A serialization disagreement leaves no ref.
    """
    header, separator, message = raw.partition(b"\n\n")
    lines = header.split(b"\n")
    if not separator or len(lines) != 4:
        raise ValueError("invalid consumer tag structure")
    match = re.fullmatch(rb"tagger ([^\x00-\x1f<>]{1,512}) <([^\s<>]{1,254})> ([0-9]{1,12}) \+0000", lines[3])
    if not match:
        raise ValueError("consumer publication requires a UTC signed tag")
    try:
        date = datetime.fromtimestamp(int(match[3]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"tag": expected["tag"], "object": expected["source_sha"], "type": "commit",
                "message": message.decode("utf-8"),
                "tagger": {"name": match[1].decode("utf-8"), "email": match[2].decode("utf-8"), "date": date}}
    except (ValueError, OverflowError, UnicodeError):
        raise ValueError("invalid consumer tag creation fields") from None


def ensure_tag(api, repository, raw, expected, public_key, fingerprint):
    """Create only an approved pre-signed tag; never replace an existing ref."""
    approval.verify_source_tag(raw, expected["tag"], expected["source_sha"],
                               expected["tag_object"], public_key, fingerprint)
    base = "/repos/" + repository
    repo = api.get(base)
    if (repo.get("full_name") != repository or type(repo.get("id")) is not int
            or repo["id"] != expected["repository_id"] or repo.get("private") is not True):
        raise ValueError("consumer tag destination mismatch")
    refpath = base + "/git/ref/tags/" + expected["tag"]
    try:
        reference = api.get(refpath)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        created = api.json("POST", base + "/git/tags", tag_payload(raw, expected))
        if created.get("sha") != expected["tag_object"]:
            raise ValueError("GitHub changed the approved signed tag bytes")
        current = api.get(base + "/git/tags/" + expected["tag_object"])
        if raw_tag(current) != raw:
            raise ValueError("created consumer tag bytes differ")
        approval.verify_source_tag(raw_tag(current), expected["tag"], expected["source_sha"],
                                   expected["tag_object"], public_key, fingerprint)
        try:
            api.json("POST", base + "/git/refs",
                     {"ref": "refs/tags/" + expected["tag"], "sha": expected["tag_object"]})
        except urllib.error.HTTPError as conflict:
            if conflict.code not in (409, 422):
                raise
        reference = api.get(refpath)
    obj = reference.get("object", {})
    if obj.get("type") != "tag" or obj.get("sha") != expected["tag_object"]:
        raise ValueError("conflicting consumer signed tag; never replace")
    current = api.get(base + "/git/tags/" + expected["tag_object"])
    if raw_tag(current) != raw:
        raise ValueError("consumer remote signed tag bytes differ")
    approval.verify_source_tag(raw_tag(current), expected["tag"], expected["source_sha"],
                               expected["tag_object"], public_key, fingerprint)


def extract_original_result(source, target, policy):
    """Extract only the exact approved archive from bounded original CI results."""
    name = policy["archive_name"]
    names = {name, "result.json", "SHA256SUMS", "ctest.txt", "dataplane-limits.txt"}
    found = set()
    total = 0
    metadata = {}
    class BoundedHeaders(tarfile.TarInfo):
        def _metadata_bound(self, archive):
            # pack_tar emits small PAX mtime records. Bound internal metadata
            # before tarfile allocates their payload, not only yielded files.
            count = getattr(archive, "_consumer_metadata", 0) + self.size
            if not 0 <= self.size <= 16384 or count > 65536:
                raise ValueError("consumer tar metadata exceeds bounds")
            archive._consumer_metadata = count

        def _proc_pax(self, archive):
            self._metadata_bound(archive)
            return super()._proc_pax(archive)

        def _proc_gnulong(self, archive):
            self._metadata_bound(archive)
            return super()._proc_gnulong(archive)

    with tarfile.open(source, "r|gz", tarinfo=BoundedHeaders) as archive:
        for item in archive:
            if (item.name not in names or item.name in found
                    or item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or item.sparse is not None
                    or not 0 < item.size <= (consumer.MAX_PREPARED if item.name == name else 1024**2)):
                raise ValueError("unsafe original consumer result inventory")
            found.add(item.name)
            total += item.size
            if total > consumer.MAX_PREPARED:
                raise ValueError("consumer original result exceeds bounds")
            with archive.extractfile(item) as src:
                if item.name == name:
                    with (target / name).open("xb") as dst:
                        shutil.copyfileobj(src, dst, 1024**2)
                    (target / name).chmod(0o600)
                else:
                    metadata[item.name] = src.read(1024**2 + 1)
    if found != names:
        raise ValueError("incomplete original consumer results")
    result = {"schema": 1, "source_sha": policy["source_sha"], "builder_sha": policy["qualifier_sha"],
              "lane": "static", "status": "success"}
    if (metadata["result.json"] != crypto.canonical(result)
            or crypto.digest(target / name) != policy["archive_sha256"]
            or metadata["SHA256SUMS"] != (policy["archive_sha256"] + "  " + name + "\n").encode()):
        raise ValueError("original consumer archive identity mismatch")


def provenance(policy, qualified, artifact, receipt_digests, selected, request_digest, tag_object):
    expected = expected_approval(policy, qualified, request_digest, tag_object, receipt_digests)
    return crypto.canonical({
        "schema": 1, "purpose": "consumer-release-provenance",
        "approval": expected, "artifact": artifact, "inputs": selected["inputs"],
        "recipe_sha256": selected["recipe_sha256"], "signer": policy["signer_fingerprint"]})


def asset_names(expected):
    name = expected["archive"]["name"]
    return {name, name + ".asc", "provenance.json", "provenance.json.asc",
            "SHA256SUMS", "SHA256SUMS.asc", "release-approval.json", "release-approval.json.asc"}


def checksum_bytes(root, expected):
    names = sorted((expected["archive"]["name"], "provenance.json", "release-approval.json"))
    return "".join(crypto.digest(root / name) + "  " + name + "\n" for name in names).encode()


def verify_assets(root, expected, public_key, fingerprint, expected_provenance):
    """Authenticate every asset without loading or executing consumer code."""
    if root.is_symlink() or {p.name for p in root.iterdir()} != asset_names(expected):
        raise ValueError("incomplete consumer publication asset inventory")
    for path in root.iterdir():
        if (not safeio.regular(path) or not 0 < path.stat().st_size <=
                (consumer.MAX_PREPARED if path.name == expected["archive"]["name"] else 1024**2)):
            raise ValueError("unsafe consumer publication asset")
    raw = (root / "release-approval.json").read_bytes()
    approval.verify_signed_approval(raw, (root / "release-approval.json.asc").read_bytes(),
                                    public_key, fingerprint, expected)
    name = expected["archive"]["name"]
    if (crypto.digest(root / name) != expected["archive"]["sha256"]
            or (root / "provenance.json").read_bytes() != expected_provenance
            or (root / "SHA256SUMS").read_bytes() != checksum_bytes(root, expected)):
        raise ValueError("consumer asset bytes differ from independent evidence")
    for name in (name, "provenance.json", "SHA256SUMS"):
        approval.verify_release_file(root / name, (root / (name + ".asc")).read_bytes(),
                                     public_key, fingerprint)
    return {p.name: crypto.digest(p) for p in root.iterdir()}


def download_original(api, path, target, digest):
    """Stream one digest-pinned artifact; credentials never follow redirects."""
    try:
        response = api.request("GET", path)
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location", "")
        parsed = urllib.parse.urlparse(location)
        if (error.code not in (301, 302, 303, 307, 308) or parsed.scheme != "https"
                or parsed.hostname not in {"results-receiver.actions.githubusercontent.com",
                                           "productionresultssa0.blob.core.windows.net",
                                           "release-assets.githubusercontent.com",
                                           "objects.githubusercontent.com"}
                and not (parsed.hostname or "").endswith(".blob.core.windows.net")
                or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError("unsafe consumer original artifact redirect") from None
        response = urllib.request.build_opener(NoRedirect()).open(
            urllib.request.Request(location, headers={"User-Agent": "consumer-publisher-v1"}), timeout=90)
    count = 0
    observed = hashlib.sha256()
    deadline = time.monotonic() + 300
    with response, target.open("xb") as dst:
        while block := response.read(1024**2):
            count += len(block)
            if count > consumer.MAX_PREPARED or time.monotonic() > deadline:
                raise ValueError("consumer original artifact exceeds bounds")
            observed.update(block)
            dst.write(block)
    target.chmod(0o600)
    if not count or observed.hexdigest() != digest:
        raise ValueError("consumer original artifact digest mismatch")


def fetch_original(work, policy, qualified, request_digest, token, publisher_private):
    values = consumer.ci.pages(
        f"repos/{consumer.ci.BUILDER}/actions/runs/{policy['run']}/artifacts", token, "artifacts")
    matches = [item for item in values if item.get("name") == f"consumer-output-static-{policy['run']}-1"]
    if (len(matches) != 1 or matches[0].get("expired") is not False
            or not consumer.integer(matches[0].get("id"))
            or not consumer.integer(matches[0].get("size_in_bytes"), 1, consumer.MAX_PREPARED)
            or not isinstance(matches[0].get("digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]["digest"])):
        raise ValueError("original direct consumer artifact unavailable")
    selected = matches[0]
    receipt = {"id": selected["id"], "sha256": selected["digest"].removeprefix("sha256:")}
    path = f"/repos/{consumer.ci.BUILDER}/actions/artifacts/{selected['id']}/zip"
    original = work / "original.zip"
    download_original(Client(token), path, original, receipt["sha256"])
    cipher = work / "publisher-results.enc"
    with zipfile.ZipFile(original) as archive:
        entries = archive.infolist()
        if (len(entries) != 3 or {item.filename for item in entries} !=
                {"results.enc", "publisher-results.enc", "diagnostics.enc"}
                or any(item.flag_bits & 1 or item.is_dir()
                       or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                       or not 0 < item.file_size <= consumer.MAX_PREPARED for item in entries)
                or sum(item.file_size for item in entries) > consumer.MAX_PREPARED):
            raise ValueError("unsafe direct consumer artifact inventory")
        with archive.open("publisher-results.enc") as src, cipher.open("xb") as dst:
            shutil.copyfileobj(src, dst, 1024**2)
    cipher.chmod(0o600)
    context = consumer.context("publisher-results", qualified)
    context.update(run=policy["run"], attempt=1, request_digest=request_digest, lane="static")
    plain = work / "original-results.tar.gz"
    crypto.decrypt_file(cipher, plain, publisher_private, context)
    return plain, receipt


def work_root():
    return Path(consumer.ci.required("RUNNER_TEMP")) / "consumer-publication"


def protected_policy():
    raw = crypto.unb64(consumer.ci.required("CONSUMER_RELEASE_POLICY_B64"))
    if len(raw) > 32768:
        raise ValueError("consumer publication policy exceeds bounds")
    policy = crypto.parse(raw)
    validate_policy(policy)
    selected = consumer.policy()
    if (hashlib.sha256(crypto.canonical(selected)).hexdigest() != policy["consumer_policy_sha256"]
            or selected["repository"] != policy["repository"]
            or selected["repository_id"] != policy["repository_id"]
            or selected["operator_id"] != policy["operator_id"]):
        raise ValueError("consumer qualification policy changed")
    return policy, selected


def guard():
    sha = consumer.ci.required("CONSUMER_RELEASE_BUILDER_SHA")
    if (not _SHA.fullmatch(sha) or os.name != "posix"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != consumer.ci.BUILDER
            or os.environ.get("GITHUB_REPOSITORY_ID") != str(consumer.ci.BUILDER_ID)
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or os.environ.get("GITHUB_ACTOR_ID") != "5323024"
            or os.environ.get("GITHUB_SHA") != sha
            or os.environ.get("GITHUB_REF") != "refs/tags/consumer-publisher-" + sha
            or os.environ.get("GITHUB_WORKFLOW_REF") !=
                consumer.ci.BUILDER + "/.github/workflows/" + WORKFLOW + "@refs/tags/consumer-publisher-" + sha
            or os.environ.get("CONSUMER_RELEASE_ENABLED") != "true"):
        raise ValueError("consumer publisher execution denied")
    return sha


def bundle_context(request_id, sha):
    if (not isinstance(request_id, str) or str(uuid.UUID(request_id)) != request_id
            or not isinstance(sha, str) or not _SHA.fullmatch(sha)):
        raise ValueError("invalid consumer publication transport identity")
    return {"schema": 1, "purpose": "consumer-release-request",
            "request_id": request_id, "publisher_sha": sha}


def read_bundle(sha, input_private):
    sealed = consumer.ci.required("CONSUMER_RELEASE_REQUEST")
    digest = consumer.ci.required("CONSUMER_RELEASE_REQUEST_DIGEST")
    if (len(sealed) > 65536 or not _HASH.fullmatch(digest)
            or hashlib.sha256(sealed.encode("ascii")).hexdigest() != digest):
        raise ValueError("consumer publication ciphertext mismatch")
    reference = bundle_context(consumer.ci.required("CONSUMER_RELEASE_REQUEST_ID"), sha)
    try:
        raw = crypto.open_message(sealed, input_private, reference)
        value = crypto.parse(raw)
    except Exception:
        raise ValueError("consumer publication transport authentication failed") from None
    if (not isinstance(value, dict) or set(value) != {"created", "expires", "bundle"}
            or not consumer.integer(value["created"], 0) or not consumer.integer(value["expires"], 0)
            or value["created"] > int(time.time()) + 300 or value["expires"] < int(time.time())
            or not 0 < value["expires"] - value["created"] <= 21600):
        raise ValueError("expired consumer publication request")
    return value["bundle"]


def decode_bundle(value):
    names = {"qualification_request", "qualification_request_id", "approval", "approval_signature",
             "tag", "receipts", "signatures"}
    if (not isinstance(value, dict) or set(value) != names
            or not isinstance(value["receipts"], dict) or set(value["receipts"]) != _KINDS
            or not isinstance(value["signatures"], dict)
            or set(value["signatures"]) != {"archive", "provenance", "checksums"}):
        raise ValueError("invalid consumer publication bundle")
    decoded = {}
    for name in ("approval", "approval_signature", "tag"):
        decoded[name] = crypto.unb64(value[name])
        if not 0 < len(decoded[name]) <= (8192 if name == "approval" else 65536):
            raise ValueError("consumer publication bundle exceeds bounds")
    decoded["receipts"] = {kind: crypto.unb64(raw) for kind, raw in value["receipts"].items()}
    decoded["signatures"] = {kind: crypto.unb64(raw) for kind, raw in value["signatures"].items()}
    if (any(not 0 < len(raw) <= 32768 for raw in decoded["receipts"].values())
            or any(not 0 < len(raw) <= 65536 for raw in decoded["signatures"].values())):
        raise ValueError("consumer publication attachments exceed bounds")
    return decoded


def receipt_digests(policy, receipts):
    identity = {"source_sha": policy["source_sha"], "builder_sha": policy["qualifier_sha"],
                "run": policy["run"], "attempt": 1, "archive_sha256": policy["archive_sha256"]}
    return {kind: approval.check_acceptance_receipt(raw, kind, identity,
                                                   tuple(policy["acceptance"][kind]))
            for kind, raw in receipts.items()}


def tag_object(raw):
    return hashlib.sha1(b"tag " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def verify():
    sha = guard()
    policy, selected = protected_policy()
    work = work_root()
    work.mkdir(mode=0o700)
    assets = work / "assets"
    assets.mkdir(mode=0o700)
    input_private = consumer.key("INPUT_PRIVATE_KEY_B64")
    bundle = read_bundle(sha, input_private)
    data = decode_bundle(bundle)
    token = consumer.ci.required("BUILDER_READ_TOKEN")
    qualified = approval.resolve_qualification(
        bundle["qualification_request"], bundle["qualification_request_id"], policy["qualifier_sha"],
        policy["run"], selected, input_private, consumer.key("VERIFY_PUBLIC_KEY_B64"), token)
    request_digest = hashlib.sha256(bundle["qualification_request"].encode("ascii")).hexdigest()
    receipts = receipt_digests(policy, data["receipts"])
    expected = expected_approval(policy, qualified, request_digest, tag_object(data["tag"]), receipts)
    public = crypto.unb64(consumer.ci.required("CONSUMER_RELEASE_VERIFY_PUBLIC_KEY_B64"))
    approval.verify_signed_approval(data["approval"], data["approval_signature"], public,
                                    policy["signer_fingerprint"], expected)
    approval.verify_source_tag(data["tag"], policy["tag"], qualified["source_sha"],
                               expected["tag_object"], public, policy["signer_fingerprint"])
    tag_payload(data["tag"], expected)
    original, artifact = fetch_original(work, policy, qualified, request_digest, token,
                                         consumer.key("PUBLISH_PRIVATE_KEY_B64"))
    extract_original_result(original, assets, policy)
    prov = provenance(policy, qualified, artifact, receipts, selected, request_digest, expected["tag_object"])
    for name, raw in (("release-approval.json", data["approval"]),
                      ("release-approval.json.asc", data["approval_signature"]), ("provenance.json", prov),
                      ("provenance.json.asc", data["signatures"]["provenance"]),
                      (policy["archive_name"] + ".asc", data["signatures"]["archive"])):
        (assets / name).write_bytes(raw)
        (assets / name).chmod(0o600)
    (assets / "SHA256SUMS").write_bytes(checksum_bytes(assets, expected))
    (assets / "SHA256SUMS.asc").write_bytes(data["signatures"]["checksums"])
    manifest = verify_assets(assets, expected, public, policy["signer_fingerprint"], prov)
    record = {"qualified": qualified, "request_digest": request_digest, "artifact": artifact,
              "receipts": {kind: crypto.b64(raw) for kind, raw in data["receipts"].items()},
              "tag": crypto.b64(data["tag"]), "manifest": manifest}
    raw = crypto.canonical(record)
    (work / "verified.json").write_bytes(raw)
    (work / "verified.json").chmod(0o600)
    with open(consumer.ci.required("GITHUB_OUTPUT"), "a", encoding="utf-8") as output:
        output.write("staging_digest=" + hashlib.sha256(raw).hexdigest() + "\n")


def recheck_qualification(policy, qualified, digest, token):
    prefix = f"repos/{consumer.ci.BUILDER}/actions/runs/{policy['run']}"
    run = consumer.ci.api_json(prefix, token)
    jobs = consumer.ci.pages(prefix + "/attempts/1/jobs", token, "jobs")
    consumer.validate_result(qualified, digest, run, jobs)
    current = consumer.ci.api_json(prefix, token)
    consumer.validate_result(qualified, digest, current, jobs)


def publish():
    guard()
    policy, selected = protected_policy()
    work = work_root()
    path = work / "verified.json"
    if not safeio.regular(path) or not 0 < path.stat().st_size <= 512 * 1024:
        raise ValueError("verified publication staging unavailable")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != consumer.ci.required("CONSUMER_RELEASE_STAGING_DIGEST"):
        raise ValueError("consumer verification receipt changed")
    record = crypto.parse(raw)
    if not isinstance(record, dict) or set(record) != {
            "qualified", "request_digest", "artifact", "receipts", "tag", "manifest"}:
        raise ValueError("invalid verified consumer publication receipt")
    receipts = receipt_digests(policy, {kind: crypto.unb64(value)
                                       for kind, value in record["receipts"].items()})
    tag = crypto.unb64(record["tag"])
    expected = expected_approval(policy, record["qualified"], record["request_digest"], tag_object(tag), receipts)
    prov = provenance(policy, record["qualified"], record["artifact"], receipts, selected,
                      record["request_digest"], expected["tag_object"])
    public = crypto.unb64(consumer.ci.required("CONSUMER_RELEASE_VERIFY_PUBLIC_KEY_B64"))
    assets = work / "assets"
    if verify_assets(assets, expected, public, policy["signer_fingerprint"], prov) != record["manifest"]:
        raise ValueError("consumer publication assets changed after verification")
    reader = consumer.ci.required("BUILDER_READ_TOKEN")
    recheck_qualification(policy, record["qualified"], record["request_digest"], reader)
    # The only destination write-credential lookup is after all independent
    # checks in this separate trusted process/step. No consumer executable runs.
    api = Client(consumer.ci.required("CONSUMER_RELEASE_PUBLISH_TOKEN"))
    ensure_tag(api, policy["repository"], tag, expected, public, policy["signer_fingerprint"])
    consumer_upload.publish_release(api, policy["repository"], assets, expected, record["manifest"])
    recheck_qualification(policy, record["qualified"], record["request_digest"], reader)


def diagnostics():
    work = work_root()
    source = work / "diagnostics"
    source.mkdir(mode=0o700, parents=True, exist_ok=True)
    public = crypto.unb64((Path(__file__).resolve().parents[1] / "ci/builder-logs-public-key.b64").read_text().strip()).decode()
    target = Path(consumer.ci.required("RUNNER_TEMP")) / "consumer-publication-diagnostics.enc"
    encrypted_logs.collect([source], target, public, encrypted_logs.github_context())


def package(args):
    if args.bundle.stat().st_size > 45000:
        raise ValueError("consumer publication bundle exceeds dispatch bounds")
    bundle = crypto.parse(args.bundle.read_bytes())
    decode_bundle(bundle)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("consumer publication dispatch output must be new")
    request_id = str(uuid.uuid4())
    now = int(time.time())
    public = args.input_public.read_text().strip()
    if not public.startswith("{"):
        public = crypto.unb64(public).decode()
    crypto.fingerprint(public)
    sealed = crypto.seal_message(crypto.canonical(
        {"created": now, "expires": now + 21600, "bundle": bundle}), public,
        bundle_context(request_id, args.publisher_sha))
    if len(sealed) > 60000:
        raise ValueError("consumer publication request exceeds dispatch bounds")
    payload = {"ref": "consumer-publisher-" + args.publisher_sha,
               "inputs": {"request_id": request_id, "request_digest": hashlib.sha256(sealed.encode("ascii")).hexdigest(),
                          "request": sealed}}
    with args.output.open("xb") as stream:
        stream.write(crypto.canonical(payload))
    args.output.chmod(0o600)


def record_failure(stage, error):
    """Best-effort private diagnostics must never replace the fixed failure marker."""
    import traceback
    try:
        work = work_root()
        if work.is_symlink():
            return
        logs = work / "diagnostics"
        logs.mkdir(mode=0o700, parents=True, exist_ok=True)
        record = {"stage": stage, "type": type(error).__name__,
                  "frames": [{"function": f.name, "line": f.lineno}
                             for f in traceback.extract_tb(error.__traceback__)[-8:]]}
        cause = error
        for _ in range(5):
            if isinstance(cause, urllib.error.HTTPError) and 400 <= cause.code <= 599:
                record["http_status"] = cause.code
                break
            cause = cause.__context__ if cause is not None else None
        (logs / ("failure-" + stage + ".json")).write_bytes(crypto.canonical(record))
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("package", "verify", "publish", "diagnostics", "cleanup"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--input-public", type=Path)
    parser.add_argument("--publisher-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.stage == "package":
            if not all((args.bundle, args.input_public, args.publisher_sha, args.output)):
                raise ValueError("publication packaging inputs missing")
            package(args)
        elif args.stage == "cleanup":
            if work_root().exists():
                consumer.ci.remove_staging(work_root())
        else:
            globals()[args.stage]()
        print("CONSUMER_PUBLISHER_SUCCESS " + args.stage)
    except Exception as error:
        if args.stage != "package":
            record_failure(args.stage, error)
        raise SystemExit("CONSUMER_PUBLISHER_FAILED " + args.stage) from None


if __name__ == "__main__":
    main()
