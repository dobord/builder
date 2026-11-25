"""Immutable builder -> isolated consumer signer -> verified builder publication."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from . import consumer_ci as consumer, consumer_publisher as publisher
from . import consumer_publication as approval, consumer_signing as signing, crypto
from .github import Client, NoRedirect

WORKFLOW = "automate-consumer-release.yml"
SIGNER_WORKFLOW = "sign-consumer-release.yml"
PREPARE_STEP = "Verify qualification and prepare encrypted signing input"
SIGN_STEP = "Authenticate and sign exact consumer release bytes"


def validate_run(value, *, repository_id, sha, ref, workflow, title, completed):
    if (not isinstance(value, dict) or not consumer.integer(value.get("id"))
            or value.get("repository", {}).get("id") != repository_id
            or value.get("head_repository", {}).get("id") != repository_id
            or value.get("head_sha") != sha or value.get("head_branch") != ref
            or value.get("path") != ".github/workflows/" + workflow
            or value.get("event") != "workflow_dispatch" or type(value.get("run_attempt")) is not int
            or value["run_attempt"] != 1 or value.get("display_title") != title
            or any(value.get(k, {}).get("id") != 5323024 for k in ("actor", "triggering_actor"))
            or value.get("status") not in ({"completed"} if completed else {"in_progress", "waiting", "completed"})
            or completed and value.get("conclusion") != "success"
            or value.get("status") == "completed" and value.get("conclusion") != "success"):
        raise ValueError("untrusted isolated signing run")


def validate_job(jobs, run, name, step):
    selected = [job for job in jobs if job.get("name") == name]
    if (len(selected) != 1 or selected[0].get("run_id") != run["id"]
            or selected[0].get("head_sha") != run["head_sha"]
            or selected[0].get("status") != "completed" or selected[0].get("conclusion") != "success"
            or len([s for s in selected[0].get("steps", []) if s.get("name") == step
                    and s.get("status") == "completed" and s.get("conclusion") == "success"]) != 1):
        raise ValueError("isolated signing stage was not executed successfully")


def storage_url(value):
    if not isinstance(value, str) or len(value) > 16384:
        raise ValueError("invalid isolated signing storage URL")
    parsed = urllib.parse.urlparse(value)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment
            or parsed.port not in (None, 443)
            or parsed.hostname not in {"objects.githubusercontent.com", "release-assets.githubusercontent.com",
                                       "results-receiver.actions.githubusercontent.com"}
            and not (parsed.hostname or "").endswith(".blob.core.windows.net")):
        raise ValueError("isolated signing storage URL rejected")
    return value


def extract_cipher(source, target, name, maximum):
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        if (len(entries) != 1 or entries[0].filename != name or entries[0].is_dir()
                or entries[0].flag_bits & 1 or not 0 < entries[0].file_size <= maximum
                or stat.S_IFMT(entries[0].external_attr >> 16) not in (0, stat.S_IFREG)):
            raise ValueError("invalid isolated signing cipher inventory")
        with archive.open(entries[0]) as src, target.open("xb") as dst:
            shutil.copyfileobj(src, dst, 1024**2)
    target.chmod(0o600)


def download_response(response, target, expected, maximum):
    count, digest, deadline = 0, hashlib.sha256(), time.monotonic() + 300
    with response, target.open("xb") as stream:
        while block := response.read(1024**2):
            count += len(block)
            if count > maximum or time.monotonic() > deadline:
                raise ValueError("isolated signing download exceeds bounds")
            digest.update(block)
            stream.write(block)
    target.chmod(0o600)
    if not count or digest.hexdigest() != expected:
        raise ValueError("isolated signing download digest mismatch")


def download_artifact(api, path, target, digest, maximum):
    try:
        response = api.request("GET", path)
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise
        location = storage_url(error.headers.get("Location", ""))
        response = urllib.request.build_opener(NoRedirect()).open(
            urllib.request.Request(location, headers={"User-Agent": "consumer-isolated-signing"}),
            timeout=90)
    download_response(response, target, digest, maximum)


def artifact(api, repository, run, name, maximum):
    values = api.get(f"/repos/{repository}/actions/runs/{run}/artifacts?per_page=100")
    if not isinstance(values, dict) or values.get("total_count", 101) > 100:
        raise ValueError("isolated signing artifact inventory exceeds bounds")
    selected = [a for a in values.get("artifacts", []) if a.get("name") == name]
    if (len(selected) != 1 or selected[0].get("expired") is not False
            or not consumer.integer(selected[0].get("id"))
            or not consumer.integer(selected[0].get("size_in_bytes"), 1, maximum)
            or not isinstance(selected[0].get("digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", selected[0]["digest"])):
        raise ValueError("isolated signing artifact unavailable")
    return selected[0]


def policy():
    value, selected = publisher.protected_policy()
    if "automation" not in value:
        raise ValueError("consumer automatic release not independently enabled")
    return value, selected


def guard(role, value):
    auto = value["automation"]
    source = role == "signer"
    repository = value["repository"] if source else consumer.ci.BUILDER
    repository_id = value["repository_id"] if source else consumer.ci.BUILDER_ID
    sha = auto["signer_sha"] if source else auto["builder_sha"]
    prefix = "consumer-signer-" if source else "consumer-automation-"
    workflow = SIGNER_WORKFLOW if source else WORKFLOW
    enabled = "CONSUMER_SIGNER_ENABLED" if source else "CONSUMER_AUTOMATION_ENABLED"
    if (os.name != "posix" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != repository
            or os.environ.get("GITHUB_REPOSITORY_ID") != str(repository_id)
            or os.environ.get("GITHUB_SHA") != sha or os.environ.get("GITHUB_REF") != "refs/tags/" + prefix + sha
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or os.environ.get("GITHUB_RUN_ATTEMPT") != "1" or os.environ.get("GITHUB_ACTOR_ID") != "5323024"
            or os.environ.get("GITHUB_WORKFLOW_REF") != repository + "/.github/workflows/" + workflow
                + "@refs/tags/" + prefix + sha or os.environ.get(enabled) != "true"):
        raise ValueError("isolated signing execution denied")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=Path(__file__).resolve().parents[1],
                                     stderr=subprocess.DEVNULL, timeout=10).decode().strip()
    if actual != auto["builder_sha"]:
        raise ValueError("isolated signing implementation pin mismatch")


def root():
    return Path(consumer.ci.required("RUNNER_TEMP")) / "consumer-automation"


def uuid_value(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid isolated signing request ID")
    return value


def request_context(request_id, sha):
    return {"schema": 1, "purpose": "consumer-automation-request",
            "request_id": uuid_value(request_id), "builder_sha": sha}


def signer_public(value):
    public = consumer.key("SIGNER_INPUT_PUBLIC_KEY_B64")
    if crypto.fingerprint(public) != value["automation"]["signer_recipient"]:
        raise ValueError("isolated signer recipient differs from protected policy")
    return public


def operator_public(value):
    public = consumer.key("VERIFY_PUBLIC_KEY_B64")
    if hashlib.sha256(crypto.canonical(crypto.parse(public))).hexdigest() != value["automation"]["operator_verify_sha256"]:
        raise ValueError("isolated signing operator trust mismatch")
    return public


def valid_payload(value):
    if (not isinstance(value, dict) or set(value) != {
            "qualification_request", "qualification_request_id", "receipts", "notes", "existing"}
            or not isinstance(value["qualification_request"], str)
            or not 0 < len(value["qualification_request"]) <= 65536
            or not isinstance(value["receipts"], dict)
            or set(value["receipts"]) != {"dataplane", "client", "supplier"}
            or any(not isinstance(v, str) or len(v) > 49152 for v in value["receipts"].values())):
        raise ValueError("invalid automatic consumer release request")
    uuid_value(value["qualification_request_id"])


def prepare():
    value, selected = policy()
    guard("builder", value)
    work = root()
    work.mkdir(mode=0o700)
    request_id = consumer.ci.required("CONSUMER_AUTOMATION_REQUEST_ID")
    sealed = consumer.ci.required("CONSUMER_AUTOMATION_REQUEST")
    digest = consumer.ci.required("CONSUMER_AUTOMATION_REQUEST_DIGEST")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(sealed.encode("ascii")).hexdigest() != digest:
        raise ValueError("automatic consumer request digest mismatch")
    private = consumer.key("INPUT_PRIVATE_KEY_B64")
    wrapped = crypto.parse(crypto.open_message(sealed, private,
                         request_context(request_id, value["automation"]["builder_sha"])))
    now = int(time.time())
    if (not isinstance(wrapped, dict) or set(wrapped) != {"created", "expires", "payload"}
            or not consumer.integer(wrapped["created"], 0) or not consumer.integer(wrapped["expires"], 0)
            or wrapped["created"] > now + 300 or wrapped["expires"] < now
            or not 0 < wrapped["expires"] - wrapped["created"] <= 21600):
        raise ValueError("automatic consumer request expired")
    payload = wrapped["payload"]
    valid_payload(payload)
    token = consumer.ci.required("BUILDER_READ_TOKEN")
    public = operator_public(value)
    qualified = approval.resolve_qualification(payload["qualification_request"],
        payload["qualification_request_id"], value["qualifier_sha"], value["run"],
        selected, private, public, token)
    original_digest = hashlib.sha256(payload["qualification_request"].encode("ascii")).hexdigest()
    document = crypto.parse(crypto.open_message(payload["qualification_request"], private,
                           consumer.context("request", qualified)))
    if crypto.verify(document, public) != qualified:
        raise ValueError("automatic consumer qualification authority changed")
    original, origin = publisher.fetch_original(work, value, qualified, original_digest, token,
                                                consumer.key("PUBLISH_PRIVATE_KEY_B64"))
    inputs = work / "inputs"
    inputs.mkdir(mode=0o700)
    publisher.extract_original_result(original, inputs, value)
    plan = dict(payload, schema=1, qualified=qualified, artifact=origin, tag_time=now)
    signing.validate_plan(plan, value, selected, inputs / value["archive_name"])
    (inputs / "plan.json").write_bytes(crypto.canonical({"plan": plan, "qualification_document": document}))
    package = work / "input.zip"
    with zipfile.ZipFile(package, "x", compression=zipfile.ZIP_STORED) as archive:
        for path in inputs.iterdir():
            archive.write(path, path.name)
    output = Path(consumer.ci.required("RUNNER_TEMP")) / "consumer-signing-input"
    output.mkdir(mode=0o700)
    context = signing.protocol_context("input", int(consumer.ci.required("GITHUB_RUN_ID")),
                                      value["automation"]["builder_sha"], value["automation"]["signer_sha"], value)
    crypto.encrypt_file(package, output / "input.enc", signer_public(value), context)


def producer(api, value, run_id):
    prefix = f"/repos/{consumer.ci.BUILDER}/actions/runs/{run_id}"
    run = api.get(prefix)
    title = run.get("display_title", "")
    if not re.fullmatch(r"Consumer automation [0-9a-f]{64}", title):
        raise ValueError("invalid automatic producer title")
    validate_run(run, repository_id=consumer.ci.BUILDER_ID, sha=value["automation"]["builder_sha"],
                 ref="consumer-automation-" + value["automation"]["builder_sha"],
                 workflow=WORKFLOW, title=title, completed=False)
    validate_job(api.get(prefix + "/attempts/1/jobs?per_page=100")["jobs"], run, "prepare-signing", PREPARE_STEP)
    return run


def orchestrate():
    value, _ = policy()
    guard("builder", value)
    work = root()
    work.mkdir(mode=0o700)
    producer_id = int(consumer.ci.required("GITHUB_RUN_ID"))
    reader = Client(consumer.ci.required("BUILDER_READ_TOKEN"))
    produced = producer(reader, value, producer_id)
    item = artifact(reader, consumer.ci.BUILDER, producer_id,
                    f"consumer-signing-input-{producer_id}-1", consumer.MAX_PREPARED)
    path = f"/repos/{consumer.ci.BUILDER}/actions/artifacts/{item['id']}/zip"
    try:
        with reader.request("GET", path):
            raise ValueError("isolated signing requires bounded temporary storage location")
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise
        location = storage_url(error.headers.get("Location", ""))
    request_id = str(uuid.uuid4())
    context = signing.protocol_context("request", producer_id, value["automation"]["builder_sha"],
                                      value["automation"]["signer_sha"], value)
    context["request_id"] = request_id
    now = int(time.time())
    sealed = crypto.seal_message(crypto.canonical({
        "created": now, "expires": now + 1800, "artifact_id": item["id"],
        "artifact_sha256": item["digest"].removeprefix("sha256:"), "artifact_size": item["size_in_bytes"],
        "url": location, "producer_digest": produced["display_title"].removeprefix("Consumer automation ")}),
        signer_public(value), context)
    digest = hashlib.sha256(sealed.encode("ascii")).hexdigest()
    dispatch = {"ref": "consumer-signer-" + value["automation"]["signer_sha"],
                "inputs": {"producer_run": str(producer_id), "request_id": request_id,
                           "request_digest": digest, "request": sealed}}
    api = Client(consumer.ci.required("CONSUMER_DISPATCH_TOKEN"))
    api.json("POST", f"/repos/{value['repository']}/actions/workflows/{SIGNER_WORKFLOW}/dispatches", dispatch)
    deadline = time.monotonic() + 1200
    chosen = None
    while time.monotonic() < deadline:
        runs = api.get(f"/repos/{value['repository']}/actions/workflows/{SIGNER_WORKFLOW}/runs"
                       f"?head_sha={value['automation']['signer_sha']}&event=workflow_dispatch&per_page=100")
        matches = [run for run in runs["workflow_runs"] if run.get("display_title") == "Consumer signer " + digest]
        if len(matches) > 1:
            raise ValueError("isolated signing dispatch replay")
        if matches:
            chosen = matches[0]
            if chosen.get("status") == "completed":
                break
            if chosen.get("run_attempt") != 1:
                raise ValueError("isolated signer rerun rejected")
        time.sleep(10)
    if chosen is None or chosen.get("status") != "completed":
        raise ValueError("isolated signing deadline exceeded")
    validate_run(chosen, repository_id=value["repository_id"], sha=value["automation"]["signer_sha"],
                 ref="consumer-signer-" + value["automation"]["signer_sha"],
                 workflow=SIGNER_WORKFLOW, title="Consumer signer " + digest, completed=True)
    jobs = api.get(f"/repos/{value['repository']}/actions/runs/{chosen['id']}/attempts/1/jobs?per_page=100")["jobs"]
    validate_job(jobs, chosen, "sign", SIGN_STEP)
    item = artifact(api, value["repository"], chosen["id"],
                    f"consumer-signature-output-{chosen['id']}-1", 4 * 1024**2)
    output = work / "result.zip"
    download_artifact(api, f"/repos/{value['repository']}/actions/artifacts/{item['id']}/zip",
                      output, item["digest"].removeprefix("sha256:"), 4 * 1024**2)
    extract_cipher(output, work / "result.enc", "result.enc", 4 * 1024**2)
    record = {"producer_run": producer_id, "signer_run": chosen["id"], "request_id": request_id,
              "request_digest": digest, "cipher_sha256": crypto.digest(work / "result.enc")}
    raw = crypto.canonical(record)
    (work / "return.json").write_bytes(raw)
    with open(consumer.ci.required("GITHUB_OUTPUT"), "a", encoding="utf-8") as stream:
        stream.write("signer_return_digest=" + hashlib.sha256(raw).hexdigest() + "\n")


def extract_plan(package, work, value):
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        if len(entries) != 2 or {entry.filename for entry in entries} != {"plan.json", value["archive_name"]}:
            raise ValueError("isolated signing input inventory mismatch")
        for entry in entries:
            maximum = 262144 if entry.filename == "plan.json" else consumer.MAX_PREPARED
            if (entry.flag_bits & 1 or entry.is_dir() or not 0 < entry.file_size <= maximum
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)):
                raise ValueError("unsafe isolated signing input member")
            with archive.open(entry) as src, (work / entry.filename).open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024**2)
    packet = crypto.parse((work / "plan.json").read_bytes())
    if not isinstance(packet, dict) or set(packet) != {"plan", "qualification_document"}:
        raise ValueError("invalid isolated signing packet")
    return packet


def sign():
    value, selected = policy()
    guard("signer", value)
    run_id = int(consumer.ci.required("CONSUMER_PRODUCER_RUN"))
    if not consumer.integer(run_id):
        raise ValueError("invalid isolated signing producer ID")
    request_id = uuid_value(consumer.ci.required("CONSUMER_SIGNER_REQUEST_ID"))
    sealed = consumer.ci.required("CONSUMER_SIGNER_REQUEST")
    digest = consumer.ci.required("CONSUMER_SIGNER_REQUEST_DIGEST")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(sealed.encode("ascii")).hexdigest() != digest:
        raise ValueError("isolated signing request digest mismatch")
    reader = Client(consumer.ci.required("BUILDER_READ_TOKEN"))
    produced = producer(reader, value, run_id)
    current_id = int(consumer.ci.required("GITHUB_RUN_ID"))
    current_runs = reader.get(f"/repos/{value['repository']}/actions/workflows/{SIGNER_WORKFLOW}/runs"
                              f"?head_sha={value['automation']['signer_sha']}&per_page=100")["workflow_runs"]
    matches = [run for run in current_runs if run.get("display_title") == "Consumer signer " + digest]
    if len(matches) != 1 or matches[0].get("id") != current_id:
        raise ValueError("isolated signing request replay")
    context = signing.protocol_context("request", run_id, value["automation"]["builder_sha"],
                                      value["automation"]["signer_sha"], value)
    context["request_id"] = request_id
    private = consumer.key("SIGNER_INPUT_PRIVATE_KEY_B64")
    if crypto.fingerprint(crypto.public_text(private)) != value["automation"]["signer_recipient"]:
        raise ValueError("isolated signing private recipient mismatch")
    request = crypto.parse(crypto.open_message(sealed, private, context))
    fields = {"created", "expires", "artifact_id", "artifact_sha256", "artifact_size", "url", "producer_digest"}
    now = int(time.time())
    if (not isinstance(request, dict) or set(request) != fields
            or not consumer.integer(request["created"], 0) or not consumer.integer(request["expires"], 0)
            or request["created"] > now + 300 or request["expires"] < now
            or not 0 < request["expires"] - request["created"] <= 1800
            or request["producer_digest"] != produced["display_title"].removeprefix("Consumer automation ")):
        raise ValueError("isolated signing request expired or mismatched")
    item = artifact(reader, consumer.ci.BUILDER, run_id,
                    f"consumer-signing-input-{run_id}-1", consumer.MAX_PREPARED)
    if (request["artifact_id"] != item["id"] or request["artifact_size"] != item["size_in_bytes"]
            or request["artifact_sha256"] != item["digest"].removeprefix("sha256:")):
        raise ValueError("isolated signing artifact authority mismatch")
    work = root()
    work.mkdir(mode=0o700)
    response = urllib.request.build_opener(NoRedirect()).open(
        urllib.request.Request(storage_url(request["url"]), headers={"User-Agent": "consumer-isolated-signing"}),
        timeout=90)
    download_response(response, work / "input.zip", request["artifact_sha256"], consumer.MAX_PREPARED)
    extract_cipher(work / "input.zip", work / "input.enc", "input.enc", consumer.MAX_PREPARED)
    context = signing.protocol_context("input", run_id, value["automation"]["builder_sha"],
                                      value["automation"]["signer_sha"], value)
    crypto.decrypt_file(work / "input.enc", work / "plan.zip", private, context)
    packet = extract_plan(work / "plan.zip", work, value)
    plan = packet["plan"]
    qualified = crypto.verify(packet["qualification_document"], operator_public(value))
    if qualified != plan.get("qualified"):
        raise ValueError("isolated signing qualification signature mismatch")
    qrun = reader.get(f"/repos/{consumer.ci.BUILDER}/actions/runs/{value['run']}")
    admitted = int(datetime.strptime(qrun["created_at"], "%Y-%m-%dT%H:%M:%SZ")
                   .replace(tzinfo=timezone.utc).timestamp())
    consumer.validate_request(qualified, admitted_at=admitted)
    qjobs = reader.get(f"/repos/{consumer.ci.BUILDER}/actions/runs/{value['run']}/attempts/1/jobs?per_page=100")["jobs"]
    original_digest = hashlib.sha256(plan["qualification_request"].encode("ascii")).hexdigest()
    consumer.validate_result(qualified, original_digest, qrun, qjobs)
    origin = artifact(reader, consumer.ci.BUILDER, value["run"],
                      f"consumer-output-static-{value['run']}-1", consumer.MAX_PREPARED)
    if plan["artifact"] != {"id": origin["id"], "sha256": origin["digest"].removeprefix("sha256:")}:
        raise ValueError("isolated signing original artifact mismatch")
    signing.validate_plan(plan, value, selected, work / value["archive_name"])
    if not consumer.integer(plan["tag_time"], now - 21600, now + 300):
        raise ValueError("isolated signing tag timestamp outside request window")
    public = crypto.unb64(consumer.ci.required("CONSUMER_RELEASE_VERIFY_PUBLIC_KEY_B64"))
    if plan["existing"] is not None:
        signing.verify_existing_bundle(plan, value, selected, work / value["archive_name"],
                                       work / "prechecked-existing", public)
    # Private signing authority is first read only after all independent gates.
    signing_private = crypto.unb64(consumer.ci.required("CONSUMER_RELEASE_SIGNING_PRIVATE_KEY_B64"))
    passphrase = consumer.ci.required("CONSUMER_RELEASE_SIGNING_PASSPHRASE").encode("utf-8")
    result_context = signing.protocol_context("result", run_id, value["automation"]["builder_sha"],
                                             value["automation"]["signer_sha"], value)
    result_context.update(signer_run=current_id, request_id=request_id)
    with signing.isolated_signer(signing_private, passphrase, value["signer_fingerprint"]) as signer:
        bundle = signing.sign_bundle(plan, value, selected, work / value["archive_name"],
                                     work / "signed", signer, public)
        certificate = dict(result_context, request_digest=digest,
                           bundle_sha256=hashlib.sha256(crypto.canonical(bundle)).hexdigest())
        signature = signer(crypto.canonical(certificate))
    packet = {"bundle": bundle, "certificate": certificate, "signature": crypto.b64(signature)}
    (work / "result.json").write_bytes(crypto.canonical(packet))
    output = Path(consumer.ci.required("RUNNER_TEMP")) / "consumer-signature-output"
    output.mkdir(mode=0o700)
    crypto.encrypt_file(work / "result.json", output / "result.enc",
                        consumer.key("BUILDER_INPUT_PUBLIC_KEY_B64"), result_context)


def complete():
    value, selected = policy()
    guard("builder", value)
    work = root()
    raw = (work / "return.json").read_bytes()
    if len(raw) > 4096 or hashlib.sha256(raw).hexdigest() != consumer.ci.required("CONSUMER_SIGNER_RETURN_DIGEST"):
        raise ValueError("isolated signing return receipt changed")
    record = crypto.parse(raw)
    if not isinstance(record, dict) or set(record) != {
            "producer_run", "signer_run", "request_id", "request_digest", "cipher_sha256"}:
        raise ValueError("invalid isolated signing return receipt")
    if record["producer_run"] != int(consumer.ci.required("GITHUB_RUN_ID")):
        raise ValueError("isolated signing producer changed")
    context = signing.protocol_context("result", record["producer_run"], value["automation"]["builder_sha"],
                                      value["automation"]["signer_sha"], value)
    context.update(signer_run=record["signer_run"], request_id=uuid_value(record["request_id"]))
    if crypto.digest(work / "result.enc") != record["cipher_sha256"]:
        raise ValueError("isolated signing ciphertext changed")
    private = consumer.key("INPUT_PRIVATE_KEY_B64")
    crypto.decrypt_file(work / "result.enc", work / "result.json", private, context)
    raw = (work / "result.json").read_bytes()
    if len(raw) > 262144:
        raise ValueError("isolated signing result exceeds bounds")
    packet = crypto.parse(raw)
    if not isinstance(packet, dict) or set(packet) != {"bundle", "certificate", "signature"}:
        raise ValueError("invalid isolated signing result")
    certificate = dict(context, request_digest=record["request_digest"],
                       bundle_sha256=hashlib.sha256(crypto.canonical(packet["bundle"])).hexdigest())
    if packet["certificate"] != certificate:
        raise ValueError("isolated signing certificate mismatch")
    public = crypto.unb64(consumer.ci.required("CONSUMER_RELEASE_VERIFY_PUBLIC_KEY_B64"))
    approval._verify_release_signature(crypto.canonical(certificate), crypto.unb64(packet["signature"]),
                                       public, value["signer_fingerprint"])
    publisher.verify_bundle(packet["bundle"], value, selected, publisher.work_root(), private,
                            consumer.ci.required("BUILDER_READ_TOKEN"))


def publish():
    value, _ = policy()
    guard("builder", value)
    publisher.publish_verified()


def package(args):
    if not all((args.bundle, args.input_public, args.builder_sha, args.output)):
        raise ValueError("automatic consumer packaging inputs missing")
    if args.bundle.stat().st_size > 24576 or not re.fullmatch(r"[0-9a-f]{40}", args.builder_sha):
        raise ValueError("automatic consumer packaging exceeds bounds")
    payload = crypto.parse(args.bundle.read_bytes())
    valid_payload(payload)
    public = args.input_public.read_text().strip()
    if not public.startswith("{"):
        public = crypto.unb64(public).decode()
    request_id, now = str(uuid.uuid4()), int(time.time())
    sealed = crypto.seal_message(crypto.canonical({"created": now, "expires": now + 21600, "payload": payload}),
                                public, request_context(request_id, args.builder_sha))
    result = {"ref": "consumer-automation-" + args.builder_sha,
              "inputs": {"request_id": request_id, "request_digest": hashlib.sha256(sealed.encode("ascii")).hexdigest(),
                         "request": sealed}}
    with args.output.open("xb") as stream:
        stream.write(crypto.canonical(result))
    args.output.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("package", "prepare", "orchestrate", "sign", "complete",
                                          "publish", "diagnostics", "cleanup"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--input-public", type=Path)
    parser.add_argument("--builder-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.stage == "package":
            package(args)
        elif args.stage == "diagnostics":
            publisher.diagnostics()
        elif args.stage == "cleanup":
            for path in (root(), publisher.work_root()):
                if path.exists():
                    consumer.ci.remove_staging(path)
        else:
            globals()[args.stage]()
        print("CONSUMER_AUTOMATION_SUCCESS " + args.stage)
    except Exception as error:
        if args.stage != "package":
            publisher.record_failure(args.stage, error)
        raise SystemExit("CONSUMER_AUTOMATION_FAILED " + args.stage) from None


if __name__ == "__main__":
    main()
