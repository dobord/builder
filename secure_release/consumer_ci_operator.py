"""Local-only operator for the independent consumer contour.

Only ciphertext is published. Signing keys and API credentials never enter
source execution. Verification is one-shot; a pending run is not a success.
"""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import subprocess
import time
import uuid
import zipfile

from . import consumer_ci as consumer, crypto, project_ci as ci, project_ci_operator as operator, safeio


def read_state(work, public):
    operator.private_directory(work)
    state = crypto.parse(operator.protected_file(work / "state.json"))
    expected = {"payload", "request", "request_digest", "builder_ref", "signature"}
    if not isinstance(state, dict) or set(state) != expected:
        raise ValueError("invalid consumer local state")
    receipt = crypto.verify(state["signature"], public)
    if receipt != {k: state[k] for k in expected - {"signature"}}:
        raise ValueError("consumer state signature mismatch")
    consumer.validate_request(state["payload"])
    if ci.digest_bytes(state["request"].encode("ascii")) != state["request_digest"]:
        raise ValueError("consumer sealed request digest mismatch")
    return state


def package(args, token):
    operator.private_directory(args.work, create=True)
    selected = crypto.parse(operator.protected_file(args.policy))
    consumer.validate_policy(selected)
    operator.builder_ref(args.builder_ref, args.builder_sha, token)
    user = subprocess.run(["gh", "api", "user", "--jq", ".id"], capture_output=True, timeout=30, check=False)
    if user.returncode or user.stdout.strip() != str(selected["operator_id"]).encode():
        raise ValueError("wrong consumer operator")
    request_id = str(uuid.uuid4())
    now = int(time.time())
    value = {
        "schema": 1, "request_id": request_id, "source": selected["repository"],
        "source_id": selected["repository_id"], "operator_id": selected["operator_id"],
        "source_sha": args.source_sha, "base_sha": args.base_sha, "builder_sha": args.builder_sha,
        "pr": args.pr, "created": now, "expires": now + 21600,
        "input_ref": "refs/tags/consumer-input-" + request_id,
        "input_commit": "0" * 40, "input_blob": "0" * 40, "source_cipher_digest": "0" * 64,
    }
    consumer.validate_request(value)
    consumer.source_identity(value, selected, token)
    public = operator.public_file(args.input_public)
    private = operator.protected_file(args.signing_private)
    crypto.fingerprint(public)
    env = ci.git_environment(os.environ, args.work)
    import base64
    env.update(GIT_CONFIG_COUNT="3", GIT_CONFIG_KEY_1="credential.helper", GIT_CONFIG_VALUE_1="",
               GIT_CONFIG_KEY_2="http.https://github.com/.extraheader",
               GIT_CONFIG_VALUE_2="AUTHORIZATION: basic " +
               base64.b64encode(("x-access-token:" + token).encode()).decode())
    repo = args.work / "repository.git"
    log = args.work / "transport.log"
    ci.checked(["git", "init", "--bare", str(repo)], args.work, env, log)
    # Preserve original commit/tree IDs without retransmitting retired files or
    # unrelated history. Both approved trees become explicit shallow roots.
    ci.checked(["git", "-C", str(repo), "fetch", "--no-tags", "--depth=1",
                "https://github.com/" + value["source"] + ".git",
                value["source_sha"] + ":refs/heads/candidate", value["base_sha"] + ":refs/heads/base"],
               args.work, env, log)
    # Inspect bounded Git data only: do not check out or run source code locally.
    result = subprocess.run(["git", "-C", str(repo), "show", value["source_sha"] + ":" + consumer.RECIPE],
                            env=env, capture_output=True, timeout=30, check=False)
    if (result.returncode or not 0 < len(result.stdout) <= 65536
            or ci.digest_bytes(result.stdout) != selected["recipe_sha256"]):
        raise ValueError("consumer recipe preflight failed")
    consumer.validate_recipe(crypto.parse(result.stdout))
    bundle = args.work / "source.bundle"
    ci.checked(["git", "-C", str(repo), "bundle", "create", str(bundle), "--all"], args.work, env, log)
    if bundle.stat().st_size > ci.MAX_GIT_INPUT - 1024**2:
        raise ValueError("consumer source exceeds transport limit")
    encrypted = args.work / "sources.enc"
    crypto.encrypt_file(bundle, encrypted, public, consumer.context("source", value))
    value["source_cipher_digest"] = crypto.digest(encrypted)
    bundle.unlink()
    ci.remove_staging(repo)
    operator.publish_input(value, encrypted, token)
    consumer.validate_request(value)
    document = crypto.sign(value, private)
    sealed = crypto.seal_message(crypto.canonical(document), public, consumer.context("request", value))
    state = {"payload": value, "request": sealed, "request_digest": ci.digest_bytes(sealed.encode("ascii")),
             "builder_ref": args.builder_ref}
    state["signature"] = crypto.sign(dict(state), private)
    operator.save(args.work / "state.json", state)
    return state


def matches(state, token):
    runs = ci.pages(f"repos/{ci.BUILDER}/actions/workflows/{consumer.WORKFLOW}/runs?head_sha={state['payload']['builder_sha']}",
                    token, "workflow_runs")
    return [r for r in runs if r["display_title"] == "Encrypted consumer " + state["request_digest"]]


def dispatch(state, work, token):
    operator.builder_ref(state["builder_ref"], state["payload"]["builder_sha"], token)
    if matches(state, token) or (work / "dispatched.json").exists():
        raise ValueError("consumer dispatch requires fresh request")
    operator.save(work / "dispatched.json", {"digest": state["request_digest"]})
    ci.api_json(f"repos/{ci.BUILDER}/actions/workflows/{consumer.WORKFLOW}/dispatches", token,
                data={"ref": state["builder_ref"].removeprefix("refs/tags/"), "inputs": {
                    "request_id": state["payload"]["request_id"],
                    "request_digest": state["request_digest"], "request": state["request"]}})


def verify(state, work, token):
    found = matches(state, token)
    if len(found) != 1:
        raise ValueError("consumer run missing or ambiguous")
    run = ci.api_json(f"repos/{ci.BUILDER}/actions/runs/{found[0]['id']}", token)
    consumer.validate_execution(state["payload"], state["request_digest"], run)
    if run["status"] != "completed":
        print("CONSUMER_PENDING " + run["html_url"])
        return
    jobs = ci.pages(f"repos/{ci.BUILDER}/actions/runs/{run['id']}/attempts/1/jobs", token, "jobs")
    consumer.validate_result(state["payload"], state["request_digest"], run, jobs)
    operator.builder_ref(state["builder_ref"], state["payload"]["builder_sha"], token)
    check = work / ("verified-" + str(uuid.uuid4()) + ".enc")
    ci.fetch_operator_input(state["payload"], token, check)
    check.unlink()
    # The PR can move while a build is running. Do not attach success to stale
    # current-head assumptions even though the status is commit-scoped.
    prefix = "repos/" + state["payload"]["source"]
    current = ci.api_json(prefix + "/pulls/" + str(state["payload"]["pr"]), token) if state["payload"]["pr"] else None
    if current is not None and (current["state"] != "open" or current["head"]["sha"] != state["payload"]["source_sha"]
                                or current["base"]["sha"] != state["payload"]["base_sha"]):
        raise ValueError("consumer PR moved during qualification")
    run = ci.api_json(f"repos/{ci.BUILDER}/actions/runs/{run['id']}", token)
    consumer.validate_result(state["payload"], state["request_digest"], run, jobs)
    ci.api_json(prefix + "/statuses/" + state["payload"]["source_sha"], token, data={
        "state": "success", "context": "Builder consumer Required",
        "description": "Verified all encrypted consumer lanes at this exact source commit", "target_url": run["html_url"]})
    operator.save(work / "qualification.json", {"run": run, "jobs": jobs, "digest": state["request_digest"]})
    print("CONSUMER_QUALIFIED " + run["html_url"])


def fetch(state, args, token):
    found = matches(state, token)
    if len(found) != 1:
        raise ValueError("consumer run missing or ambiguous")
    run = ci.api_json(f"repos/{ci.BUILDER}/actions/runs/{found[0]['id']}", token)
    consumer.validate_execution(state["payload"], state["request_digest"], run)
    jobs = ci.pages(f"repos/{ci.BUILDER}/actions/runs/{run['id']}/attempts/1/jobs", token, "jobs")
    consumer.validate_result(state["payload"], state["request_digest"], run, jobs)
    operator.builder_ref(state["builder_ref"], state["payload"]["builder_sha"], token)
    if args.lane not in consumer.LANES or args.output.exists() or args.output.is_symlink():
        raise ValueError("new output directory and exact consumer lane required")
    artifacts = ci.pages(f"repos/{ci.BUILDER}/actions/runs/{run['id']}/artifacts", token, "artifacts")
    name = f"consumer-output-{args.lane}-{run['id']}-1"
    selected = [a for a in artifacts if a["name"] == name]
    if (len(selected) != 1 or selected[0]["expired"]
            or not 0 < selected[0]["size_in_bytes"] <= consumer.MAX_PREPARED):
        raise ValueError("consumer result artifact unavailable")
    artifact = selected[0]
    raw = ci.api(f"repos/{ci.BUILDER}/actions/artifacts/{artifact['id']}/zip", token, limit=consumer.MAX_PREPARED)
    if (not isinstance(artifact.get("digest"), str)
            or artifact["digest"] != "sha256:" + ci.digest_bytes(raw)):
        raise ValueError("consumer artifact digest mismatch")
    private = operator.protected_file(args.output_private)
    if not private.lstrip().startswith("{"):
        private = crypto.unb64(private.strip()).decode()
    temporary = args.work / ("result-" + str(uuid.uuid4()))
    temporary.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = {e.filename for e in entries}
            inventories = [{"results.enc", "diagnostics.enc"}]
            if args.lane == "static":
                inventories.append({"results.enc", "diagnostics.enc", "publisher-results.enc"})
            if (len(entries) != len(names) or names not in inventories
                    or any(e.flag_bits & 1 or not 0 < e.file_size <= consumer.MAX_PREPARED for e in entries)):
                raise ValueError("unsafe consumer result artifact")
            (temporary / "results.enc").write_bytes(archive.read("results.enc"))
        # Expected context comes from the signed local request and verified run,
        # never from the untrusted ciphertext header.
        value = state["payload"]
        ctx = consumer.context("results", value)
        ctx.update(run=run["id"], attempt=1, request_digest=state["request_digest"], lane=args.lane)
        crypto.decrypt_file(temporary / "results.enc", temporary / "results.tar.gz", private, ctx)
        safeio.extract_tar(temporary / "results.tar.gz", temporary / "plain")
        receipt = crypto.parse((temporary / "plain/result.json").read_bytes())
        if receipt != {"schema": 1, "source_sha": value["source_sha"], "builder_sha": value["builder_sha"],
                       "lane": args.lane, "status": "success"}:
            raise ValueError("consumer result identity mismatch")
        (temporary / "plain").rename(args.output)
    finally:
        ci.remove_staging(temporary)
    print("CONSUMER_RESULT_VERIFIED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("package", "dispatch", "verify", "fetch"))
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--signing-private", type=Path)
    parser.add_argument("--signing-public", type=Path)
    parser.add_argument("--input-public", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--builder-sha")
    parser.add_argument("--builder-ref")
    parser.add_argument("--pr", type=int, default=0)
    parser.add_argument("--lane", choices=consumer.LANES)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-private", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            raise ValueError("consumer operator is local only")
        args.work = args.work.resolve()
        credential = operator.token()
        if args.stage == "package":
            state = package(args, credential)
        else:
            state = read_state(args.work, operator.public_file(args.signing_public))
            if args.stage == "dispatch":
                dispatch(state, args.work, credential)
            elif args.stage == "fetch":
                fetch(state, args, credential)
                return
            else:
                verify(state, args.work, credential)
                return
        print("CONSUMER_OPERATOR_" + args.stage.upper() + " " + state["request_digest"])
    except Exception as error:
        # Protected local breadcrumbs contain code identity, never exception data.
        import traceback
        if args.work.is_dir() and not args.work.is_symlink():
            path = args.work / "failure.json"
            if not path.exists():
                operator.save(path, {"type": type(error).__name__, "frames": [
                    {"function": f.name, "line": f.lineno} for f in traceback.extract_tb(error.__traceback__)[-8:]]})
        raise SystemExit("CONSUMER_OPERATOR_FAILED " + args.stage) from None


if __name__ == "__main__":
    main()
