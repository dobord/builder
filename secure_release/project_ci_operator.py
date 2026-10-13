"""Local-only schema-2 client. Never execute source or print private API replies.

Only ciphertext enters public Git. Signing/status credentials stay with this
operator; native qualification receives neither. State and logs are private.
"""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

from . import crypto, project_ci as ci


def protected_file(path):
    if os.name != "posix":
        raise ValueError("operator file ownership requires a POSIX-local client")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ValueError("operator file must be owner-only and regular")
    if info.st_size > 1024 * 1024:
        raise ValueError("operator file exceeds bound")
    return path.read_text(encoding="utf-8")


def public_file(path):
    if os.name != "posix":
        raise ValueError("operator file ownership requires a POSIX-local client")
    """Accept owner-controlled public backups, including read-only-to-others 0644."""
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_uid != os.getuid() or
            not 0 < info.st_size <= 1024 * 1024):
        raise ValueError("public operator file must be bounded, regular and owner-controlled")
    return path.read_text(encoding="utf-8")


def private_directory(path, *, create=False):
    if os.name != "posix":
        raise ValueError("operator staging ownership requires a POSIX-local client")
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ValueError("operator staging must be owner-only")


def save(path, value):
    with path.open("x", encoding="ascii") as stream:
        os.chmod(path, 0o600)
        stream.write(crypto.canonical(value).decode("ascii"))


def token():
    # Credential helper output remains in memory, never argv, logs or staging.
    result = subprocess.run(["gh", "auth", "token", "--hostname", "github.com"],
                            capture_output=True, timeout=30, check=False)
    if result.returncode or not 0 < len(result.stdout) <= 16384:
        raise ValueError("operator authentication unavailable")
    return result.stdout.decode("ascii").strip()


def builder_ref(reference, revision, credential):
    if not re.fullmatch(r"refs/tags/[A-Za-z0-9_.-]+", reference) or not ci.SHA.fullmatch(revision):
        raise ValueError("immutable builder tag and exact reviewed SHA required")
    repo = ci.api_json(f"repos/{ci.BUILDER}", credential, limit=16384)
    if repo["id"] != ci.BUILDER_ID:
        raise ValueError("builder repository identity mismatch")
    obj = ci.api_json(f"repos/{ci.BUILDER}/git/ref/" + reference.removeprefix("refs/"), credential)["object"]
    for _ in range(4):
        if obj["type"] == "commit":
            break
        if obj["type"] != "tag":
            raise ValueError("invalid builder ref")
        obj = ci.api_json(f"repos/{ci.BUILDER}/git/tags/{obj['sha']}", credential)["object"]
    if obj["type"] != "commit" or obj["sha"] != revision:
        raise ValueError("builder ref moved from reviewed revision")


def baseline(policy, tag, credential):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("stable baseline tag required")
    prefix = f"repos/{policy['repository']}"
    released = ci.api_json(prefix + "/releases/tags/" + tag, credential)
    if released["draft"] or released["prerelease"] or released["tag_name"] != tag or not released["published_at"]:
        raise ValueError("published stable baseline required")
    obj = ci.api_json(prefix + "/git/ref/tags/" + tag, credential)["object"]
    for _ in range(4):
        if obj["type"] == "commit":
            break
        if obj["type"] != "tag":
            raise ValueError("invalid baseline object")
        obj = ci.api_json(prefix + "/git/tags/" + obj["sha"], credential)["object"]
    if obj["type"] != "commit" or not ci.SHA.fullmatch(obj["sha"]):
        raise ValueError("invalid baseline commit")
    return obj["sha"]


def publish_input(value, path, credential):
    raw = path.read_bytes()
    if not 0 < len(raw) <= ci.MAX_GIT_INPUT:
        raise ValueError("ciphertext exceeds Git transport bound")
    prefix = f"repos/{ci.BUILDER}/git/"
    blob = ci.api_json(prefix + "blobs", credential,
                       data={"encoding": "base64", "content": crypto.b64(raw)}, limit=16384)
    if blob["sha"] != ci.git_blob_sha(raw):
        raise ValueError("published blob identity mismatch")
    tree = ci.api_json(prefix + "trees", credential, data={"tree": [
        {"path": "sources.enc", "mode": "100644", "type": "blob", "sha": blob["sha"]}]}, limit=16384)
    if not ci.SHA.fullmatch(tree["sha"]):
        raise ValueError("invalid published tree")
    # No parents, source names, source revisions or source metadata in public Git.
    commit = ci.api_json(prefix + "commits", credential, data={"message": "Encrypted project input",
                         "tree": tree["sha"], "parents": []}, limit=16384)
    if not ci.SHA.fullmatch(commit["sha"]):
        raise ValueError("invalid published commit")
    value.update(input_blob=blob["sha"], input_commit=commit["sha"])
    ci.api_json(prefix + "refs", credential, data={"ref": value["input_ref"], "sha": commit["sha"]}, limit=16384)
    check = path.parent / "verified.enc"
    ci.fetch_operator_input(value, credential, check)
    check.unlink()


def package(args, credential):
    private_directory(args.work, create=True)
    policy = crypto.parse(protected_file(args.policy))
    if (not re.fullmatch(r"dobord/[A-Za-z0-9_.-]+", policy["repository"]) or
            type(policy["repository_id"]) is not int or
            policy.get("operator_origin") != "local-operator" or policy.get("operator_id") != 5323024):
        raise ValueError("explicit operator source policy required")
    ci.verify_request_schema(policy, 2)
    builder_ref(args.builder_ref, args.builder_sha, credential)
    # api() deliberately only permits repos/ paths; gh obtains the authenticated
    # user locally with bounded captured output instead of expanding that API.
    result = subprocess.run(["gh", "api", "user", "--jq", ".id"], capture_output=True, timeout=30, check=False)
    if result.returncode or result.stdout.strip() != b"5323024":
        raise ValueError("wrong local operator")
    prefix = f"repos/{policy['repository']}"
    if args.pr:
        pr = ci.api_json(prefix + f"/pulls/{args.pr}", credential)
        head, base = pr["head"]["sha"], pr["base"]["sha"]
    else:
        head = ci.api_json(prefix + "/git/ref/heads/main", credential)["object"]["sha"]
        base = head
    if head != args.source_sha or base != args.base_sha:
        raise ValueError("current source head/base differs from operator exact revisions")
    now = int(time.time())
    request_id = str(uuid.uuid4())
    value = {"schema": 2, "request_id": request_id, "source": policy["repository"],
             "source_id": policy["repository_id"], "source_sha": head, "base_sha": base,
             "builder_sha": args.builder_sha, "suite": args.suite, "pr": args.pr,
             "created": now, "expires": now + 21600, "origin": "local-operator", "operator_id": 5323024,
             "baseline_tag": args.baseline_tag, "baseline_sha": baseline(policy, args.baseline_tag, credential),
             "input_ref": "refs/tags/project-ci-input-" + request_id,
             "input_commit": "0" * 40, "input_blob": "0" * 40, "source_cipher_digest": "0" * 64}
    ci.validate_payload(value)
    # Local policy preflight does not replace builder's independently configured policy.
    with preflight_policy(policy):
        ci.verify_source_policy(value, credential)
    public = public_file(args.input_public)
    signing = protected_file(args.signing_private)
    crypto.fingerprint(public)  # Reject private material in an input public key.
    env = ci.git_environment(os.environ, args.work)
    env.update({"GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_1": "credential.helper", "GIT_CONFIG_VALUE_1": "",
                "GIT_CONFIG_KEY_2": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_2": "AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + credential).encode()).decode()})
    repo = args.work / "repository.git"
    log = args.work / "transport.log"
    ci.checked(["git", "init", "--bare", str(repo)], args.work, env, log)
    refs = [head + ":refs/heads/candidate", base + ":refs/heads/base",
            value["baseline_sha"] + ":refs/heads/performance-baseline"]
    ci.checked(["git", "-C", str(repo), "fetch", "--no-tags", "https://github.com/" + value["source"] + ".git", *refs], args.work, env, log)
    # Parse inert recipe data; no checkout, hooks, filters or source execution.
    raw_recipes = {}
    for profile in ci.SUITES[value["suite"]]:
        recipe = args.work / (profile + ".yml")
        object_name = head + ":ci/builder/" + profile + ".yml"
        size = subprocess.run(["git", "-C", str(repo), "cat-file", "-s", object_name],
                              env=env, capture_output=True, timeout=30, check=False)
        if size.returncode or len(size.stdout) > 32 or not 0 < int(size.stdout) <= ci.MAX_RECIPE:
            raise ValueError("recipe size exceeds bound")
        with recipe.open("wb") as output:
            result = subprocess.run(["git", "-C", str(repo), "show", object_name],
                                    env=env, stdout=output, stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode or recipe.stat().st_size > ci.MAX_RECIPE:
            raise ValueError("recipe inventory unavailable")
        raw_recipes[profile] = recipe.read_bytes()
        recipe.unlink()
    lanes = ci.expand_recipes(value["suite"], raw_recipes)
    lane_ids = [lane["id"] for lane in lanes]
    if not 1 <= len(lane_ids) <= 100 or len(set(lane_ids)) != len(lane_ids) or (args.suite == "release" and len(lane_ids) != 39):
        raise ValueError("incomplete lane inventory")
    plain = args.work / "repository.bundle"
    ci.checked(["git", "-C", str(repo), "bundle", "create", str(plain), "--all"], args.work, env, log)
    if not 0 < plain.stat().st_size <= ci.MAX_GIT_INPUT - 1024**2:
        raise ValueError("source exceeds Git transport bound")
    ciphertext = args.work / "sources.enc"
    crypto.encrypt_file(plain, ciphertext, public, ci.source_context(value))
    value["source_cipher_digest"] = crypto.digest(ciphertext)
    plain.unlink()
    # The fresh Linux bare repository has writable Git objects.
    import shutil
    shutil.rmtree(repo)
    publish_input(value, ciphertext, credential)
    ci.validate_payload(value)
    document = crypto.sign(value, signing)
    request = crypto.seal_message(crypto.canonical(document), public,
                                  ci.message_context(request_id, 2, value["builder_sha"]))
    state = {"payload": value, "request": request, "request_digest": ci.digest_bytes(request.encode("ascii")),
             "builder_ref": args.builder_ref, "inventory": crypto.sign({"payload": value, "lanes": lane_ids,
                 "request_digest": ci.digest_bytes(request.encode("ascii")), "builder_ref": args.builder_ref}, signing),
             "lanes": lane_ids}
    save(args.work / "state.json", state)
    return state


class preflight_policy:
    """Temporarily supply local preflight configuration, never source execution."""
    def __init__(self, policy):
        self.values = {"CI_SOURCE_POLICY_B64": crypto.b64(crypto.canonical(policy)), "GITHUB_ACTOR_ID": str(policy["operator_id"])}

    def __enter__(self):
        self.old = {key: os.environ.get(key) for key in self.values}
        os.environ.update(self.values)

    def __exit__(self, *unused):
        for key, value in self.old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def validate_state(state, signing_public):
    """Local evidence is bound by the same independently supplied signer key."""
    ci.validate_payload(state["payload"])
    if state["payload"]["schema"] != 2 or ci.digest_bytes(state["request"].encode("ascii")) != state["request_digest"]:
        raise ValueError("local request binding mismatch")
    inventory = crypto.verify(state["inventory"], signing_public)
    if inventory != {"payload": state["payload"], "lanes": state["lanes"],
                     "request_digest": state["request_digest"], "builder_ref": state["builder_ref"]}:
        raise ValueError("local signed inventory mismatch")
    lanes = state["lanes"]
    if (not isinstance(lanes, list) or not 1 <= len(lanes) <= 100 or len(set(lanes)) != len(lanes) or
            any(not re.fullmatch(r"[a-z0-9-]+", lane) for lane in lanes) or
            (state["payload"]["suite"] == "release" and len(lanes) != 39)):
        raise ValueError("local qualification inventory incomplete")


def mirror_success(state, run, jobs, credential):
    value = state["payload"]
    ci.validate_payload(value)
    if run is None:
        raise ValueError("qualification missing")
    ci.validate_run(run, value["builder_sha"], state["request_digest"], 1)
    if (run.get("actor", {}).get("id") != value["operator_id"] or
            run.get("triggering_actor", {}).get("id") != value["operator_id"] or
            run["html_url"] != f"https://github.com/{ci.BUILDER}/actions/runs/{run['id']}"):
        raise ValueError("builder actor or URL mismatch")
    expected = {"prepare", "Encrypted qualification required"} | {"Encrypted lane " + lane for lane in state["lanes"]}
    if (len(jobs) != len(expected) or {job["name"] for job in jobs} != expected or
            any(job["status"] != "completed" or job["conclusion"] != "success" or
                job["run_id"] != run["id"] or job["head_sha"] != value["builder_sha"] for job in jobs)):
        raise ValueError("qualification aggregate incomplete")
    ci.api_json(f"repos/{value['source']}/statuses/{value['source_sha']}", credential,
                data={"state": "success", "context": "Builder " + value["suite"] + " Required",
                      "description": "Verified complete encrypted qualification on the exact source SHA",
                      "target_url": run["html_url"]})


def dispatch(state, work, credential):
    value = state["payload"]
    ci.validate_payload(value)
    builder_ref(state["builder_ref"], value["builder_sha"], credential)
    # Replaying an existing request, including a cancelled run, is forbidden.
    matches = matching_runs(state, credential)
    if matches or (work / "dispatched.json").exists():
        raise ValueError("dispatch requires a fresh request")
    save(work / "dispatched.json", {"request_digest": state["request_digest"]})
    ci.api_json(f"repos/{ci.BUILDER}/actions/workflows/{ci.WORKFLOW}/dispatches", credential,
                data={"ref": state["builder_ref"].removeprefix("refs/tags/"), "inputs": {
                    "request_schema": "2", "request_id": value["request_id"],
                    "request_digest": state["request_digest"], "request": state["request"]}})


def matching_runs(state, credential):
    runs = ci.pages(f"repos/{ci.BUILDER}/actions/workflows/{ci.WORKFLOW}/runs?head_sha={state['payload']['builder_sha']}",
                    credential, "workflow_runs")
    return [run for run in runs if run["display_title"] == "Encrypted qualification " + state["request_digest"]]


def wait(state, work, credential):
    deadline = time.monotonic() + 21600
    while time.monotonic() < deadline:
        ci.validate_payload(state["payload"])
        matches = matching_runs(state, credential)
        if len(matches) > 1:
            raise ValueError("replayed request")
        if matches:
            run = ci.api_json(f"repos/{ci.BUILDER}/actions/runs/{matches[0]['id']}", credential)
            if run["run_attempt"] != 1:
                raise ValueError("rerun requires fresh request")
            if run["status"] == "completed":
                jobs = ci.pages(f"repos/{ci.BUILDER}/actions/runs/{run['id']}/attempts/1/jobs", credential, "jobs")
                builder_ref(state["builder_ref"], state["payload"]["builder_sha"], credential)
                verification = work / ("input-check-" + str(uuid.uuid4()) + ".enc")
                ci.fetch_operator_input(state["payload"], credential, verification)
                verification.unlink()
                # Snapshot the current attempt again immediately before mirroring.
                run = ci.api_json(f"repos/{ci.BUILDER}/actions/runs/{run['id']}", credential)
                mirror_success(state, run, jobs, credential)
                save(work / "qualification.json", {"run": run, "jobs": jobs, "request_digest": state["request_digest"]})
                return run["html_url"]
        time.sleep(30)
    raise ValueError("qualification timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("package", "dispatch", "wait"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--pr", type=int, default=0)
    parser.add_argument("--suite", choices=ci.SUITES, default="release")
    parser.add_argument("--baseline-tag")
    parser.add_argument("--builder-sha")
    parser.add_argument("--builder-ref")
    parser.add_argument("--source-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--signing-private", type=Path)
    parser.add_argument("--input-public", type=Path)
    parser.add_argument("--signing-public", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        args.work = args.work.resolve()
        credential = token()
        if args.stage == "package":
            state = package(args, credential)
        else:
            private_directory(args.work)
            state = crypto.parse(protected_file(args.work / "state.json"))
            validate_state(state, public_file(args.signing_public))
            if args.stage == "dispatch":
                dispatch(state, args.work, credential)
            else:
                url = wait(state, args.work, credential)
                print("BUILDER_QUALIFICATION_SUCCESS " + url + " " + state["request_digest"])
                return
        print("PROJECT_CI_OPERATOR_" + args.stage.upper() + " " + state["request_digest"])
    except Exception:
        print("PROJECT_CI_OPERATOR_FAILED stage=" + args.stage, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
