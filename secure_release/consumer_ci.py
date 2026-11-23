"""Independent encrypted Linux consumer qualification; no release authority.

Only trusted preparation receives source credentials. Policy, crypto and Git
transport admission precede source execution. Existing project CI is untouched.
"""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import crypto, encrypted_logs, project_ci as ci, safeio

WORKFLOW = "encrypted-consumer-ci.yml"
LANES = ("gcc", "clang", "asan", "tsan", "ubsan", "static", "offline", "browser")
MAX_RESOURCE = 1900 * 1024**2
MAX_PREPARED = 2 * 1024**3
RECIPE = "ci/builder/consumer.json"


def integer(value, minimum=1, maximum=2**63 - 1):
    return type(value) is int and minimum <= value <= maximum


def repository(value):
    return isinstance(value, str) and re.fullmatch(r"dobord/[A-Za-z0-9_.-]{1,100}", value)


def validate_request(value):
    fields = {"schema", "request_id", "source", "source_id", "operator_id", "source_sha",
              "base_sha", "builder_sha", "pr", "created", "expires", "input_ref",
              "input_commit", "input_blob", "source_cipher_digest"}
    if not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("invalid consumer request")
    if (not isinstance(value["request_id"], str) or str(uuid.UUID(value["request_id"])) != value["request_id"]
            or not repository(value["source"]) or not integer(value["source_id"])
            or type(value["operator_id"]) is not int or value["operator_id"] != 5323024
            or not integer(value["pr"], 0)):
        raise ValueError("invalid consumer identity")
    if any(not isinstance(value[k], str) or not ci.SHA.fullmatch(value[k])
           for k in ("source_sha", "base_sha", "builder_sha", "input_commit", "input_blob")):
        raise ValueError("invalid consumer revision")
    if (value["input_ref"] != "refs/tags/consumer-input-" + value["request_id"]
            or not isinstance(value["source_cipher_digest"], str)
            or not ci.HASH.fullmatch(value["source_cipher_digest"])):
        raise ValueError("invalid consumer transport")
    now = int(time.time())
    if (not integer(value["created"], 0) or not integer(value["expires"], 0)
            or value["created"] > now + 300 or value["expires"] < now
            or not 0 < value["expires"] - value["created"] <= 21600):
        raise ValueError("expired consumer request")


def validate_policy(value):
    if (not isinstance(value, dict) or set(value) !=
            {"schema", "repository", "repository_id", "operator_id", "recipe_sha256", "inputs"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not repository(value["repository"]) or not integer(value["repository_id"])
            or type(value["operator_id"]) is not int or value["operator_id"] != 5323024
            or not isinstance(value["recipe_sha256"], str) or not ci.HASH.fullmatch(value["recipe_sha256"])
            or not isinstance(value["inputs"], list) or not 1 <= len(value["inputs"]) <= 8):
        raise ValueError("invalid consumer policy")
    names = set()
    total = 0
    for item in value["inputs"]:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.(?:bundle|zip|json)", item["name"])
                or item["name"] in names or not repository(item.get("repository"))):
            raise ValueError("invalid consumer input")
        names.add(item["name"])
        if item.get("kind") == "git":
            if (set(item) != {"name", "kind", "repository", "sha"}
                    or not item["name"].endswith(".bundle") or not isinstance(item["sha"], str)
                    or not ci.SHA.fullmatch(item["sha"])):
                raise ValueError("invalid immutable consumer Git input")
            total += ci.MAX_GIT_INPUT
        elif item.get("kind") == "asset":
            if (set(item) != {"name", "kind", "repository", "tag", "asset", "sha256", "max_bytes"}
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", item["tag"])
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,150}", item["asset"])
                    or not isinstance(item["sha256"], str) or not ci.HASH.fullmatch(item["sha256"])
                    or not integer(item["max_bytes"], 1, MAX_RESOURCE)):
                raise ValueError("invalid pinned consumer asset")
            total += item["max_bytes"]
        else:
            raise ValueError("unsupported consumer input")
    if total > MAX_PREPARED:
        raise ValueError("consumer inputs exceed aggregate limit")


def validate_recipe(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "lanes"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["lanes"], list) or len(value["lanes"]) != len(LANES)):
        raise ValueError("invalid consumer recipe")
    names = []
    for lane in value["lanes"]:
        if (not isinstance(lane, dict) or set(lane) != {"id", "argv", "timeout"}
                or lane["id"] not in LANES or lane["argv"] != ["bash", "ci/builder/qualify.sh", lane["id"]]
                or not integer(lane["timeout"], 60, 10800)):
            raise ValueError("invalid consumer lane")
        names.append(lane["id"])
    if set(names) != set(LANES):
        raise ValueError("incomplete consumer recipe")
    return value["lanes"]


def context(purpose, value, *, hosted=False):
    result = {"schema": 1, "purpose": "consumer-ci-" + purpose,
              "request_id": value["request_id"], "builder_id": ci.BUILDER_ID,
              "builder_sha": value["builder_sha"]}
    if hosted:
        result.update(run=int(ci.required("GITHUB_RUN_ID")), attempt=1,
                      request_digest=ci.required("CONSUMER_REQUEST_DIGEST"))
    return result


def key(name):
    return ci.key_env("CONSUMER_" + name)


def policy():
    value = crypto.parse(crypto.unb64(ci.required("CONSUMER_POLICY_B64")))
    validate_policy(value)
    return value


def source_identity(value, selected, token):
    if (value["source"] != selected["repository"] or value["source_id"] != selected["repository_id"]
            or value["operator_id"] != selected["operator_id"]):
        raise ValueError("consumer source denied")
    prefix = "repos/" + value["source"]
    repo = ci.api_json(prefix, token, limit=32768)
    if repo["id"] != value["source_id"] or repo["full_name"] != value["source"] or repo["private"] is not True:
        raise ValueError("consumer repository identity mismatch")
    if value["pr"]:
        pr = ci.api_json(prefix + "/pulls/" + str(value["pr"]), token, limit=512 * 1024)
        if (pr["state"] != "open" or pr["head"]["sha"] != value["source_sha"]
                or pr["base"]["sha"] != value["base_sha"] or pr["base"]["ref"] != "main"
                or any(pr[k]["repo"]["id"] != value["source_id"] for k in ("head", "base"))):
            raise ValueError("stale or foreign consumer PR")
    else:
        ref = ci.api_json(prefix + "/git/ref/heads/main", token, limit=16384)["object"]
        if (ref.get("type") != "commit" or ref.get("sha") != value["source_sha"]
                or value["base_sha"] != value["source_sha"]):
            raise ValueError("consumer must qualify current main")


def validate_execution(value, digest, run):
    if (not isinstance(run, dict) or not
            {"repository", "head_repository", "head_sha", "path", "event", "run_attempt",
             "display_title", "actor", "triggering_actor", "html_url", "id"} <= set(run)):
        raise ValueError("malformed consumer execution")
    if (run["repository"]["id"] != ci.BUILDER_ID or run["head_repository"]["id"] != ci.BUILDER_ID
            or run["path"].split("@", 1)[0] != ".github/workflows/" + WORKFLOW
            or run["head_sha"] != value["builder_sha"] or run["event"] != "workflow_dispatch"
            or run["run_attempt"] != 1 or run["display_title"] != "Encrypted consumer " + digest
            or any(run[k]["id"] != value["operator_id"] for k in ("actor", "triggering_actor"))
            or run["html_url"] != f"https://github.com/{ci.BUILDER}/actions/runs/{run['id']}"):
        raise ValueError("untrusted consumer execution")


def validate_result(value, digest, run, jobs):
    validate_execution(value, digest, run)
    expected = {"prepare", "Consumer required"} | {"Consumer " + lane for lane in LANES}
    if (run["status"] != "completed" or run["conclusion"] != "success" or len(jobs) != len(expected)
            or {job["name"] for job in jobs} != expected
            or any(job["status"] != "completed" or job["conclusion"] != "success"
                   or job["run_id"] != run["id"] or job["head_sha"] != value["builder_sha"]
                   or not job.get("steps") or any(s["status"] != "completed" or
                      s["conclusion"] not in {"success", "skipped"} for s in job["steps"]) for job in jobs)):
        raise ValueError("consumer qualification incomplete")
    required_steps = {"prepare": "Authenticate consumer and prepare pinned inputs",
                      "Consumer required": "Require every consumer lane"}
    for job in jobs:
        name = required_steps.get(job["name"], "Execute native recipe")
        if sum(s.get("name") == name and s["conclusion"] == "success" for s in job["steps"]) != 1:
            raise ValueError("consumer required step was not executed")


def signed_request():
    digest = ci.required("CONSUMER_REQUEST_DIGEST")
    sealed = ci.required("CONSUMER_REQUEST")
    if not ci.HASH.fullmatch(digest) or ci.digest_bytes(sealed.encode("ascii")) != digest:
        raise ValueError("consumer request digest mismatch")
    reference = {"request_id": ci.required("CONSUMER_REQUEST_ID"), "builder_sha": ci.required("GITHUB_SHA")}
    document = crypto.parse(crypto.open_message(sealed, key("INPUT_PRIVATE_KEY_B64"), context("request", reference)))
    value = crypto.verify(document, key("VERIFY_PUBLIC_KEY_B64"))
    validate_request(value)
    if value["request_id"] != reference["request_id"] or value["builder_sha"] != reference["builder_sha"]:
        raise ValueError("consumer request binding mismatch")
    return document, value


def git_bundle(repository_name, revision, path, token, work):
    """Fetch immutable objects without checking out or running project code."""
    repo = work / (path.stem + "-git")
    env = ci.git_environment(os.environ, work)
    env.update(GIT_CONFIG_COUNT="3", GIT_CONFIG_KEY_1="credential.helper", GIT_CONFIG_VALUE_1="",
               GIT_CONFIG_KEY_2="http.https://github.com/.extraheader",
               GIT_CONFIG_VALUE_2="AUTHORIZATION: basic " +
               base64.b64encode(("x-access-token:" + token).encode()).decode())
    log = work / "preparation.log"
    ci.checked(["git", "init", "--bare", str(repo)], work, env, log)
    ci.checked(["git", "-C", str(repo), "fetch", "--no-tags", "--depth=1",
                "https://github.com/" + repository_name + ".git", revision + ":refs/heads/input"], work, env, log)
    ci.checked(["git", "-C", str(repo), "bundle", "create", str(path), "--all"], work, env, log)
    if path.stat().st_size > ci.MAX_GIT_INPUT:
        raise ValueError("consumer Git input too large")
    ci.remove_staging(repo)


def download_asset(item, path, token):
    release = ci.api_json(f"repos/{item['repository']}/releases/tags/{item['tag']}", token, limit=2 * 1024**2)
    matches = [a for a in release["assets"] if a["name"] == item["asset"]]
    if (release["draft"] or release["prerelease"] or release["tag_name"] != item["tag"]
            or len(matches) != 1 or not integer(matches[0]["size"], 1, item["max_bytes"])):
        raise ValueError("consumer asset metadata rejected")
    url = f"https://api.github.com/repos/{item['repository']}/releases/assets/{matches[0]['id']}"
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, target):
            return None
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                              "Accept": "application/octet-stream"})
    try:
        stream = urllib.request.build_opener(NoRedirect()).open(req, timeout=90)
    except urllib.error.HTTPError as error:
        target = error.headers.get("Location", "")
        host = urllib.parse.urlparse(target)
        if error.code not in (301, 302, 303, 307, 308) or host.scheme != "https" or host.username or host.password:
            raise ValueError("consumer asset redirect rejected") from None
        stream = urllib.request.urlopen(target, timeout=90)  # No Authorization on storage.
    count = 0
    with stream, path.open("xb") as out:
        while block := stream.read(1024 * 1024):
            count += len(block)
            if count > item["max_bytes"]:
                raise ValueError("consumer asset exceeds bound")
            out.write(block)
    if count != matches[0]["size"] or crypto.digest(path) != item["sha256"]:
        raise ValueError("consumer asset checksum mismatch")


def checkout(bundle, root, revision, work):
    env = ci.git_environment(os.environ, work)
    log = work / "preparation.log"
    ci.checked(["git", "clone", "--no-checkout", str(bundle), str(root)], work, env, log)
    ci.checked(["git", "-C", str(root), "fsck", "--no-reflogs"], work, env, log)
    ci.checked(["git", "-C", str(root), "-c", "core.autocrlf=false", "checkout", "--detach", revision], work, env, log)
    return env


def recipe(root, selected):
    path = root / RECIPE
    if (path.is_symlink() or not path.resolve().is_relative_to(root.resolve())
            or any(p.is_symlink() for p in (root / "ci", root / "ci/builder"))
            or not path.is_file() or path.stat().st_size > 65536
            or crypto.digest(path) != selected["recipe_sha256"]):
        raise ValueError("consumer recipe differs from protected policy")
    return validate_recipe(crypto.parse(path.read_bytes()))


def work_root():
    return Path(ci.required("RUNNER_TEMP")) / "consumer-ci"


def prepare():
    if (ci.required("GITHUB_REPOSITORY") != ci.BUILDER
            or ci.required("GITHUB_REPOSITORY_ID") != str(ci.BUILDER_ID)
            or ci.required("GITHUB_SHA") != ci.required("CONSUMER_BUILDER_SHA")
            or ci.required("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or ci.required("GITHUB_RUN_ATTEMPT") != "1" or os.environ.get("RUNNER_DEBUG") == "1"):
        raise ValueError("unapproved consumer builder")
    document, value = signed_request()
    selected = policy()
    token = ci.required("SOURCE_READ_TOKEN")
    source_identity(value, selected, token)
    reader = ci.required("BUILDER_READ_TOKEN")
    runs = ci.pages(f"repos/{ci.BUILDER}/actions/workflows/{WORKFLOW}/runs?head_sha={value['builder_sha']}",
                    reader, "workflow_runs")
    matches = [r for r in runs if r["display_title"] == "Encrypted consumer " + ci.required("CONSUMER_REQUEST_DIGEST")]
    if len(matches) != 1 or matches[0]["id"] != int(ci.required("GITHUB_RUN_ID")):
        raise ValueError("consumer request replay")
    validate_execution(value, ci.required("CONSUMER_REQUEST_DIGEST"), matches[0])
    work = work_root()
    work.mkdir(mode=0o700)
    ci.fetch_operator_input(value, reader, work / "source.enc")
    crypto.decrypt_file(work / "source.enc", work / "source.bundle", key("INPUT_PRIVATE_KEY_B64"),
                        context("source", value))
    root = work / "source"
    checkout(work / "source.bundle", root, value["source_sha"], work)
    lanes = recipe(root, selected)
    # Resources are independent protected policy, never source-selected URLs.
    inputs = work / "inputs"
    inputs.mkdir(mode=0o700)
    for item in selected["inputs"]:
        if item["kind"] == "git":
            git_bundle(item["repository"], item["sha"], inputs / item["name"], token, work)
        else:
            download_asset(item, inputs / item["name"], token)
    source_identity(value, selected, token)  # Refuse a PR moved during preparation.
    (work / "request.json").write_bytes(crypto.canonical(document))
    with tarfile.open(work / "prepared.tar", "w") as archive:
        for name in ("source.bundle", "request.json"):
            archive.add(work / name, arcname=name, recursive=False)
        archive.add(inputs, arcname="inputs")
    if (work / "prepared.tar").stat().st_size > MAX_PREPARED:
        raise ValueError("prepared consumer inputs exceed bound")
    out = Path(ci.required("RUNNER_TEMP")) / "consumer-cipher"
    out.mkdir(mode=0o700)
    crypto.encrypt_file(work / "prepared.tar", out / "inputs.enc",
                        crypto.public_text(key("INPUT_PRIVATE_KEY_B64")), context("prepared", value, hosted=True))
    # The request document is already public-key signed and remains private.
    ci.output("matrix", crypto.canonical({"include": [{"lane": lane["id"]} for lane in lanes]}).decode())
    ci.remove_staging(work)


def materialize():
    _, value = signed_request()
    selected = policy()
    if value["source"] != selected["repository"] or value["source_id"] != selected["repository_id"]:
        raise ValueError("consumer source denied")
    work = work_root()
    work.mkdir(mode=0o700)
    crypto.decrypt_file(Path(ci.required("RUNNER_TEMP")) / "consumer-cipher/inputs.enc", work / "prepared.tar",
                        key("INPUT_PRIVATE_KEY_B64"), context("prepared", value, hosted=True))
    staging = work / "staging"
    safeio.extract_tar(work / "prepared.tar", staging)
    document = crypto.parse((staging / "request.json").read_bytes())
    if crypto.verify(document, key("VERIFY_PUBLIC_KEY_B64")) != value:
        raise ValueError("consumer distributed request mismatch")
    expected = {"source.bundle", "request.json", "inputs"}
    if {p.name for p in staging.iterdir()} != expected:
        raise ValueError("unexpected consumer prepared member")
    inputs = staging / "inputs"
    if {p.name for p in inputs.iterdir()} != {i["name"] for i in selected["inputs"]}:
        raise ValueError("consumer input inventory mismatch")
    root = work / "source"
    checkout(staging / "source.bundle", root, value["source_sha"], work)
    recipe(root, selected)
    for item in selected["inputs"]:
        path = inputs / item["name"]
        if item["kind"] == "asset":
            if path.stat().st_size > item["max_bytes"] or crypto.digest(path) != item["sha256"]:
                raise ValueError("distributed consumer asset mismatch")
            if path.suffix == ".zip":
                safeio.zip_files(path)
        else:
            dep = work / (path.stem + "-source")
            env = checkout(path, dep, item["sha"], work)
            ci.checked(["git", "-C", str(dep), "archive", "--format=tar.gz", item["sha"],
                        "-o", str(inputs / (path.stem + ".tar.gz"))], work, env, work / "preparation.log")
            ci.remove_staging(dep)
            path.unlink()
    (work / "request.json").write_bytes(crypto.canonical(value))
    (work / "prepared.tar").unlink()


def run():
    work = work_root()
    value = crypto.parse((work / "request.json").read_bytes())
    validate_request(value)
    root = work / "source"
    lanes = recipe(root, policy())
    selected = [lane for lane in lanes if lane["id"] == ci.required("CONSUMER_LANE")]
    if len(selected) != 1:
        raise ValueError("unknown consumer lane")
    env = ci.build_environment(os.environ)
    env.update(CONSUMER_INPUTS_DIR=str(work / "staging/inputs"), CONSUMER_RESULTS_DIR=str(work / "results"),
               CONSUMER_SOURCE_SHA=value["source_sha"], CONSUMER_BASE_SHA=value["base_sha"],
               CI="true", GIT_TERMINAL_PROMPT="0",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    Path(env["CONSUMER_RESULTS_DIR"]).mkdir(mode=0o700)
    code = ci.quiet(selected[0]["argv"], root, env, work / "logs/native.log", timeout=selected[0]["timeout"])
    if code:
        raise ValueError("consumer command failed")
    (work / "results/result.json").write_bytes(crypto.canonical({"schema": 1, "source_sha": value["source_sha"],
        "builder_sha": value["builder_sha"], "lane": selected[0]["id"], "status": "success"}))


def outputs():
    """Keep results and native diagnostics private, including after failure."""
    work = work_root()
    if not work.exists():
        work.mkdir(mode=0o700)
    public = crypto.unb64((Path(__file__).resolve().parents[1] / "ci/builder-logs-public-key.b64").read_text().strip()).decode()
    cipher = Path(ci.required("RUNNER_TEMP")) / "consumer-output"
    cipher.mkdir(mode=0o700, exist_ok=True)
    encrypted_logs.collect([work], cipher / "diagnostics.enc", public, encrypted_logs.github_context())
    results = work / "results"
    if results.is_dir():
        archive = work / "results.tar.gz"
        safeio.pack_tar(results, archive)
        if archive.stat().st_size > MAX_PREPARED:
            raise ValueError("consumer result archive exceeds bound")
        value = crypto.parse((work / "request.json").read_bytes())
        validate_request(value)
        ctx = context("results", value, hosted=True)
        ctx["lane"] = ci.required("CONSUMER_LANE")
        crypto.encrypt_file(archive, cipher / "results.enc", public, ctx)
        archive.unlink()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "materialize", "run", "outputs", "cleanup"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.stage == "cleanup":
            if work_root().exists():
                ci.remove_staging(work_root())
        else:
            globals()[args.stage]()
        print("CONSUMER_STAGE_SUCCESS " + args.stage)
    except Exception as error:
        # No exception text, source lines, locals, input names, URLs or credentials.
        work = work_root()
        work.mkdir(mode=0o700, exist_ok=True)
        import traceback
        (work / "failure.json").write_bytes(crypto.canonical({"stage": args.stage, "type": type(error).__name__,
            "frames": [{"function": f.name, "line": f.lineno}
                       for f in traceback.extract_tb(error.__traceback__)[-8:]]}))
        raise SystemExit("CONSUMER_STAGE_FAILED " + args.stage) from None


if __name__ == "__main__":
    main()
