"""Signed project-CI requests and ciphertext-only cross-repository transport.

This uses the existing Tink envelope, not a new cipher. Fetch/decrypt stages
never execute source code. The separate recipe runner receives no credentials.
All errors exposed to Actions are bounded stage identities, never exceptions.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile

from . import crypto, encrypted_logs

BUILDER = "dobord/builder"
BUILDER_ID = 1372874997
WORKFLOW = "encrypted-project-ci.yml"
SHA = re.compile(r"[0-9a-f]{40}")
HASH = re.compile(r"[0-9a-f]{64}")
MAX_ARCHIVE = 2 * 1024**3
SUITES = {"ci": ("ci", "wasm-async"), "async": ("wasm-async",),
          "nightly": ("nightly-stress",), "performance": ("performance",),
          "vcpkg": ("vcpkg-port",),
          "release": ("ci", "wasm-async", "nightly-stress", "performance", "vcpkg-port")}
AGGREGATES = {"ci-required", "async-required", "dependency-review"}
EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise ValueError("missing configuration")
    return value


def key_env(name):
    return crypto.unb64(required(name)).decode("utf-8")


def api(path, token, *, data=None, limit=MAX_ARCHIVE):
    if not path.startswith("repos/") or ".." in path:
        raise ValueError("unsafe API path")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    body = None if data is None else crypto.canonical(data)
    # Never forward Authorization to artifact storage redirect hosts.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(urllib.request.Request("https://api.github.com/" + path,
                                                      data=body, headers=headers), timeout=90)
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308) or data is not None:
            raise ValueError("GitHub API refused request") from None
        url = error.headers.get("Location", "")
        if not url.startswith("https://"):
            raise ValueError("unsafe artifact redirect")
        response = urllib.request.urlopen(url, timeout=90)
    with response:
        content = response.read(limit + 1)
    if len(content) > limit:
        raise ValueError("API response too large")
    return content


def api_json(path, token, **kwargs):
    raw = api(path, token, **kwargs)
    return crypto.parse(raw) if raw else None


def pages(path, token, field=None):
    result = []
    for page in range(1, 101):
        separator = "&" if "?" in path else "?"
        value = api_json(f"{path}{separator}per_page=100&page={page}", token, limit=8 * 1024**2)
        items = value[field] if field else value
        if not isinstance(items, list):
            raise ValueError("invalid paginated response")
        result.extend(items)
        if len(items) < 100:
            return result
    raise ValueError("pagination limit exceeded")


def quiet(command, cwd, env, log, *, timeout=21600):
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
        try:
            return child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], stdout=output,
                               stderr=subprocess.STDOUT, check=False, timeout=30)
            else:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=30)
            raise ValueError("private subprocess timed out") from None


def checked(command, cwd, env, log):
    if quiet(command, cwd, env, log):
        raise ValueError("private subprocess failed")


def build_environment(environ):
    names = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
             "SystemRoot", "SYSTEMROOT", "COMSPEC", "PATHEXT", "USERPROFILE",
             "ProgramFiles", "ProgramFiles(x86)", "NUMBER_OF_PROCESSORS",
             "VCPKG_INSTALLATION_ROOT", "RUNNER_OS", "RUNNER_ARCH", "SystemDrive", "SYSTEMDRIVE",
             "ProgramData", "ALLUSERSPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH",
             "PSModulePath", "ChocolateyInstall", "VCToolsInstallDir", "WindowsSdkDir", "VSINSTALLDIR",
             "VCINSTALLDIR", "UniversalCRTSdkDir", "INCLUDE", "LIB", "LIBPATH"}
    return {name: value for name, value in environ.items() if name in names}


def git_environment(environ, work):
    """Fetch/check out data without host hooks, filters or credential helpers."""
    env = build_environment(environ)
    hooks = work / "no-hooks"
    hooks.mkdir(mode=0o700, exist_ok=True)
    if hooks.is_symlink() or any(hooks.iterdir()):
        raise ValueError("unsafe Git hook staging")
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": str(hooks)})
    return env


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def message_context(request_id):
    if str(uuid.UUID(request_id)) != request_id:
        raise ValueError("invalid request ID")
    return {"schema": 1, "purpose": "project-ci-request", "request_id": request_id,
            "builder_id": BUILDER_ID}


def source_context(payload):
    return {"schema": 1, "purpose": "project-ci-sources", "request_id": payload["request_id"],
            "source_id": payload["source_id"], "source_run": payload["source_run"],
            "source_attempt": payload["source_attempt"], "builder_sha": payload["builder_sha"]}


def validate_payload(payload):
    fields = {"schema", "request_id", "source", "source_id", "source_sha", "base_sha",
              "source_run", "source_attempt", "source_event", "pr", "builder_sha", "suite",
              "created", "expires", "artifact_id", "artifact_digest", "source_cipher_digest", "baseline_run",
              "baseline_tag", "baseline_sha"}
    if set(payload) != fields or type(payload["schema"]) is not int or payload["schema"] != 1:
        raise ValueError("invalid CI request schema")
    message_context(payload["request_id"])
    if not re.fullmatch(r"dobord/[A-Za-z0-9_.-]+", payload["source"]):
        raise ValueError("invalid source repository")
    for name in ("source_sha", "base_sha", "builder_sha", "baseline_sha"):
        if not isinstance(payload[name], str) or not SHA.fullmatch(payload[name]):
            raise ValueError("invalid exact revision")
    for name in ("source_id", "source_run", "source_attempt", "artifact_id"):
        if type(payload[name]) is not int or not 1 <= payload[name] < 2**63:
            raise ValueError("invalid identity")
    for name in ("pr", "baseline_run"):
        if type(payload[name]) is not int or not 0 <= payload[name] < 2**63:
            raise ValueError("invalid optional identity")
    if payload["suite"] not in SUITES or payload["source_event"] not in {"push", "workflow_dispatch", "schedule"}:
        raise ValueError("unsupported CI profile or authorizer")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", payload["baseline_tag"]) or payload["baseline_run"]:
        raise ValueError("hosted comparisons require an immutable release tag, not a rolling runner baseline")
    if payload["suite"] in {"performance", "release"} and payload["baseline_sha"] == payload["source_sha"]:
        raise ValueError("benchmark baseline must differ from candidate")
    if not HASH.fullmatch(payload["artifact_digest"]) or not HASH.fullmatch(payload["source_cipher_digest"]):
        raise ValueError("invalid artifact digest")
    now = int(time.time())
    if any(type(payload[name]) is not int for name in ("created", "expires")):
        raise ValueError("invalid request clock")
    if (not payload["created"] <= now + 300 or payload["expires"] < now or
            not 0 < payload["expires"] - payload["created"] <= 21600):
        raise ValueError("expired CI request")


def expand(text, context):
    if not isinstance(text, str):
        return text
    def replacement(match):
        expression = match.group(1)
        if expression not in context:
            raise ValueError("unsupported recipe expression")
        return str(context[expression])
    return EXPRESSION.sub(replacement, text)


def expand_recipe(profile, recipe):
    lanes = []
    for job_id, job in recipe["jobs"].items():
        if job_id in AGGREGATES:
            continue
        matrix = job.get("strategy", {}).get("matrix", {})
        if "include" in matrix:
            if set(matrix) != {"include"}:
                raise ValueError("unsupported mixed matrix")
            rows = matrix["include"]
        elif matrix:
            rows = [dict(zip(matrix, values)) for values in itertools.product(*matrix.values())]
        else:
            rows = [{}]
        for index, row in enumerate(rows):
            context = {"matrix." + key: value for key, value in row.items()}
            runner = job["runs-on"]
            labels = runner if isinstance(runner, list) else [expand(runner, context)]
            lanes.append({"id": f"{profile}-{job_id}-{index}", "runner": labels,
                          "profile": profile, "job": job, "matrix": row})
    return lanes


def recipes(root, suite):
    import yaml
    lanes = []
    for profile in SUITES[suite]:
        path = root / "ci/builder" / (profile + ".yml")
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        lanes.extend(expand_recipe(profile, document))
    if not 1 <= len(lanes) <= 100 or len({lane["id"] for lane in lanes}) != len(lanes):
        raise ValueError("invalid lane inventory")
    return lanes


def unwrap_artifact(archive, target, member="sources.enc"):
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if (len(entries) != 1 or entries[0].filename != member or
                not 1 <= entries[0].file_size <= MAX_ARCHIVE or entries[0].flag_bits & 1):
            raise ValueError("unsafe source artifact")
        with source.open(entries[0]) as incoming, target.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)


def output(name, value):
    if not re.fullmatch(r"[a-z_]+", name) or "\n" in value or "\r" in value:
        raise ValueError("unsafe workflow output")
    with Path(required("GITHUB_OUTPUT")).open("a", encoding="utf-8") as out:
        out.write(name + "=" + value + "\n")


def package():
    """Trusted sender: git-only fetch, bundle, and encryption; no source execution."""
    work = Path(required("RUNNER_TEMP")) / "project-ci-package"
    work.mkdir(mode=0o700)
    log = work / "transport.log"
    source = required("GITHUB_REPOSITORY")
    source_sha = required("CI_SOURCE_SHA")
    base_sha = required("CI_BASE_SHA")
    builder_sha = required("CI_BUILDER_SHA")
    if any(not SHA.fullmatch(value) for value in (source_sha, base_sha, builder_sha)):
        raise ValueError("exact commits required")
    request_id = str(uuid.uuid4())
    now = int(time.time())
    payload = {"schema": 1, "request_id": request_id, "source": source,
               "source_id": int(required("GITHUB_REPOSITORY_ID")), "source_sha": source_sha,
               "base_sha": base_sha, "builder_sha": builder_sha,
               "source_run": int(required("GITHUB_RUN_ID")),
               "source_attempt": int(required("GITHUB_RUN_ATTEMPT")),
               "source_event": required("GITHUB_EVENT_NAME"), "pr": int(os.environ.get("CI_PR", "0")),
               "suite": required("CI_SUITE"), "created": now, "expires": now + 21600,
               "artifact_id": 1, "artifact_digest": "0" * 64,
               "source_cipher_digest": "0" * 64,
               "baseline_run": int(os.environ.get("CI_BASELINE_RUN", "0"))}
    payload["baseline_tag"] = required("CI_BASELINE_TAG")
    payload["baseline_sha"] = required("CI_BASELINE_SHA")
    validate_payload(payload)
    env = git_environment(os.environ, work)
    auth = base64.b64encode(("x-access-token:" + required("SOURCE_READ_TOKEN")).encode()).decode()
    env.update({"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_1": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_1": "AUTHORIZATION: basic " + auth})
    repo = work / "repository"
    checked(["git", "init", "--bare", str(repo)], work, env, log)
    checked(["git", "-C", str(repo), "fetch", "--no-tags", "https://github.com/" + source + ".git",
             source_sha + ":refs/heads/candidate", base_sha + ":refs/heads/base"], work, env, log)
    if payload["suite"] in {"performance", "release"}:
        checked(["git", "-C", str(repo), "fetch", "--no-tags", "https://github.com/" + source + ".git",
                 payload["baseline_sha"] + ":refs/heads/performance-baseline"], work, env, log)
    plain = work / "repository.bundle"
    checked(["git", "-C", str(repo), "bundle", "create", str(plain), "--all"], work, env, log)
    if not 0 < plain.stat().st_size <= MAX_ARCHIVE - 1024**2:
        raise ValueError("source bundle exceeds project-CI limit")
    crypto.encrypt_file(plain, work / "sources.enc", key_env("CI_INPUT_PUBLIC_KEY_B64"), source_context(payload))
    payload["source_cipher_digest"] = crypto.digest(work / "sources.enc")
    (work / "pending.json").write_bytes(crypto.canonical(payload))
    plain.unlink()
    shutil.rmtree(repo)
    output("request_id", request_id)


def validate_run(run, revision, request_digest, attempt):
    if (run["repository"]["id"] != BUILDER_ID or run["head_repository"]["id"] != BUILDER_ID or
            run["path"].split("@", 1)[0] != ".github/workflows/" + WORKFLOW or
            run["head_sha"] != revision or run["event"] != "workflow_dispatch" or
            run["run_attempt"] != attempt or
            run["display_title"] != "Encrypted qualification " + request_digest or
            run["status"] != "completed" or run["conclusion"] != "success"):
        raise ValueError("untrusted or unsuccessful builder run")


def dispatch():
    work = Path(required("RUNNER_TEMP")) / "project-ci-package"
    payload = crypto.parse((work / "pending.json").read_bytes())
    payload["artifact_id"] = int(required("CI_ARTIFACT_ID"))
    payload["artifact_digest"] = required("CI_ARTIFACT_DIGEST").removeprefix("sha256:")
    validate_payload(payload)
    request = crypto.seal_message(crypto.canonical(crypto.sign(payload, key_env("CI_SIGNING_PRIVATE_KEY_B64"))),
                                  key_env("CI_INPUT_PUBLIC_KEY_B64"), message_context(payload["request_id"]))
    request_digest = digest_bytes(request.encode("ascii"))
    token = required("BUILDER_DISPATCH_TOKEN")
    api_json(f"repos/{BUILDER}/actions/workflows/{WORKFLOW}/dispatches", token, data={
        "ref": required("CI_BUILDER_REF"), "inputs": {"request_id": payload["request_id"],
            "request_digest": request_digest, "request": request}})
    deadline = time.monotonic() + 21600
    run = None
    while time.monotonic() < deadline:
        runs = pages(f"repos/{BUILDER}/actions/workflows/{WORKFLOW}/runs?head_sha={payload['builder_sha']}",
                     token, "workflow_runs")
        matches = [item for item in runs if item["display_title"] == "Encrypted qualification " + request_digest]
        if len(matches) > 1:
            raise ValueError("ambiguous/replayed CI request")
        if matches:
            run = matches[0]
            if run["run_attempt"] != 1:
                raise ValueError("rerun requires a fresh signed request")
            if run["status"] == "completed":
                break
        time.sleep(30)
    if run is None:
        raise ValueError("builder dispatch timed out")
    validate_run(run, payload["builder_sha"], request_digest, 1)
    validate_payload(payload)
    # Only a verified external completion is mirrored. A failed sender leaves
    # no successful status and therefore cannot authorize release.
    api_json(f"repos/{payload['source']}/statuses/{payload['source_sha']}", required("SOURCE_STATUS_TOKEN"),
             data={"state": "success", "context": "Builder " + payload["suite"] + " Required",
                   "description": "Verified encrypted qualification on the exact source SHA",
                   "target_url": run["html_url"]})
    print("BUILDER_QUALIFICATION_SUCCESS " + run["html_url"])


def verify_source_policy(payload, token):
    policy = crypto.parse(required("CI_SOURCE_POLICY"))
    if payload["source"] != policy["repository"] or payload["source_id"] != policy["repository_id"]:
        raise ValueError("source not authorized")
    if payload["suite"] in {"performance", "release"}:
        released = api_json(f"repos/{payload['source']}/releases/tags/{payload['baseline_tag']}", token)
        if released["draft"] or released["prerelease"] or released["tag_name"] != payload["baseline_tag"] or not released["published_at"]:
            raise ValueError("baseline is not a published stable release")
        reference = api_json(f"repos/{payload['source']}/git/ref/tags/{payload['baseline_tag']}", token)["object"]
        for _ in range(4):
            if reference["type"] == "commit":
                break
            if reference["type"] != "tag":
                raise ValueError("invalid released baseline")
            reference = api_json(f"repos/{payload['source']}/git/tags/{reference['sha']}", token)["object"]
        if reference["type"] != "commit" or reference["sha"] != payload["baseline_sha"]:
            raise ValueError("released baseline identity mismatch")
    run = api_json(f"repos/{payload['source']}/actions/runs/{payload['source_run']}", token)
    if (run["repository"]["id"] != payload["source_id"] or
            run["head_repository"]["id"] != payload["source_id"] or
            run["path"].split("@", 1)[0] != ".github/workflows/builder-ci.yml" or
            run["run_attempt"] != payload["source_attempt"] or
            run["event"] != payload["source_event"] or
            run["head_branch"] != policy["authorizer_branch"]):
        raise ValueError("untrusted source authorizer")
    if not payload["pr"]:
        if payload["source_sha"] != run["head_sha"]:
            raise ValueError("non-PR request must qualify the authorizer tree")
        return
    pr = api_json(f"repos/{payload['source']}/pulls/{payload['pr']}", token)
    if (pr["head"]["sha"] != payload["source_sha"] or pr["base"]["sha"] != payload["base_sha"] or
            pr["head"]["repo"]["id"] != payload["source_id"] or pr["state"] != "open"):
        raise ValueError("stale or foreign PR")
    # The release profile is authorized by the protected signer and complete
    # exact-SHA CI qualification, without a separate manual approval gate.
    # Ordinary CI retains its existing sensitive-boundary PR review policy.
    if payload["suite"] != "release":
        files = pages(f"repos/{payload['source']}/pulls/{payload['pr']}/files", token)
        paths = [item["filename"] for item in files]
        boundaries = sum(any(re.search(pattern, name) for name in paths) for pattern in policy["approval_boundaries"])
        platforms = sum(any(re.search(r"(^|/)" + platform + r"(/|\.|_)", name) for name in paths)
                        for platform in ("linux", "windows", "bsd", "macos", "apple", "darwin"))
        needed = 2 if boundaries > 1 or platforms > 1 else int(boundaries > 0)
        reviews = pages(f"repos/{payload['source']}/pulls/{payload['pr']}/reviews", token)
        latest = {}
        for review in sorted(reviews, key=lambda item: item["id"]):
            if review["state"] != "COMMENTED":
                latest[review["user"]["login"]] = review
        approvals = {login for login, review in latest.items() if review["state"] == "APPROVED" and
                     review["commit_id"] == payload["source_sha"] and login != pr["user"]["login"] and
                     review["user"].get("type") == "User"}
        if len(approvals) < needed:
            raise ValueError("current-head independent approval missing")
    comparison = pages(f"repos/{payload['source']}/dependency-graph/compare/{payload['base_sha']}...{payload['source_sha']}", token)
    for dependency in comparison:
        if dependency.get("change_type") != "added":
            continue
        for vulnerability in dependency["vulnerabilities"]:
            severity = vulnerability["severity"].lower()
            if severity not in {"low", "moderate", "high", "critical"} or severity != "low":
                raise ValueError("dependency-review gate failed")


def prepare():
    if (required("GITHUB_REPOSITORY") != BUILDER or int(required("GITHUB_REPOSITORY_ID")) != BUILDER_ID or
            required("GITHUB_SHA") != required("CI_BUILDER_SHA") or
            os.environ.get("RUNNER_DEBUG") == "1" or required("GITHUB_EVENT_NAME") != "workflow_dispatch" or
            int(required("GITHUB_RUN_ATTEMPT")) != 1):
        raise ValueError("unapproved builder execution")
    request = required("CI_REQUEST")
    if digest_bytes(request.encode("ascii")) != required("CI_REQUEST_DIGEST"):
        raise ValueError("request hash mismatch")
    previous = pages(f"repos/{BUILDER}/actions/workflows/{WORKFLOW}/runs?head_sha={required('GITHUB_SHA')}",
                     required("BUILDER_READ_TOKEN"), "workflow_runs")
    matches = [run for run in previous if run["display_title"] == "Encrypted qualification " + required("CI_REQUEST_DIGEST")]
    if len(matches) != 1 or matches[0]["id"] != int(required("GITHUB_RUN_ID")):
        raise ValueError("CI request replay or ambiguous execution")
    document = crypto.parse(crypto.open_message(request, key_env("CI_INPUT_PRIVATE_KEY_B64"),
                            message_context(required("CI_REQUEST_ID"))))
    payload = crypto.verify(document, key_env("CI_VERIFY_PUBLIC_KEY_B64"))
    validate_payload(payload)
    if payload["request_id"] != required("CI_REQUEST_ID") or payload["builder_sha"] != required("GITHUB_SHA"):
        raise ValueError("request identity mismatch")
    token = required("SOURCE_READ_TOKEN")
    verify_source_policy(payload, token)
    artifact = api_json(f"repos/{payload['source']}/actions/artifacts/{payload['artifact_id']}", token)
    if (artifact["expired"] or artifact["workflow_run"]["id"] != payload["source_run"] or
            artifact["name"] != "encrypted-sources-" + payload["request_id"] or
            not 1 <= artifact["size_in_bytes"] <= MAX_ARCHIVE):
        raise ValueError("source artifact provenance mismatch")
    work = Path(required("RUNNER_TEMP")) / "project-ci-prepare"
    work.mkdir(mode=0o700)
    zipped = api(f"repos/{payload['source']}/actions/artifacts/{payload['artifact_id']}/zip", token)
    if digest_bytes(zipped) != payload["artifact_digest"]:
        raise ValueError("source artifact digest mismatch")
    archive = work / "input.zip"
    archive.write_bytes(zipped)
    unwrap_artifact(archive, work / "sources.enc")
    archive.unlink()
    if crypto.digest(work / "sources.enc") != payload["source_cipher_digest"]:
        raise ValueError("signed ciphertext digest mismatch")
    crypto.decrypt_file(work / "sources.enc", work / "repository.bundle", key_env("CI_INPUT_PRIVATE_KEY_B64"),
                        source_context(payload))
    root = work / "source"
    env = git_environment(os.environ, work)
    log = work / "prepare.log"
    checked(["git", "clone", "--no-checkout", str(work / "repository.bundle"), str(root)], work, env, log)
    checked(["git", "-C", str(root), "-c", "core.autocrlf=false", "checkout", "--detach", payload["source_sha"]], work, env, log)
    lanes = recipes(root, payload["suite"])
    (work / "request.json").write_bytes(crypto.canonical(document))
    # Re-encrypt for this builder run/attempt before distributing to native jobs.
    archive = work / "prepared.tar"
    with tarfile.open(archive, "w") as out:
        out.add(work / "sources.enc", arcname="sources.enc", recursive=False)
        out.add(work / "request.json", arcname="request.json", recursive=False)
    crypto.encrypt_file(archive, Path(required("RUNNER_TEMP")) / "cipher-input/sources.enc",
                        crypto.public_text(key_env("CI_INPUT_PRIVATE_KEY_B64")), builder_context("sources"))
    output("matrix", json.dumps({"include": [{"lane": item["id"], "runner": item["runner"]} for item in lanes]}, separators=(",", ":")))
    shutil.rmtree(work)


def builder_context(purpose):
    return {"schema": 1, "purpose": "project-ci-" + purpose,
            "builder_sha": required("GITHUB_SHA"), "request_digest": required("CI_REQUEST_DIGEST"),
            "run": int(required("GITHUB_RUN_ID")), "attempt": int(required("GITHUB_RUN_ATTEMPT"))}


def materialize():
    work = Path(required("RUNNER_TEMP")) / "project-ci"
    work.mkdir(mode=0o700)
    archive = work / "prepared.tar"
    crypto.decrypt_file(Path(required("RUNNER_TEMP")) / "cipher-input/sources.enc", archive,
                        key_env("CI_INPUT_PRIVATE_KEY_B64"), builder_context("sources"))
    with tarfile.open(archive, "r") as incoming:
        entries = incoming.getmembers()
        if ({item.name for item in entries} != {"sources.enc", "request.json"} or len(entries) != 2 or
                any(not item.isfile() or not 0 < item.size <= (24576 if item.name == "request.json" else MAX_ARCHIVE) for item in entries)):
            raise ValueError("unsafe prepared bundle")
        incoming.extractall(work, filter="data")
    archive.unlink()
    document = crypto.parse((work / "request.json").read_bytes())
    payload = crypto.verify(document, key_env("CI_VERIFY_PUBLIC_KEY_B64"))
    validate_payload(payload)
    if payload["builder_sha"] != required("GITHUB_SHA") or payload["request_id"] != required("CI_REQUEST_ID"):
        raise ValueError("distributed request identity mismatch")
    if crypto.digest(work / "sources.enc") != payload["source_cipher_digest"]:
        raise ValueError("distributed source ciphertext digest mismatch")
    crypto.decrypt_file(work / "sources.enc", work / "repository.bundle", key_env("CI_INPUT_PRIVATE_KEY_B64"), source_context(payload))
    (work / "request.json").write_bytes(crypto.canonical(payload))
    root = Path(required("GITHUB_WORKSPACE")) / "private-source"
    env = git_environment(os.environ, work)
    log = work / "materialize.log"
    checked(["git", "clone", "--no-checkout", str(work / "repository.bundle"), str(root)], work, env, log)
    checked(["git", "-C", str(root), "-c", "core.autocrlf=false", "checkout", "--detach", payload["source_sha"]], work, env, log)
    checked(["git", "-C", str(root), "update-ref", "refs/remotes/origin/main", payload["base_sha"]], work, env, log)
    (work / "repository.bundle").unlink()
    if payload["suite"] in {"performance", "release"}:
        checked(["git", "-C", str(root), "worktree", "add", "--detach", str(work / "source-baseline"),
                 payload["baseline_sha"]], work, env, log)
    output("source_root", str(root))


def restore_baseline(payload, root, work):
    token = required("BUILDER_READ_TOKEN")
    run_id = payload["baseline_run"]
    run = api_json(f"repos/{BUILDER}/actions/runs/{run_id}", token)
    prefix = "Encrypted qualification "
    if not run["display_title"].startswith(prefix):
        raise ValueError("untrusted baseline run")
    request_digest = run["display_title"][len(prefix):]
    if not HASH.fullmatch(request_digest):
        raise ValueError("untrusted baseline request")
    validate_run(run, required("GITHUB_SHA"), request_digest, run["run_attempt"])
    artifacts = pages(f"repos/{BUILDER}/actions/runs/{run_id}/artifacts", token, "artifacts")
    selected = [item for item in artifacts if item["name"] == f"baseline-{run_id}-{run['run_attempt']}" and not item["expired"]]
    if len(selected) != 1 or not 0 < selected[0]["size_in_bytes"] <= MAX_ARCHIVE:
        raise ValueError("baseline artifact missing or ambiguous")
    artifact = selected[0]
    zipped = api(f"repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip", token)
    if artifact.get("digest") != "sha256:" + digest_bytes(zipped):
        raise ValueError("baseline artifact digest mismatch")
    zip_path = work / "baseline.zip"
    zip_path.write_bytes(zipped)
    unwrap_artifact(zip_path, work / "baseline.enc", "baseline.enc")
    zip_path.unlink()
    context = {"schema": 1, "purpose": "project-ci-baseline", "builder_sha": run["head_sha"],
               "request_digest": request_digest, "run": run_id, "attempt": run["run_attempt"]}
    crypto.decrypt_file(work / "baseline.enc", work / "baseline.tar", key_env("CI_INPUT_PRIVATE_KEY_B64"), context)
    destination = root / "out/performance/baseline"
    destination.mkdir(parents=True)
    with tarfile.open(work / "baseline.tar", "r") as archive:
        entries = archive.getmembers()
        if len(entries) != 7 or any(not member.isfile() or not 0 < member.size <= 16 * 1024**2 for member in entries):
            raise ValueError("invalid baseline archive")
        by_name = {member.name: member for member in entries}
        if len(by_name) != len(entries) or "manifest.json" not in by_name:
            raise ValueError("invalid baseline manifest")
        manifest = crypto.parse(archive.extractfile(by_name["manifest.json"]).read())
        if (manifest["source_id"] != payload["source_id"] or manifest["context"] != context or
                manifest["runner"] != ["self-hosted", "linux", "x64", "lfc-benchmark"] or
                manifest["runner_name"] != required("RUNNER_NAME")):
            raise ValueError("incompatible fixed-runner baseline")
        expected = {"queue.json", "runtime.json", "scheduler-submission-epoll.json",
                    "scheduler-submission-io-uring.json", "filesystem.json", "timer-wheel.json"}
        if set(manifest["files"]) != expected or set(by_name) != expected | {"manifest.json"}:
            raise ValueError("incomplete baseline")
        for name in expected:
            data = archive.extractfile(by_name[name]).read()
            if digest_bytes(data) != manifest["files"][name]:
                raise ValueError("baseline file digest mismatch")
            (destination / name).write_bytes(data)
    (work / "baseline.tar").unlink()


def validate_action(action):
    allowed = {"actions/checkout", "actions/upload-artifact", "actions/cache/restore",
               "actions/cache/save", "mymindstorm/setup-emsdk"}
    parts = action.split("@", 1)
    if len(parts) != 2 or parts[0] not in allowed or not SHA.fullmatch(parts[1]):
        raise ValueError("unsupported recipe action")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("package", "dispatch", "prepare", "materialize", "run", "reports", "diagnostics", "cleanup"))
    args = parser.parse_args()
    try:
        if args.stage == "run":
            from . import project_ci_runner
            project_ci_runner.run()
        elif args.stage == "reports":
            from . import project_ci_runner
            project_ci_runner.collect_reports()
        elif args.stage == "diagnostics":
            roots = [Path(required("RUNNER_TEMP")) / "project-ci", Path(required("GITHUB_WORKSPACE")) / "private-source"]
            roots = [root for root in roots if root.exists()]
            target = Path(required("RUNNER_TEMP")) / "cipher-logs/diagnostics.enc"
            key = (Path(__file__).resolve().parents[1] / "ci/builder-logs-public-key.b64").read_text().strip()
            encrypted_logs.collect(roots, target, crypto.unb64(key).decode(), encrypted_logs.github_context())
        elif args.stage == "cleanup":
            for root in (Path(required("RUNNER_TEMP")) / "project-ci", Path(required("RUNNER_TEMP")) / "project-ci-prepare",
                         Path(required("RUNNER_TEMP")) / "project-ci-package", Path(required("GITHUB_WORKSPACE")) / "private-source"):
                if root.exists():
                    shutil.rmtree(root)
        else:
            globals()[args.stage]()
    except Exception:
        print("::error::PROJECT_CI_STAGE_FAILED stage=" + args.stage + "; diagnostics remain private", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
