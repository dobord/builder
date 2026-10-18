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
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
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
MAX_GIT_INPUT = 90 * 1024**2  # Below GitHub's 100 MB blob API limit.
MAX_RECIPE = 1024 * 1024
MAX_LANES = 100
MAX_MATRIX_DIMENSIONS = 16
# Builder-owned, reviewed byte contract. No request, policy, environment or
# candidate recipe may replace these pins; changes require a reviewed revision.
RELEASE_RECIPE_DIGESTS = {
    "ci": "62e43aa051f7da623c0a655f68e3a2eee92ea4a27a58e3f9b3f0894fa732f57d",
    "wasm-async": "d3f5f2bb2641333c4b68337ec723379746fe701ae06307b1099946d64080082c",
    "nightly-stress": "6399682b004cde5f7b724d46594644edf6b7130e42440fa6f022d97303c79160",
    "performance": "f34215c2364d7f705c162f3f66378b4ca49c1116d1317cc552a26c298e96e93a",
    "vcpkg-port": "263a8c59ac57ff06993b408aa24ce4bf0caa43965f88bd647056c9377f7513f6",
}
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


def source_policy():
    """Decode opaque secret transport privately; malformed encodings fail closed."""
    if "CI_SOURCE_POLICY_B64" in os.environ:
        encoded = required("CI_SOURCE_POLICY_B64")
        if len(encoded) > 1024 * 1024:
            raise ValueError("source policy exceeds bound")
        raw = crypto.unb64(encoded)
    else:
        raw = required("CI_SOURCE_POLICY").encode()
    if len(raw) > 1024 * 1024:
        raise ValueError("source policy exceeds bound")
    policy = crypto.parse(raw)
    if not isinstance(policy, dict):
        raise ValueError("invalid source policy object")
    return policy


def api(path, token, *, data=None, limit=MAX_ARCHIVE):
    decoded = urllib.parse.unquote(path)
    if (not path.startswith("repos/") or any(part in {".", ".."} for part in decoded.split("?", 1)[0].split("/")) or
            any(ord(character) < 32 for character in decoded) or "#" in decoded):
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


def quiet(command, cwd, env, log, *, timeout=21600, on_timeout=None):
    from .process import spawn, terminate_tree
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as output:
        # Approved recipes are noninteractive. Never inherit the privileged
        # caller's input stream, even when stdout/stderr are private files.
        child = spawn(command, cwd=cwd, env=env, stdout=output)
        try:
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if on_timeout is not None:
                    try:
                        on_timeout(child.pid)
                    except Exception:
                        try:
                            output.write(b"\nPRIVATE_TIMEOUT_OBSERVER_FAILED\n")
                        except BaseException:
                            pass
                raise ValueError("private subprocess timed out") from None
        except BaseException:
            # Ordinary wait failures, cancellation and observers all preserve
            # their original exception even when retirement itself fails.
            try:
                terminate_tree(child)
            except BaseException:
                try:
                    output.write(b"\nPRIVATE_PROCESS_RETIREMENT_FAILED\n")
                except BaseException:
                    pass
            raise
        if os.name == "nt":
            terminate_tree(child)
        return code


def checked(command, cwd, env, log):
    if quiet(command, cwd, env, log):
        raise ValueError("private subprocess failed")


def build_environment(environ):
    names = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
             "SystemRoot", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE",
             "ProgramFiles", "ProgramFiles(x86)", "NUMBER_OF_PROCESSORS",
             "VCPKG_INSTALLATION_ROOT", "RUNNER_OS", "RUNNER_ARCH", "SystemDrive", "SYSTEMDRIVE",
             "ProgramData", "ALLUSERSPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH",
             "PSModulePath", "ChocolateyInstall", "VCToolsInstallDir", "WindowsSdkDir", "VSINSTALLDIR",
             "VCINSTALLDIR", "UniversalCRTSdkDir", "INCLUDE", "LIB", "LIBPATH"}
    allowed = {name.upper() for name in names}
    env = {name: value for name, value in environ.items() if name.upper() in allowed}
    if environ.get("RUNNER_OS") == "Linux" and "PATH" in env:
        # setup-python belongs to the trusted crypto stage. Native recipes use
        # host Python so their apt-installed grpc/protobuf modules remain visible.
        runtime_directory = sys.executable.rsplit("/", 1)[0]
        runtime_paths = ({runtime_directory, runtime_directory.removesuffix("/bin")}
                         if runtime_directory not in {"/bin", "/usr/bin", "/usr/local/bin"} else set())
        env["PATH"] = ":".join(path for path in env["PATH"].split(":") if path not in runtime_paths)
    return env


def remove_staging(root):
    """Remove ephemeral Git objects, including read-only pack files on Windows."""
    if root.is_symlink() or root.is_junction():
        raise ValueError("linked staging root")
    def writable_retry(operation, path, error):
        if (not isinstance(error, PermissionError) or operation not in {os.unlink, os.remove, os.rmdir}
                or Path(path).is_symlink() or Path(path).is_junction()):
            raise error
        os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | stat.S_IWUSR)
        operation(path)
    shutil.rmtree(root, onexc=writable_retry)


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


def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def fetch_operator_input(payload, token, target):
    """Fixed public builder transport; publish output only after all checks pass."""
    prefix = f"repos/{BUILDER}/git/"
    path = prefix + "ref/" + payload["input_ref"].removeprefix("refs/")
    def check_ref():
        reference = api_json(path, token, limit=16384)
        if (reference["ref"] != payload["input_ref"] or reference["object"]["type"] != "commit" or
                reference["object"]["sha"] != payload["input_commit"]):
            raise ValueError("moved operator input ref")
    check_ref()
    commit = api_json(prefix + "commits/" + payload["input_commit"], token, limit=16384)
    if (commit["sha"] != payload["input_commit"] or commit["parents"] or
            not SHA.fullmatch(commit["tree"]["sha"])):
        raise ValueError("invalid isolated input commit")
    tree = api_json(prefix + "trees/" + commit["tree"]["sha"], token, limit=16384)
    entries = tree["tree"]
    if tree["sha"] != commit["tree"]["sha"] or tree["truncated"] is not False or len(entries) != 1:
        raise ValueError("invalid input tree")
    entry = entries[0]
    if (entry["path"] != "sources.enc" or entry["mode"] != "100644" or entry["type"] != "blob" or
            entry["sha"] != payload["input_blob"] or type(entry["size"]) is not int or
            not 0 < entry["size"] <= MAX_GIT_INPUT):
        raise ValueError("invalid input blob entry")
    blob = api_json(prefix + "blobs/" + payload["input_blob"], token, limit=MAX_GIT_INPUT * 2)
    if (blob["sha"] != payload["input_blob"] or blob["encoding"] != "base64" or
            type(blob["size"]) is not int or blob["size"] != entry["size"] or
            not isinstance(blob["content"], str) or len(blob["content"]) > MAX_GIT_INPUT * 2):
        raise ValueError("invalid Git blob identity or encoding")
    # GitHub wraps base64 at newlines; reject other non-alphabet bytes.
    raw = crypto.unb64(blob["content"].replace("\n", ""))
    if (len(raw) != blob["size"] or git_blob_sha(raw) != payload["input_blob"] or
            digest_bytes(raw) != payload["source_cipher_digest"]):
        raise ValueError("input ciphertext digest mismatch")
    check_ref()
    with target.open("xb") as stream:
        stream.write(raw)


def message_context(request_id, schema=1, builder_sha=None):
    if str(uuid.UUID(request_id)) != request_id:
        raise ValueError("invalid request ID")
    if type(schema) is not int or schema not in {1, 2}:
        raise ValueError("invalid explicit transport schema")
    if schema == 2:
        if not isinstance(builder_sha, str) or not SHA.fullmatch(builder_sha):
            raise ValueError("invalid builder revision")
        return {"schema": 2, "purpose": "project-ci-operator-request", "request_id": request_id,
                "builder_id": BUILDER_ID, "builder_sha": builder_sha}
    return {"schema": 1, "purpose": "project-ci-request", "request_id": request_id, "builder_id": BUILDER_ID}


def source_context(payload):
    if payload["schema"] == 2:
        return {"schema": 2, "purpose": "project-ci-operator-sources", "request_id": payload["request_id"],
                "builder_id": BUILDER_ID, "builder_sha": payload["builder_sha"]}
    return {"schema": 1, "purpose": "project-ci-sources", "request_id": payload["request_id"],
            "source_id": payload["source_id"], "source_run": payload["source_run"],
            "source_attempt": payload["source_attempt"], "builder_sha": payload["builder_sha"]}


def validate_payload(payload):
    fields = {"schema", "request_id", "source", "source_id", "source_sha", "base_sha",
              "source_run", "source_attempt", "source_event", "pr", "builder_sha", "suite",
              "created", "expires", "artifact_id", "artifact_digest", "source_cipher_digest", "baseline_run",
              "baseline_tag", "baseline_sha"}
    schema = payload.get("schema")
    if type(schema) is not int or schema not in {1, 2}:
        raise ValueError("invalid CI request schema")
    if schema == 2:
        fields -= {"source_run", "source_attempt", "source_event", "artifact_id", "artifact_digest", "baseline_run"}
        fields |= {"origin", "operator_id", "input_commit", "input_blob", "input_ref"}
    if set(payload) != fields:
        raise ValueError("invalid CI request fields")
    message_context(payload["request_id"], schema, payload["builder_sha"])
    if not re.fullmatch(r"dobord/[A-Za-z0-9_.-]+", payload["source"]):
        raise ValueError("invalid source repository")
    for name in ("source_sha", "base_sha", "builder_sha", "baseline_sha") + (("input_commit", "input_blob") if schema == 2 else ()):
        if not isinstance(payload[name], str) or not SHA.fullmatch(payload[name]):
            raise ValueError("invalid exact revision")
    for name in (("source_id", "operator_id") if schema == 2 else ("source_id", "source_run", "source_attempt", "artifact_id")):
        if type(payload[name]) is not int or not 1 <= payload[name] < 2**63:
            raise ValueError("invalid identity")
    for name in (("pr",) if schema == 2 else ("pr", "baseline_run")):
        if type(payload[name]) is not int or not 0 <= payload[name] < 2**63:
            raise ValueError("invalid optional identity")
    if payload["suite"] not in SUITES or (schema == 1 and payload["source_event"] not in {"push", "workflow_dispatch", "schedule"}):
        raise ValueError("unsupported CI profile or authorizer")
    if schema == 2 and (payload["origin"] != "local-operator" or
                        payload["input_ref"] != "refs/tags/project-ci-input-" + payload["request_id"]):
        raise ValueError("invalid operator origin or input ref")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", payload["baseline_tag"]) or (schema == 1 and payload["baseline_run"]):
        raise ValueError("hosted comparisons require an immutable release tag, not a rolling runner baseline")
    if payload["suite"] in {"performance", "release"} and payload["baseline_sha"] == payload["source_sha"]:
        raise ValueError("benchmark baseline must differ from candidate")
    if (schema == 1 and not HASH.fullmatch(payload["artifact_digest"])) or not HASH.fullmatch(payload["source_cipher_digest"]):
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


def matrix_key(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,63}", value))


def matrix_value(value):
    return (type(value) in {bool, int} or
            (type(value) is float and math.isfinite(value)) or
            (isinstance(value, str) and len(value) <= 4096))


def expand_recipe(profile, recipe, *, limit=MAX_LANES):
    """Validate bounded matrix shapes/cardinality before producing any rows."""
    if (type(limit) is not int or not 0 <= limit <= MAX_LANES or
            not isinstance(recipe, dict) or not isinstance(recipe.get("jobs"), dict) or
            not 1 <= len(recipe["jobs"]) <= MAX_LANES + len(AGGREGATES)):
        raise ValueError("invalid recipe shape or lane budget")
    lanes = []
    for job_id, job in recipe["jobs"].items():
        if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,127}", job_id) or not isinstance(job, dict):
            raise ValueError("invalid job shape")
        if job_id in AGGREGATES:
            continue
        strategy = job.get("strategy", {})
        if not isinstance(strategy, dict) or not isinstance(strategy.get("matrix", {}), dict):
            raise ValueError("invalid strategy or matrix shape")
        matrix = strategy.get("matrix", {})
        remaining = limit - len(lanes)
        if "include" in matrix:
            if (set(matrix) != {"include"} or not isinstance(matrix["include"], list) or
                    not 1 <= len(matrix["include"]) <= remaining):
                raise ValueError("unsupported mixed matrix")
            if any(not isinstance(row, dict) or len(row) > MAX_MATRIX_DIMENSIONS or
                   any(not matrix_key(key) or not matrix_value(value) for key, value in row.items())
                   for row in matrix["include"]):
                raise ValueError("invalid include row")
            rows = matrix["include"]
        elif matrix:
            if len(matrix) > MAX_MATRIX_DIMENSIONS:
                raise ValueError("matrix dimension bound exceeded")
            cardinality = 1
            for key, values in matrix.items():
                if (not matrix_key(key) or key == "exclude" or not isinstance(values, list) or
                        not 1 <= len(values) <= MAX_LANES or any(not matrix_value(value) for value in values)):
                    raise ValueError("invalid matrix dimension")
                # Division checks the budget before multiplication/expansion.
                if cardinality > remaining // len(values):
                    raise ValueError("matrix cardinality exceeds remaining lane budget")
                cardinality *= len(values)
            rows = (dict(zip(matrix, values)) for values in itertools.product(*matrix.values()))
        else:
            if remaining < 1:
                raise ValueError("lane budget exhausted")
            rows = [{}]
        runner = job.get("runs-on")
        if (not isinstance(runner, (str, list)) or
                (isinstance(runner, str) and not 0 < len(runner) <= 4096) or
                (isinstance(runner, list) and (not 1 <= len(runner) <= 16 or
                 any(not isinstance(label, str) or not 0 < len(label) <= 4096 for label in runner)))):
            raise ValueError("invalid runner labels")
        for index, row in enumerate(rows):
            context = {"matrix." + key: value for key, value in row.items()}
            labels = [expand(label, context) for label in (runner if isinstance(runner, list) else [runner])]
            lanes.append({"id": f"{profile}-{job_id}-{index}", "runner": labels,
                          "profile": profile, "job": job, "matrix": row})
    return lanes


def expand_recipes(suite, raw_recipes):
    """Authenticate all release bytes before YAML parsing or matrix expansion."""
    import yaml
    if (suite not in SUITES or not isinstance(raw_recipes, dict) or set(raw_recipes) != set(SUITES[suite]) or
            any(not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RECIPE for raw in raw_recipes.values())):
        raise ValueError("incomplete or oversized recipe inventory")
    if suite == "release":
        if (set(RELEASE_RECIPE_DIGESTS) != set(SUITES["release"]) or
                any(digest_bytes(raw_recipes[profile]) != digest for profile, digest in RELEASE_RECIPE_DIGESTS.items())):
            raise ValueError("release recipe differs from reviewed builder contract")
    lanes = []
    for profile in SUITES[suite]:
        document = yaml.safe_load(raw_recipes[profile])
        lanes.extend(expand_recipe(profile, document, limit=MAX_LANES - len(lanes)))
    if not 1 <= len(lanes) <= MAX_LANES or len({lane["id"] for lane in lanes}) != len(lanes):
        raise ValueError("invalid lane inventory")
    if suite == "release" and len(lanes) != 39:
        raise ValueError("release requires the complete 39-lane qualification")
    return lanes


def recipes(root, suite):
    raw_recipes = {}
    for profile in SUITES[suite]:
        path = root / "ci/builder" / (profile + ".yml")
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing or linked recipe")
        with path.open("rb") as stream:
            raw_recipes[profile] = stream.read(MAX_RECIPE + 1)
    return expand_recipes(suite, raw_recipes)


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


def validate_execution(run, revision, request_digest, attempt):
    if (run["repository"]["id"] != BUILDER_ID or run["head_repository"]["id"] != BUILDER_ID or
            run["path"].split("@", 1)[0] != ".github/workflows/" + WORKFLOW or
            run["head_sha"] != revision or run["event"] != "workflow_dispatch" or
            run["run_attempt"] != attempt or
            run["display_title"] != "Encrypted qualification " + request_digest):
        raise ValueError("untrusted builder execution")


def validate_run(run, revision, request_digest, attempt):
    validate_execution(run, revision, request_digest, attempt)
    if run["status"] != "completed" or run["conclusion"] != "success":
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


def verify_request_schema(policy, schema):
    """An explicit allowlist rejects legacy origins before any admission API."""
    if "request_schemas" not in policy:
        return  # Existing schema-1 policies retain their original behavior.
    allowed = policy["request_schemas"]
    if (not isinstance(allowed, list) or not 1 <= len(allowed) <= 2 or
            any(type(item) is not int or item not in {1, 2} for item in allowed) or
            len(set(allowed)) != len(allowed) or schema not in allowed):
        raise ValueError("request schema denied by source policy")


def verify_source_policy(payload, token):
    policy = source_policy()
    verify_request_schema(policy, payload["schema"])
    if payload["source"] != policy["repository"] or payload["source_id"] != policy["repository_id"]:
        raise ValueError("source not authorized")
    if payload["schema"] == 2:
        if (policy.get("operator_origin") != "local-operator" or
                type(policy.get("operator_id")) is not int or
                payload["operator_id"] != policy["operator_id"] or
                int(required("GITHUB_ACTOR_ID")) != policy["operator_id"]):
            raise ValueError("unauthorized operator")
        repository = api_json(f"repos/{payload['source']}", token)
        if repository["id"] != payload["source_id"] or repository["full_name"] != payload["source"]:
            raise ValueError("source identity mismatch")
    if payload["schema"] == 2 or payload["suite"] in {"performance", "release"}:
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
    if payload["schema"] == 1:
        run = api_json(f"repos/{payload['source']}/actions/runs/{payload['source_run']}", token)
        if (run["repository"]["id"] != payload["source_id"] or
                run["head_repository"]["id"] != payload["source_id"] or
                run["path"].split("@", 1)[0] != ".github/workflows/builder-ci.yml" or
                run["run_attempt"] != payload["source_attempt"] or
                run["event"] != payload["source_event"] or
                run["head_branch"] != policy["authorizer_branch"]):
            raise ValueError("untrusted source authorizer")
    if not payload["pr"]:
        if payload["schema"] == 2:
            reference = api_json(f"repos/{payload['source']}/git/ref/heads/main", token)["object"]
            if (reference["type"] != "commit" or reference["sha"] != payload["source_sha"] or
                    payload["base_sha"] != payload["source_sha"]):
                raise ValueError("non-PR request must qualify exact current main")
        elif payload["source_sha"] != run["head_sha"]:
            raise ValueError("non-PR request must qualify the authorizer tree")
        return
    pr = api_json(f"repos/{payload['source']}/pulls/{payload['pr']}", token)
    if (pr["head"]["sha"] != payload["source_sha"] or pr["base"]["sha"] != payload["base_sha"] or
            pr["head"]["repo"]["id"] != payload["source_id"] or pr["state"] != "open" or
            (payload["schema"] == 2 and (pr["base"]["repo"]["id"] != payload["source_id"] or
             pr["base"]["ref"] != policy["authorizer_branch"]))):
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


def prepare():
    if (required("GITHUB_REPOSITORY") != BUILDER or int(required("GITHUB_REPOSITORY_ID")) != BUILDER_ID or
            required("GITHUB_SHA") != required("CI_BUILDER_SHA") or
            os.environ.get("RUNNER_DEBUG") == "1" or required("GITHUB_EVENT_NAME") != "workflow_dispatch" or
            int(required("GITHUB_RUN_ATTEMPT")) != 1):
        raise ValueError("unapproved builder execution")
    request = required("CI_REQUEST")
    if digest_bytes(request.encode("ascii")) != required("CI_REQUEST_DIGEST"):
        raise ValueError("request hash mismatch")
    schema = int(os.environ.get("CI_REQUEST_SCHEMA", "1"))
    verify_request_schema(source_policy(), schema)
    previous = pages(f"repos/{BUILDER}/actions/workflows/{WORKFLOW}/runs?head_sha={required('GITHUB_SHA')}",
                     required("BUILDER_READ_TOKEN"), "workflow_runs")
    matches = [run for run in previous if run["display_title"] == "Encrypted qualification " + required("CI_REQUEST_DIGEST")]
    if len(matches) != 1 or matches[0]["id"] != int(required("GITHUB_RUN_ID")):
        raise ValueError("CI request replay or ambiguous execution")
    document = crypto.parse(crypto.open_message(request, key_env("CI_INPUT_PRIVATE_KEY_B64"),
                            message_context(required("CI_REQUEST_ID"), schema, required("GITHUB_SHA"))))
    payload = crypto.verify(document, key_env("CI_VERIFY_PUBLIC_KEY_B64"))
    validate_payload(payload)
    if (payload["schema"] != schema or payload["request_id"] != required("CI_REQUEST_ID") or
            payload["builder_sha"] != required("GITHUB_SHA")):
        raise ValueError("request identity mismatch")
    if schema == 2 and (matches[0].get("actor", {}).get("id") != payload["operator_id"] or
                        matches[0].get("triggering_actor", {}).get("id") != payload["operator_id"] or
                        matches[0].get("run_attempt") != 1):
        raise ValueError("builder operator identity mismatch")
    if schema == 2:
        validate_execution(matches[0], payload["builder_sha"], required("CI_REQUEST_DIGEST"), 1)
    token = required("SOURCE_READ_TOKEN")
    verify_source_policy(payload, token)
    work = Path(required("RUNNER_TEMP")) / "project-ci-prepare"
    work.mkdir(mode=0o700)
    if schema == 2:
        fetch_operator_input(payload, required("BUILDER_READ_TOKEN"), work / "sources.enc")
    else:
        artifact = api_json(f"repos/{payload['source']}/actions/artifacts/{payload['artifact_id']}", token)
        if (artifact["expired"] or artifact["workflow_run"]["id"] != payload["source_run"] or
                artifact["name"] != "encrypted-sources-" + payload["request_id"] or
                not 1 <= artifact["size_in_bytes"] <= MAX_ARCHIVE):
            raise ValueError("source artifact provenance mismatch")
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
    # Authenticate the independently reviewed recipe contract before any
    # dependency extractor parses candidate-controlled recipe YAML.
    lanes = recipes(root, payload["suite"])
    from . import project_dependency_review
    receipt = project_dependency_review.verify(root, payload, env)
    (work / "dependency-review.json").write_bytes(crypto.canonical(receipt))
    crypto.encrypt_file(work / "dependency-review.json", Path(required("RUNNER_TEMP")) / "cipher-dependency/dependency-review.enc",
                        crypto.public_text(key_env("CI_INPUT_PRIVATE_KEY_B64")), builder_context("dependency-review"))
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


PREPARE_DIAGNOSTIC_MAX_BYTES = 16384
PREPARE_DIAGNOSTIC_REASONS = frozenset({
    "missing configuration", "unapproved builder execution", "request hash mismatch",
    "invalid explicit transport schema", "request schema denied by source policy",
    "CI request replay or ambiguous execution", "expired CI request", "request identity mismatch",
    "builder operator identity mismatch", "untrusted builder execution", "source not authorized",
    "unauthorized operator", "source identity mismatch", "baseline is not a published stable release",
    "released baseline identity mismatch", "stale or foreign PR", "moved operator input ref",
    "invalid isolated input commit", "invalid input tree", "invalid input blob entry",
    "invalid Git blob identity or encoding", "input ciphertext digest mismatch",
    "signed ciphertext digest mismatch", "release recipe differs from reviewed builder contract",
    "dependency-review gate failed", "dependency data unavailable", "unsupported dependency manifest",
    "unresolved OpenSSL dependency", "unsupported external dependency", "empty dependency inventory",
    "private subprocess failed", "private subprocess timed out",
})


def _diagnostic_identifier(value, *, module=False):
    # Never truncate untrusted text into something that looks like a valid symbol.
    # These are bounded code identifiers, not exception messages or local values.
    if type(value) is not str or len(value) > 4096 or any(part in value for part in ("://", "\x00", "\r", "\n", "?", "#")):
        return "<invalid>"
    if module:
        value = Path(value).name
        return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}\.py", value) else "<invalid>"
    if value in {"<module>", "<lambda>", "<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>"}:
        return value
    return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,95}", value) else "<invalid>"


def prepare_failure_record(error):
    """Return bounded failure identity without stringifying errors or inspecting locals."""
    argument = error.args[0] if error.args else None
    reason = argument if type(argument) is str and argument in PREPARE_DIAGNOSTIC_REASONS else "unclassified prepare failure"
    report = {"schema": 1, "stage": "prepare", "exception": _diagnostic_identifier(type(error).__name__),
              "code": reason, "frames": []}
    current = error.__traceback__
    for _ in range(64):
        if current is None:
            break
        code = current.tb_frame.f_code
        line = current.tb_lineno
        report["frames"].append({"module": _diagnostic_identifier(code.co_filename, module=True),
            "function": _diagnostic_identifier(code.co_name), "line": line if type(line) is int and 0 < line <= 10000000 else 0})
        report["frames"] = report["frames"][-16:]
        current = current.tb_next
    report["frames_truncated"] = current is not None
    if isinstance(error, urllib.error.HTTPError):
        status = error.code
        if type(status) is int and 400 <= status <= 599:
            report["http_status"] = status  # Never URL, headers, body or reason.
    return report


def _prepare_diagnostic_directory(*, fresh):
    parent = Path(required("RUNNER_TEMP"))
    if not parent.is_absolute() or not parent.is_dir():
        raise ValueError("unsafe prepare diagnostic parent")
    directory = parent / "project-ci-prepare-diagnostics"
    if fresh or not (directory.exists() or directory.is_symlink()):
        directory.mkdir(mode=0o700)
    if directory.is_symlink() or directory.is_junction() or not directory.is_dir():
        raise ValueError("unsafe prepare diagnostic directory")
    info = directory.stat(follow_symlinks=False)
    if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe prepare diagnostic ownership")
    return directory


def _write_prepare_diagnostic(directory, name, report):
    data = crypto.canonical(report)
    if len(data) > PREPARE_DIAGNOSTIC_MAX_BYTES:
        raise ValueError("prepare diagnostic exceeds bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(directory / name, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        if os.name == "posix":
            os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


def record_prepare_failure(error):
    """A fresh private record cannot replace old evidence or follow a linked root."""
    report = prepare_failure_record(error)
    directory = _prepare_diagnostic_directory(fresh=True)
    _write_prepare_diagnostic(directory, "prepare-error.json", report)


def ensure_prepare_diagnostics():
    """Missing records (e.g. installer failure) are not a successful admission receipt."""
    directory = _prepare_diagnostic_directory(fresh=False)
    found = False
    for name in ("prepare-error.json", "prepare-status.json"):
        path = directory / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > PREPARE_DIAGNOSTIC_MAX_BYTES):
            raise ValueError("unsafe prepare diagnostic record")
        if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("unsafe prepare diagnostic record ownership")
        found = True
    if not found:
        _write_prepare_diagnostic(directory, "prepare-status.json",
            {"schema": 1, "stage": "prepare", "state": "no-prepare-error-record"})


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
            if os.environ.get("GITHUB_JOB") == "prepare":
                ensure_prepare_diagnostics()
            roots = [Path(required("RUNNER_TEMP")) / "project-ci", Path(required("GITHUB_WORKSPACE")) / "private-source",
                     Path(required("RUNNER_TEMP")) / "project-ci-prepare-diagnostics",
                     Path(required("RUNNER_TEMP")) / "project-ci-prepare",
                     Path(required("RUNNER_TEMP")) / "project-ci-native-contract"]
            roots = [root for root in roots if root.exists()]
            target = Path(required("RUNNER_TEMP")) / "cipher-logs/diagnostics.enc"
            key = (Path(__file__).resolve().parents[1] / "ci/builder-logs-public-key.b64").read_text().strip()
            encrypted_logs.collect(roots, target, crypto.unb64(key).decode(), encrypted_logs.github_context())
        elif args.stage == "cleanup":
            for root in (Path(required("RUNNER_TEMP")) / "project-ci", Path(required("RUNNER_TEMP")) / "project-ci-native-contract",
                         Path(required("RUNNER_TEMP")) / "project-ci-prepare",
                         Path(required("RUNNER_TEMP")) / "project-ci-prepare-diagnostics",
                         Path(required("RUNNER_TEMP")) / "project-ci-package", Path(required("GITHUB_WORKSPACE")) / "private-source"):
                if root.exists():
                    remove_staging(root)
        else:
            globals()[args.stage]()
    except Exception as error:
        if args.stage == "prepare":
            try:
                record_prepare_failure(error)
            except BaseException:
                pass  # Diagnostic failure must not replace admission failure.
        print("::error::PROJECT_CI_STAGE_FAILED stage=" + args.stage + "; diagnostics remain private", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
