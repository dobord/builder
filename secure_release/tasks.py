"""Private request preparation and platform build drivers. No private stdout."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from . import crypto, safeio, process, build_support, cef_build, cef_contract, cef_cache
from .github import Client
from .protocol import *


def work() -> Path:
    root = Path(env("RUNNER_TEMP")) / "encrypted-release-private"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def event() -> dict:
    return crypto.parse(Path(env("GITHUB_EVENT_PATH")).read_bytes())


def clean_env() -> dict:
    # Credential hygiene, NOT a sandbox against malicious approved code.
    return {k: v for k, v in os.environ.items() if not any(x in k.upper() for x in
            ("TOKEN", "PRIVATE_KEY", "PUBLIC_KEY", "SECRET", "GITHUB_", "ACTIONS_", "GIT_CONFIG", "GIT_TRACE", "GIT_CURL"))}


def run(args: list[str], log: Path, *, cwd: Path | None = None, environment: dict | None = None,
        timeout=18000, stage="fetch", public_progress=False) -> None:
    process.run(args, log, cwd=cwd, environment=clean_env() if environment is None else environment,
                timeout=timeout, stage=stage, public_progress=public_progress)


def _artifact_selector(client: Client, platform: str, run: int, attempt: int,
                       builder_sha: str, kind: str, *, required: bool) -> dict | None:
    """Resolve one exact trusted builder artifact; never discover an older/latest run."""
    run = number(run); attempt = number(attempt)
    if platform not in cef_contract.TRIPLETS or kind not in {"cef-checkpoint", "vcpkg-binaries"}:
        raise ValueError("invalid CEF continuation selector")
    producer = client.get(f"/repos/{BUILDER}/actions/runs/{run}/attempts/{attempt}")
    check_run(producer, BUILDER, "build-release.yml", builder_sha, attempt,
              "workflow_dispatch", success=False)
    if producer.get("status") != "completed":
        raise ValueError("CEF continuation producer is still running")
    current = client.get(f"/repos/{BUILDER}/actions/runs/{run}")
    if current.get("run_attempt") != attempt or current.get("status") != "completed":
        raise ValueError("CEF continuation producer was rerun")
    expected = f"{kind}-{platform}-{run}-{attempt}"
    matches = []
    for artifact in client.artifacts(BUILDER, run):
        workflow = artifact.get("workflow_run", {})
        if artifact.get("name") != expected:
            continue
        if (artifact.get("expired") is True or workflow.get("id") != run
                or workflow.get("head_sha") != builder_sha):
            raise ValueError("untrusted CEF continuation artifact")
        value = artifact.get("digest", "")
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise ValueError("CEF continuation artifact has no GitHub digest")
        matches.append({"run": run, "attempt": attempt,
                        "artifact_id": number(artifact.get("id")),
                        "artifact_sha256": cef_contract.digest(value[7:])})
    if len(matches) > 1 or (required and len(matches) != 1):
        raise ValueError("missing or ambiguous CEF continuation artifact")
    return matches[0] if matches else None


def _apply_continuation(plan: dict, inputs: dict, builder_sha: str, client: Client) -> dict:
    """Turn explicit run/attempt inputs into authenticated source-resume selectors."""
    if plan.get("version") != 2 or plan.get("cef", {}).get("profile") != "static-third-party":
        raise ValueError("CEF continuation requires the signed strict source profile")
    result = crypto.parse(crypto.canonical(plan))
    changed = False
    for platform in cef_contract.TRIPLETS:
        run_text = str(inputs.get(platform + "_builder_run", "")).strip()
        attempt_text = str(inputs.get(platform + "_builder_attempt", "")).strip()
        if bool(run_text) != bool(attempt_text):
            raise ValueError("CEF continuation run and attempt must be supplied together")
        if not run_text:
            continue
        selected = result["cef"]["platforms"][platform]
        if selected != {"mode": "source-fresh", "checkpoint": None, "binary_cache": None}:
            raise ValueError("CEF continuation only starts from a fresh signed plan")
        run, attempt = number(run_text), number(attempt_text)
        checkpoint = _artifact_selector(client, platform, run, attempt, builder_sha,
                                        "cef-checkpoint", required=True)
        binary = _artifact_selector(client, platform, run, attempt, builder_sha,
                                    "vcpkg-binaries", required=False)
        selected.update(mode="source-resume", checkpoint=checkpoint, binary_cache=binary)
        changed = True
    if not changed:
        raise ValueError("manual continuation requires at least one explicit builder run")
    validate_plan(result)
    return result


def request():
    guard(SOURCE)
    e = event()
    event_name = env("GITHUB_EVENT_NAME")
    if not e["repository"]["private"] or env("GITHUB_REF_TYPE") != "tag":
        raise ValueError("release requests require a private immutable tag ref")
    tag = env("GITHUB_REF_NAME")
    if not TAG.fullmatch(tag):
        raise ValueError("invalid release tag")
    if event_name == "push":
        if e["deleted"] or not e.get("created"):
            raise ValueError("only newly created release tag pushes are supported")
        continuation_inputs = None
    elif event_name == "workflow_dispatch":
        values = e.get("inputs")
        if not isinstance(values, dict) or values.get("source_tag") != tag:
            raise ValueError("manual continuation must execute from the exact source tag")
        continuation_inputs = values
    else:
        raise ValueError("unsupported release request event")
    source_sha = sha(env("GITHUB_SHA"))
    builder_sha = sha(env("BUILDER_COMMIT_SHA"))
    client = Client(env("SOURCE_TOKEN"))
    record = client.get(f"/repos/{SOURCE}/contents/ci/release-plan.json?ref={source_sha}")
    plan = crypto.parse(crypto.unb64(record["content"].replace("\n", "")))
    validate_plan(plan)
    builder = Client(env("BUILDER_DISPATCH_TOKEN"))
    if continuation_inputs is not None:
        cache_reader = Client(env("BUILDER_CACHE_READ_TOKEN"))
        plan = _apply_continuation(plan, continuation_inputs, builder_sha, cache_reader)
    created = int(time.time())
    rid, salt = str(uuid.uuid4()), crypto.b64(os.urandom(32))
    payload = {"version": 1, "release_id": rid, "salt": salt, "source_sha": source_sha, "source_tag": tag,
               "request_run": number(env("GITHUB_RUN_ID")), "request_attempt": number(env("GITHUB_RUN_ATTEMPT")),
               "builder_sha": builder_sha, "output_key": crypto.fingerprint(env("ARTIFACT_ENCRYPTION_PUBLIC_KEY")),
               "input_key": crypto.fingerprint(env("BUILDER_INPUT_PUBLIC_KEY")), "created": created, "expires": created + 172800,
               "source_id": IDS[SOURCE], "builder_id": IDS[BUILDER], "bin_id": IDS[BIN], "plan": plan}
    document = crypto.sign(payload, env("REQUEST_SIGNING_PRIVATE_KEY"))
    encrypted = crypto.seal_message(crypto.canonical(document), env("BUILDER_INPUT_PUBLIC_KEY"), message_context(rid, salt))
    answer = builder.dispatch(BUILDER, "build-release.yml", {"release_id": rid, "salt": salt, "request": encrypted})
    with open(env("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as summary:
        summary.write(f"Accepted release request `{rid}`. Builder run: {answer['workflow_run_id']}\n")


def _open_request() -> tuple[dict, dict]:
    data = event()["inputs"]
    ctx = message_context(data["release_id"], data["salt"])
    document = crypto.parse(crypto.open_message(data["request"], env("BUILDER_INPUT_PRIVATE_KEY"), ctx))
    payload = verified(document, env("REQUEST_VERIFY_PUBLIC_KEY"))
    if (payload["release_id"] != ctx["release_id"] or payload["salt"] != ctx["salt"]
            or payload["builder_sha"] != env("GITHUB_SHA") or payload["builder_sha"] != env("BUILDER_COMMIT_SHA")
            or payload["input_key"] != crypto.fingerprint(crypto.public_text(env("BUILDER_INPUT_PRIVATE_KEY")))
            or payload["output_key"] != crypto.fingerprint(env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"))):
        raise ValueError("request does not match local policy")
    return document, payload


def git_archive(repo: str, revision: str, destination: Path, token: str | None, log: Path):
    sha(revision)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid repository path")
    with tempfile.TemporaryDirectory(prefix="fetch-", dir=work()) as folder:
        root = Path(folder)
        environment = clean_env()
        environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GCM_INTERACTIVE": "never"})
        settings = {"credential.helper": "", "core.hooksPath": str(root / "no-hooks"), "http.followRedirects": "false"}
        if token:
            settings["http.https://github.com/.extraheader"] = "AUTHORIZATION: basic " + crypto.b64(("x-access-token:" + token).encode())
        environment["GIT_CONFIG_COUNT"] = str(len(settings))
        for i, (k, v) in enumerate(settings.items()):
            environment[f"GIT_CONFIG_KEY_{i}"] = k
            environment[f"GIT_CONFIG_VALUE_{i}"] = v
        run(["git", "init", "--template=", str(root)], log, environment=environment, timeout=60)
        run(["git", "-C", str(root), "fetch", "--no-tags", "--depth=1", "https://github.com/" + repo + ".git", revision], log, environment=environment, timeout=1200)
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "FETCH_HEAD"], env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        if result.stdout.decode().strip() != revision:
            raise ValueError("unexpected fetched revision")
        run(["git", "-C", str(root), "-c", "core.autocrlf=false", "archive", "--format=tar.gz", revision, "-o", str(destination)],
            log, environment=environment, timeout=600)


def prepare():
    guard(BUILDER, event="workflow_dispatch")
    document, payload = _open_request()
    root, log = work(), work() / "prepare.log"
    client = Client(env("SOURCE_READ_TOKEN"))
    repo = client.get(f"/repos/{SOURCE}")
    if repo["id"] != IDS[SOURCE] or not repo["private"] or repo["owner"]["id"] != OWNER:
        raise ValueError("source repository identity changed")
    requester = client.get(f"/repos/{SOURCE}/actions/runs/{payload['request_run']}/attempts/{payload['request_attempt']}")
    requester_event = requester.get("event")
    if requester_event not in {"push", "workflow_dispatch"}:
        raise ValueError("unsupported requester event")
    check_run(requester, SOURCE, "release-request.yml", payload["source_sha"],
              payload["request_attempt"], requester_event, success=False)
    ref = client.get(f"/repos/{SOURCE}/git/ref/tags/{payload['source_tag']}")["object"]
    for _ in range(5):
        if ref["type"] == "commit":
            break
        if ref["type"] != "tag":
            raise ValueError("unsupported ref")
        ref = client.get(f"/repos/{SOURCE}/git/tags/{sha(ref['sha'])}")["object"]
    if ref["type"] != "commit" or ref["sha"] != payload["source_sha"]:
        raise ValueError("tag moved")
    comparison = client.get(f"/repos/{SOURCE}/compare/{payload['source_sha']}...main")
    if comparison["status"] not in {"identical", "ahead"}:
        raise ValueError("source is outside approved main history")
    allowed = set(env("SOURCE_ALLOWLIST").split(","))
    if SOURCE not in allowed:
        raise ValueError("source allowlist missing workspace")
    bundle = root / "input"
    bundle.mkdir()
    (bundle / "request.json").write_bytes(crypto.canonical(document))
    git_archive(SOURCE, payload["source_sha"], bundle / "workspace.tgz", env("SOURCE_READ_TOKEN"), log)
    safeio.extract_tar(bundle / "workspace.tgz", root / "workspace-check")
    workspace = root / "workspace-check"
    plan = payload["plan"]
    tree = client.get(f"/repos/{SOURCE}/git/trees/{payload['source_sha']}")["tree"]
    gitlinks = [item for item in tree if item["path"] == "upstream"]
    if len(gitlinks) != 1 or gitlinks[0]["mode"] != "160000" or gitlinks[0]["sha"] != plan["upstream_sha"]:
        raise ValueError("upstream gitlink mismatch")
    git_archive("microsoft/vcpkg", plan["upstream_sha"], bundle / "upstream.tgz", None, log)
    downloads = bundle / "downloads"
    downloads.mkdir()
    for port in plan["ports"]:
        if port["repository"] not in allowed:
            raise ValueError("source repository not allowed")
        text = (workspace / "ports" / port["name"] / "portfile.cmake").read_text()
        if (re.findall(r'\bREF\s+"([0-9a-f]{40})"', text) != [port["sha"]]
                or re.findall(r'\bURL\s+"([^"]+)"', text) != ["https://github.com/" + port["repository"] + ".git"]):
            raise ValueError("port sources differ from signed plan")
        git_archive(port["repository"], port["sha"], downloads / f"{port['name']}-{port['sha']}.tar.gz", env("SOURCE_READ_TOKEN"), log)
    if plan["version"] == 2:
        revision = plan["cef"]["recipe_commit"]
        # Public recipe only; never send the private source token to this fetch.
        git_archive("dobord/cef", revision, downloads / f"cef-static-{revision}.tar.gz", None, log)
    archive = root / "input.tgz"
    safeio.pack_tar(bundle, archive)
    context = file_context(payload["release_id"], payload["salt"], int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")),
                           env("GITHUB_SHA"), "sources", "all")
    crypto.encrypt_file(archive, Path(env("CIPHER_DIR")) / "input.enc", crypto.public_text(env("BUILDER_INPUT_PRIVATE_KEY")), context)


def _persist_binary_cache(binary_cache: Path | None, cache_key: str | None,
                          platform: str, input_private: str | None) -> bool:
    """Persist completed packages even when the engine only produced a checkpoint."""
    if binary_cache is None or not any(binary_cache.rglob("*.zip")):
        return False
    if cache_key is None or input_private is None:
        raise ValueError("CEF binary cache lacks its authenticated context")
    output = Path(env("RUNNER_TEMP")) / "cipher-cache/vcpkg-binaries"
    if output.exists():
        raise ValueError("CEF binary cache output already exists")
    cache_context = cef_cache.context("vcpkg-binaries", platform, cache_key,
                                      int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")),
                                      env("GITHUB_SHA"), "index")
    cef_cache.seal(binary_cache, output, crypto.public_text(input_private), cache_context)
    cef_build.write_output("binary_cache_ready", True)
    return True


def build():
    guard(BUILDER, event="workflow_dispatch")
    platform = env("TARGET_PLATFORM")
    if platform not in {"linux", "windows"}:
        raise ValueError("unsupported platform")
    root, log = work(), work() / "build.log"
    data = event()["inputs"]
    context = file_context(data["release_id"], data["salt"], int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")), env("GITHUB_SHA"), "sources", "all")
    crypto.decrypt_file(Path(env("INPUT_FILE")), root / "input.tgz", env("BUILDER_INPUT_PRIVATE_KEY"), context)
    safeio.extract_tar(root / "input.tgz", root / "input")
    document = crypto.parse((root / "input/request.json").read_bytes())
    payload = verified(document, env("REQUEST_VERIFY_PUBLIC_KEY"))
    if (payload["release_id"] != data["release_id"] or payload["salt"] != data["salt"]
            or payload["builder_sha"] != env("GITHUB_SHA") or payload["builder_sha"] != env("BUILDER_COMMIT_SHA")
            or payload["output_key"] != crypto.fingerprint(env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"))):
        raise ValueError("input bundle mismatch")
    cfg = payload["plan"].get("cef")
    input_private = env("BUILDER_INPUT_PRIVATE_KEY") if cfg is not None else None
    os.environ.pop("BUILDER_INPUT_PRIVATE_KEY", None)
    safeio.extract_tar(root / "input/workspace.tgz", root / "workspace")
    safeio.extract_tar(root / "input/upstream.tgz", root / "upstream")
    upstream = root / "upstream"
    downloads = upstream / "downloads"
    downloads.mkdir(exist_ok=True)
    for source in (root / "input/downloads").iterdir():
        if not safeio.regular(source):
            raise ValueError("unsafe source archive")
        shutil.copyfile(source, downloads / source.name)
    source_ports = list(payload["plan"]["ports"])
    if cfg is not None:
        revision = cfg["recipe_commit"]
        recipe_archive = downloads / f"cef-static-{revision}.tar.gz"
        safeio.extract_tar(recipe_archive, root / "cef-recipe")
        source_ports.append({"name": "cef-static", "sha": revision})
    build_support.protect_source_archives(root / "workspace", downloads, source_ports)
    environment = build_support.build_environment(clean_env(), downloads, upstream)
    def execute(args, *, stage, timeout, cwd=upstream):
        run(args, log, cwd=cwd, environment=environment, stage=stage, timeout=timeout, public_progress=True)
    if platform == "linux":
        environment.update({"CC": "gcc-14", "CXX": "g++-14"})
        execute(["nasm", "-v"], stage="preflight", timeout=60)
        execute(["bash", str(upstream / "bootstrap-vcpkg.sh"), "-disableMetrics"], stage="bootstrap", timeout=600)
        executable = str(upstream / "vcpkg")
        triplet = "x64-linux-static-release"
    else:
        execute(["cmd.exe", "/d", "/c", str(upstream / "bootstrap-vcpkg.bat"), "-disableMetrics"], stage="bootstrap", timeout=600)
        executable = str(upstream / "vcpkg.exe")
        triplet = "x64-windows-static-release"
    triplets = Path(__file__).resolve().parent.parent / "triplets"
    installed = root / "installed"
    args = build_support.native_release_options(["--triplet=" + triplet, "--overlay-triplets=" + str(triplets), "--overlay-ports=" + str(root / "workspace/ports"), "--x-install-root=" + str(installed)])
    packages = payload["plan"]["platforms"][platform]["packages"]
    binary_cache = None
    cache_key = None
    if cfg is not None:
        binary_cache = root / "binary-cache"
        cache_key = cef_build.binary_key(payload["plan"]["upstream_sha"], platform, env("GITHUB_SHA"),
                                         triplets / (triplet + ".cmake"))
        selected = cfg["platforms"][platform]["binary_cache"]
        if selected is not None:
            cef_cache.fetch(Client(env("BUILD_CACHE_READ_TOKEN")), selected, binary_cache,
                            platform=platform, kind="vcpkg-binaries", key=cache_key,
                            revision=env("GITHUB_SHA"), private=input_private)
        else:
            binary_cache.mkdir()
        platform_probe = cef_build.capture_platform_dependencies(
            root, cfg, platform, execute, executable, args, binary_cache)
        platform_sha256 = platform_probe["sha256"] if platform_probe is not None else None
        if not cef_build.run_engine(root, cfg, platform, execute, environment, input_private,
                                    env("GITHUB_SHA"), platform_probe):
            _persist_binary_cache(binary_cache, cache_key, platform, input_private)
            return  # Persisted checkpoint + completed packages; never an installed/published SDK.
    # Preserve downloads through the entire graph. Remove them at final job cleanup.
    try:
        execute(build_support.install_command(executable, packages, args, binary_cache=binary_cache), stage="install", timeout=14400)
    finally:
        _persist_binary_cache(binary_cache, cache_key, platform, input_private)
    input_private = None
    export = root / "export"
    export.mkdir()
    export_packages = sorted({p.split("[", 1)[0] for p in packages})
    execute([executable, "export", *export_packages, *args, "--raw", "--output=sdk", "--output-dir=" + str(export)], stage="export", timeout=900)
    sdk = export / "sdk"
    build_support.copy_export_triplet(sdk, triplets, triplet)
    package = root / "sdk.zip"
    safeio.sdk_zip(sdk, package)
    safeio.extract_zip(package, root / "consumer-sdk")
    source = root / "workspace" / payload["plan"]["smoke_path"]
    out = root / "smoke-build"
    configure = build_support.consumer_configure_command(source, out, root / "consumer-sdk", triplet)
    if cfg is not None:
        configure.append("-DCEF_STATIC_SMOKE_SOURCE=" + str(root / "cef-recipe/vcpkg/ports/cef-static/smoke.c"))
    execute(configure, stage="consumer-configure", timeout=600)
    execute(["cmake", "--build", str(out), "--config", "Release", "--parallel", "2"], stage="consumer-build", timeout=1800)
    execute(["ctest", "--test-dir", str(out), "-C", "Release", "--output-on-failure", "--timeout", "60"], stage="consumer-test", timeout=180)
    cef_proof = cef_build.verify_consumer(root, cfg, platform, execute, platform_sha256) if cfg is not None else None
    bundle = root / "result"
    bundle.mkdir()
    shutil.copyfile(package, bundle / "sdk.zip")
    (bundle / "request.json").write_bytes(crypto.canonical(document))
    manifest = {"version": 1, "platform": platform, "triplet": triplet, "sdk_sha256": crypto.digest(package),
                "request_sha256": hashlib.sha256(crypto.canonical(document)).hexdigest(), "builder_sha": env("GITHUB_SHA"),
                "build_run": int(env("GITHUB_RUN_ID")), "build_attempt": int(env("GITHUB_RUN_ATTEMPT")),
                "source_sha": payload["source_sha"], "upstream_sha": payload["plan"]["upstream_sha"],
                "image_os": os.environ.get("ImageOS", ""), "image_version": os.environ.get("ImageVersion", "")}
    if cfg is not None:
        manifest["cef"] = {"build_contract_sha256": cef_contract.build_key(cfg, platform, platform_sha256),
                           "profile": cfg["profile"], "consumer": cef_proof}
    (bundle / "manifest.json").write_bytes(crypto.canonical(manifest))
    safeio.pack_tar(bundle, root / "result.tgz")
    context = file_context(payload["release_id"], payload["salt"], int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")), env("GITHUB_SHA"), "sdk", platform)
    crypto.encrypt_file(root / "result.tgz", Path(env("CIPHER_DIR")) / "sdk.enc", env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"), context)
    cef_build.write_output("sdk_ready", True)


def diagnostics():
    """Compiler/supervisor logs only; never credentialed prepare/fetch logs."""
    guard(BUILDER, event="workflow_dispatch")
    root = work()
    source = root / "build.log"
    if not source.is_file():
        return
    # Include bounded detailed CMake logs for the next diagnosis, still encrypted.
    combined = root / "diagnostic.log"
    with combined.open("wb") as out:
        with source.open("rb") as stream:
            shutil.copyfileobj(stream, out, 1024 * 1024)
        remaining = 16 * 1024**2
        for folder in sorted((root / "upstream/buildtrees").glob("*")):
            if not folder.is_dir() or folder.is_symlink():
                continue
            for log in sorted(folder.glob("*.log")):
                if not safeio.regular(log) or remaining <= 0:
                    continue
                out.write(("\nDETAIL_LOG " + log.relative_to(root).as_posix() + "\n").encode())
                with log.open("rb") as stream:
                    data = stream.read(min(remaining, 1024**2))
                out.write(data)
                remaining -= len(data)
    data = event()["inputs"]
    context = file_context(data["release_id"], data["salt"], int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")), env("GITHUB_SHA"), "diagnostic", env("TARGET_PLATFORM"))
    crypto.encrypt_file(combined, Path(env("DIAGNOSTIC_DIR")) / "diagnostic.enc", env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"), context)


def cleanup():
    process.remove_tree(Path(env("RUNNER_TEMP")) / "encrypted-release-private")
