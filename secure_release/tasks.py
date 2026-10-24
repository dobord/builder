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
    value = crypto.parse(Path(env("GITHUB_EVENT_PATH")).read_bytes())
    if os.environ.get("SDK_JOINT_RELEASE") == "true" and env("GITHUB_EVENT_NAME") == "workflow_dispatch":
        platform = env("TARGET_PLATFORM")
        if platform not in {"linux", "windows"}:
            raise ValueError("Invalid joint SDK platform")
        original = value["inputs"]
        value["inputs"] = {"release_id": original["release_id"], "salt": original["salt"],
                           "request": original[platform + "_request"]}
    return value


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
    builder_sha = cef_cache.producer_revision(platform, kind, run, attempt, builder_sha)
    workflow = build_workflow(producer.get("path", ""))
    if platform not in BUILD_WORKFLOWS[workflow]:
        raise ValueError("continuation platform differs from producer workflow")
    if cef_cache.continuation_record(run) is not None and workflow != "build-linux-release.yml":
        raise ValueError("reviewed Linux continuation workflow changed")
    check_run(producer, BUILDER, workflow, builder_sha, attempt,
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
    selected = matches[0] if matches else None
    if selected is not None:
        cef_cache.selected_revision(selected, platform, kind, builder_sha)
    return selected


def _apply_continuation(plan: dict, inputs: dict, builder_sha: str, client: Client,
                        platforms: tuple[str, ...] = ("linux", "windows")) -> dict:
    """Turn explicit run/attempt inputs into authenticated source-resume selectors."""
    if plan.get("version") != 2 or plan.get("cef", {}).get("profile") != "static-third-party":
        raise ValueError("CEF continuation requires the signed strict source profile")
    result = crypto.parse(crypto.canonical(plan))
    changed = False
    for platform in cef_contract.TRIPLETS:
        run_text = str(inputs.get(platform + "_builder_run", "")).strip()
        attempt_text = str(inputs.get(platform + "_builder_attempt", "")).strip()
        if platform not in platforms and (run_text or attempt_text):
            raise ValueError("unrequested continuation platform")
        if bool(run_text) != bool(attempt_text):
            raise ValueError("CEF continuation run and attempt must be supplied together")
        if not run_text:
            continue
        selected = result["cef"]["platforms"][platform]
        if selected != {"mode": "source-fresh", "checkpoint": None, "binary_cache": None}:
            raise ValueError("CEF continuation only starts from a fresh signed plan")
        run, attempt = number(run_text), number(attempt_text)
        reviewed = cef_cache.continuation_record(run)
        if reviewed is not None:
            if (platform != "linux" or result["cef"]["recipe_commit"] != reviewed["recipe_commit"]):
                raise ValueError("Reviewed Linux continuation recipe changed")
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
    scope = os.environ.get("SDK_RELEASE_PLATFORMS", "all")
    main_windows_request = (scope == "windows" and event_name == "workflow_dispatch"
                            and env("GITHUB_REF") == "refs/heads/main"
                            and env("GITHUB_REF_TYPE") == "branch")
    if not e["repository"]["private"] or (env("GITHUB_REF_TYPE") != "tag" and not main_windows_request):
        raise ValueError("release requests require an immutable tag or an explicit main Windows retry")
    tag = e.get("inputs", {}).get("source_tag") if main_windows_request else env("GITHUB_REF_NAME")
    if not isinstance(tag, str) or not TAG.fullmatch(tag):
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
    requester_sha = sha(env("GITHUB_SHA"))
    source_sha = requester_sha
    builder_sha = sha(env("BUILDER_COMMIT_SHA"))
    scope = os.environ.get("SDK_RELEASE_PLATFORMS", "all")
    if scope not in {"all", "linux", "windows"}:
        raise ValueError("unsupported requested release scope")
    workflow = "build-release.yml" if scope == "all" else f"build-{scope}-release.yml"
    platforms = BUILD_WORKFLOWS[workflow]
    client = Client(env("SOURCE_TOKEN"))
    if main_windows_request:
        if not tag.endswith("-windows"):
            raise ValueError("Main Windows retry requires a Windows release tag")
        ref = client.get(f"/repos/{SOURCE}/git/ref/tags/{tag}")["object"]
        for _ in range(5):
            if ref["type"] == "commit":
                break
            if ref["type"] != "tag":
                raise ValueError("unsupported source tag ref")
            ref = client.get(f"/repos/{SOURCE}/git/tags/{sha(ref['sha'])}")["object"]
        if ref["type"] != "commit":
            raise ValueError("source tag does not resolve to a commit")
        source_sha = sha(ref["sha"])
    plan_path = "ci/release-windows-plan.json" if scope == "windows" else "ci/release-plan.json"
    record = client.get(f"/repos/{SOURCE}/contents/{plan_path}?ref={source_sha}")
    plan = crypto.parse(crypto.unb64(record["content"].replace("\n", "")))
    validate_plan(plan)
    builder = Client(env("BUILDER_DISPATCH_TOKEN"))
    if continuation_inputs is not None and any(
        str(continuation_inputs.get(p + suffix, "")).strip()
        for p in cef_contract.TRIPLETS for suffix in ("_builder_run", "_builder_attempt")
    ):
        run_text = str(continuation_inputs.get("linux_builder_run", "")).strip()
        reviewed = cef_cache.continuation_record(int(run_text)) if run_text.isdecimal() else None
        if reviewed is not None and source_sha != reviewed["source_sha"]:
            raise ValueError("reviewed Linux continuation source revision changed")
        cache_reader = Client(env("BUILDER_CACHE_READ_TOKEN"))
        plan = _apply_continuation(plan, continuation_inputs, builder_sha, cache_reader, platforms)
    created = int(time.time())
    rid, salt = str(uuid.uuid4()), crypto.b64(os.urandom(32))
    payload = {"version": 1, "release_id": rid, "salt": salt, "source_sha": source_sha, "source_tag": tag,
               "request_run": number(env("GITHUB_RUN_ID")), "request_attempt": number(env("GITHUB_RUN_ATTEMPT")),
               "builder_sha": builder_sha, "output_key": crypto.fingerprint(env("ARTIFACT_ENCRYPTION_PUBLIC_KEY")),
               "input_key": crypto.fingerprint(env("BUILDER_INPUT_PUBLIC_KEY")), "created": created, "expires": created + 172800,
                "source_id": IDS[SOURCE], "builder_id": IDS[BUILDER], "bin_id": IDS[BIN], "plan": plan}
    if scope != "all":
        payload.update(version=2, platforms=[scope])
    if main_windows_request:
        payload.update(version=3, requester_sha=requester_sha)
    document = crypto.sign(payload, env("REQUEST_SIGNING_PRIVATE_KEY"))
    encrypted = crypto.seal_message(crypto.canonical(document), env("BUILDER_INPUT_PUBLIC_KEY"), message_context(rid, salt))
    answer = builder.dispatch(BUILDER, workflow, {"release_id": rid, "salt": salt, "request": encrypted})
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
    workflow = os.environ.get("SDK_BUILD_WORKFLOW", "build-release.yml")
    if workflow not in BUILD_WORKFLOWS or release_platforms(payload) != BUILD_WORKFLOWS[workflow]:
        raise ValueError("signed platform selection differs from builder workflow")
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
    request_workflow = "release-windows-request.yml" if release_platforms(payload) == ("windows",) else "release-request.yml"
    if os.environ.get("SDK_JOINT_RELEASE") == "true":
        request_workflow = "release-combined-request.yml"
    requester_sha = payload.get("requester_sha", payload["source_sha"])
    if payload["version"] == 3:
        if requester_event != "workflow_dispatch" or requester.get("head_branch") != "main":
            raise ValueError("Windows retry must be dispatched from approved source main")
        request_comparison = client.get(f"/repos/{SOURCE}/compare/{requester_sha}...main")
        if request_comparison["status"] not in {"identical", "ahead"}:
            raise ValueError("Windows requester is outside approved main history")
    check_run(requester, SOURCE, request_workflow, requester_sha,
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
    workflow = os.environ.get("SDK_BUILD_WORKFLOW", "build-release.yml")
    if (workflow not in BUILD_WORKFLOWS or release_platforms(payload) != BUILD_WORKFLOWS[workflow]
            or platform not in release_platforms(payload)):
        raise ValueError("build platform is not authorized by the signed request")
    cfg = payload["plan"].get("cef")
    if cfg is not None:
        cef_build.require_source_capacity(root, cfg, platform)
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
    linux_sources = None
    if workflow == "build-linux-release.yml" and cfg is not None:
        from . import linux_sdk
        linux_sources = linux_sdk.capture_sources(root, payload["plan"])
    guarded_ports = [p for p in source_ports if linux_sources is None or p["name"] != "cef-static"]
    build_support.protect_source_archives(root / "workspace", downloads, guarded_ports)
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
    linux_native = None
    if cfg is not None:
        binary_cache = root / "binary-cache"
        selected = cfg["platforms"][platform]["binary_cache"]
        cache_revision = cef_cache.selected_revision(selected, platform, "vcpkg-binaries", env("GITHUB_SHA"))
        cache_key = cef_build.binary_key(payload["plan"]["upstream_sha"], platform, env("GITHUB_SHA"),
                                         triplets / (triplet + ".cmake"))
        if selected is not None:
            restore_cache_key = cef_build.binary_key(payload["plan"]["upstream_sha"], platform, cache_revision,
                                                     triplets / (triplet + ".cmake"),
                                                     image=cef_cache.binary_cache_image(selected, platform, env("GITHUB_SHA")))
            cef_cache.fetch(Client(env("BUILD_CACHE_READ_TOKEN")), selected, binary_cache,
                            platform=platform, kind="vcpkg-binaries", key=restore_cache_key,
                            revision=env("GITHUB_SHA"), private=input_private)
        else:
            binary_cache.mkdir()
        platform_probe = cef_build.capture_platform_dependencies(
            root, cfg, platform, execute, executable, args, binary_cache)
        platform_sha256 = platform_probe["sha256"] if platform_probe is not None else None
        profile_args = {"linux_sdk_profile": True} if linux_sources is not None else {}
        if workflow == "build-windows-release.yml":
            from . import windows_sdk
            windows_sdk.run_engine(root, cfg, execute, environment, input_private)
            engine_ready = True
        else:
            engine_ready = cef_build.run_engine(root, cfg, platform, execute, environment, input_private,
                                                env("GITHUB_SHA"), platform_probe, **profile_args)
        if not engine_ready:
            _persist_binary_cache(binary_cache, cache_key, platform, input_private)
            return  # Persisted checkpoint + completed packages; never an installed/published SDK.
        if linux_sources is not None:
            linux_native = linux_sdk.prepare_install(root, cfg, platform_probe, upstream, triplets)
            linux_sdk.fresh_replay_installation(root)
            args = ["--overlay-triplets=" + str(linux_native["triplets"])
                    if a.startswith("--overlay-triplets=") else a for a in args]
            build_support.protect_source_archives(root / "workspace", downloads,
                                                  [{"name": "cef-static", "sha": cfg["recipe_commit"]}])
    # Preserve downloads through the entire graph. Remove them at final job cleanup.
    try:
        execute(build_support.install_command(executable, packages, args, binary_cache=binary_cache), stage="install", timeout=14400)
    finally:
        _persist_binary_cache(binary_cache, cache_key, platform, input_private)
    input_private = None
    windows_isolation = None
    if workflow == "build-windows-release.yml" and cfg is not None:
        from . import windows_runtime_isolation
        windows_isolation = windows_runtime_isolation.install(
            installed, Path(env("RUNNER_TEMP")) / "w/download/chromium/src", root / "windows-runtime-isolation")
    linux_review = None
    windows_objects = None
    if platform == "windows" and "freerdp[full]" in packages:
        from . import windows_multimedia
        windows_objects = windows_multimedia.capture(root / "workspace", installed, upstream)
    linux_publication = workflow == "build-linux-release.yml" and cfg is not None
    if linux_publication:
        from . import linux_sdk
        linux_review = linux_sdk.prepare(root, installed, upstream, linux_sources, linux_native, platform_probe)
    export = root / "export"
    export.mkdir()
    export_packages = sorted({p.split("[", 1)[0] for p in packages})
    execute([executable, "export", *export_packages, *args, "--raw", "--output=sdk", "--output-dir=" + str(export)], stage="export", timeout=900)
    sdk = export / "sdk"
    build_support.copy_export_triplet(sdk, triplets, triplet)
    package = root / "sdk.zip"
    source_review = None
    if linux_review is not None:
        source_review = linux_sdk.package(root, sdk, package, linux_review, platform_probe)
    elif windows_objects is not None:
        source_review = windows_multimedia.package(sdk, package, windows_objects,
            diagnostics=root / "windows-runtime-isolation/sdk-source-inventory.json")
    else:
        safeio.sdk_zip(sdk, package)
    if windows_isolation is not None:
        windows_runtime_isolation.validate_archive(package, windows_isolation)
    safeio.extract_zip(package, root / "consumer-sdk")
    multimedia_tools_proof = None
    if platform == "linux" and "ffmpeg[static-full-gpl]" in packages:
        from . import multimedia_tools
        multimedia_tools_proof = multimedia_tools.verify_linux(
            root / "consumer-sdk", root, execute, freerdp_full="freerdp[full]" in packages)
    if windows_objects is not None:
        windows_multimedia.relocated(root / "consumer-sdk", windows_objects, source_review)
    source = root / "workspace" / payload["plan"]["smoke_path"]
    smoke_fixture = root / "cef-recipe/vcpkg/ports/cef-static/smoke.c"
    if workflow == "build-windows-release.yml" and cfg is not None:
        source = root / "windows-smoke-project"
        smoke_fixture = source / "smoke.c"
    if linux_review is not None:
        from . import cef_combined_smoke
        source = cef_combined_smoke.prepare(source, smoke_fixture, root / "linux-smoke-project")
        smoke_fixture = source / "smoke.c"
    out = root / "smoke-build"
    configure = build_support.consumer_configure_command(source, out, root / "consumer-sdk", triplet)
    if cfg is not None:
        configure.append("-DCEF_STATIC_SMOKE_SOURCE=" + str(smoke_fixture))
        if workflow == "build-windows-release.yml":
            configure.append("-DCMAKE_EXE_LINKER_FLAGS=/MAP /MAPINFO:EXPORTS /DEBUG:FULL /INCREMENTAL:NO")
        if platform == "linux":
            from . import cef_consumer_linker
            configure.append(cef_consumer_linker.cmake_flag())
    execute(configure, stage="consumer-configure", timeout=600)
    build_consumer = ["cmake", "--build", str(out), "--config", "Release", "--parallel", "2"]
    if workflow == "build-windows-release.yml" and cfg is not None:
        linker = Path(env("RUNNER_TEMP")) / "w/download/chromium/src/third_party/llvm-build/Release+Asserts/bin/lld-link.exe"
        if not safeio.regular(linker):
            raise ValueError("Qualified native Windows LLD consumer linker is missing")
        build_consumer += ["--", "/p:LinkToolExe=lld-link.exe", "/p:LinkToolPath=" + str(linker.parent), "/v:normal"]
    linker_log_offset = log.stat().st_size if log.exists() else 0
    execute(build_consumer, stage="consumer-build", timeout=1800)
    if workflow == "build-windows-release.yml" and cfg is not None:
        with log.open("rb") as stream:
            stream.seek(linker_log_offset)
            invocation = stream.read(64 * 1024**2).decode("utf-8", errors="replace").replace("\\", "/").lower()
        if linker.as_posix().lower() not in invocation:
            raise ValueError("Windows consumer build did not invoke the qualified native LLD")
        (root / "windows-consumer-linker.json").write_bytes(crypto.canonical({
            "kind": "qualified-native-lld", "sha256": crypto.digest(linker), "invocation_verified": True}))
    execute(["ctest", "--test-dir", str(out), "-C", "Release", "--output-on-failure", "--timeout", "60"], stage="consumer-test", timeout=180)
    cef_proof = cef_build.verify_consumer(
        root, cfg, platform, execute, platform_sha256, platform_probe,
        **({"reviewed_objects": linux_review["objects"]["objects"],
            "reviewed_host_tools": linux_review["host_tools"]["records"]} if linux_review is not None else
           {"reviewed_objects": windows_objects["objects"]} if windows_objects is not None else {})
    ) if cfg is not None else None
    cpp_proof = linux_sdk.verify_cpp(root, root / "consumer-sdk", linux_review, execute) if linux_review is not None else None
    platform_preflight = None
    if cfg is not None and cfg["profile"] == "static-third-party" and platform == "linux":
        if platform_probe is None:
            raise ValueError("Strict Linux result lost its platform preflight")
        platform_preflight = crypto.parse(platform_probe["qualification"].read_bytes())
        cef_build.validate_platform_preflight(platform_preflight, cef_proof, cfg, platform)
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
        if multimedia_tools_proof is not None:
            manifest["cef"]["multimedia_tools"] = multimedia_tools_proof
        if workflow == "build-windows-release.yml":
            if windows_objects is not None:
                manifest["cef"]["windows_multimedia_sources"] = source_review
            manifest["cef"]["windows_engine"] = windows_sdk.binding(cfg)
            manifest["cef"]["windows_runtime_isolation"] = windows_isolation
            manifest["cef"]["windows_consumer_linker"] = crypto.parse((root / "windows-consumer-linker.json").read_bytes())
        if platform_preflight is not None:
            manifest["cef"]["platform_preflight"] = platform_preflight
        if cpp_proof is not None:
            manifest["cef"]["cpp_consumer"] = cpp_proof
            manifest["cef"]["sdk_sources"] = source_review
    (bundle / "manifest.json").write_bytes(crypto.canonical(manifest))
    safeio.pack_tar(bundle, root / "result.tgz")
    context = file_context(payload["release_id"], payload["salt"], int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")), env("GITHUB_SHA"), "sdk", platform)
    crypto.encrypt_file(root / "result.tgz", Path(env("CIPHER_DIR")) / "sdk.enc", env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"), context)
    cef_build.write_output("sdk_ready", True)


def diagnostics():
    """Compiler/supervisor logs only; never credentialed prepare/fetch logs."""
    guard(BUILDER, event="workflow_dispatch")
    root = work()
    if os.name == "nt" and os.environ.get("SDK_BUILD_WORKFLOW") == "build-windows-release.yml":
        target = root / "windows-runtime-isolation"
        target.mkdir(exist_ok=True)
        script = (
            "$ErrorActionPreference='Stop'; "
            "$events=Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1001;"
            "StartTime=(Get-Date).AddMinutes(-20)} -ErrorAction SilentlyContinue | "
            "Where-Object {$_.Message -match 'cef_static_combined_smoke'} | "
            "Select-Object -First 20 TimeCreated,Id,Message; "
            "$events | ConvertTo-Json -Depth 3")
        try:
            with (target / "application-events.json").open("wb") as output:
                subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                               stdout=output, stderr=subprocess.DEVNULL, env=clean_env(), timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass  # Diagnostic collection cannot alter the original failed result.
        debugger = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Windows Kits/10/Debuggers/x64/cdb.exe"
        (target / "crash-debugger-status.json").write_bytes(crypto.canonical({
            "debugger_available": debugger.is_file(),
            "dump_count": len(list((root / "windows-crash-dumps").glob("*.dmp")))}))
        if debugger.is_file():
            for index, dump in enumerate(sorted((root / "windows-crash-dumps").glob("*.dmp"))[:4]):
                try:
                    with (target / f"crash-stack-{index}.log").open("wb") as output:
                        subprocess.run([str(debugger), "-z", str(dump), "-y", str(root / "smoke-build/Release"),
                                        "-i", str(root / "cef-consumer-deployed"),
                                        "-c", ".ecxr; r; kv; !analyze -v; q"], stdout=output,
                                       stderr=output, env=clean_env(), timeout=180)
                except (OSError, subprocess.TimeoutExpired):
                    pass
    source = root / "build.log"
    if not source.is_file():
        return
    # Include bounded detailed CMake logs for the next diagnosis, still encrypted.
    combined = root / "diagnostic.log"
    with combined.open("wb") as out:
        with source.open("rb") as stream:
            shutil.copyfileobj(stream, out, 1024 * 1024)
        remaining = 32 * 1024**2
        candidates = []
        for path in sorted((root / "smoke-build").rglob("*.map")):
            candidates.append(path)
        if (root / "windows-runtime-isolation").is_dir():
            candidates.extend(sorted((root / "windows-runtime-isolation").glob("*.log")))
            candidates.extend(sorted((root / "windows-runtime-isolation").glob("*.json")))
        if (root / "cef-consumer-evidence").is_dir():
            for pattern in ("static-smoke.log", "cef-static.log", "static-smoke-status.json", "timeout-processes.json", "smoke-runs.json"):
                candidates.extend(sorted((root / "cef-consumer-evidence").rglob(pattern)))
        runtime_logs = root / "upstream/buildtrees/cef-static/diagnostics"
        if runtime_logs.is_dir() and not runtime_logs.is_symlink():
            for pattern in ("smoke-progress-*.json", "smoke-modules-*.txt",
                            "static-smoke.log", "static-smoke-status.json", "smoke-runs.json",
                            "stdout.txt", "stderr.txt", "cef-static.log"):
                candidates.extend(sorted(runtime_logs.rglob(pattern)))
        for folder in sorted((root / "upstream/buildtrees").glob("*")):
            if folder.is_dir() and not folder.is_symlink():
                candidates.extend(sorted(folder.glob("*.log")))
        for folder in (root / "cef-logs", root / "cef-platform-probe/native-work/logs",
                       root / "cef-consumer-evidence", root / "windows-runtime-isolation"):
            if folder.is_dir() and not folder.is_symlink():
                for pattern in ("*.log", "*.json", "*.txt"):
                    candidates.extend(sorted(folder.rglob(pattern)))
        seen = set()
        for log in candidates:
            try:
                key = log.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if key in seen or not safeio.regular(log) or remaining <= 0:
                continue
            if not key.is_relative_to(root.resolve()):
                continue
            seen.add(key)
            out.write(("\nDETAIL_LOG " + log.relative_to(root).as_posix() + "\n").encode())
            with log.open("rb") as stream:
                data = stream.read(min(remaining, 2 * 1024**2))
            out.write(data)
            remaining -= len(data)
    data = event()["inputs"]
    context = file_context(data["release_id"], data["salt"], int(env("GITHUB_RUN_ID")), int(env("GITHUB_RUN_ATTEMPT")), env("GITHUB_SHA"), "diagnostic", env("TARGET_PLATFORM"))
    crypto.encrypt_file(combined, Path(env("DIAGNOSTIC_DIR")) / "diagnostic.enc", env("ARTIFACT_ENCRYPTION_PUBLIC_KEY"), context)


def cleanup():
    temporary = Path(env("RUNNER_TEMP"))
    process.remove_tree(temporary / "encrypted-release-private")
    process.remove_tree(temporary / "verified-release")
    if os.environ.get("SDK_BUILD_WORKFLOW") == "build-windows-release.yml":
        process.remove_tree(temporary / "w")
