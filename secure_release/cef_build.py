"""CEF integration for the encrypted builder; worker stdout stays private."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import sys
from . import crypto, safeio, cef_contract, cef_cache
from .protocol import BUILDER
from .github import Client


def materialize(workspace: Path, cfg: dict, platform: str) -> str:
    contract = cef_contract.port_contract(cfg, platform)
    port = workspace / "ports/cef-static"
    if not (port / "portfile.cmake").is_file() or port.is_symlink():
        raise ValueError("CEF acquisition port is missing")
    # This file exists BEFORE vcpkg calculates any ABI, including cache lookup.
    (port / "cef-build.json").write_bytes(crypto.canonical(contract))
    return cef_contract.build_key(cfg, platform)


def binary_key(upstream_sha: str, platform: str, revision: str, triplet: Path) -> str:
    return hashlib.sha256(crypto.canonical({"schema": 1, "upstream": upstream_sha,
        "platform": platform, "builder": revision, "triplet_sha256": crypto.digest(triplet),
        "image": os.environ.get("ImageVersion", "")})).hexdigest()


def worker_environment(environment: dict, recipe_sha: str) -> dict:
    result = dict(environment)
    # The canonical codec binds the actual orchestration scope and runner image.
    # Only these non-credential GitHub values enter the worker process.
    for name in ("GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if name in os.environ:
            result[name] = os.environ[name]
    result["GITHUB_SHA"] = recipe_sha
    return result


def write_output(name: str, value: bool) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"{name}={str(value).lower()}\n")


def run_engine(root: Path, cfg: dict, platform: str, execute, environment: dict,
               input_private: str, revision: str) -> bool:
    """Return False only for a clean, persisted unfinished compilation slice."""
    cef_contract.validate(cfg)
    selected = cfg["platforms"][platform]
    key = materialize(root / "workspace", cfg, platform)
    if selected["mode"] == "release-import":
        if cfg["profile"] != "engine-static":
            raise ValueError("The selected release has no strict platform-dependency qualification")
        return True
    # Strict mode must fail BEFORE downloading Chromium if its dependency
    # qualification has not been supplied by a reviewed recipe.
    if cfg["profile"] != "engine-static":
        raise ValueError("Source recipe has not yet qualified the static-third-party runtime closure")
    recipe = root / "cef-recipe"
    work = root / "cef-work"
    logs = root / "cef-logs"
    logs.mkdir(exist_ok=True)
    driver = recipe / "vcpkg/integration/driver.py"
    if not driver.is_file():
        raise ValueError("Selected CEF recipe lacks the integration worker")
    environment.update(worker_environment(environment, cfg["recipe_commit"]))
    environment["CEF_STATIC_WORK"] = str(work)
    environment["CEF_STATIC_BUILD_TIMEOUT_SECONDS"] = "18000"
    checkpoint = root / "cef-checkpoint"
    if selected["mode"] == "source-resume":
        restored = root / "cef-restored-checkpoint"
        cef_cache.fetch(Client(os.environ["BUILD_CACHE_READ_TOKEN"]), selected["checkpoint"], restored,
                        platform=platform, kind="cef-checkpoint", key=key, revision=revision, private=input_private)
        execute([sys.executable, str(driver), "restore", "--work", str(work), "--logs", str(logs),
                 "--contract", key, "--state", str(logs / "restored.json"), "--checkpoint", str(restored)],
                stage="preflight", timeout=7200, cwd=recipe)
        shutil.rmtree(restored)
    elif work.exists() and any(work.iterdir()):
        raise ValueError("Explicit fresh build cannot erase an existing workspace")
    else:
        work.mkdir(parents=True, exist_ok=True)
    # Install Chromium's locked build prerequisites before GN compilation.
    execute([sys.executable, str(recipe / "vcpkg/ports/cef-static/source_build.py"), "prepare",
             "--work", str(work), "--logs", str(logs)], stage="preflight", timeout=10800, cwd=recipe)
    if platform == "linux":
        execute(["sudo", str(work / "download/chromium/src/build/install-build-deps.sh"),
                 "--no-prompt", "--no-arm", "--no-chromeos-fonts"], stage="preflight", timeout=1800, cwd=recipe)
    state = logs / "iteration.json"
    failure = None
    try:
        execute([sys.executable, str(driver), "slice", "--work", str(work), "--logs", str(logs),
                 "--contract", key, "--state", str(state), "--checkpoint", str(checkpoint),
                 "--seconds", str(cfg["slice_seconds"]), "--jobs", str(cfg["jobs"])],
                stage="install", timeout=cfg["slice_seconds"] + 5400, cwd=recipe)
    except Exception as error:
        failure = error
    if state.is_file():
        result = crypto.parse(state.read_bytes())
        if result.get("checkpoint_ready") is True:
            base = cef_cache.context("cef-checkpoint", platform, key, int(os.environ["GITHUB_RUN_ID"]),
                                     int(os.environ["GITHUB_RUN_ATTEMPT"]), revision, "index")
            output = Path(os.environ["RUNNER_TEMP"]) / "cipher-cache/cef-checkpoint"
            cef_cache.seal(checkpoint, output, crypto.public_text(input_private), base)
            write_output("cef_checkpoint_ready", True)
            shutil.rmtree(checkpoint)
        if failure is not None:
            raise failure
        if result.get("ready") is not True:
            write_output("sdk_ready", False)
            return False
    elif failure is not None:
        raise failure
    else:
        raise ValueError("CEF iteration returned no completion state")
    return True


def verify_consumer(root: Path, cfg: dict, platform: str, execute) -> dict:
    """Run a NEW relocated combined consumer; upstream receipts are provenance only."""
    recipe = root / "cef-recipe"
    name = "cef_static_combined_smoke" + (".exe" if platform == "windows" else "")
    candidates = [p for p in (root / "smoke-build").rglob(name) if p.is_file()]
    if len(candidates) != 1:
        raise ValueError("Expected one combined CEF consumer executable")
    executable = candidates[0]
    deployed = root / "cef-consumer-deployed"
    deployed.mkdir()
    shutil.copyfile(executable, deployed / name)
    shutil.copymode(executable, deployed / name)
    for resource in ("icudtl.dat", "resources.pak", "chrome_100_percent.pak", "chrome_200_percent.pak",
                     "snapshot_blob.bin", "v8_context_snapshot.bin"):
        path = executable.parent / resource
        if path.is_file():
            shutil.copyfile(path, deployed / resource)
    if (executable.parent / "locales").is_dir():
        shutil.copytree(executable.parent / "locales", deployed / "locales")
    if not (deployed / "icudtl.dat").is_file():
        raise ValueError("Combined consumer is missing ICU resources")
    logs = root / "cef-consumer-evidence"
    state = logs / "consumer.json"
    command = [sys.executable, str(recipe / "vcpkg/integration/driver.py"), "verify-consumer",
               "--work", str(root / "cef-work"), "--logs", str(logs),
               "--contract", cef_contract.build_key(cfg, platform), "--state", str(state),
               "--executable", str(deployed / name)]
    for folder in (root / "installed", root / "consumer-sdk", root / "cef-work"):
        if folder.exists():
            command.extend(["--hide", str(folder)])
    execute(command, stage="consumer-test", timeout=900, cwd=recipe)
    proof = crypto.parse(state.read_bytes())
    validate_evidence(proof, cfg, platform)
    return proof


def validate_evidence(proof: dict, cfg: dict, platform: str) -> None:
    """Used by both the build driver and independent private publisher."""
    cef_contract.validate(cfg)
    if cfg["profile"] != "engine-static":
        raise ValueError("A strict profile needs a separately qualified platform closure")
    if (proof.get("schema") != 1 or proof.get("kind") != "consumer-verification"
            or proof.get("engine_linkage") != "static" or proof.get("capi_only") is not True
            or proof.get("system_libraries_static") is not False or proof.get("sandbox_verified") is not False):
        raise ValueError("Invalid CEF consumer evidence")
    sha256 = cef_contract.digest(proof.get("executable_sha256"))
    smoke = proof.get("smoke", {})
    if (smoke.get("cef") != "152.0.6+g708dc14+chromium-152.0.7977.83"
            or smoke.get("engine") != "static" or smoke.get("interface") != "capi"
            or not all(smoke.get(field) is True for field in ("javascript", "paint", "browser_modules_clean", "renderer_modules_clean"))):
        raise ValueError("CEF runtime validation is incomplete")
    browser, renderer = smoke.get("browser_pid"), smoke.get("renderer_pid")
    if type(browser) is not int or type(renderer) is not int or min(browser, renderer) < 1 or browser == renderer:
        raise ValueError("CEF renderer is not a distinct process")
    runs = proof.get("smoke_runs", {})
    count = 3 if platform == "windows" else 1
    if (runs.get("executable_sha256") != sha256 or runs.get("status") != "success"
            or runs.get("engine_runtime_verified") is not True or runs.get("no_retry_on_failure") is not True
            or type(runs.get("required_runs")) is not int or runs["required_runs"] != count
            or type(runs.get("passed_runs")) is not int or runs["passed_runs"] != count
            or not isinstance(runs.get("runs"), list) or len(runs["runs"]) != count):
        raise ValueError("Incomplete independent CEF runtime repetitions")
    directories = set()
    for i, run in enumerate(runs["runs"], 1):
        if (run.get("number") != i or run.get("status") != "success" or run.get("engine_runtime_verified") is not True
                or not isinstance(run.get("cwd"), str) or not run["cwd"] or run["cwd"] in directories):
            raise ValueError("Invalid CEF runtime repetition")
        directories.add(run["cwd"])
