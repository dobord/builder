"""CEF integration for the encrypted builder; worker stdout stays private."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import sys
from . import crypto, safeio, cef_contract, cef_cache, static_audit, build_support
from .protocol import BUILDER
from .github import Client


MIN_SOURCE_FREE_BYTES = 80 * 1024**3


def require_source_capacity(root: Path, cfg: dict, platform: str) -> None:
    """Reject undersized source runners before dependency/bootstrap work.

    The pinned CEF recipe repeats its own capacity check immediately before
    source preparation; this early gate only avoids wasting a standard hosted
    runner on a build that cannot start.
    """
    cef_contract.validate(cfg)
    if platform not in cef_contract.TRIPLETS:
        raise ValueError("Invalid CEF platform")
    if not cfg["platforms"][platform]["mode"].startswith("source-"):
        return
    free = shutil.disk_usage(root).free
    if free < MIN_SOURCE_FREE_BYTES:
        raise RuntimeError(
            "CEF source build requires at least 80 GiB free; configure trusted "
            "CEF_STATIC_LINUX_RUNNER_LABELS/CEF_STATIC_WINDOWS_RUNNER_LABELS "
            "for a larger or self-hosted runner"
        )


def materialize(workspace: Path, cfg: dict, platform: str, platform_sha256: str | None = None) -> str:
    contract = cef_contract.port_contract(cfg, platform, platform_sha256)
    port = workspace / "ports/cef-static"
    if not (port / "portfile.cmake").is_file() or port.is_symlink():
        raise ValueError("CEF acquisition port is missing")
    # This file exists BEFORE vcpkg calculates any ABI, including cache lookup.
    (port / "cef-build.json").write_bytes(crypto.canonical(contract))
    return cef_contract.build_key(cfg, platform, platform_sha256)


def capture_platform_dependencies(root: Path, cfg: dict, platform: str, execute,
                                  executable: str, install_args: list[str],
                                  binary_cache: Path | None) -> dict | None:
    """Build the signed vcpkg closure, then snapshot immutable Linux target inputs."""
    cef_contract.validate(cfg)
    if cfg["profile"] != "static-third-party" or platform != "linux":
        return None
    probe = root / "cef-platform-probe"
    if probe.exists():
        raise ValueError("Strict platform probe already exists")
    execute(build_support.install_command(executable, ["cef-platform-deps"], install_args,
                                          binary_cache=binary_cache),
            stage="preflight", timeout=14400)
    prefix = root / "installed" / cef_contract.TRIPLETS[platform]
    pkgconf = shutil.which("pkg-config")
    if not pkgconf:
        raise ValueError("Native pkg-config is required to freeze the static platform closure")
    probe.mkdir()
    manifest = probe / "platform-inputs.json"
    snapshot = probe / "target-prefix"
    receipt = probe / "qualification.json"
    native_work = probe / "native-work"
    script = root / "workspace/ci/cef-full/verify_prefix.py"
    if not script.is_file() or script.is_symlink():
        raise ValueError("Signed workspace lacks the complete CEF platform preflight")
    execute([sys.executable, str(script), "--installed", str(prefix),
             "--destination", str(snapshot), "--manifest", str(manifest),
             "--receipt", str(receipt), "--cef-recipe", str(root / "cef-recipe"),
             "--work", str(native_work)],
            stage="preflight", timeout=3600, cwd=root / "workspace")
    result = crypto.parse(receipt.read_bytes())
    if (result.get("schema") != 1 or result.get("kind") != "cef-static-platform-preflight"
            or result.get("status") != "success"
            or result.get("full_platform_graph_qualified") is not True
            or result.get("cef_runtime_verified") is not False
            or result.get("gpu_runtime_qualified") is not False
            or result.get("module_count") != 37):
        raise ValueError("Complete CEF platform preflight did not qualify the signed dependency graph")
    sha256 = cef_contract.digest(result.get("manifest_sha256"))
    return {"manifest": manifest, "prefix": snapshot, "sha256": sha256,
            "qualification": receipt, "qualification_sha256": crypto.digest(receipt)}


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
               input_private: str, revision: str, platform_probe: dict | None = None) -> bool:
    """Return False only for a clean, persisted unfinished compilation slice."""
    cef_contract.validate(cfg)
    selected = cfg["platforms"][platform]
    strict = cfg["profile"] == "static-third-party"
    if selected["mode"] == "release-import":
        if strict:
            raise ValueError("Strict CEF profiles require source-built engines")
        materialize(root / "workspace", cfg, platform)
        return True
    if strict and platform == "linux" and platform_probe is None:
        raise ValueError("Strict Linux source build requires a frozen vcpkg platform closure")
    if (not strict or platform != "linux") and platform_probe is not None:
        raise ValueError("Unexpected platform closure for this CEF profile")
    platform_sha256 = platform_probe["sha256"] if platform_probe is not None else None
    key = materialize(root / "workspace", cfg, platform, platform_sha256)
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
    platform_inputs = None
    platform_args: list[str] = []
    if platform_probe is not None:
        platform_inputs = {"manifest": str(work / "platform-inputs.json"),
                           "prefix": str(work / "target-prefix"),
                           "sha256": platform_probe["sha256"]}
        platform_args = ["--platform-manifest", platform_inputs["manifest"],
                         "--platform-prefix", platform_inputs["prefix"],
                         "--platform-sha256", platform_inputs["sha256"]]
        environment.update({"CEF_STATIC_PLATFORM_MANIFEST": platform_inputs["manifest"],
                            "CEF_STATIC_PLATFORM_PREFIX": platform_inputs["prefix"],
                            "CEF_STATIC_PLATFORM_SHA256": platform_inputs["sha256"]})
    if strict:
        environment["CEF_STATIC_STRICT_THIRD_PARTY"] = "1"
    if selected["mode"] == "source-resume":
        restored = root / "cef-restored-checkpoint"
        cef_cache.fetch(Client(os.environ["BUILD_CACHE_READ_TOKEN"]), selected["checkpoint"], restored,
                        platform=platform, kind="cef-checkpoint", key=key, revision=revision, private=input_private)
        if platform_probe is not None:
            shutil.rmtree(Path(platform_probe["prefix"]))
            Path(platform_probe["manifest"]).unlink()
        execute([sys.executable, str(driver), "restore", "--work", str(work), "--logs", str(logs),
                 "--contract", key, "--state", str(logs / "restored.json"), "--checkpoint", str(restored),
                 *platform_args],
                stage="preflight", timeout=7200, cwd=recipe)
        shutil.rmtree(restored)
    elif work.exists() and any(work.iterdir()):
        raise ValueError("Explicit fresh build cannot erase an existing workspace")
    else:
        work.mkdir(parents=True, exist_ok=True)
        if platform_probe is not None:
            Path(platform_probe["prefix"]).rename(Path(platform_inputs["prefix"]))
            Path(platform_probe["manifest"]).rename(Path(platform_inputs["manifest"]))
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
                 "--seconds", str(cfg["slice_seconds"]), "--jobs", str(cfg["jobs"]), *platform_args],
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


def verify_consumer(root: Path, cfg: dict, platform: str, execute,
                    platform_sha256: str | None = None,
                    platform_preflight: dict | None = None,
                    *, recipe_root: Path | None = None) -> dict:
    """Run a NEW relocated combined consumer; upstream receipts are provenance only."""
    recipe = root / "cef-recipe" if recipe_root is None else recipe_root
    if recipe_root is not None:
        # Combined qualification uses a real pinned checkout for exact recipe
        # reconstruction, rather than the ordinary worker's copied recipe tree.
        driver = recipe / "vcpkg/integration/driver.py"
        if recipe.is_symlink() or driver.is_symlink() or not driver.is_file():
            raise ValueError("Explicit CEF consumer recipe is missing or redirected")
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
               "--contract", cef_contract.build_key(cfg, platform, platform_sha256), "--state", str(state),
               "--executable", str(deployed / name)]
    for folder in (root / "installed", root / "consumer-sdk", root / "cef-work",
                   root / "export/sdk", root / "smoke-build"):
        if folder.exists():
            command.extend(["--hide", str(folder)])
    execute(command, stage="consumer-test", timeout=900, cwd=recipe)
    proof = crypto.parse(state.read_bytes())
    if cfg["profile"] == "static-third-party":
        if platform == "linux":
            if (not isinstance(platform_preflight, dict)
                    or platform_preflight.get("sha256") != platform_sha256
                    or not isinstance(platform_preflight.get("qualification_sha256"), str)
                    or not isinstance(platform_preflight.get("qualification"), Path)
                    or not platform_preflight["qualification"].is_file()):
                raise ValueError("Strict Linux SDK lacks its complete platform qualification receipt")
            qualification = crypto.parse(platform_preflight["qualification"].read_bytes())
            if (qualification.get("schema") != 1
                    or qualification.get("kind") != "cef-static-platform-preflight"
                    or qualification.get("status") != "success"
                    or qualification.get("full_platform_graph_qualified") is not True
                    or qualification.get("cef_runtime_verified") is not False
                    or qualification.get("module_count") != 37
                    or qualification.get("manifest_sha256") != platform_sha256
                    or crypto.digest(platform_preflight["qualification"])
                       != platform_preflight["qualification_sha256"]):
                raise ValueError("Strict Linux platform qualification receipt changed or is incomplete")
            inventory = root / "consumer-sdk" / "installed" / cef_contract.TRIPLETS[platform] / "share/cef-static/static-platform-inventory.json"
            if not inventory.is_file() or inventory.is_symlink():
                raise ValueError("Strict Linux SDK is missing the exported platform inventory")
            value = crypto.parse(inventory.read_bytes())
            if (value.get("schema") != 1 or value.get("kind") != "external-vcpkg-archives"
                    or value.get("manifest_sha256") != platform_sha256
                    or not isinstance(value.get("archives"), list) or not value["archives"]):
                raise ValueError("Strict Linux platform inventory does not match the build contract")
            proof["platform_closure"] = {"kind": "linux-frozen-vcpkg",
                                         "manifest_sha256": platform_sha256,
                                         "inventory_sha256": crypto.digest(inventory),
                                         "qualification_sha256": platform_preflight["qualification_sha256"],
                                         "full_platform_graph_qualified": True,
                                         "archive_count": len(value["archives"])}
        else:
            proof["platform_closure"] = {"kind": "windows-native-os-abi", "manifest_sha256": None}
    # The final ZIP (not the pre-export installed tree) is the audit input.
    # Detailed paths stay in encrypted diagnostics. A clean structural audit
    # does not upgrade the engine-only runtime profile.
    report = static_audit.inspect_sdk(root / "sdk.zip", platform)
    (logs / "target-archive-audit.json").write_bytes(crypto.canonical(report))
    proof["target_archive_audit"] = static_audit.summarize(report)
    validate_evidence(proof, cfg, platform)
    return proof



def platform_preflight_digest(value: dict) -> str:
    """Digest the pinned CEF platform-contract canonical JSON (including newline)."""
    if not isinstance(value, dict):
        raise ValueError("Invalid CEF platform preflight record")
    return hashlib.sha256(crypto.canonical(value) + b"\n").hexdigest()


def validate_platform_preflight(value: dict | None, proof: dict, cfg: dict, platform: str) -> None:
    """Bind the builder's complete dependency preflight to final runtime evidence."""
    cef_contract.validate(cfg)
    strict_linux = cfg["profile"] == "static-third-party" and platform == "linux"
    if not strict_linux:
        if value is not None:
            raise ValueError("Only strict Linux carries a platform preflight record")
        return
    if not isinstance(value, dict):
        raise ValueError("Strict Linux publication lacks its platform preflight record")
    closure = proof.get("platform_closure", {})
    if (set(value) < {"schema", "kind", "status", "full_platform_graph_qualified",
                      "cef_runtime_verified", "gpu_runtime_qualified", "module_count",
                      "manifest_sha256"}
            or value.get("schema") != 1
            or value.get("kind") != "cef-static-platform-preflight"
            or value.get("status") != "success"
            or value.get("full_platform_graph_qualified") is not True
            or value.get("cef_runtime_verified") is not False
            or value.get("gpu_runtime_qualified") is not False
            or value.get("module_count") != 37
            or value.get("manifest_sha256") != closure.get("manifest_sha256")
            or platform_preflight_digest(value) != closure.get("qualification_sha256")):
        raise ValueError("Strict Linux platform preflight is not bound to final CEF evidence")


def qualified_contract(proof: dict, cfg: dict, platform: str) -> tuple[str, dict]:
    """Bind publication to the exact strict Linux frozen-prefix digest.

    Runtime evidence is validated before its closure digest is trusted. Windows
    and engine-static builds deliberately carry no external platform digest.
    """
    validate_evidence(proof, cfg, platform)
    platform_sha256 = None
    if cfg["profile"] == "static-third-party" and platform == "linux":
        platform_sha256 = cef_contract.digest(proof["platform_closure"]["manifest_sha256"])
    return (cef_contract.build_key(cfg, platform, platform_sha256),
            cef_contract.port_contract(cfg, platform, platform_sha256))


def validate_evidence(proof: dict, cfg: dict, platform: str) -> None:
    """Used by both the build driver and independent private publisher."""
    cef_contract.validate(cfg)
    strict = cfg["profile"] == "static-third-party"
    if (proof.get("schema") != 1 or proof.get("kind") != "consumer-verification"
            or proof.get("engine_linkage") != "static" or proof.get("capi_only") is not True
            or proof.get("system_libraries_static") is not False or proof.get("sandbox_verified") is not False):
        raise ValueError("Invalid CEF consumer evidence")
    if strict:
        if proof.get("third_party_libraries_static") is not True:
            raise ValueError("Strict CEF consumer did not prove static third-party runtime linkage")
        closure = proof.get("platform_closure", {})
        if platform == "linux":
            if (closure.get("kind") != "linux-frozen-vcpkg"
                    or not isinstance(closure.get("archive_count"), int) or closure["archive_count"] < 1
                    or not isinstance(closure.get("manifest_sha256"), str)
                    or not isinstance(closure.get("inventory_sha256"), str)
                    or not isinstance(closure.get("qualification_sha256"), str)
                    or closure.get("full_platform_graph_qualified") is not True):
                raise ValueError("Strict Linux CEF platform closure evidence is incomplete")
            for name in ("manifest_sha256", "inventory_sha256", "qualification_sha256"):
                cef_contract.digest(closure[name])
        elif closure != {"kind": "windows-native-os-abi", "manifest_sha256": None}:
            raise ValueError("Strict Windows CEF platform closure evidence is incomplete")
    elif proof.get("third_party_libraries_static") not in (None, False):
        raise ValueError("Engine-only proof cannot claim strict third-party linkage")
    audit = proof.get("target_archive_audit", {})
    if (audit.get("kind") != "target-archive-audit-summary" or audit.get("target_archives_static") is not True
            or audit.get("violation_count") != 0):
        raise ValueError("Final SDK archive audit is incomplete")
    sha256 = cef_contract.digest(proof.get("executable_sha256"))
    smoke = proof.get("smoke", {})
    if (smoke.get("cef") != "152.0.6+g708dc14+chromium-152.0.7977.83"
            or smoke.get("engine") != "static" or smoke.get("interface") != "capi"
            or not all(smoke.get(field) is True for field in ("javascript", "paint", "browser_modules_clean", "renderer_modules_clean"))
            or (strict and smoke.get("third_party_modules_static") is not True)):
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
