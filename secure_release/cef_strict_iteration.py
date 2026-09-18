"""One strict Linux CEF qualification iteration on a trusted builder runner.

Private vcpkg output and compiler logs stay on the runner. The only resumable
artifact is encrypted with the builder input recipient. A completed slice is
additionally subjected to the pinned CEF browser/renderer runtime verification.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import cef_cache, cef_contract, crypto

VCPKG = "fb0c27ec25ae3d9f297edb8bcd5a36378e38ce2e"
UPSTREAM = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
CEF = "37729fd2b1db127c1658098d69ab63adc70e045f"
TRIPLET = "x64-linux-static-release"


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()


def run(command, *, cwd: Path, env: dict, log: Path, timeout: int,
        check: bool = True) -> subprocess.CompletedProcess:
    command = list(map(str, command))
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as stream:
        stream.write(subprocess.list2cmdline(command) + "\n")
        stream.flush()
        result = subprocess.run(
            command, cwd=cwd, env=env, stdout=stream,
            stderr=subprocess.STDOUT, timeout=timeout
        )
    if check and result.returncode:
        raise RuntimeError("strict CEF qualification subprocess failed")
    return result


def output(name: str, value: bool) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as stream:
            stream.write(f"{name}={str(value).lower()}\n")


def main() -> None:
    if sys.platform != "linux":
        raise ValueError("Strict CEF qualification requires native Linux")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    registry = workspace / "private-vcpkg"
    upstream = registry / ".full-upstream"
    recipe = registry / ".full-cef"
    if (git_head(registry), git_head(upstream), git_head(recipe)) != (VCPKG, UPSTREAM, CEF):
        raise ValueError("Strict CEF qualification source revision mismatch")

    evidence = temp / "cef-strict-evidence"
    platform_work = temp / "cef-platform-work"
    engine_work = temp / "cef-strict-engine-work"
    engine_logs = temp / "cef-strict-engine-logs"
    checkpoint = temp / "cef-strict-checkpoint"
    encrypted = temp / "cef-strict-checkpoint-encrypted"
    summary_path = temp / "cef-strict-iteration-summary.json"
    for path in (evidence, platform_work, engine_work, engine_logs, checkpoint, encrypted):
        if path.exists():
            raise ValueError("Strict CEF qualification requires fresh runner paths")
    evidence.mkdir()

    summary = {
        "schema": 1,
        "status": "running",
        "ready": False,
        "checkpoint_ready": False,
        "runtime_verified": False,
        "vcpkg_commit": VCPKG,
        "upstream_commit": UPSTREAM,
        "cef_recipe_commit": CEF,
    }
    clean_env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("PKG_CONFIG_", "LD_"))
        and key not in {
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LIBRARY_PATH",
            "CPATH", "CPLUS_INCLUDE_PATH", "C_INCLUDE_PATH", "GN_DEFINES",
        }
    }
    try:
        contract_env = dict(clean_env)
        contract_env["CEF_CONTRACT_SOURCE"] = str(recipe)
        run(
            [sys.executable, "-I", "-m", "unittest", "discover",
             "-s", "ci/cef-full/tests", "-v"],
            cwd=registry, env=contract_env,
            log=temp / "cef-strict-contract.log", timeout=300
        )
        run(
            [sys.executable, "ci/cef-full/native.py", "--root", ".",
             "--work", platform_work, "--evidence", evidence],
            cwd=registry, env=clean_env,
            log=temp / "cef-platform-native.log", timeout=10800
        )
        platform_receipt = json.loads((evidence / "native-full.json").read_text())
        required = {
            "schema": 1,
            "kind": "cef-static-platform-preflight",
            "status": "success",
            "full_platform_graph_qualified": True,
            "cef_runtime_verified": False,
            "gpu_runtime_qualified": False,
            "module_count": 36,
        }
        if any(platform_receipt.get(key) != value for key, value in required.items()):
            raise RuntimeError("Complete static platform graph is not qualified")
        platform_sha = cef_contract.digest(platform_receipt.get("manifest_sha256"))
        summary["platform_sha256"] = platform_sha
        summary["platform_graph_qualified"] = True

        engine_work.mkdir()
        shutil.move(str(platform_work / "frozen-target-prefix"), engine_work / "target-prefix")
        shutil.copy2(evidence / "platform-build-inputs.json", engine_work / "platform-inputs.json")
        shutil.rmtree(platform_work)
        # The frozen prefix is now the only target dependency input Chromium needs.
        for path in (upstream / "buildtrees", upstream / "packages", upstream / "downloads"):
            if path.exists():
                shutil.rmtree(path)

        plan = json.loads((registry / "ci/release-plan.json").read_text())
        cfg = plan["cef"]
        build_key = cef_contract.build_key(cfg, "linux", platform_sha)
        summary["build_key"] = build_key

        recipe_env = dict(clean_env)
        # The CEF integration receipt records the reviewed recipe revision, while
        # GitHub artifact provenance continues to use the real builder head.
        recipe_env["GITHUB_SHA"] = CEF
        recipe_env["CEF_STATIC_STRICT_THIRD_PARTY"] = "1"
        recipe_env["CEF_STATIC_BUILD_TIMEOUT_SECONDS"] = "18000"
        recipe_env["CEF_STATIC_JOBS"] = "4"
        run(
            [sys.executable, recipe / "vcpkg/ports/cef-static/source_build.py",
             "prepare", "--work", engine_work, "--logs", engine_logs],
            cwd=recipe, env=recipe_env,
            log=temp / "cef-source-prepare.log", timeout=10800
        )
        run(
            ["sudo", engine_work / "download/chromium/src/build/install-build-deps.sh",
             "--no-prompt", "--no-arm", "--no-chromeos-fonts"],
            cwd=recipe, env=clean_env,
            log=temp / "cef-install-build-deps.log", timeout=1800
        )

        state = temp / "cef-strict-iteration.json"
        slice_result = run(
            [sys.executable, recipe / "vcpkg/integration/driver.py", "slice",
             "--work", engine_work, "--logs", engine_logs, "--contract", build_key,
             "--state", state, "--checkpoint", checkpoint,
             "--seconds", "9000", "--jobs", "4",
             "--platform-manifest", engine_work / "platform-inputs.json",
             "--platform-prefix", engine_work / "target-prefix",
             "--platform-sha256", platform_sha],
            cwd=recipe, env=recipe_env,
            log=temp / "cef-engine-slice.log", timeout=14400, check=False
        )
        state_value = json.loads(state.read_text()) if state.is_file() else {}
        if state_value.get("checkpoint_ready") is True and checkpoint.is_dir():
            base = cef_cache.context(
                "cef-checkpoint", "linux", build_key,
                int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"]),
                os.environ["GITHUB_SHA"], "index"
            )
            cef_cache.seal(
                checkpoint, encrypted,
                crypto.public_text(os.environ["BUILDER_INPUT_PRIVATE_KEY"]), base
            )
            summary["checkpoint_ready"] = True
            output("checkpoint_ready", True)
        if slice_result.returncode:
            raise RuntimeError("Strict CEF compilation slice failed")
        if state_value.get("ready") is True:
            summary["ready"] = True
            output("ready", True)
            run(
                [sys.executable, recipe / "vcpkg/ports/cef-static/source_build.py",
                 "build", "--work", engine_work, "--logs", engine_logs, "--jobs", "4",
                 "--platform-manifest", engine_work / "platform-inputs.json",
                 "--platform-prefix", engine_work / "target-prefix",
                 "--platform-sha256", platform_sha],
                cwd=recipe, env=recipe_env,
                log=temp / "cef-engine-runtime.log", timeout=21600
            )
            receipt = json.loads((engine_logs / "engine-build-receipt.json").read_text())
            if not (
                receipt.get("source_build_verified") is True
                and receipt.get("engine_linkage") == "static"
                and receipt.get("platform_build_inputs", {}).get("manifest_sha256") == platform_sha
                and receipt.get("platform_graph", {}).get("status")
                    == "static-platform-graph-verified"
                and receipt.get("smoke", {}).get("third_party_modules_static") is True
            ):
                raise RuntimeError("Strict CEF engine runtime receipt is incomplete")
            summary["runtime_verified"] = True
        progress = state_value.get("progress")
        if isinstance(progress, dict):
            summary["progress"] = {
                key: progress[key] for key in (
                    "status", "changed_outputs", "new_outputs", "removed_outputs",
                    "before_outputs", "after_outputs", "engine_compilation_complete"
                ) if key in progress
            }
        summary["status"] = "success"
    except BaseException:
        summary["status"] = "failed"
        raise
    finally:
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
