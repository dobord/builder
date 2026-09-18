"""Resumable native Windows CEF source-build iteration.

The Chromium/CEF workspace never leaves the runner in plaintext. An unfinished
Ninja slice is saved through CEF's native Windows checkpoint adapter, encrypted
with the builder recipient and uploaded by the workflow. A later reviewed lock
selects the exact producer run/artifact for continuation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from . import cef_cache, cef_contract, crypto, safeio
from .github import Client
from .protocol import BUILDER, check_run

VCPKG = "6bc7ecd4dcfcea6caeedb209b67627aa4deb1564"
CEF = "0d3ebf395343d584e2c0ed266c5b3b61063de30c"
TRIPLET = "x64-windows-static-release"
WORKFLOW = "cef-windows-engine-iteration.yml"


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
            stderr=subprocess.STDOUT, timeout=timeout,
        )
    if check and result.returncode:
        raise RuntimeError("Windows CEF qualification subprocess failed")
    return result


def classify_private_failure(primary: Path, logs: Path) -> tuple[str, str]:
    """Return bounded Windows compiler/linker identity without exposing build output."""
    pieces = []
    candidates = [primary]
    if logs.is_dir():
        candidates += sorted(
            [p for p in logs.rglob("*")
             if p.is_file() and p.suffix.lower() in {".log", ".txt"}],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:16]
    total = 0
    for candidate in candidates:
        try:
            if (not safeio.regular(candidate)
                    or candidate.stat().st_size > 64 * 1024**2):
                continue
            data = candidate.read_text(
                encoding="utf-8", errors="replace"
            )[-1024 * 1024:]
        except OSError:
            continue
        pieces.append(data)
        total += len(data)
        if total >= 8 * 1024**2:
            break
    text = "\n".join(pieces)
    checks = (
        ("ctad-warning", r"\[-Werror,(-Wctad-maybe-unsupported)\]"),
        ("clang-warning", r"\[-Werror,(-W[A-Za-z0-9_.+-]+)\]"),
        ("msvc-compile", r"(?:fatal error|error)\s+(C[0-9]{4}):"),
        ("link", r"\b(LNK[0-9]{4})\b"),
        ("missing-header",
         r"(?:cannot open include file|file not found|No such file or directory)"),
        ("capacity",
         r"(?:No space left|not enough space|out of memory|compiler is out of heap)"),
        ("compile", r"(?:^|\n)FAILED:|ninja: build stopped"),
    )
    for category, pattern in checks:
        match = re.search(pattern, text, re.I)
        if match:
            token = (match.group(1) if match.lastindex else "").lower()
            if token and not re.fullmatch(r"[-a-z0-9_.+]+", token):
                token = ""
            return category, token
    return "unknown", ""


def output(name: str, value: bool) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as stream:
            stream.write(f"{name}={str(value).lower()}\n")


def qualification_lock(workspace: Path) -> dict:
    path = workspace / "ci/cef-windows-engine-lock.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict)
            or set(value) != {"schema", "platform", "vcpkg_commit",
                              "cef_recipe_commit", "checkpoint"}
            or value["schema"] != 1 or value["platform"] != "windows"
            or value["vcpkg_commit"] != VCPKG
            or value["cef_recipe_commit"] != CEF):
        raise ValueError("Invalid Windows CEF qualification lock")
    selected = value["checkpoint"]
    if selected is not None:
        if (not isinstance(selected, dict)
                or set(selected) != {
                    "run", "attempt", "producer_sha",
                    "artifact_id", "artifact_sha256",
                    "summary_artifact_id", "summary_artifact_sha256",
                    "build_key",
                }
                or type(selected["run"]) is not int or selected["run"] < 1
                or type(selected["attempt"]) is not int or selected["attempt"] < 1
                or type(selected["artifact_id"]) is not int or selected["artifact_id"] < 1
                or type(selected["summary_artifact_id"]) is not int
                or selected["summary_artifact_id"] < 1
                or not re.fullmatch(r"[0-9a-f]{40}", selected["producer_sha"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["artifact_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["summary_artifact_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["build_key"])):
            raise ValueError("Invalid Windows CEF checkpoint selector")
    return value


def verify_producer_summary(api: Client, selected: dict) -> dict:
    run_id, attempt, revision = (
        selected["run"], selected["attempt"], selected["producer_sha"]
    )
    expected = f"cef-windows-engine-summary-{run_id}-{attempt}"
    matches = [
        item for item in api.artifacts(BUILDER, run_id)
        if item.get("id") == selected["summary_artifact_id"]
    ]
    if len(matches) != 1:
        raise ValueError("Selected Windows CEF summary artifact is missing")
    artifact = matches[0]
    if (artifact.get("name") != expected or artifact.get("expired") is not False
            or artifact.get("digest") != "sha256:" + selected["summary_artifact_sha256"]
            or artifact.get("workflow_run", {}).get("id") != run_id
            or artifact.get("workflow_run", {}).get("head_sha") != revision):
        raise ValueError("Windows CEF summary artifact provenance mismatch")
    with tempfile.TemporaryDirectory(prefix=".windows-cef-summary-") as folder:
        root = Path(folder)
        archive = root / "summary.zip"
        api.download(
            f"/repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip",
            archive, selected["summary_artifact_sha256"], max_size=4 * 1024**2,
        )
        extracted = root / "payload"
        safeio.extract_zip(archive, extracted)
        files = [path for path in extracted.rglob("*") if path.is_file()]
        if len(files) != 1 or files[0].name != "cef-windows-engine-summary.json":
            raise ValueError("Unexpected Windows CEF summary artifact members")
        value = crypto.parse(files[0].read_bytes())
    if (not isinstance(value, dict) or value.get("schema") != 1
            or value.get("status") != "success"
            or value.get("checkpoint_ready") is not True
            or value.get("build_key") != selected["build_key"]
            or value.get("vcpkg_commit") != VCPKG
            or value.get("cef_recipe_commit") != CEF):
        raise ValueError("Windows CEF producer summary does not qualify checkpoint")
    return value


def restore_checkpoint(selected: dict, destination: Path, build_key: str,
                       private_key: str) -> dict:
    api = Client(os.environ["GITHUB_TOKEN"])
    verify_producer_summary(api, selected)
    if build_key != selected["build_key"]:
        raise ValueError("Windows CEF checkpoint build key mismatch")
    run_id, attempt, revision = (
        selected["run"], selected["attempt"], selected["producer_sha"]
    )
    producer = api.get(
        f"/repos/{BUILDER}/actions/runs/{run_id}/attempts/{attempt}"
    )
    check_run(
        producer, BUILDER, WORKFLOW, revision, attempt, "push", success=False
    )
    if producer.get("status") != "completed":
        raise ValueError("Windows CEF checkpoint producer is still running")
    current = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}")
    if (current.get("run_attempt") != attempt
            or current.get("status") != "completed"
            or current.get("head_sha") != revision):
        raise ValueError("Windows CEF checkpoint producer changed or was rerun")

    expected = f"cef-windows-engine-checkpoint-{run_id}-{attempt}"
    matches = [
        item for item in api.artifacts(BUILDER, run_id)
        if item.get("id") == selected["artifact_id"]
    ]
    if len(matches) != 1:
        raise ValueError("Selected Windows CEF checkpoint artifact is missing")
    artifact = matches[0]
    if (artifact.get("name") != expected or artifact.get("expired") is not False
            or artifact.get("digest") != "sha256:" + selected["artifact_sha256"]
            or artifact.get("workflow_run", {}).get("id") != run_id
            or artifact.get("workflow_run", {}).get("head_sha") != revision):
        raise ValueError("Windows CEF checkpoint artifact provenance mismatch")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
            prefix=".windows-cef-fetch-", dir=destination.parent) as folder:
        root = Path(folder)
        archive = root / "artifact.zip"
        api.download(
            f"/repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip",
            archive, selected["artifact_sha256"], max_size=cef_cache.MAX_TOTAL,
        )
        encrypted = root / "ciphertext"
        encrypted.mkdir()
        with zipfile.ZipFile(archive) as stream:
            infos = stream.infolist()
            if not 0 < len(infos) <= cef_cache.MAX_ENTRIES + 1:
                raise ValueError("Invalid Windows CEF encrypted checkpoint transport")
            seen = set()
            total = 0
            for info in infos:
                name = info.filename
                if (not re.fullmatch(r"(?:index|part[0-9]{6})\.enc", name)
                        or name in seen or info.is_dir() or info.flag_bits & 1
                        or stat.S_IFMT(info.external_attr >> 16)
                            not in (0, stat.S_IFREG)):
                    raise ValueError("Unsafe Windows CEF encrypted checkpoint member")
                seen.add(name)
                total += info.file_size
                if total > cef_cache.MAX_TOTAL:
                    raise ValueError("Windows CEF encrypted checkpoint exceeds limit")
            if shutil.disk_usage(root).free <= total + 1024**3:
                raise ValueError("Insufficient space for Windows CEF checkpoint")
            for info in infos:
                target = encrypted / info.filename
                with stream.open(info) as source, target.open("xb") as output_stream:
                    shutil.copyfileobj(source, output_stream, 1024 * 1024)
        result = cef_cache.unseal(
            encrypted, destination, private_key,
            cef_cache.context(
                "cef-checkpoint", "windows", build_key,
                run_id, attempt, revision, "index",
            ),
        )
    stable = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}")
    if (stable.get("run_attempt") != attempt
            or stable.get("status") != "completed"
            or stable.get("head_sha") != revision):
        shutil.rmtree(destination, ignore_errors=True)
        raise ValueError("Windows CEF checkpoint producer changed during restore")
    return result


def main() -> None:
    if sys.platform != "win32":
        raise ValueError("Windows CEF iteration requires native Windows")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    registry = workspace / "private-vcpkg"
    recipe = workspace / "private-cef"
    if (git_head(registry), git_head(recipe)) != (VCPKG, CEF):
        raise ValueError("Windows CEF iteration source revision mismatch")

    plan = json.loads((registry / "ci/release-plan.json").read_text())
    cfg = plan["cef"]
    cef_contract.validate(cfg)
    if (cfg["profile"] != "static-third-party"
            or cfg["recipe_commit"] != CEF
            or cfg["platforms"]["windows"]["mode"] != "source-fresh"):
        raise ValueError("Unexpected Windows strict CEF plan")
    build_key = cef_contract.build_key(cfg, "windows")
    lock = qualification_lock(workspace)
    selected = lock["checkpoint"]
    if selected is not None and selected["build_key"] != build_key:
        raise ValueError("Locked Windows CEF build key no longer matches plan")

    engine_work = temp / "cef-windows-engine-work"
    engine_logs = temp / "cef-windows-engine-logs"
    checkpoint = temp / "cef-windows-engine-checkpoint"
    encrypted = temp / "cef-windows-engine-checkpoint-encrypted"
    summary_path = temp / "cef-windows-engine-summary.json"
    for path in (engine_work, engine_logs, checkpoint, encrypted):
        if path.exists():
            raise ValueError("Windows CEF iteration requires fresh runner paths")

    summary = {
        "schema": 1,
        "kind": "cef-windows-engine-iteration",
        "status": "running",
        "ready": False,
        "checkpoint_ready": False,
        "runtime_verified": False,
        "vcpkg_commit": VCPKG,
        "cef_recipe_commit": CEF,
        "build_key": build_key,
    }
    clean_env = {
        key: value for key, value in os.environ.items()
        if not any(token in key.upper() for token in (
            "TOKEN", "PRIVATE_KEY", "PUBLIC_KEY", "SECRET",
            "GIT_CONFIG", "GIT_TRACE", "GIT_CURL",
        ))
        and key not in {
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
            "LIBRARY_PATH", "CPATH", "CPLUS_INCLUDE_PATH",
            "C_INCLUDE_PATH", "GN_DEFINES",
        }
    }
    recipe_env = dict(clean_env)
    recipe_env.update({
        "GITHUB_SHA": CEF,
        "CEF_STATIC_BUILD_TIMEOUT_SECONDS": "18000",
        "CEF_STATIC_JOBS": "4",
    })
    stage = "restore"
    try:
        if selected is not None:
            restored = temp / "cef-windows-restored-checkpoint"
            restore_checkpoint(
                selected, restored, build_key,
                os.environ["BUILDER_INPUT_PRIVATE_KEY"],
            )
            run(
                [
                    sys.executable, recipe / "vcpkg/integration/driver.py", "restore",
                    "--work", engine_work, "--logs", engine_logs,
                    "--contract", build_key,
                    "--state", temp / "cef-windows-restore.json",
                    "--checkpoint", restored,
                ],
                cwd=recipe, env=recipe_env,
                log=temp / "cef-windows-restore.log", timeout=7200,
            )
            shutil.rmtree(restored)
            summary["mode"] = "checkpoint-resume"
        else:
            summary["mode"] = "source-fresh"

        stage = "source-prepare"
        run(
            [
                sys.executable,
                recipe / "vcpkg/ports/cef-static/source_build.py", "prepare",
                "--work", engine_work, "--logs", engine_logs,
            ],
            cwd=recipe, env=recipe_env,
            log=temp / "cef-windows-source-prepare.log", timeout=10800,
        )

        stage = "compile-slice"
        state = temp / "cef-windows-engine-state.json"
        slice_result = run(
            [
                sys.executable, recipe / "vcpkg/integration/driver.py", "slice",
                "--work", engine_work, "--logs", engine_logs,
                "--contract", build_key, "--state", state,
                "--checkpoint", checkpoint,
                "--seconds", "9000", "--jobs", "4",
            ],
            cwd=recipe, env=recipe_env,
            log=temp / "cef-windows-engine-slice.log",
            timeout=14400, check=False,
        )
        summary["slice_exit_code"] = slice_result.returncode
        summary["slice_state_present"] = state.is_file()
        state_value = json.loads(state.read_text()) if state.is_file() else {}
        if state_value.get("checkpoint_ready") is True and checkpoint.is_dir():
            base = cef_cache.context(
                "cef-checkpoint", "windows", build_key,
                int(os.environ["GITHUB_RUN_ID"]),
                int(os.environ["GITHUB_RUN_ATTEMPT"]),
                os.environ["GITHUB_SHA"], "index",
            )
            cef_cache.seal(
                checkpoint, encrypted,
                crypto.public_text(os.environ["BUILDER_INPUT_PRIVATE_KEY"]), base,
            )
            summary["checkpoint_ready"] = True
            output("checkpoint_ready", True)
        if slice_result.returncode:
            raise RuntimeError("Windows CEF compilation slice failed")

        if state_value.get("ready") is True:
            stage = "engine-runtime"
            summary["ready"] = True
            output("ready", True)
            run(
                [
                    sys.executable,
                    recipe / "vcpkg/ports/cef-static/source_build.py", "build",
                    "--work", engine_work, "--logs", engine_logs, "--jobs", "4",
                ],
                cwd=recipe, env=recipe_env,
                log=temp / "cef-windows-engine-runtime.log", timeout=21600,
            )
            receipt = json.loads(
                (engine_logs / "engine-build-receipt.json").read_text()
            )
            if (receipt.get("source_build_verified") is not True
                    or receipt.get("engine_linkage") != "static"
                    or receipt.get("smoke", {}).get("third_party_modules_static")
                        is not True):
                raise RuntimeError("Windows strict CEF runtime receipt is incomplete")
            summary["runtime_verified"] = True

        progress = state_value.get("progress")
        if isinstance(progress, dict):
            summary["progress"] = {
                key: progress[key] for key in (
                    "status", "changed_outputs", "new_outputs", "removed_outputs",
                    "before_outputs", "after_outputs",
                    "engine_compilation_complete",
                ) if key in progress
            }
        summary["status"] = "success"
    except BaseException as error:
        summary["status"] = "failed"
        summary["failure_stage"] = stage
        summary["failure_type"] = type(error).__name__
        if stage in {"compile-slice", "engine-runtime"}:
            category, token = classify_private_failure(
                temp / ("cef-windows-engine-slice.log"
                        if stage == "compile-slice"
                        else "cef-windows-engine-runtime.log"),
                engine_logs,
            )
            summary["failure_category"] = category
            if token:
                summary["failure_token"] = token
        raise
    finally:
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
