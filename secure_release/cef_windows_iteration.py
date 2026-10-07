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
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from . import cef_cache, cef_contract, crypto, safeio
from . import cef_windows_source_repair as source_repair
from .github import Client
from .protocol import BUILDER, check_run

VCPKG = "39dccd415da14d8051559d66069019475d95787c"
CEF = "03abd124ebe3b8a57fb78470a75b5aa3ce064e31"
TRIPLET = "x64-windows-static-release"
WORKFLOW = "cef-windows-engine-iteration.yml"

# Hosted runner image labels roll independently of the pinned CEF source and
# recipe. The private checkpoint codec intentionally binds ImageVersion. Permit
# a legacy logical identity only after the current Windows host proves the exact
# reviewed ABI/toolchain fingerprint; never edit the checkpoint manifest.
LEGACY_CHECKPOINT_IMAGE_BY_RUN = {
    37441180545: "20260927.320.1",
}
REVIEWED_LEGACY_IMAGE_MIGRATIONS = {
    ("20260927.320.1", "20261004.326.1"): {
        "schema": 1,
        "os_build": "20348",
        "ubr": 5622,
        "machine": "amd64",
        "python": "3.12.10",
        "vc_tools": "14.44.35207",
        "windows_sdk": "10.0.26100.0",
        "ucrt": "10.0.26100.0",
        "llvm": "20.1.8",
    },
}


def _version_output(command: list[str], pattern: str) -> str:
    output = subprocess.check_output(
        command, text=True, stderr=subprocess.STDOUT, timeout=60
    ).splitlines()
    if not output:
        raise ValueError("Critical Windows host tool returned no version")
    match = re.search(pattern, output[0])
    if not match:
        raise ValueError("Critical Windows host tool version is unrecognized")
    return match.group(1)


def critical_windows_host_fingerprint() -> dict:
    if os.name != "nt":
        raise ValueError("Windows host fingerprint requires native Windows")
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    ) as key:
        build = str(winreg.QueryValueEx(key, "CurrentBuildNumber")[0])
        ubr = winreg.QueryValueEx(key, "UBR")[0]
    if not re.fullmatch(r"[0-9]{4,6}", build) or type(ubr) is not int:
        raise ValueError("Windows build identity is unrecognized")

    program_files_x86 = Path(os.environ.get("ProgramFiles(x86)", ""))
    if not program_files_x86.is_absolute():
        raise ValueError("ProgramFiles(x86) is required for Windows host fingerprint")
    vswhere = program_files_x86 / "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.is_file() or vswhere.is_symlink():
        raise ValueError("Visual Studio discovery tool is missing")
    installation = subprocess.check_output(
        [
            str(vswhere), "-latest", "-products", "*", "-version", "[17.0,18.0)",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ],
        text=True, timeout=60,
    ).strip()
    vs = Path(installation)
    if not installation or not vs.is_absolute() or not vs.is_dir() or vs.is_symlink():
        raise ValueError("Visual Studio installation is invalid")
    vc_tools = (
        vs / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt"
    ).read_text(encoding="utf-8-sig").strip()
    if not re.fullmatch(r"14\.[0-9]+\.[0-9]+", vc_tools):
        raise ValueError("MSVC toolset version is invalid")

    vcvars = vs / "VC/Auxiliary/Build/vcvarsall.bat"
    if not vcvars.is_file() or vcvars.is_symlink():
        raise ValueError("vcvarsall.bat is missing")
    with tempfile.TemporaryDirectory(prefix=".windows-host-fingerprint-") as folder:
        batch = Path(folder) / "vcenv.cmd"
        batch.write_text(
            '@echo off\r\n'
            f'call "{vcvars}" x64 >nul\r\n'
            'if errorlevel 1 exit /b %errorlevel%\r\n'
            'set\r\n',
            encoding="utf-8",
        )
        environment_text = subprocess.check_output(
            ["cmd.exe", "/d", "/c", str(batch)],
            text=True, errors="replace", timeout=120,
        )
    vcenv = {}
    for line in environment_text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            vcenv[key.casefold()] = value.strip()
    sdk = vcenv.get("windowssdkversion", "").rstrip("\\/")
    ucrt = vcenv.get("ucrtversion", "").rstrip("\\/")
    if (not re.fullmatch(r"10\.0\.[0-9]+\.0", sdk)
            or not re.fullmatch(r"10\.0\.[0-9]+\.0", ucrt)
            or vcenv.get("vctoolsversion") != vc_tools
            or vcenv.get("vscmd_arg_tgt_arch", "").lower() != "x64"):
        raise ValueError("Visual Studio x64 environment is inconsistent")

    program_files = Path(os.environ.get("ProgramFiles", ""))
    clang = program_files / "LLVM/bin/clang-cl.exe"
    if not clang.is_file() or clang.is_symlink():
        raise ValueError("Reviewed Windows LLVM installation is missing")
    llvm = _version_output(
        [str(clang), "--version"], r"clang version ([0-9]+\.[0-9]+\.[0-9]+)"
    )
    return {
        "schema": 1,
        "os_build": build,
        "ubr": ubr,
        "machine": platform.machine().lower(),
        "python": platform.python_version(),
        "vc_tools": vc_tools,
        "windows_sdk": sdk,
        "ucrt": ucrt,
        "llvm": llvm,
    }


def _validate_windows_fingerprint(value: object) -> None:
    fields = {
        "schema", "os_build", "ubr", "machine", "python",
        "vc_tools", "windows_sdk", "ucrt", "llvm",
    }
    if (not isinstance(value, dict) or set(value) != fields
            or value.get("schema") != 1
            or type(value.get("ubr")) is not int
            or not 0 <= value["ubr"] < 100000
            or not re.fullmatch(r"[0-9]{4,6}", str(value.get("os_build", "")))
            or value.get("machine") != "amd64"):
        raise ValueError("Invalid Windows checkpoint host fingerprint")
    for key in ("python", "vc_tools", "windows_sdk", "ucrt", "llvm"):
        item = value.get(key)
        if not isinstance(item, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,3}", item):
            raise ValueError("Invalid Windows checkpoint host fingerprint")


def checkpoint_image_identity(selected: dict | None, producer_summary: dict | None,
                              summary: dict) -> str:
    actual = os.environ.get("ImageVersion")
    if not actual or not re.fullmatch(r"[0-9.]{1,64}", actual):
        raise ValueError("ImageVersion is required for Windows checkpoint qualification")
    current = critical_windows_host_fingerprint()
    _validate_windows_fingerprint(current)
    summary["checkpoint_host_verified"] = False
    if selected is None:
        logical = actual
    else:
        logical = (
            producer_summary.get("checkpoint_image_identity")
            if isinstance(producer_summary, dict) else None
        )
        producer_fingerprint = (
            producer_summary.get("critical_host_fingerprint")
            if isinstance(producer_summary, dict) else None
        )
        if logical is None:
            logical = LEGACY_CHECKPOINT_IMAGE_BY_RUN.get(selected["run"])
        if not isinstance(logical, str) or not re.fullmatch(r"[0-9.]{1,64}", logical):
            raise ValueError("Checkpoint producer image identity is unavailable")
        if actual != logical:
            if producer_fingerprint is not None:
                _validate_windows_fingerprint(producer_fingerprint)
                if producer_fingerprint != current:
                    raise ValueError(
                        "Critical Windows host fingerprint changed; refusing checkpoint reuse"
                    )
            else:
                reviewed = REVIEWED_LEGACY_IMAGE_MIGRATIONS.get((logical, actual))
                if reviewed != current:
                    raise ValueError(
                        "Windows runner image migration is not reviewed for this host fingerprint"
                    )
    summary.update({
        "runner_image_actual": actual,
        "checkpoint_image_identity": logical,
        "critical_host_fingerprint": current,
        "runner_image_migrated": actual != logical,
        "checkpoint_host_verified": True,
    })
    return logical


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
    header_patterns = (
        r"C1083:\s*Cannot open include file:\s*['\"]([^'\"]+)['\"]",
        r"(?:fatal error:\s*)?['\"]([^'\"]+\.(?:h|hpp|inc))['\"]\s*(?:file not found|: No such file or directory)",
    )
    for pattern in header_patterns:
        match = re.search(pattern, text, re.I)
        if match:
            name = match.group(1).replace("\\", "/").rsplit("/", 1)[-1].lower()
            if re.fullmatch(r"[a-z0-9_.+-]{1,120}", name):
                return "missing-header", name

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
    value = crypto.parse(path.read_bytes())
    fields = {"schema", "platform", "vcpkg_commit", "cef_recipe_commit", "checkpoint"}
    if (not isinstance(value, dict) or type(value.get("schema")) is not int
            or value["schema"] not in {1, 2}
            or set(value) != fields | ({"source_repair"} if value["schema"] == 2 else set())
            or value["platform"] != "windows"
            or value["vcpkg_commit"] != VCPKG
            or value["cef_recipe_commit"] != CEF):
        raise ValueError("Invalid Windows CEF qualification lock")
    # Retain schema-1 inspection for archived locks; main requires schema 2.
    if (value["schema"] == 2 and crypto.canonical(value["source_repair"])
            != crypto.canonical(source_repair.profile())):
        raise ValueError("Windows source repair lock profile mismatch")
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
    source_repair.verify_summary(value, selected)
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
    if (producer.get("status") != "completed"
            or producer.get("conclusion") != "success"):
        raise ValueError("Windows CEF checkpoint producer is not successful and complete")
    current = api.get(f"/repos/{BUILDER}/actions/runs/{run_id}")
    if (current.get("run_attempt") != attempt
            or current.get("status") != "completed"
            or current.get("conclusion") != "success"
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
            or stable.get("conclusion") != "success"
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
    base_build_key = cef_contract.build_key(cfg, "windows")
    build_key = source_repair.build_key(base_build_key)
    lock = qualification_lock(workspace)
    if lock["schema"] != 2:
        raise ValueError("Windows source repair requires an explicit schema-2 lock")
    selected = lock["checkpoint"]
    input_build_key, repair_origin = source_repair.restore_contract(selected, base_build_key)

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
        "base_build_key": base_build_key,
        "source_repair": source_repair.profile(),
        "source_repair_verified": False,
        "input_build_key": input_build_key,
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
    stage = "checkpoint-host-identity"
    try:
        producer_summary = None
        if selected is not None:
            token = os.environ.get("GITHUB_TOKEN")
            if not token:
                raise ValueError("GITHUB_TOKEN is required to review checkpoint host compatibility")
            producer_summary = verify_producer_summary(Client(token), selected)
        checkpoint_image = checkpoint_image_identity(selected, producer_summary, summary)
        # Keep the real runner identity in this process and public summary. Only
        # the unchanged private recipe child receives the reviewed logical image
        # so its strict checkpoint identity comparison remains exact.
        recipe_env["ImageVersion"] = checkpoint_image
        stage = "restore"
        if selected is not None:
            restored = temp / "cef-windows-restored-checkpoint"
            restore_checkpoint(
                selected, restored, input_build_key,
                os.environ["BUILDER_INPUT_PRIVATE_KEY"],
            )
            run(
                [
                    sys.executable, recipe / "vcpkg/integration/driver.py", "restore",
                    "--work", engine_work, "--logs", engine_logs,
                    "--contract", input_build_key,
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

        stage = "source-repair"
        if git_head(engine_work / "download/chromium/src") != source_repair.CHROMIUM:
            raise ValueError("Windows source repair Chromium revision mismatch")
        summary["source_repair_state"] = source_repair.apply(engine_work, build_key, repair_origin)
        summary["source_repair_verified"] = True

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
        source_repair.apply(engine_work, build_key, "resume")
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
            source_repair.apply(engine_work, build_key, "resume")
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
