"""One strict Linux CEF qualification iteration on a trusted builder runner.

Private vcpkg output and compiler logs stay on the runner. The only resumable
artifact is encrypted with the builder input recipient. A completed slice is
additionally subjected to the pinned CEF browser/renderer runtime verification.
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

VCPKG = "b4bb281192ea8bb004542012ac804b988a4ff403"
UPSTREAM = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
CEF = "2aff22e09daaa5c28780c5766a70ee13e61c93b6"
CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
TRIPLET = "x64-linux-static-release"
CHROMIUM_SYSROOT_AMD64 = {
    "Sha256Sum": "52d61d4446ffebfaa3dda2cd02da4ab4876ff237853f46d273e7f9b666652e1d",
    "SysrootDir": "debian_bullseye_amd64-sysroot",
    "Tarball": "debian_bullseye_amd64_sysroot.tar.xz",
    "URL": "https://commondatastorage.googleapis.com/chrome-linux-sysroot",
}
CHROMIUM_SYSROOT_REQUIRED_HEADER = "usr/include/X11/Xlib-xcb.h"


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


def ensure_chromium_sysroot(
        source: Path, temp: Path, env: dict, summary: dict) -> None:
    """Verify or restore Chromium's exact pinned amd64 sysroot.

    Target compilation runs with use_sysroot=true, so a host /usr/include
    package must never paper over a damaged checkpoint. The installer consumes
    the pinned sysroots.json entry and verifies the tarball SHA-256 itself.
    """
    scripts = source / "build/linux/sysroot_scripts"
    spec_path = scripts / "sysroots.json"
    if not spec_path.is_file() or spec_path.is_symlink():
        raise ValueError("Pinned Chromium sysroots.json is missing or redirected")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    entry = spec.get("bullseye_amd64") if isinstance(spec, dict) else None
    if entry != CHROMIUM_SYSROOT_AMD64:
        raise ValueError("Pinned Chromium amd64 sysroot definition changed")

    linux_root = source / "build/linux"
    sysroot = linux_root / CHROMIUM_SYSROOT_AMD64["SysrootDir"]
    header = sysroot / CHROMIUM_SYSROOT_REQUIRED_HEADER
    stamp = sysroot / ".stamp"
    expected_stamp = (
        CHROMIUM_SYSROOT_AMD64["URL"].rstrip("/")
        + "/" + CHROMIUM_SYSROOT_AMD64["Sha256Sum"]
    )

    def valid() -> bool:
        return (
            sysroot.is_dir()
            and not sysroot.is_symlink()
            and header.is_file()
            and not header.is_symlink()
            and header.stat().st_size > 0
            and stamp.is_file()
            and not stamp.is_symlink()
            and stamp.read_text(encoding="utf-8").strip() == expected_stamp
        )

    repaired = False
    if not valid():
        if sysroot.exists() or sysroot.is_symlink():
            if sysroot.is_symlink() or not sysroot.is_dir():
                raise ValueError("Chromium sysroot path is redirected or not a directory")
            if not sysroot.resolve().is_relative_to(linux_root.resolve()):
                raise ValueError("Chromium sysroot escaped the source workspace")
            shutil.rmtree(sysroot)
        installer = scripts / "install-sysroot.py"
        if not installer.is_file() or installer.is_symlink():
            raise ValueError("Pinned Chromium sysroot installer is missing or redirected")
        run(
            [sys.executable, installer, "--arch=amd64"],
            cwd=source, env=env,
            log=temp / "cef-chromium-sysroot-install.log", timeout=1800,
        )
        repaired = True

    if not valid():
        raise RuntimeError("Pinned Chromium amd64 sysroot is incomplete after verification")
    summary["sysroot_repaired"] = repaired
    summary["sysroot_header_verified"] = True
    summary["sysroot_name"] = CHROMIUM_SYSROOT_AMD64["SysrootDir"]



DAWN_X11_PATCH_MARKER_V1 = "# CEF_STATIC_DAWN_X11_HEADERS_V1"
DAWN_X11_PATCH_MARKER = "# CEF_STATIC_DAWN_X11_HEADERS_V2"


def ensure_dawn_static_x11_headers(source: Path, summary: dict) -> None:
    """Give all Dawn native X11 users headers from the frozen platform prefix."""
    if git_head(source) != CHROMIUM:
        raise ValueError("Pinned Chromium source revision mismatch before Dawn repair")
    deps = source / "DEPS"
    if not deps.is_file() or deps.is_symlink():
        raise ValueError("Pinned Chromium DEPS is missing or redirected")
    revisions = re.findall(
        r"(?m)^\s*['\"]dawn_revision['\"]\s*:\s*['\"]([0-9a-f]{40})['\"]\s*,?\s*$",
        deps.read_text(encoding="utf-8"),
    )
    if len(revisions) != 1:
        raise ValueError("Pinned Chromium DEPS has an unexpected Dawn revision contract")
    dawn = source / "third_party/dawn"
    revision = revisions[0]
    if git_head(dawn) != revision:
        raise ValueError("Dawn checkout differs from pinned Chromium DEPS")
    build = dawn / "src/dawn/native/BUILD.gn"
    if not build.is_file() or build.is_symlink():
        raise ValueError("Pinned Dawn native BUILD.gn is missing or redirected")
    text = build.read_text(encoding="utf-8")

    import_anchor = 'import("${dawn_root}/scripts/dawn_features.gni")\n'
    patched_import_v1 = (
        import_anchor + DAWN_X11_PATCH_MARKER_V1 + "\n"
        + 'import("//build/config/linux/pkg_config.gni")\n'
    )
    patched_import = (
        import_anchor + DAWN_X11_PATCH_MARKER + "\n"
        + 'import("//build/config/linux/pkg_config.gni")\n'
    )
    x11_anchor = '  if (dawn_use_x11) {\n    sources += [\n'
    patched_x11 = (
        '  if (dawn_use_x11) {\n'
        '    if (cef_static_platform_manifest != "") {\n'
        '      include_dirs += [ cef_static_platform_prefix + "/include" ]\n'
        '    }\n'
        '    sources += [\n'
    )
    component_anchor = (
        'dawn_component("native") {\n'
        '  DEFINE_PREFIX = "DAWN_NATIVE"\n'
    )
    patched_component = (
        component_anchor
        + '\n'
        + '  if (dawn_use_x11 && cef_static_platform_manifest != "") {\n'
        + '    include_dirs = [ cef_static_platform_prefix + "/include" ]\n'
        + '  }\n'
    )

    repaired = False
    if DAWN_X11_PATCH_MARKER in text:
        if (text.count(DAWN_X11_PATCH_MARKER) != 1
                or DAWN_X11_PATCH_MARKER_V1 in text
                or patched_import not in text
                or patched_x11 not in text
                or patched_component not in text):
            raise ValueError("Existing Dawn static X11 header repair V2 is malformed")
    elif DAWN_X11_PATCH_MARKER_V1 in text:
        if (text.count(DAWN_X11_PATCH_MARKER_V1) != 1
                or patched_import_v1 not in text
                or patched_x11 not in text
                or text.count(component_anchor) != 1
                or patched_component in text):
            raise ValueError("Existing Dawn static X11 header repair V1 is malformed")
        text = text.replace(patched_import_v1, patched_import, 1)
        text = text.replace(component_anchor, patched_component, 1)
        build.write_text(text, encoding="utf-8", newline="\n")
        repaired = True
    else:
        if (text.count(import_anchor) != 1
                or text.count(x11_anchor) != 1
                or text.count(component_anchor) != 1
                or 'cef_static_platform_prefix + "/include"' in text):
            raise ValueError("Pinned Dawn X11 GN anchors differ from reviewed source")
        text = text.replace(import_anchor, patched_import, 1)
        text = text.replace(x11_anchor, patched_x11, 1)
        text = text.replace(component_anchor, patched_component, 1)
        build.write_text(text, encoding="utf-8", newline="\n")
        repaired = True

    summary["chromium_commit"] = CHROMIUM
    summary["dawn_revision"] = revision
    summary["dawn_x11_headers_repaired"] = repaired
    summary["dawn_x11_headers_verified"] = True
    summary["dawn_x11_component_headers_verified"] = True


def classify_private_log(path: Path) -> tuple[str, str]:
    """Return only bounded failure identity; never expose private build output."""
    if not path.is_file() or path.stat().st_size > 64 * 1024**2:
        return "missing-log", "unknown"
    text = path.read_text(encoding="utf-8", errors="replace")[-8 * 1024**2:]
    package = "unknown"
    for pattern in (
        r"error: building ([a-z0-9][a-z0-9+_.-]*):",
        r"BUILD_FAILED[^\n]*?([a-z0-9][a-z0-9+_.-]+):x64-linux-static-release",
        r"([a-z0-9][a-z0-9+_.-]+):x64-linux-static-release failed",
    ):
        match = re.search(pattern, text, re.I)
        if match:
            package = match.group(1).lower()
            break
    checks = (
        ("patch", r"patch failed|does not apply|corrupt patch|malformed patch"),
        ("missing-header", r"fatal error:\s*[A-Za-z0-9_+./-]+:\s*No such file"),
        ("missing-library", r"(?:cannot find|unable to find)\s+-l[A-Za-z0-9_+.-]+"),
        ("missing-dependency", r"(?:Dependency|Could NOT find|Package).*?(?:not found|found:\s*NO)"),
        ("undefined-reference", r"undefined reference to"),
        ("multiple-definition", r"multiple definition of"),
        ("configure", r"CMake Error|meson\.build:\d+:\d+: ERROR:|configure.*(?:failed|error)"),
        ("compile", r"(?:^|\n)FAILED:|ninja: build stopped|compilation terminated"),
        ("post-build-validation", r"post-build validation|Found unexpected shared"),
        ("timeout", r"timed out|TimeoutExpired"),
    )
    category = next((label for label, pattern in checks if re.search(pattern, text, re.I)), "unknown")
    if not re.fullmatch(r"[a-z0-9][a-z0-9+_.-]*", package):
        package = "unknown"
    return category, package


def classify_compile_slice(logs: Path) -> dict:
    """Expose only bounded compiler-failure identity, never raw build logs."""
    status_path = logs / "ninja-slice.json"
    log_path = logs / "ninja-slice.log"
    if (not status_path.is_file() or not log_path.is_file()
            or status_path.stat().st_size > 1024**2
            or log_path.stat().st_size > 64 * 1024**2):
        return {"compile_failure_category": "missing-log"}
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"compile_failure_category": "invalid-status"}
    text = log_path.read_text(encoding="utf-8", errors="replace")[-8 * 1024**2:]
    failed = []
    for raw in re.findall(r"^FAILED:\s+(.+)$", text, re.M):
        name = re.sub(r"^\[code=[12]\]\s+", "", raw.strip())
        if re.fullmatch(r"obj/[A-Za-z0-9_./+-]+\.o", name):
            failed.append(name)
    if re.search(r"(?:out of memory|cannot allocate memory|\bkilled\b|LLVM ERROR:.*memory)", text, re.I):
        category = "resource"
    elif re.search(r"(?:internal compiler error|please submit a bug report|clang frontend command failed)", text, re.I):
        category = "compiler-crash"
    elif re.search(r"fatal error:.*(?:file not found|No such file)", text, re.I):
        category = "missing-header"
    elif re.search(r"(?:^|\n)[^\n]*\berror:", text, re.I):
        category = "compiler-error"
    else:
        category = "unknown"
    sysroot_flags = re.findall(r"(?:^|\\s)--sysroot=([^\\s\"']+)", text)
    result = {
        "compile_failure_category": category,
        "compile_failure_timed_out": status.get("timed_out") is True,
        "compile_failure_unsafe_stop": status.get("unsafe_stop") is True,
        "compile_failure_failed_output_count": len(failed),
        "compile_failure_failed_outputs": [Path(name).name for name in failed[-4:]],
        "compile_failure_uses_sysroot": bool(sysroot_flags),
    }
    if sysroot_flags:
        sysroot_name = Path(sysroot_flags[-1].replace("\\\\", "/")).name
        if re.fullmatch(r"debian_[A-Za-z0-9_-]+-sysroot", sysroot_name):
            result["compile_failure_sysroot_name"] = sysroot_name
    source = re.search(
        r"(?:^|\n)(?:[^\r\n ]*[/\\])?([A-Za-z0-9_.+-]+\.(?:c|cc|cpp|cxx|m|mm))"
        r":\d+(?::\d+)?:\s+(?:fatal\s+)?error:",
        text, re.I,
    )
    if source:
        result["compile_failure_source"] = source.group(1)
    missing_header = re.search(
        r"fatal error:\s*[<\"']?([A-Za-z0-9_+./\\-]+)[>\"']?(?::)?\s*"
        r"(?:file not found|No such file(?: or directory)?)",
        text, re.I,
    )
    if missing_header:
        name = Path(missing_header.group(1).replace("\\", "/")).name
        if re.fullmatch(r"[A-Za-z0-9_+.-]{1,160}", name):
            result["compile_failure_missing_header"] = name
    return result


def output(name: str, value: bool) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as stream:
            stream.write(f"{name}={str(value).lower()}\n")


def reviewed_binary_caches(temp: Path) -> list[Path]:
    result = []
    seen = set()
    for name in (
        "CEF_STRICT_BINARY_CACHE_CORE",
        "CEF_STRICT_BINARY_CACHE_CUPS",
        "CEF_STRICT_BINARY_CACHE_GBM",
    ):
        raw = os.environ.get(name)
        if not raw:
            raise ValueError("Missing reviewed strict CEF binary cache")
        path = Path(raw).resolve(strict=True)
        if (not path.is_dir() or path.is_symlink() or not path.is_relative_to(temp)
                or path in seen):
            raise ValueError("Invalid reviewed strict CEF binary cache")
        seen.add(path)
        result.append(path)
    return result


def qualification_lock(
        workspace: Path, lock_name: str = "cef-strict-engine-lock.json") -> dict:
    if lock_name not in {"cef-strict-engine-lock.json", "cef-strict-combined-lock.json"}:
        raise ValueError("Invalid strict CEF qualification lock name")
    path = workspace / "ci" / lock_name
    value = json.loads(path.read_text())
    if (not isinstance(value, dict)
            or set(value) != {"schema", "platform", "vcpkg_commit", "upstream_commit",
                              "cef_recipe_commit", "checkpoint"}
            or value["schema"] != 1 or value["platform"] != "linux"
            or value["vcpkg_commit"] != VCPKG or value["upstream_commit"] != UPSTREAM
            or value["cef_recipe_commit"] != CEF):
        raise ValueError("Invalid strict CEF qualification lock")
    selected = value["checkpoint"]
    if selected is not None:
        if (not isinstance(selected, dict)
                or set(selected) != {"run", "attempt", "producer_sha",
                                     "artifact_id", "artifact_sha256",
                                     "summary_artifact_id", "summary_artifact_sha256",
                                     "build_key", "platform_sha256"}
                or type(selected["run"]) is not int or selected["run"] < 1
                or type(selected["attempt"]) is not int or selected["attempt"] < 1
                or type(selected["artifact_id"]) is not int or selected["artifact_id"] < 1
                or type(selected["summary_artifact_id"]) is not int
                or selected["summary_artifact_id"] < 1
                or not re.fullmatch(r"[0-9a-f]{40}", selected["producer_sha"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["artifact_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["summary_artifact_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["build_key"])
                or not re.fullmatch(r"[0-9a-f]{64}", selected["platform_sha256"])):
            raise ValueError("Invalid strict CEF qualification checkpoint selector")
    return value


def verify_producer_summary(
        api: Client, selected: dict, *, allow_resumable: bool = True) -> dict:
    run, revision = selected["run"], selected["producer_sha"]
    expected = f"cef-strict-iteration-summary-{run}-{selected['attempt']}"
    matches = [
        item for item in api.artifacts(BUILDER, run)
        if item.get("id") == selected["summary_artifact_id"]
    ]
    if len(matches) != 1:
        raise ValueError("Selected strict CEF summary artifact is missing")
    artifact = matches[0]
    if (artifact.get("name") != expected or artifact.get("expired") is not False
            or artifact.get("digest") != "sha256:" + selected["summary_artifact_sha256"]
            or artifact.get("workflow_run", {}).get("id") != run
            or artifact.get("workflow_run", {}).get("head_sha") != revision):
        raise ValueError("Strict CEF summary artifact provenance mismatch")
    with tempfile.TemporaryDirectory(prefix=".strict-cef-summary-") as folder:
        root = Path(folder)
        archive = root / "summary.zip"
        api.download(
            f"/repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip",
            archive, selected["summary_artifact_sha256"], max_size=4 * 1024**2
        )
        extracted = root / "payload"
        safeio.extract_zip(archive, extracted)
        files = [path for path in extracted.rglob("*") if path.is_file()]
        if len(files) != 1 or files[0].name != "cef-strict-iteration-summary.json":
            raise ValueError("Unexpected strict CEF summary artifact members")
        value = crypto.parse(files[0].read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Strict CEF producer summary is not a JSON object")
    resumable_compile_failure = (
        value.get("status") == "failed"
        and value.get("failure_stage") == "compile-slice"
        and value.get("failure_type") == "RuntimeError"
        and value.get("slice_state_present") is True
        and value.get("slice_exit_code") in (1, 2)
        and value.get("ready") is False
        and value.get("runtime_verified") is False
    )
    reusable_status = (
        value.get("status") == "success"
        or (allow_resumable and resumable_compile_failure)
    )
    complete_engine = (
        value.get("status") == "success"
        and value.get("ready") is True
        and value.get("runtime_verified") is True
    )
    if (value.get("schema") != 1
            or not reusable_status
            or (not allow_resumable and not complete_engine)
            or value.get("checkpoint_ready") is not True
            or value.get("platform_graph_qualified") is not True
            or value.get("gn_graph_qualified") is not True
            or value.get("build_key") != selected["build_key"]
            or value.get("platform_sha256") != selected["platform_sha256"]
            or value.get("vcpkg_commit") != VCPKG
            or value.get("cef_recipe_commit") != CEF):
        raise ValueError("Strict CEF producer summary does not qualify the selected checkpoint")
    return value


def restore_checkpoint(selected: dict, destination: Path, build_key: str,
                       private_key: str, *, allow_resumable: bool = True) -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN is required to restore reviewed strict checkpoint")
    api = Client(token)
    producer_summary = verify_producer_summary(
        api, selected, allow_resumable=allow_resumable)
    if build_key != selected["build_key"]:
        raise ValueError("Strict CEF checkpoint build key differs from producer summary")
    run, attempt, revision = (
        selected["run"], selected["attempt"], selected["producer_sha"]
    )
    producer = api.get(f"/repos/{BUILDER}/actions/runs/{run}/attempts/{attempt}")
    check_run(
        producer, BUILDER, "cef-strict-engine-iteration.yml", revision,
        attempt, "push", success=False
    )
    expected_conclusion = (
        "failure" if producer_summary.get("status") == "failed" else "success"
    )
    if (producer.get("status") != "completed"
            or producer.get("conclusion") != expected_conclusion):
        raise ValueError("Strict CEF checkpoint producer conclusion mismatch")
    current = api.get(f"/repos/{BUILDER}/actions/runs/{run}")
    if (current.get("run_attempt") != attempt or current.get("status") != "completed"
            or current.get("head_sha") != revision):
        raise ValueError("Strict CEF checkpoint producer changed or was rerun")
    expected_name = f"cef-strict-checkpoint-linux-{run}-{attempt}"
    matches = [
        item for item in api.artifacts(BUILDER, run)
        if item.get("id") == selected["artifact_id"]
    ]
    if len(matches) != 1:
        raise ValueError("Selected strict CEF checkpoint artifact is missing")
    artifact = matches[0]
    if (artifact.get("name") != expected_name or artifact.get("expired") is not False
            or artifact.get("digest") != "sha256:" + selected["artifact_sha256"]
            or artifact.get("workflow_run", {}).get("id") != run
            or artifact.get("workflow_run", {}).get("head_sha") != revision):
        raise ValueError("Strict CEF checkpoint artifact provenance mismatch")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
            prefix=".strict-cef-fetch-", dir=destination.parent) as folder:
        root = Path(folder)
        archive = root / "artifact.zip"
        api.download(
            f"/repos/{BUILDER}/actions/artifacts/{artifact['id']}/zip",
            archive, selected["artifact_sha256"], max_size=cef_cache.MAX_TOTAL
        )
        encrypted = root / "ciphertext"
        encrypted.mkdir()
        with zipfile.ZipFile(archive) as stream:
            infos = stream.infolist()
            if not 0 < len(infos) <= cef_cache.MAX_ENTRIES + 1:
                raise ValueError("Invalid strict CEF encrypted checkpoint transport")
            seen = set()
            total = 0
            for info in infos:
                name = info.filename
                if (not re.fullmatch(r"(?:index|part[0-9]{6})\.enc", name)
                        or name in seen or info.is_dir() or info.flag_bits & 1
                        or stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG)):
                    raise ValueError("Unsafe strict CEF encrypted checkpoint member")
                seen.add(name)
                total += info.file_size
                if total > cef_cache.MAX_TOTAL:
                    raise ValueError("Strict CEF encrypted checkpoint exceeds limit")
            if shutil.disk_usage(root).free <= total + 1024**3:
                raise ValueError("Insufficient space for strict CEF checkpoint transport")
            for info in infos:
                target = encrypted / info.filename
                with stream.open(info) as source, target.open("xb") as output_stream:
                    shutil.copyfileobj(source, output_stream, 1024 * 1024)
        result = cef_cache.unseal(
            encrypted, destination, private_key,
            cef_cache.context(
                "cef-checkpoint", "linux", build_key, run, attempt, revision, "index"
            )
        )
    stable = api.get(f"/repos/{BUILDER}/actions/runs/{run}")
    if (stable.get("run_attempt") != attempt or stable.get("status") != "completed"
            or stable.get("head_sha") != revision):
        shutil.rmtree(destination, ignore_errors=True)
        raise ValueError("Strict CEF checkpoint producer changed during restore")
    return result


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
        "gn_graph_qualified": False,
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
        plan = json.loads((registry / "ci/release-plan.json").read_text())
        cfg = plan["cef"]
        lock = qualification_lock(workspace)
        selected = lock["checkpoint"]
        if selected is None:
            cache_args = []
            for cache in reviewed_binary_caches(temp):
                cache_args.extend(["--binary-cache", cache])
            stage = "platform-preflight"
            run(
                [sys.executable, "ci/cef-full/native.py", "--root", ".",
                 "--work", platform_work, "--evidence", evidence, *cache_args],
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
                "module_count": 37,
            }
            if any(platform_receipt.get(key) != value for key, value in required.items()):
                raise RuntimeError("Complete static platform graph is not qualified")
            platform_sha = cef_contract.digest(platform_receipt.get("manifest_sha256"))
            build_key = cef_contract.build_key(cfg, "linux", platform_sha)
            engine_work.mkdir()
            shutil.move(
                str(platform_work / "frozen-target-prefix"),
                engine_work / "target-prefix"
            )
            shutil.copy2(
                evidence / "platform-build-inputs.json",
                engine_work / "platform-inputs.json"
            )
            shutil.rmtree(platform_work)
            summary["mode"] = "source-fresh"
            summary["platform_graph_qualified"] = True
        else:
            platform_sha = cef_contract.digest(selected["platform_sha256"])
            build_key = cef_contract.digest(selected["build_key"])
            if cef_contract.build_key(cfg, "linux", platform_sha) != build_key:
                raise ValueError("Locked strict CEF build key no longer matches the signed plan")
            restored_package = temp / "cef-strict-restored-checkpoint"
            restore_checkpoint(
                selected, restored_package, build_key,
                os.environ["BUILDER_INPUT_PRIVATE_KEY"]
            )
            restore_state = temp / "cef-strict-restore.json"
            recipe_env_restore = dict(clean_env)
            recipe_env_restore["GITHUB_SHA"] = CEF
            run(
                [sys.executable, recipe / "vcpkg/integration/driver.py", "restore",
                 "--work", engine_work, "--logs", engine_logs,
                 "--contract", build_key, "--state", restore_state,
                 "--checkpoint", restored_package,
                 "--platform-manifest", engine_work / "platform-inputs.json",
                 "--platform-prefix", engine_work / "target-prefix",
                 "--platform-sha256", platform_sha],
                cwd=recipe, env=recipe_env_restore,
                log=temp / "cef-checkpoint-restore.log", timeout=7200
            )
            shutil.rmtree(restored_package)
            summary["mode"] = "source-resume"
            summary["restored_from_run"] = selected["run"]
            summary["restored_from_attempt"] = selected["attempt"]
            summary["platform_graph_qualified"] = True
        summary["platform_sha256"] = platform_sha
        summary["build_key"] = build_key
        # A fresh qualification may have transient vcpkg producer state; a
        # resume does not need any package rebuild at all.
        for path in (upstream / "buildtrees", upstream / "packages", upstream / "downloads"):
            if path.exists():
                shutil.rmtree(path)

        recipe_env = dict(clean_env)
        # The CEF integration receipt records the reviewed recipe revision, while
        # GitHub artifact provenance continues to use the real builder head.
        recipe_env["GITHUB_SHA"] = CEF
        recipe_env["CEF_STATIC_STRICT_THIRD_PARTY"] = "1"
        recipe_env["CEF_STATIC_BUILD_TIMEOUT_SECONDS"] = "18000"
        recipe_env["CEF_STATIC_JOBS"] = "2"
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

        stage = "sysroot-preflight"
        ensure_chromium_sysroot(
            engine_work / "download/chromium/src", temp, clean_env, summary
        )

        stage = "dawn-x11-headers"
        ensure_dawn_static_x11_headers(
            engine_work / "download/chromium/src", summary
        )

        stage = "gn-check"
        run(
            [sys.executable, recipe / "vcpkg/ports/cef-static/source_build.py",
             "check", "--work", engine_work, "--logs", engine_logs, "--jobs", "4",
             "--platform-manifest", engine_work / "platform-inputs.json",
             "--platform-prefix", engine_work / "target-prefix",
             "--platform-sha256", platform_sha],
            cwd=recipe, env=recipe_env,
            log=temp / "cef-engine-gn-check.log", timeout=7200
        )
        graph_receipt = json.loads(
            (engine_logs / "platform-graph-receipt.json").read_text()
        )
        if (graph_receipt.get("schema") != 1
                or graph_receipt.get("status") != "static-platform-graph-verified"
                or graph_receipt.get("runtime_verified") is not False
                or graph_receipt.get("manifest_sha256") != platform_sha
                or not isinstance(graph_receipt.get("archives"), list)
                or not graph_receipt["archives"]):
            raise RuntimeError("Strict CEF GN graph qualification is incomplete")
        summary["gn_graph_qualified"] = True

        stage = "compile-slice"
        state = temp / "cef-strict-iteration.json"
        slice_result = run(
            [sys.executable, recipe / "vcpkg/integration/driver.py", "slice",
             "--work", engine_work, "--logs", engine_logs, "--contract", build_key,
             "--state", state, "--checkpoint", checkpoint,
             "--seconds", "9000", "--jobs", "2",
             "--platform-manifest", engine_work / "platform-inputs.json",
             "--platform-prefix", engine_work / "target-prefix",
             "--platform-sha256", platform_sha],
            cwd=recipe, env=recipe_env,
            log=temp / "cef-engine-slice.log", timeout=14400, check=False
        )
        summary["slice_exit_code"] = slice_result.returncode
        summary["slice_state_present"] = state.is_file()
        state_value = json.loads(state.read_text()) if state.is_file() else {}
        progress = state_value.get("progress")
        if isinstance(progress, dict):
            summary["progress"] = {
                key: progress[key] for key in (
                    "status", "changed_outputs", "new_outputs", "removed_outputs",
                    "before_outputs", "after_outputs", "engine_compilation_complete"
                ) if key in progress
            }
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
            summary.update(classify_compile_slice(engine_logs))
            raise RuntimeError("Strict CEF compilation slice failed")
        if state_value.get("ready") is True:
            stage = "engine-runtime"
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
                and receipt.get("platform_build_inputs", {}).get("sha256") == platform_sha
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
    except BaseException as error:
        summary["status"] = "failed"
        summary["failure_stage"] = locals().get("stage", "preflight")
        summary["failure_type"] = type(error).__name__
        if summary["failure_stage"] == "platform-preflight":
            category, package = classify_private_log(temp / "cef-platform-native.log")
            summary["failure_category"] = category
            summary["failure_package"] = package
        raise
    finally:
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
