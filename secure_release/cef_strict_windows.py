"""Qualify locked Windows CEF release reuse through the private vcpkg port.

This is a native Windows gate for the mixed strict plan. It installs the exact
cef-static port, then links and runs a new relocated consumer. It never upgrades
the upstream engine-static receipt by itself; only the new PE/module/runtime
evidence may qualify static-third-party on Windows.
"""
from __future__ import annotations
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

from . import build_support, cef_build, cef_contract, crypto, static_audit

VCPKG = "324c4c677119df4f4d4b8beced7ef4623afc2512"
UPSTREAM = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
CEF = "6a36621ea5493a94d7e79dc388746bbb8829b1d2"
TRIPLET = "x64-windows-static-release"


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()


def run(command, *, cwd: Path, env: dict, log: Path, timeout: int) -> None:
    command = list(map(str, command))
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as stream:
        stream.write(subprocess.list2cmdline(command) + "\n")
        stream.flush()
        result = subprocess.run(
            command, cwd=cwd, env=env, stdout=stream,
            stderr=subprocess.STDOUT, timeout=timeout
        )
    if result.returncode:
        raise RuntimeError("strict Windows CEF qualification subprocess failed at " + log.stem)


def clean_environment() -> dict:
    return {
        key: value for key, value in os.environ.items()
        if not any(token in key.upper() for token in (
            "TOKEN", "PRIVATE_KEY", "PUBLIC_KEY", "SECRET",
            "GIT_CONFIG", "GIT_TRACE", "GIT_CURL"
        ))
    }


def main() -> None:
    if os.name != "nt":
        raise ValueError("Strict Windows CEF qualification requires native Windows")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    registry = workspace / "private-vcpkg"
    upstream = registry / ".windows-upstream"
    recipe = registry / ".full-cef"
    if (git_head(registry), git_head(upstream), git_head(recipe)) != (VCPKG, UPSTREAM, CEF):
        raise ValueError("Strict Windows CEF source revision mismatch")

    plan = json.loads((registry / "ci/release-plan.json").read_text())
    cfg = plan["cef"]
    cef_contract.validate(cfg)
    selected = cfg["platforms"]["windows"]
    if (cfg["profile"] != "static-third-party"
            or selected != {"mode": "release-import", "checkpoint": None, "binary_cache": None}
            or cfg["release_lock"] is None):
        raise ValueError("Windows strict plan is not the reviewed locked release reuse mode")
    build_key = cef_build.materialize(registry, cfg, "windows")

    installed = temp / "cef-windows-installed"
    build = temp / "cef-windows-consumer-build"
    deployed = temp / "cef-windows-deployed"
    evidence = temp / "cef-windows-evidence"
    downloads = temp / "cef-windows-downloads"
    sdk_zip = temp / "cef-windows-sdk.zip"
    for path in (installed, build, deployed, evidence, downloads):
        if path.exists():
            raise ValueError("Strict Windows qualification requires fresh runner paths")
    evidence.mkdir()

    env = clean_environment()
    env.update({
        "VCPKG_ROOT": str(upstream),
        "VCPKG_DOWNLOADS": str(downloads),
        "VCPKG_DEFAULT_HOST_TRIPLET": TRIPLET,
        "VCPKG_DISABLE_METRICS": "1",
        "VCPKG_BINARY_SOURCES": "clear",
        "VCPKG_MAX_CONCURRENCY": "2",
        "CMAKE_BUILD_PARALLEL_LEVEL": "2",
        "CEF_STATIC_STRICT_THIRD_PARTY": "1",
    })
    run(
        ["cmd.exe", "/d", "/c", upstream / "bootstrap-vcpkg.bat", "-disableMetrics"],
        cwd=upstream, env=env, log=evidence / "bootstrap.log", timeout=600
    )
    vcpkg = upstream / "vcpkg.exe"
    options = build_support.native_release_options([
        "--triplet=" + TRIPLET,
        "--host-triplet=" + TRIPLET,
        "--overlay-ports=" + str(registry / "ports"),
        "--overlay-triplets=" + str(registry / "triplets"),
        "--x-install-root=" + str(installed),
    ])
    run(
        build_support.install_command(
            str(vcpkg), ["cef-static[strict-platform]"], options
        ),
        cwd=upstream, env=env, log=evidence / "install.log", timeout=7200
    )

    prefix = installed / TRIPLET
    acquisition_path = prefix / "share/cef-static/acquisition.json"
    contract_path = prefix / "share/cef-static/build-contract.json"
    if not acquisition_path.is_file() or not contract_path.is_file():
        raise ValueError("Installed strict Windows CEF lacks acquisition/build contract")
    acquisition = crypto.parse(acquisition_path.read_bytes())
    contract = crypto.parse(contract_path.read_bytes())
    expected_contract = cef_contract.port_contract(cfg, "windows")
    if (contract != expected_contract
            or hashlib_sha(contract_path) != build_key
            or acquisition.get("mode") != "release-import"
            or acquisition.get("requested_profile") != "static-third-party"
            or acquisition.get("strict_requalification_required") is not True
            or acquisition.get("engine_linkage") != "static"
            or acquisition.get("target_triplet") != TRIPLET):
        raise ValueError("Installed strict Windows CEF acquisition evidence is incomplete")

    run(
        ["cmake", "-S", recipe / "vcpkg/static/consumer", "-B", build,
         "-G", "Visual Studio 17 2022", "-A", "x64",
         "-DCMAKE_PREFIX_PATH=" + str(prefix),
         "-DCEF_STATIC_SMOKE_SOURCE=" + str(recipe / "vcpkg/ports/cef-static/smoke.c"),
         "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
         "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF",
         "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"],
        cwd=workspace, env=env, log=evidence / "configure.log", timeout=600
    )
    run(
        ["cmake", "--build", build, "--config", "Release", "--parallel", "2"],
        cwd=workspace, env=env, log=evidence / "build.log", timeout=3600
    )
    binary_dir = build / "Release"
    deployed.mkdir()
    executable = deployed / "cef_static_smoke.exe"
    shutil.copy2(binary_dir / executable.name, executable)
    for resource in (
        "icudtl.dat", "resources.pak", "chrome_100_percent.pak",
        "chrome_200_percent.pak", "snapshot_blob.bin", "v8_context_snapshot.bin"
    ):
        source = binary_dir / resource
        if source.is_file():
            shutil.copy2(source, deployed / resource)
    if (binary_dir / "locales").is_dir():
        shutil.copytree(binary_dir / "locales", deployed / "locales")
    if not (deployed / "icudtl.dat").is_file():
        raise ValueError("Relocated strict Windows CEF consumer lacks ICU data")

    state = evidence / "consumer.json"
    run(
        [sys.executable, recipe / "vcpkg/integration/driver.py", "verify-consumer",
         "--work", temp / "no-chromium-workspace", "--logs", evidence,
         "--contract", build_key, "--state", state, "--executable", executable,
         "--hide", prefix, "--hide", build],
        cwd=workspace, env=env, log=evidence / "runtime.log", timeout=1800
    )
    proof = crypto.parse(state.read_bytes())
    proof["platform_closure"] = {
        "kind": "windows-native-os-abi", "manifest_sha256": None
    }

    with zipfile.ZipFile(sdk_zip, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for path in sorted(prefix.rglob("*")):
            if path.is_file() and not path.is_symlink():
                archive.write(path, "installed/" + TRIPLET + "/" + path.relative_to(prefix).as_posix())
    audit = static_audit.inspect_sdk(sdk_zip, "windows")
    proof["target_archive_audit"] = static_audit.summarize(audit)
    if audit["violations"]:
        diagnostic = {
            "schema": 1,
            "status": "failed",
            "kind": "cef-strict-windows-release-requalification",
            "vcpkg_commit": VCPKG,
            "upstream_commit": UPSTREAM,
            "cef_recipe_commit": CEF,
            "failure_stage": "archive-audit",
            "failure_type": "ValueError",
            "target_archive_audit": proof["target_archive_audit"],
            "violations": [
                {"path": item["path"], "reason": item["reason"]}
                for item in audit["violations"][:16]
            ],
            "unqualified_archives": [
                {
                    "path": item["path"],
                    "kinds": item["kinds"],
                    "unqualified_samples": item["unqualified_samples"][:8],
                }
                for item in audit["archives"]
                if not item["qualified_objects_only"]
            ][:8],
        }
        (temp / "cef-strict-windows-summary.json").write_text(
            json.dumps(diagnostic, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    cef_build.validate_evidence(proof, cfg, "windows")

    summary = {
        "schema": 1,
        "status": "success",
        "kind": "cef-strict-windows-release-requalification",
        "vcpkg_commit": VCPKG,
        "upstream_commit": UPSTREAM,
        "cef_recipe_commit": CEF,
        "release_tag": cfg["release_lock"]["tag"],
        "build_contract_sha256": build_key,
        "manifest_sha256": acquisition["manifest_sha256"],
        "engine_linkage": "static",
        "third_party_libraries_static": True,
        "third_party_modules_static": True,
        "required_runs": proof["smoke_runs"]["required_runs"],
        "passed_runs": proof["smoke_runs"]["passed_runs"],
        "target_archives_static": proof["target_archive_audit"]["target_archives_static"],
        "sdk_code_executed": True,
    }
    (temp / "cef-strict-windows-summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


def hashlib_sha(path: Path) -> str:
    import hashlib
    with path.open("rb") as stream:
        return hashlib.sha256(crypto.canonical(crypto.parse(stream.read()))).hexdigest()


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        temp = Path(os.environ.get("RUNNER_TEMP", ".")).resolve()
        path = temp / "cef-strict-windows-summary.json"
        if path.is_file():
            try:
                summary = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                summary = {}
        else:
            summary = {}
        summary.update({
            "schema": 1,
            "status": "failed",
            "kind": "cef-strict-windows-release-requalification",
            "vcpkg_commit": VCPKG,
            "upstream_commit": UPSTREAM,
            "cef_recipe_commit": CEF,
            "failure_type": type(error).__name__,
        })
        message = str(error)
        match = re.search(r"failed at ([A-Za-z0-9_.-]+)\Z", message)
        summary["failure_stage"] = match.group(1) if match else "validation"
        path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        raise
