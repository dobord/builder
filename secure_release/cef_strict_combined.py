"""Final private-source static SDK qualification from a reviewed strict CEF checkpoint.

This diagnostic runs only on the public builder. Private source checkouts are
prefetched by Actions with credentials removed before this process starts.
Compiler output, the restored Chromium workspace and the final SDK remain
runner-local; only a bounded non-sensitive summary may be uploaded by the caller.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

from . import build_support, cef_build, cef_contract, crypto, safeio
from . import cef_strict_iteration

VCPKG = "c01f6ebc41c9282bee4ed6d409f9a8a4a7a39535"
UPSTREAM = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
CEF = "befa5c26c0c608165f27ac348e892305837fd614"
LOCKFREECORO = "24038aed3a0be642adb60e71bd994ae8f0d90140"
LFC_UI = "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5"
TRIPLET = "x64-linux-static-release"


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()


def clean_environment() -> dict[str, str]:
    return {
        key: value for key, value in os.environ.items()
        if not any(token in key.upper() for token in (
            "TOKEN", "PRIVATE_KEY", "PUBLIC_KEY", "SECRET",
            "GIT_CONFIG", "GIT_TRACE", "GIT_CURL",
        ))
        and key not in {
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LIBRARY_PATH",
            "CPATH", "CPLUS_INCLUDE_PATH", "C_INCLUDE_PATH", "GN_DEFINES",
        }
    }


def run(command, *, cwd: Path, env: dict, log: Path, timeout: int) -> None:
    command = list(map(str, command))
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as stream:
        stream.write(subprocess.list2cmdline(command) + "\n")
        stream.flush()
        result = subprocess.run(
            command, cwd=cwd, env=env, stdout=stream,
            stderr=subprocess.STDOUT, timeout=timeout,
        )
    if result.returncode:
        raise RuntimeError("strict combined SDK subprocess failed at " + log.stem)


def archive_checkout(source: Path, revision: str, target: Path) -> None:
    if git_head(source) != revision or target.exists():
        raise ValueError("Private source checkout/revision mismatch")
    target.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "-C", str(source), "-c", "core.autocrlf=false",
         "archive", "--format=tar.gz", revision, "-o", str(target)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300,
    )
    if result.returncode or not target.is_file() or target.is_symlink() or target.stat().st_size == 0:
        raise RuntimeError("Exact private source archive creation failed")


def reviewed_cache_args(temp: Path) -> list[str]:
    result = ["--binarysource=clear"]
    seen = set()
    for name in (
        "CEF_STRICT_BINARY_CACHE_CORE",
        "CEF_STRICT_BINARY_CACHE_CUPS",
        "CEF_STRICT_BINARY_CACHE_GBM",
    ):
        raw = os.environ.get(name)
        if not raw:
            raise ValueError("Missing reviewed strict binary cache")
        path = Path(raw).resolve(strict=True)
        if (not path.is_dir() or path.is_symlink()
                or not path.is_relative_to(temp) or path in seen):
            raise ValueError("Invalid reviewed strict binary cache")
        seen.add(path)
        result.append("--binarysource=files," + str(path) + ",read")
    return result


def main() -> None:
    if sys.platform != "linux":
        raise ValueError("Strict combined SDK qualification requires native Linux")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    registry = workspace / "private-vcpkg"
    upstream = registry / ".full-upstream"
    recipe_checkout = registry / ".full-cef"
    lockfree = workspace / "private-lockfreecoro"
    lfc_ui = workspace / "private-lfc-ui"
    expected_heads = {
        registry: VCPKG,
        upstream: UPSTREAM,
        recipe_checkout: CEF,
        lockfree: LOCKFREECORO,
        lfc_ui: LFC_UI,
    }
    for path, revision in expected_heads.items():
        if git_head(path) != revision:
            raise ValueError("Strict combined SDK source revision mismatch")

    plan = json.loads((registry / "ci/release-plan.json").read_text(encoding="utf-8"))
    cfg = plan["cef"]
    cef_contract.validate(cfg)
    if (cfg["profile"] != "static-third-party"
            or cfg["platforms"]["linux"]["mode"] != "source-fresh"
            or cfg["recipe_commit"] != CEF):
        raise ValueError("Unexpected strict combined SDK plan")

    lock = cef_strict_iteration.qualification_lock(workspace)
    selected = lock["checkpoint"]
    if selected is None:
        raise ValueError("Strict combined SDK requires an explicit reviewed CEF checkpoint")
    platform_sha = cef_contract.digest(selected["platform_sha256"])
    build_key = cef_contract.digest(selected["build_key"])
    if cef_contract.build_key(cfg, "linux", platform_sha) != build_key:
        raise ValueError("Strict combined checkpoint build key no longer matches the signed plan")

    root = temp / "cef-strict-combined"
    if root.exists():
        raise ValueError("Strict combined SDK requires a fresh runner root")
    root.mkdir()
    engine_work = temp / "cef-strict-engine-work"
    if engine_work.exists():
        raise ValueError("Strict combined SDK requires a fresh restored engine path")
    engine_logs = root / "engine-logs"
    recipe = root / "cef-recipe"
    shutil.copytree(
        recipe_checkout / "vcpkg", recipe / "vcpkg",
        symlinks=False,
    )

    summary_path = temp / "cef-strict-combined-summary.json"
    summary = {
        "schema": 1,
        "kind": "cef-strict-combined-sdk-qualification",
        "status": "running",
        "platform": "linux",
        "vcpkg_commit": VCPKG,
        "upstream_commit": UPSTREAM,
        "cef_recipe_commit": CEF,
        "build_contract_sha256": build_key,
        "platform_sha256": platform_sha,
        "runtime_verified": False,
        "target_archives_static": False,
    }
    stage = "checkpoint-restore"
    try:
        restored_package = root / "restored-checkpoint"
        cef_strict_iteration.restore_checkpoint(
            selected, restored_package, build_key,
            os.environ["BUILDER_INPUT_PRIVATE_KEY"],
        )
        driver = recipe / "vcpkg/integration/driver.py"
        recipe_env = clean_environment()
        recipe_env.update({
            "GITHUB_SHA": CEF,
            "CEF_STATIC_STRICT_THIRD_PARTY": "1",
            "CEF_STATIC_BUILD_TIMEOUT_SECONDS": "18000",
            "CEF_STATIC_JOBS": "4",
        })
        restore_state = root / "restore.json"
        run(
            [sys.executable, driver, "restore",
             "--work", engine_work, "--logs", engine_logs,
             "--contract", build_key, "--state", restore_state,
             "--checkpoint", restored_package,
             "--platform-manifest", engine_work / "platform-inputs.json",
             "--platform-prefix", engine_work / "target-prefix",
             "--platform-sha256", platform_sha],
            cwd=recipe, env=recipe_env,
            log=root / "checkpoint-restore.log", timeout=7200,
        )
        shutil.rmtree(restored_package)

        stage = "engine-runtime"
        source_build = recipe / "vcpkg/ports/cef-static/source_build.py"
        run(
            [sys.executable, source_build, "prepare",
             "--work", engine_work, "--logs", engine_logs, "--jobs", "4"],
            cwd=recipe, env=recipe_env,
            log=root / "source-prepare.log", timeout=10800,
        )
        run(
            ["sudo", engine_work / "download/chromium/src/build/install-build-deps.sh",
             "--no-prompt", "--no-arm", "--no-chromeos-fonts"],
            cwd=recipe, env=clean_environment(),
            log=root / "install-build-deps.log", timeout=1800,
        )
        run(
            [sys.executable, source_build, "build",
             "--work", engine_work, "--logs", engine_logs, "--jobs", "4",
             "--platform-manifest", engine_work / "platform-inputs.json",
             "--platform-prefix", engine_work / "target-prefix",
             "--platform-sha256", platform_sha],
            cwd=recipe, env=recipe_env,
            log=root / "engine-runtime.log", timeout=21600,
        )
        receipt = json.loads((engine_logs / "engine-build-receipt.json").read_text())
        if (receipt.get("source_build_verified") is not True
                or receipt.get("engine_linkage") != "static"
                or receipt.get("platform_build_inputs", {}).get("sha256") != platform_sha
                or receipt.get("platform_graph", {}).get("status")
                    != "static-platform-graph-verified"
                or receipt.get("smoke", {}).get("third_party_modules_static") is not True):
            raise RuntimeError("Restored strict engine runtime receipt is incomplete")

        stage = "platform-requalification"
        requalified = root / "requalified-target-prefix"
        requalified_manifest = root / "requalified-platform-inputs.json"
        qualification = root / "platform-qualification.json"
        run(
            [sys.executable, registry / "ci/cef-full/verify_prefix.py",
             "--installed", engine_work / "target-prefix",
             "--destination", requalified,
             "--manifest", requalified_manifest,
             "--receipt", qualification,
             "--cef-recipe", recipe,
             "--work", root / "platform-requalification-work"],
            cwd=registry, env=clean_environment(),
            log=root / "platform-requalification.log", timeout=3600,
        )
        preflight = crypto.parse(qualification.read_bytes())
        if (preflight.get("schema") != 1
                or preflight.get("kind") != "cef-static-platform-preflight"
                or preflight.get("status") != "success"
                or preflight.get("full_platform_graph_qualified") is not True
                or preflight.get("module_count") != 37
                or preflight.get("manifest_sha256") != platform_sha):
            raise RuntimeError("Restored platform prefix did not reproduce its qualification")
        shutil.rmtree(requalified)
        requalified_manifest.unlink()

        stage = "source-archives"
        downloads = upstream / "downloads"
        archive_checkout(
            lockfree, LOCKFREECORO,
            downloads / f"lockfreecoro-{LOCKFREECORO}.tar.gz",
        )
        archive_checkout(
            lfc_ui, LFC_UI,
            downloads / f"lfc-ui-{LFC_UI}.tar.gz",
        )
        archive_checkout(
            recipe_checkout, CEF,
            downloads / f"cef-static-{CEF}.tar.gz",
        )
        source_ports = list(plan["ports"]) + [{"name": "cef-static", "sha": CEF}]
        build_support.protect_source_archives(registry, downloads, source_ports)
        cef_build.materialize(registry, cfg, "linux", platform_sha)

        stage = "vcpkg-install"
        build_env = build_support.build_environment(
            clean_environment(), downloads, upstream
        )
        build_env.update({
            "CC": "gcc-14",
            "CXX": "g++-14",
            "CEF_STATIC_WORK": str(engine_work),
            "CEF_STATIC_PLATFORM_MANIFEST": str(engine_work / "platform-inputs.json"),
            "CEF_STATIC_PLATFORM_PREFIX": str(engine_work / "target-prefix"),
            "CEF_STATIC_PLATFORM_SHA256": platform_sha,
            "CEF_STATIC_STRICT_THIRD_PARTY": "1",
            "CEF_STATIC_BUILD_TIMEOUT_SECONDS": "18000",
        })
        run(
            ["bash", upstream / "bootstrap-vcpkg.sh", "-disableMetrics"],
            cwd=upstream, env=build_env,
            log=root / "vcpkg-bootstrap.log", timeout=600,
        )
        installed = root / "installed"
        install_args = build_support.native_release_options([
            "--triplet=" + TRIPLET,
            "--host-triplet=" + TRIPLET,
            "--overlay-ports=" + str(registry / "ports"),
            "--overlay-triplets=" + str(workspace / "triplets"),
            "--x-install-root=" + str(installed),
        ])
        command = [
            str(upstream / "vcpkg"), "install",
            *plan["platforms"]["linux"]["packages"],
            *install_args,
            *reviewed_cache_args(temp),
            "--clean-buildtrees-after-build",
            "--clean-packages-after-build",
        ]
        run(
            command, cwd=upstream, env=build_env,
            log=root / "vcpkg-install.log", timeout=21600,
        )

        stage = "vcpkg-export"
        package_names = list(dict.fromkeys(
            item.split("[", 1)[0] for item in plan["platforms"]["linux"]["packages"]
        ))
        export_root = root / "export"
        export_root.mkdir()
        run(
            [upstream / "vcpkg", "export", *package_names, *install_args,
             "--raw", "--output=sdk", "--output-dir=" + str(export_root)],
            cwd=upstream, env=build_env,
            log=root / "vcpkg-export.log", timeout=1800,
        )
        sdk = export_root / "sdk"
        build_support.copy_export_triplet(
            sdk, workspace / "triplets", TRIPLET
        )
        sdk_zip = root / "sdk.zip"
        safeio.sdk_zip(sdk, sdk_zip)
        consumer_sdk = root / "consumer-sdk"
        safeio.extract_zip(sdk_zip, consumer_sdk)

        expected_contract = cef_contract.port_contract(cfg, "linux", platform_sha)
        contract_path = (
            consumer_sdk / "installed" / TRIPLET
            / "share/cef-static/build-contract.json"
        )
        if (not contract_path.is_file()
                or crypto.parse(contract_path.read_bytes()) != expected_contract):
            raise RuntimeError("Final SDK CEF build contract differs from the signed plan")

        stage = "combined-consumer"
        smoke_build = root / "smoke-build"
        configure = build_support.consumer_configure_command(
            registry / plan["smoke_path"], smoke_build, consumer_sdk, TRIPLET
        )
        configure.append(
            "-DCEF_STATIC_SMOKE_SOURCE="
            + str(recipe / "vcpkg/ports/cef-static/smoke.c")
        )
        run(
            configure, cwd=root, env=build_env,
            log=root / "consumer-configure.log", timeout=900,
        )
        run(
            ["cmake", "--build", smoke_build, "--config", "Release",
             "--parallel", "2"],
            cwd=root, env=build_env,
            log=root / "consumer-build.log", timeout=3600,
        )
        run(
            ["ctest", "--test-dir", smoke_build, "-C", "Release",
             "--output-on-failure", "--timeout", "120"],
            cwd=root, env=build_env,
            log=root / "consumer-test.log", timeout=600,
        )

        stage = "lfc-ui-freerdp-cef-consumer"
        proxy_source = root / "lfc-ui-freerdp-cef-source"
        proxy_source.mkdir()
        for name in (
            "freerdp_proxy_web_engine_view_cef.cpp",
            "freerdp_graphics_mode_args.hpp",
        ):
            shutil.copy2(lfc_ui / "examples" / name, proxy_source / name)
        (proxy_source / "CMakeLists.txt").write_text(
            """cmake_minimum_required(VERSION 3.32)
project(lfc_ui_freerdp_cef_qualification LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(lfc-ui CONFIG REQUIRED COMPONENTS WebEngine)
foreach(required_target IN ITEMS
    lfc::ui
    lfc::ui-webengine
    CEF::static
    CEF::cpp
    freerdp
    freerdp-client
    freerdp-server
    freerdp-server-proxy
    freerdp-shadow)
  if(NOT TARGET ${required_target})
    message(FATAL_ERROR "Missing final SDK target: ${required_target}")
  endif()
endforeach()
add_executable(freerdp_proxy_web_engine_view_cef
    freerdp_proxy_web_engine_view_cef.cpp)
target_link_libraries(freerdp_proxy_web_engine_view_cef PRIVATE
    lfc::ui-webengine)
target_link_options(freerdp_proxy_web_engine_view_cef PRIVATE
    -static-libstdc++ -static-libgcc)
cef_static_deploy_resources(freerdp_proxy_web_engine_view_cef)
""",
            encoding="utf-8",
        )
        proxy_build = root / "lfc-ui-freerdp-cef-build"
        proxy_configure = build_support.consumer_configure_command(
            proxy_source, proxy_build, consumer_sdk, TRIPLET
        )
        run(
            proxy_configure, cwd=root, env=build_env,
            log=root / "lfc-ui-freerdp-cef-configure.log", timeout=900,
        )
        run(
            ["cmake", "--build", proxy_build, "--config", "Release",
             "--parallel", "2"],
            cwd=root, env=build_env,
            log=root / "lfc-ui-freerdp-cef-build.log", timeout=3600,
        )
        executables = [
            path for path in proxy_build.rglob("freerdp_proxy_web_engine_view_cef")
            if path.is_file() and not path.is_symlink()
        ]
        if len(executables) != 1:
            raise RuntimeError("Final FreeRDP/CEF qualification executable is missing")
        proxy_exe = executables[0]
        target_prefix = consumer_sdk / "installed" / TRIPLET
        shared_payload = sorted(
            path.relative_to(target_prefix).as_posix()
            for path in target_prefix.rglob("*")
            if path.is_file() and (
                path.suffix.lower() in {".dll", ".dylib"}
                or ".so" in path.name
            )
        )
        if shared_payload:
            raise RuntimeError(
                "Final vcpkg target prefix contains shared payload: "
                + ", ".join(shared_payload[:20])
            )
        dynamic = subprocess.check_output(
            ["readelf", "-d", proxy_exe], text=True, timeout=120
        ).lower()
        forbidden_needed = [
            token for token in (
                "libcef.so", "libfreerdp", "libwinpr", "libavcodec",
                "libavformat", "libavutil", "libavfilter", "libswscale",
                "libswresample", "libx264", "libx265", "libvpx",
                "libaom", "libopus", "libssl.so", "libcrypto.so",
                "libstdc++.so", "libgcc_s.so",
            )
            if token in dynamic
        ]
        if forbidden_needed:
            raise RuntimeError(
                "Final FreeRDP/CEF executable has shared third-party runtime dependencies: "
                + ", ".join(forbidden_needed)
            )
        usage = subprocess.run(
            ["xvfb-run", "-a", str(proxy_exe)],
            cwd=proxy_exe.parent, env=build_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=120,
        )
        if usage.returncode != 2 or "Usage:" not in usage.stdout:
            raise RuntimeError("Final FreeRDP/CEF executable did not reach its usage path")
        summary["lfc_ui_freerdp_cef_link_verified"] = True
        summary["lfc_ui_freerdp_cef_runtime_loader_verified"] = True
        summary["target_shared_payload_count"] = 0

        certificate = root / "proxy-cert.pem"
        private_key = root / "proxy-key.pem"
        run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", private_key, "-out", certificate,
             "-sha256", "-days", "1", "-nodes", "-subj", "/CN=localhost"],
            cwd=root, env=build_env,
            log=root / "lfc-ui-freerdp-cef-certificate.log", timeout=60,
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            proxy_port = reservation.getsockname()[1]
        proxy_config = root / "freerdp-proxy.ini"
        proxy_config.write_text(
            f"""[Server]
Host=127.0.0.1
Port={proxy_port}

[Target]
FixedTarget=true
Host=127.0.0.1
Port=1
User=
Domain=
Password=

[Security]
ServerRdpSecurity=true
ServerTlsSecurity=true
ServerNlaSecurity=false
ClientRdpSecurity=true
ClientTlsSecurity=true
ClientNlaSecurity=false
ClientAllowFallbackToTls=true

[Channels]
GFX=false
DisplayControl=true
PassthroughIsBlacklist=false
Passthrough=drdynvc,Microsoft::Windows::RDS::DisplayControl,FreeRDP::Advanced::Input
Clipboard=false
AudioInput=false
AudioOutput=false
DeviceRedirection=false
VideoRedirection=false
CameraRedirection=false
RemoteApp=false

[Input]
Keyboard=true
Mouse=true
Multitouch=false

[Codecs]
RFX=true
NSC=true

[Certificates]
CertificateFile={certificate}
PrivateKeyFile={private_key}
""",
            encoding="utf-8",
        )
        lifecycle_log = root / "lfc-ui-freerdp-cef-runtime.log"
        with lifecycle_log.open("w", encoding="utf-8") as stream:
            process = subprocess.Popen(
                ["xvfb-run", "-a", str(proxy_exe), str(proxy_config)],
                cwd=proxy_exe.parent, env=build_env,
                stdout=stream, stderr=subprocess.STDOUT, text=True,
            )
            listening = False
            deadline = time.monotonic() + 60
            try:
                while time.monotonic() < deadline:
                    code = process.poll()
                    if code is not None:
                        raise RuntimeError(
                            "Final FreeRDP/CEF process exited before proxy listener startup"
                        )
                    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    probe.settimeout(0.25)
                    try:
                        listening = probe.connect_ex(
                            ("127.0.0.1", proxy_port)
                        ) == 0
                    finally:
                        probe.close()
                    if listening:
                        break
                    time.sleep(0.25)
                if not listening:
                    raise RuntimeError(
                        "Final FreeRDP/CEF proxy listener did not start"
                    )
                process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=60)
                if code != 0:
                    raise RuntimeError(
                        "Final FreeRDP/CEF process did not stop cleanly"
                    )
            except BaseException:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=30)
                raise
        summary["lfc_ui_freerdp_cef_process_initialized"] = True
        summary["lfc_ui_freerdp_proxy_listener_verified"] = True

        # The checkpoint codec binds this exact work path. Rename only after all
        # source/vcpkg operations are complete so verify_consumer can hide it
        # under the production layout before starting the relocated runtime.
        production_work = root / "cef-work"
        engine_work.rename(production_work)

        def execute(command, *, stage: str, timeout: int, cwd: Path | None = None):
            run(
                command, cwd=cwd or root, env=build_env,
                log=root / ("verify-" + re.sub(r"[^A-Za-z0-9_.-]", "-", stage) + ".log"),
                timeout=timeout,
            )

        platform_preflight = {
            "sha256": platform_sha,
            "qualification": qualification,
            "qualification_sha256": crypto.digest(qualification),
        }
        proof = cef_build.verify_consumer(
            root, cfg, "linux", execute,
            platform_sha256=platform_sha,
            platform_preflight=platform_preflight,
        )
        cef_build.validate_platform_preflight(preflight, proof, cfg, "linux")
        final_key, final_contract = cef_build.qualified_contract(
            proof, cfg, "linux"
        )
        if final_key != build_key or final_contract != expected_contract:
            raise RuntimeError("Final strict Linux contract identity changed")

        summary.update({
            "status": "success",
            "runtime_verified": True,
            "target_archives_static": True,
            "sdk_sha256": crypto.digest(sdk_zip),
            "platform_qualification_sha256": platform_preflight["qualification_sha256"],
            "third_party_libraries_static": proof.get("third_party_libraries_static"),
            "third_party_modules_static": proof.get("smoke", {}).get(
                "third_party_modules_static"
            ),
            "archive_count": proof.get("platform_closure", {}).get("archive_count"),
            "final_build_contract_sha256": final_key,
        })
        print("STRICT_CEF_COMBINED_SDK_QUALIFIED", flush=True)
    except BaseException as error:
        summary.update({
            "status": "failed",
            "failure_stage": stage,
            "failure_type": type(error).__name__,
        })
        raise
    finally:
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
