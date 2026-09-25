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

from . import (
    build_support, cef_build, cef_contract, cef_native_link_static,
    cef_nss_isolation, cef_unwind_backtrace, cef_x11_static, crypto, safeio,
)
from . import cef_combined_identity, cef_strict_iteration

ENGINE_VCPKG = "b4bb281192ea8bb004542012ac804b988a4ff403"
SDK_VCPKG = "936bbb0e7cb7d6d10f8f5ef5874521466278c799"
UPSTREAM = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
CEF = "2aff22e09daaa5c28780c5766a70ee13e61c93b6"
LOCKFREECORO = "24038aed3a0be642adb60e71bd994ae8f0d90140"
LFC_UI = "307afeab287b283514e036aa82ea1bd331dbac2a"
TRIPLET = "x64-linux-static-release"


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()


def registry_snapshot(root: Path) -> dict[str, str]:
    result = {}
    ignored_roots = {".git", ".full-upstream", ".full-cef"}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not relative.parts or relative.parts[0] in ignored_roots:
            continue
        if path.is_symlink():
            raise ValueError("Registry snapshot contains a symlink")
        if path.is_file():
            result[relative.as_posix()] = crypto.digest(path)
    return result


def verify_engine_registry_delta(engine: Path, sdk: Path) -> None:
    if git_head(engine) != ENGINE_VCPKG or git_head(sdk) != SDK_VCPKG:
        raise ValueError("Strict combined registry provenance mismatch")
    before, after = registry_snapshot(engine), registry_snapshot(sdk)
    if ENGINE_VCPKG == SDK_VCPKG:
        if before != after:
            raise ValueError("Unified strict registry snapshots differ")
        return

    changed = {
        name for name in set(before) | set(after)
        if before.get(name) != after.get(name)
    }
    required = {
        "ci/release-plan.json",
        "ports/freerdp/portfile.cmake",
        "ports/freerdp/static-shadow-winpr-tools-dependency.patch",
        "ports/freerdp/vcpkg.json",
        "ports/lfc-ui/portfile.cmake",
        "ports/lfc-ui/use-installed-lockfreecoro.patch",
        "ports/lfc-ui/usage",
        "ports/lfc-ui/vcpkg.json",
        "versions/baseline.json",
        "versions/f-/freerdp.json",
        "versions/l-/lfc-ui.json",
    }
    if changed != required:
        raise ValueError(
            "Final SDK registry changed outside the reviewed lfc-ui/FreeRDP dependency delta"
        )

    old_baseline = json.loads((engine / "versions/baseline.json").read_text())
    new_baseline = json.loads((sdk / "versions/baseline.json").read_text())
    old_lfc = old_baseline["default"].pop("lfc-ui")
    new_lfc = new_baseline["default"].pop("lfc-ui")
    old_freerdp = old_baseline["default"].pop("freerdp")
    new_freerdp = new_baseline["default"].pop("freerdp")
    if old_baseline != new_baseline:
        raise ValueError("Registry baseline changed outside lfc-ui/FreeRDP")
    if (old_lfc.get("baseline"), old_lfc.get("port-version")) != ("0.3.0", 8):
        raise ValueError("Unexpected engine-registry lfc-ui baseline")
    if (new_lfc.get("baseline"), new_lfc.get("port-version")) != ("0.3.0", 11):
        raise ValueError("Unexpected final-registry lfc-ui baseline")
    if (old_freerdp.get("baseline"), old_freerdp.get("port-version")) != ("3.31.1", 23):
        raise ValueError("Unexpected engine-registry FreeRDP baseline")
    if (new_freerdp.get("baseline"), new_freerdp.get("port-version")) != ("3.31.1", 24):
        raise ValueError("Unexpected final-registry FreeRDP baseline")

    old_manifest = json.loads((engine / "ports/lfc-ui/vcpkg.json").read_text())
    new_manifest = json.loads((sdk / "ports/lfc-ui/vcpkg.json").read_text())
    old_port_version = old_manifest.pop("port-version")
    new_port_version = new_manifest.pop("port-version")
    old_feature = old_manifest["features"].pop("freerdp")
    new_feature = new_manifest["features"].pop("freerdp")
    if old_port_version != 8 or new_port_version != 11 or old_manifest != new_manifest:
        raise ValueError("lfc-ui registry delta changed outside the reviewed FreeRDP dependency request")
    if old_feature.get("supports") != "linux" or new_feature.get("supports") != "linux":
        raise ValueError("lfc-ui FreeRDP platform contract changed")
    expected_old = [{
        "name": "freerdp", "default-features": False, "features": ["full"]
    }]
    expected_new = [{
        "name": "freerdp", "default-features": False,
        "features": ["ffmpeg", "proxy", "x11"]
    }]
    if (old_feature.get("dependencies") != expected_old
            or new_feature.get("dependencies") != expected_new):
        raise ValueError("Unexpected lfc-ui FreeRDP dependency transition")

    old_portfile = (engine / "ports/lfc-ui/portfile.cmake").read_text()
    new_portfile = (sdk / "ports/lfc-ui/portfile.cmake").read_text()
    if old_portfile.replace(
            "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5",
            "307afeab287b283514e036aa82ea1bd331dbac2a",
            1) != new_portfile:
        raise ValueError("lfc-ui source pin changed outside the reviewed FFmpeg revision")

    old_plan = json.loads((engine / "ci/release-plan.json").read_text())
    new_plan = json.loads((sdk / "ci/release-plan.json").read_text())
    old_lfc_source = next(item for item in old_plan["ports"] if item["name"] == "lfc-ui")
    new_lfc_source = next(item for item in new_plan["ports"] if item["name"] == "lfc-ui")
    if old_lfc_source.get("sha") != "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5":
        raise ValueError("Unexpected engine release-plan lfc-ui source")
    if new_lfc_source.get("sha") != "307afeab287b283514e036aa82ea1bd331dbac2a":
        raise ValueError("Unexpected final release-plan lfc-ui source")
    old_lfc_source["sha"] = new_lfc_source["sha"]
    if old_plan != new_plan:
        raise ValueError("Release plan changed outside the reviewed lfc-ui source revision")

    old_freerdp_manifest = json.loads((engine / "ports/freerdp/vcpkg.json").read_text())
    new_freerdp_manifest = json.loads((sdk / "ports/freerdp/vcpkg.json").read_text())
    old_freerdp_port_version = old_freerdp_manifest.pop("port-version")
    new_freerdp_port_version = new_freerdp_manifest.pop("port-version")
    if (old_freerdp_port_version != 23 or new_freerdp_port_version != 24
            or old_freerdp_manifest != new_freerdp_manifest):
        raise ValueError("FreeRDP registry delta changed outside port-version")

    old_freerdp_portfile = (engine / "ports/freerdp/portfile.cmake").read_text()
    new_freerdp_portfile = (sdk / "ports/freerdp/portfile.cmake").read_text()
    patch_anchor = "        static-libusb-client.patch\n        install-layout.patch\n"
    expected_portfile = old_freerdp_portfile.replace(
        patch_anchor,
        "        static-libusb-client.patch\n"
        "        static-shadow-winpr-tools-dependency.patch\n"
        "        install-layout.patch\n",
        1,
    )
    if (patch_anchor not in old_freerdp_portfile
            or expected_portfile != new_freerdp_portfile):
        raise ValueError("Unexpected FreeRDP portfile delta")

    expected_patch = """diff --git a/server/shadow/FreeRDP-ShadowConfig.cmake.in b/server/shadow/FreeRDP-ShadowConfig.cmake.in
index 3a7f5aa..4bc04cf 100644
--- a/server/shadow/FreeRDP-ShadowConfig.cmake.in
+++ b/server/shadow/FreeRDP-ShadowConfig.cmake.in
@@ -1,5 +1,8 @@
 include(CMakeFindDependencyMacro)
 find_dependency(WinPR @FREERDP_VERSION@)
+if("@WITH_WINPR_TOOLS@" AND NOT "@BUILD_SHARED_LIBS@")
+  find_dependency(WinPR-tools @FREERDP_VERSION@)
+endif()
 find_dependency(FreeRDP @FREERDP_VERSION@)
 find_dependency(FreeRDP-Server @FREERDP_VERSION@)
 
"""
    if (sdk / "ports/freerdp/static-shadow-winpr-tools-dependency.patch").read_text() != expected_patch:
        raise ValueError("Unexpected FreeRDP static Shadow dependency patch")

    old_versions = json.loads((engine / "versions/f-/freerdp.json").read_text())
    new_versions = json.loads((sdk / "versions/f-/freerdp.json").read_text())
    expected_new_entry = {
        "git-tree": "aceadca1288983390522864e4d6c42b38ae84a6a",
        "version": "3.31.1",
        "port-version": 24,
    }
    if (not isinstance(old_versions.get("versions"), list)
            or not isinstance(new_versions.get("versions"), list)
            or new_versions["versions"][:1] != [expected_new_entry]
            or new_versions["versions"][1:] != old_versions["versions"]):
        raise ValueError("Unexpected FreeRDP versions registry delta")

    old_lockfree_patch = (
        engine / "ports/lfc-ui/use-installed-lockfreecoro.patch"
    ).read_text()
    new_lockfree_patch = (
        sdk / "ports/lfc-ui/use-installed-lockfreecoro.patch"
    ).read_text()
    old_config_hunk = """@@ -1,6 +1,10 @@
 @PACKAGE_INIT@
 
 include(CMakeFindDependencyMacro)
+if(@LFC_UI_PACKAGE_HAS_LOCKFREECORO@)
+    find_dependency(lockfreecoro CONFIG COMPONENTS core)
+endif()
+
 include("${CMAKE_CURRENT_LIST_DIR}/lfc_ui_compiler_requirements.cmake")
 lfc_ui_require_supported_compiler("${CMAKE_CXX_COMPILER_ID}" "${CMAKE_CXX_COMPILER_VERSION}")
"""
    new_config_hunk = """@@ -1,7 +1,11 @@
 @PACKAGE_INIT@
 
 include(CMakeFindDependencyMacro)
+if(@LFC_UI_PACKAGE_HAS_LOCKFREECORO@)
+    find_dependency(lockfreecoro CONFIG COMPONENTS core)
+endif()
+
 include("${CMAKE_CURRENT_LIST_DIR}/lfc_ui_compiler_requirements.cmake")
 include("${CMAKE_CURRENT_LIST_DIR}/lfc_ui_pkgconfig_runtime.cmake")
 lfc_ui_require_supported_compiler("${CMAKE_CXX_COMPILER_ID}" "${CMAKE_CXX_COMPILER_VERSION}")
"""
    if (old_lockfree_patch.count(old_config_hunk) != 1
            or old_lockfree_patch.replace(
                old_config_hunk, new_config_hunk, 1) != new_lockfree_patch):
        raise ValueError("Unexpected lfc-ui lockfreecoro overlay rebase")

    old_lfc_versions = json.loads((engine / "versions/l-/lfc-ui.json").read_text())
    new_lfc_versions = json.loads((sdk / "versions/l-/lfc-ui.json").read_text())
    expected_lfc_entries = [
        {"git-tree": "d635813c8ca3903f7300987e3d24d1c8c6cdea9a",
         "version": "0.3.0", "port-version": 11},
        {"git-tree": "9cc7498e3dd005babec671f17cc7dcea26797c45",
         "version": "0.3.0", "port-version": 10},
        {"git-tree": "cf9f360b1433c1aec5c8eabb4a2fcd3b551627bf",
         "version": "0.3.0", "port-version": 9},
    ]
    if (not isinstance(old_lfc_versions.get("versions"), list)
            or not isinstance(new_lfc_versions.get("versions"), list)
            or new_lfc_versions["versions"][:3] != expected_lfc_entries
            or new_lfc_versions["versions"][3:] != old_lfc_versions["versions"]):
        raise ValueError("Unexpected lfc-ui versions registry delta")


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


def verify_relocated_metadata(sdk: Path, forbidden_roots: list[Path]) -> None:
    """Reject exported CMake/pkg-config metadata tied to producer-only roots."""
    needles = [
        str(path.resolve()).replace("\\", "/")
        for path in forbidden_roots
    ]
    hits = []
    for path in sdk.rglob("*"):
        if (not path.is_file() or path.is_symlink()
                or path.suffix.lower() not in {".cmake", ".pc", ".la"}
                or path.stat().st_size > 16 * 1024**2):
            continue
        text = path.read_text(encoding="utf-8", errors="replace").replace("\\", "/")
        if any(needle in text for needle in needles):
            hits.append(path.relative_to(sdk).as_posix())
    if hits:
        raise RuntimeError(
            "Final SDK metadata retains producer-only absolute paths: "
            + ", ".join(Path(item).name for item in hits[:20])
        )


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


def source_fresh_binary_args() -> list[str]:
    """Final SDK graph must be reproducible without producer binary caches."""
    cache_env = (
        "CEF_STRICT_BINARY_CACHE_CORE",
        "CEF_STRICT_BINARY_CACHE_CUPS",
        "CEF_STRICT_BINARY_CACHE_GBM",
    )
    if any(os.environ.get(name) for name in cache_env):
        raise ValueError("Final combined SDK must not consume producer binary caches")
    return ["--binarysource=clear"]


ISOLATED_RUNTIME_SYMBOLS = frozenset({
    "CEF_NSS_SHA256_Update",
    "CEF_GTK_CODEC_jpeg_std_error",
    "CEF_GTK_CODEC_TIFFOpen",
})


def verify_isolated_runtime_symbols(executable: Path) -> int:
    """Prove relocated re-link consumed derived NSS/JPEG/TIFF providers."""
    if not executable.is_file() or executable.is_symlink():
        raise RuntimeError("Relocated CEF smoke executable is missing")
    nm = shutil.which("nm")
    if not nm:
        raise RuntimeError("nm is required for relocated isolation verification")
    result = subprocess.run(
        [nm, "-a", "--defined-only", str(executable)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=180,
    )
    if result.returncode or len(result.stdout) > 64 * 1024**2:
        raise RuntimeError("Cannot inspect relocated CEF isolation symbols")
    names = {
        fields[-1]
        for line in result.stdout.splitlines()
        if (fields := line.split())
    }
    if ISOLATED_RUNTIME_SYMBOLS - names:
        raise RuntimeError("Relocated CEF executable lost isolated static providers")
    return len(ISOLATED_RUNTIME_SYMBOLS)


def verify_os_only_elf(executable: Path) -> int:
    dynamic = subprocess.check_output(
        ["readelf", "-d", str(executable)], text=True, timeout=120
    )
    needed = re.findall(
        r"\(NEEDED\).*?Shared library:\s*\[([^\]]+)\]", dynamic
    )
    if set(needed) - cef_x11_static.OS_NEEDED:
        raise RuntimeError("Relocated CEF smoke imports non-OS shared libraries")
    return len(needed)


def main() -> None:
    if sys.platform != "linux":
        raise ValueError("Strict combined SDK qualification requires native Linux")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    registry = workspace / "private-vcpkg"
    engine_registry = workspace / "private-engine-vcpkg"
    upstream = registry / ".full-upstream"
    recipe_checkout = registry / ".full-cef"
    lockfree = workspace / "private-lockfreecoro"
    lfc_ui = workspace / "private-lfc-ui"
    expected_heads = {
        registry: SDK_VCPKG,
        engine_registry: ENGINE_VCPKG,
        upstream: UPSTREAM,
        recipe_checkout: CEF,
        lockfree: LOCKFREECORO,
        lfc_ui: LFC_UI,
    }
    for path, revision in expected_heads.items():
        if git_head(path) != revision:
            raise ValueError("Strict combined SDK source revision mismatch")
    verify_engine_registry_delta(engine_registry, registry)

    plan = json.loads((registry / "ci/release-plan.json").read_text(encoding="utf-8"))
    cfg = plan["cef"]
    cef_contract.validate(cfg)
    if (cfg["profile"] != "static-third-party"
            or cfg["platforms"]["linux"]["mode"] != "source-fresh"
            or cfg["recipe_commit"] != CEF):
        raise ValueError("Unexpected strict combined SDK plan")

    lock = cef_strict_iteration.qualification_lock(
        workspace, "cef-strict-combined-lock.json")
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
    # Keep Git provenance available for exact checkpoint-recipe reconstruction.
    # Later git archive reads the pinned revision, not reviewed worktree edits.
    recipe = recipe_checkout

    summary_path = temp / "cef-strict-combined-summary.json"
    summary = {
        "schema": 1,
        "kind": "cef-strict-combined-sdk-qualification",
        "status": "running",
        "platform": "linux",
        "engine_vcpkg_commit": ENGINE_VCPKG,
        "sdk_vcpkg_commit": SDK_VCPKG,
        "upstream_commit": UPSTREAM,
        "cef_recipe_commit": CEF,
        "build_contract_sha256": build_key,
        "platform_sha256": platform_sha,
        "runtime_verified": False,
        "target_archives_static": False,
    }
    stage = "checkpoint-host-identity"
    try:
        recipe_env = cef_combined_identity.prepare_environment(
            selected, clean_environment(), summary
        )
        stage = "checkpoint-restore"
        restored_package = root / "restored-checkpoint"
        cef_strict_iteration.restore_checkpoint(
            selected, restored_package, build_key,
            os.environ["BUILDER_INPUT_PRIVATE_KEY"],
            allow_resumable=False,
        )
        restore_profile = cef_native_link_static.prepare_restore(
            recipe / "vcpkg/ports/cef-static/source_build.py",
            restored_package,
        )
        if (restore_profile.get("profile") != "native-link-v1"
                or restore_profile.get("recorded_recipe_matched") is not True):
            raise RuntimeError(
                "Combined checkpoint recipe profile is not the qualified native-link state"
            )
        summary["checkpoint_recipe_profile"] = restore_profile["profile"]
        driver = recipe / "vcpkg/integration/driver.py"
        recipe_env.update({
            "GITHUB_SHA": CEF,
            "CEF_STATIC_STRICT_THIRD_PARTY": "1",
            "CEF_STATIC_BUILD_TIMEOUT_SECONDS": "18000",
            "CEF_STATIC_JOBS": "2",
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
             "--work", engine_work, "--logs", engine_logs, "--jobs", "2"],
            cwd=recipe, env=recipe_env,
            log=root / "source-prepare.log", timeout=10800,
        )
        run(
            ["sudo", engine_work / "download/chromium/src/build/install-build-deps.sh",
             "--no-prompt", "--no-arm", "--no-chromeos-fonts"],
            cwd=recipe, env=clean_environment(),
            log=root / "install-build-deps.log", timeout=1800,
        )
        stage = "engine-sysroot-preflight"
        cef_strict_iteration.ensure_chromium_sysroot(
            engine_work / "download/chromium/src",
            root, clean_environment(), summary,
        )
        cef_strict_iteration.ensure_dawn_static_x11_headers(
            engine_work / "download/chromium/src", summary
        )
        cef_nss_isolation.install(
            engine_work / "download/chromium/src",
            engine_work / "platform-inputs.json",
            engine_work / "target-prefix",
            platform_sha,
            summary,
        )
        cef_strict_iteration.ensure_static_linux_gtk(
            engine_work / "download/chromium/src",
            engine_work / "platform-inputs.json",
            engine_work / "target-prefix",
            platform_sha,
            summary,
        )
        source = engine_work / "download/chromium/src"
        native_link = cef_native_link_static.install(source_build, source)
        backtrace = cef_unwind_backtrace.install(source)
        x11 = cef_x11_static.install(
            source,
            engine_work / "platform-inputs.json",
            engine_work / "target-prefix",
            platform_sha,
        )
        if (native_link.get("expat_backend") != "frozen-static-expat"
                or native_link.get("unwind_backend") != "chromium-libunwind"
                or backtrace.get("backend") != "in-tree-unwind-backtrace"
                or x11.get("webrtc_x11_static") is not True
                or x11.get("gtk_rendering") != "cairo-software"):
            raise RuntimeError("Combined engine profile differs from qualified engine #83")
        prebuild_elf = cef_x11_static.audit_native(source)
        if prebuild_elf.get("runtime_native_elf_verified") is not True:
            raise RuntimeError("Restored qualified engine no longer has an OS-only ELF")
        summary.update({
            "runtime_expat_backend": native_link["expat_backend"],
            "runtime_unwind_backend": native_link["unwind_backend"],
            "runtime_backtrace_backend": backtrace["backend"],
            "runtime_x11_backend": "static-x11",
            "runtime_webrtc_x11_static": True,
            "runtime_gtk_rendering": x11["gtk_rendering"],
            "runtime_native_elf_prebuild_verified": True,
            "runtime_native_elf_prebuild_needed_count":
                prebuild_elf["runtime_native_elf_needed_count"],
        })
        stage = "engine-runtime"
        run(
            [sys.executable, source_build, "build",
             "--work", engine_work, "--logs", engine_logs, "--jobs", "2",
             "--platform-manifest", engine_work / "platform-inputs.json",
             "--platform-prefix", engine_work / "target-prefix",
             "--platform-sha256", platform_sha],
            cwd=recipe, env=recipe_env,
            log=root / "engine-runtime.log", timeout=21600,
        )
        postbuild_elf = cef_x11_static.audit_native(source)
        if postbuild_elf.get("runtime_native_elf_verified") is not True:
            raise RuntimeError("Combined engine runtime changed its OS-only ELF")
        summary["runtime_native_elf_verified"] = True
        summary["runtime_native_elf_needed_count"] = (
            postbuild_elf["runtime_native_elf_needed_count"]
        )
        cef_nss_isolation.record_receipt(
            engine_work / "download/chromium/src", summary, required=True
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
            *source_fresh_binary_args(),
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
        verify_relocated_metadata(
            consumer_sdk,
            [installed, sdk, upstream / "buildtrees", upstream / "packages"],
        )
        shutil.rmtree(installed)
        shutil.rmtree(export_root)
        if installed.exists() or export_root.exists():
            raise RuntimeError("Producer SDK roots survived relocation boundary")
        summary["producer_sdk_roots_removed"] = True
        summary["relocated_metadata_verified"] = True

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
        relocated_smokes = [
            path for path in smoke_build.rglob("cef_static_smoke")
            if path.is_file() and not path.is_symlink()
        ]
        if len(relocated_smokes) != 1:
            raise RuntimeError("Relocated SDK CEF smoke executable is missing")
        summary["relocated_engine_isolation_symbol_count"] = (
            verify_isolated_runtime_symbols(relocated_smokes[0])
        )
        summary["relocated_engine_isolation_symbols_verified"] = True
        summary["relocated_engine_os_needed_count"] = verify_os_only_elf(
            relocated_smokes[0]
        )
        summary["relocated_engine_os_only_elf_verified"] = True
        run(
            ["ctest", "--test-dir", smoke_build, "-C", "Release",
             "--output-on-failure", "--timeout", "120"],
            cwd=root, env=build_env,
            log=root / "consumer-test.log", timeout=600,
        )

        stage = "lfc-ui-freerdp-cef-consumer"
        canonical_proxy_example = (
            lfc_ui / "examples/freerdp_proxy_web_engine_view_cef.cpp"
        )
        canonical_graphics_args = (
            lfc_ui / "examples/freerdp_graphics_mode_args.hpp"
        )
        if not canonical_proxy_example.is_file() or not canonical_graphics_args.is_file():
            raise ValueError("Pinned lfc-ui lacks the canonical FreeRDP/CEF example")

        proxy_source = (
            consumer_sdk / "installed" / TRIPLET
            / "share/lfc-ui/examples/freerdp-proxy-cef"
        )
        installed_proxy_example = (
            proxy_source / "freerdp_proxy_web_engine_view_cef.cpp"
        )
        installed_graphics_args = proxy_source / "freerdp_graphics_mode_args.hpp"
        installed_project = proxy_source / "CMakeLists.txt"
        for required in (
            installed_proxy_example, installed_graphics_args, installed_project
        ):
            if not required.is_file() or required.is_symlink():
                raise RuntimeError(
                    "Final SDK is missing the installed canonical FreeRDP/CEF example"
                )
        source_sha = crypto.digest(canonical_proxy_example)
        if crypto.digest(installed_proxy_example) != source_sha:
            raise RuntimeError(
                "Installed FreeRDP/CEF example differs from the pinned lfc-ui source"
            )
        if crypto.digest(installed_graphics_args) != crypto.digest(canonical_graphics_args):
            raise RuntimeError(
                "Installed FreeRDP/CEF helper differs from the pinned lfc-ui source"
            )
        project_text = installed_project.read_text(encoding="utf-8")
        for required_text in (
            "find_package(lfc-ui CONFIG REQUIRED COMPONENTS WebEngine)",
            "freerdp-server-proxy",
            "freerdp-shadow",
            "target_link_libraries(freerdp_proxy_web_engine_view_cef PRIVATE",
            "lfc::ui-webengine",
            "-static-libstdc++ -static-libgcc",
            "cef_static_deploy_resources(freerdp_proxy_web_engine_view_cef)",
        ):
            if required_text not in project_text:
                raise RuntimeError(
                    "Installed FreeRDP/CEF example project lost its static SDK contract"
                )
        summary["lfc_ui_freerdp_cef_example_source_sha256"] = source_sha
        summary["lfc_ui_freerdp_cef_installed_example_verified"] = True
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
        )
        (root / "lfc-ui-freerdp-cef-readelf.log").write_text(
            dynamic, encoding="utf-8"
        )
        needed = re.findall(
            r"\(NEEDED\).*?Shared library:\s*\[([^\]]+)\]",
            dynamic,
        )
        forbidden_prefixes = (
            "libcef.so", "libfreerdp", "libwinpr", "libavcodec",
            "libavformat", "libavutil", "libavfilter", "libswscale",
            "libswresample", "libx264", "libx265", "libvpx",
            "libaom", "libopus", "libssl.so", "libcrypto.so",
            "libstdc++.so", "libgcc_s.so",
        )
        forbidden_needed = sorted({
            name for name in needed
            if any(name.lower().startswith(prefix) for prefix in forbidden_prefixes)
        })
        summary["lfc_ui_freerdp_cef_dt_needed_count"] = len(needed)
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
