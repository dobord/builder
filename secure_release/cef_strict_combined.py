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
from . import (
    cef_combined_identity, cef_combined_port, cef_combined_smoke, cef_consumer_linker, cef_dependency_source,
    cef_freerdp_profile, cef_frozen_dependencies, cef_sdk_example, cef_sdk_headers, cef_sdk_aliases, cef_sdk_protoc, cef_sdk_xz, cef_sdk_objects, cef_sdk_source_interfaces, cef_strict_iteration,
    cef_boringssl_isolation,
)

ENGINE_VCPKG = "b4bb281192ea8bb004542012ac804b988a4ff403"
SDK_VCPKG_CHECKOUT = "56f9a7ce6bf25e3325d9d71e5fdd6255de33cb57"
SDK_VCPKG_CHECKOUT_TREE = "5d798711a13c08389ca55c84ace774c912314b8e"
SDK_VCPKG = "56f9a7ce6bf25e3325d9d71e5fdd6255de33cb57"
SDK_VCPKG_TREE = "5d798711a13c08389ca55c84ace774c912314b8e"
SDK_LFC_UI_TREE = "fd125f0896683fc0391803b4a52bf7c4cc651c20"
UPSTREAM = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
CEF = "2aff22e09daaa5c28780c5766a70ee13e61c93b6"
LOCKFREECORO = "24038aed3a0be642adb60e71bd994ae8f0d90140"
LFC_UI = "29146a706499f83d464dd28fe29301fee06bcb3d"
TRIPLET = "x64-linux-static-release"

MAX_PROXY_RUNTIME_LOG_BYTES = 1024 * 1024
_PROXY_RUNTIME_FAILURE_MARKERS = (
    ("Failed to load FreeRDP proxy config:", "config-load"),
    ("Failed to create FreeRDP proxy server", "server-create"),
    ("Failed to initialize process-owned CEF runner:", "cef-initialize"),
    ("Failed to register lfc-ui FreeRDP proxy CEF module", "module-register"),
    ("Failed to start FreeRDP proxy server", "server-start"),
)


def classify_proxy_runtime_failure(log: Path, exit_code: int) -> dict[str, object]:
    """Publish only bounded startup classification, never raw runtime diagnostics."""
    result: dict[str, object] = {
        "lfc_ui_freerdp_cef_runtime_exit_code": exit_code,
    }
    if not log.is_file() or log.is_symlink():
        result["lfc_ui_freerdp_cef_runtime_failure_class"] = "log-missing"
        return result
    size = log.stat().st_size
    result["lfc_ui_freerdp_cef_runtime_log_bytes"] = size
    if size > MAX_PROXY_RUNTIME_LOG_BYTES:
        result["lfc_ui_freerdp_cef_runtime_failure_class"] = "log-oversized"
        return result
    data = log.read_bytes()
    result["lfc_ui_freerdp_cef_runtime_log_sha256"] = crypto.digest(log)
    text = data.decode("utf-8", errors="replace")
    for marker, failure_class in _PROXY_RUNTIME_FAILURE_MARKERS:
        if marker in text:
            result["lfc_ui_freerdp_cef_runtime_failure_class"] = failure_class
            return result
    if exit_code < 0:
        result["lfc_ui_freerdp_cef_runtime_failure_class"] = (
            "signal-before-log" if not data else "signal-unclassified"
        )
    elif "Starting one-shot FreeRDP Proxy CEF lifecycle example" in text:
        result["lfc_ui_freerdp_cef_runtime_failure_class"] = "server-run"
    elif exit_code == 0:
        result["lfc_ui_freerdp_cef_runtime_failure_class"] = "unexpected-clean-exit"
    else:
        result["lfc_ui_freerdp_cef_runtime_failure_class"] = "early-exit-unclassified"
    return result


MAX_PROXY_BACKTRACE_LOG_BYTES = 4 * 1024 * 1024
_PROXY_BACKTRACE_DOMAINS = (
    ("static-initializer", ("__static_initialization_and_destruction_0", "_GLOBAL__sub_I_", "call_init")),
    ("logger", ("lfc::ui::detail::logImpl", "__vfprintf_internal", "vfprintf", "fprintf")),
    ("cef", ("CefExecuteProcess", "CefInitialize", "cef_execute_process", "cef_initialize")),
    ("freerdp", ("pf_server_", "freerdp")),
    ("cxx-runtime", ("__cxa_", "std::", "libstdc++")),
    ("libc", ("__libc_start_main", "libc_start_main")),
)


def capture_proxy_startup_backtrace(
    proxy_exe: Path, cwd: Path, env: dict[str, str], log: Path
) -> dict[str, object]:
    """Capture a bounded native stack after an already-observed startup crash.

    The full stack remains runner-local/encrypted. Public output is limited to
    a signal bit, frame count/hash and one fixed crash-domain label.
    """
    with log.open("w", encoding="utf-8") as stream:
        try:
            completed = subprocess.run(
                [
                    "gdb", "--batch", "--quiet",
                    "-ex", "set pagination off",
                    "-ex", "run",
                    "-ex", "thread apply all bt",
                    "--args", str(proxy_exe),
                ],
                cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                text=True, timeout=60,
            )
            gdb_returncode = completed.returncode
        except subprocess.TimeoutExpired:
            gdb_returncode = 124
    result: dict[str, object] = {
        "lfc_ui_freerdp_cef_backtrace_gdb_returncode": gdb_returncode,
    }
    if not log.is_file() or log.is_symlink():
        result["lfc_ui_freerdp_cef_backtrace_class"] = "log-missing"
        return result
    size = log.stat().st_size
    result["lfc_ui_freerdp_cef_backtrace_log_bytes"] = size
    if size > MAX_PROXY_BACKTRACE_LOG_BYTES:
        result["lfc_ui_freerdp_cef_backtrace_class"] = "log-oversized"
        return result
    data = log.read_bytes()
    result["lfc_ui_freerdp_cef_backtrace_log_sha256"] = crypto.digest(log)
    text = data.decode("utf-8", errors="replace")
    result["lfc_ui_freerdp_cef_backtrace_sigsegv"] = (
        "Program received signal SIGSEGV" in text
    )
    frames = [line for line in text.splitlines() if re.match(r"^#[0-9]+\\s", line)]
    result["lfc_ui_freerdp_cef_backtrace_frame_count"] = len(frames)
    normalized_frames = "\\n".join(frames).encode("utf-8", errors="replace")
    result["lfc_ui_freerdp_cef_backtrace_frames_sha256"] = (
        __import__("hashlib").sha256(normalized_frames).hexdigest()
    )
    if not result["lfc_ui_freerdp_cef_backtrace_sigsegv"]:
        result["lfc_ui_freerdp_cef_backtrace_class"] = "not-reproduced"
        return result
    for domain, markers in _PROXY_BACKTRACE_DOMAINS:
        if any(marker in text for marker in markers):
            result["lfc_ui_freerdp_cef_backtrace_class"] = domain
            return result
    result["lfc_ui_freerdp_cef_backtrace_class"] = "unknown"
    return result


def git_head(path: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()


def _git_value(path: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), *args], text=True, timeout=30
    ).strip()


def materialize_sdk_registry(root: Path) -> dict[str, str]:
    """Replay only the reviewed child tree when CI checked out its pinned parent."""
    root = root.resolve()
    checkout = git_head(root)
    if checkout == SDK_VCPKG:
        return {
            "mode": "direct-checkout",
            "checkout_commit": checkout,
            "tree": SDK_VCPKG_TREE,
        }
    head_tree = _git_value(root, "rev-parse", "HEAD^{tree}")
    tracked = _git_value(root, "status", "--porcelain=v1", "--untracked-files=no")
    if tracked:
        raise ValueError("Final SDK registry checkout is not tracked-clean")
    if checkout != SDK_VCPKG_CHECKOUT or head_tree != SDK_VCPKG_CHECKOUT_TREE:
        raise ValueError("Final SDK registry checkout is not the reviewed replay parent")

    edits = (
        (
            "ports/lfc-ui/use-installed-freerdp.cmake",
            "        target_link_libraries(lfc-ui ${_lfc_ui_usage_scope}\n"
            "            freerdp-server-proxy freerdp-client freerdp-server freerdp\n"
            "            disp-server rdpgfx-server)\n"
            "        target_compile_definitions(lfc-ui ${_lfc_ui_usage_scope} LFC_UI_ENABLE_FREERDP_PROXY_PLATFORM=1)\n",
            "        target_link_libraries(lfc-ui ${_lfc_ui_usage_scope}\n"
            "            freerdp-server-proxy freerdp-client freerdp-server freerdp\n"
            "            disp-server rdpgfx-server)\n"
            "        target_link_libraries(lfc-ui INTERFACE \"$<TARGET_OBJECTS:rdpgfx-server>\")\n"
            "        target_compile_definitions(lfc-ui ${_lfc_ui_usage_scope} LFC_UI_ENABLE_FREERDP_PROXY_PLATFORM=1)\n",
        ),
        (
            "ports/lfc-ui/vcpkg.json",
            '  "port-version": 14\n}\n',
            '  "port-version": 15\n}\n',
        ),
        (
            "versions/baseline.json",
            '    "lfc-ui": {\n'
            '      "baseline": "0.3.0",\n'
            '      "port-version": 14\n'
            '    },\n',
            '    "lfc-ui": {\n'
            '      "baseline": "0.3.0",\n'
            '      "port-version": 15\n'
            '    },\n',
        ),
        (
            "versions/l-/lfc-ui.json",
            '  "versions": [\n'
            '    {\n'
            '      "git-tree": "cb1a947459fe788d6d697e9e62bb87edec24f3e2",\n'
            '      "version": "0.3.0",\n'
            '      "port-version": 14\n'
            '    },\n',
            '  "versions": [\n'
            '    {\n'
            '      "git-tree": "bbc00cc70e557268570db3e08714d26171c8f06e",\n'
            '      "version": "0.3.0",\n'
            '      "port-version": 15\n'
            '    },\n'
            '    {\n'
            '      "git-tree": "cb1a947459fe788d6d697e9e62bb87edec24f3e2",\n'
            '      "version": "0.3.0",\n'
            '      "port-version": 14\n'
            '    },\n',
        ),
    )
    rendered: dict[Path, str] = {}
    for relative, before, after in edits:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("Final SDK registry replay input is invalid")
        data = path.read_text(encoding="utf-8")
        if data.count(before) != 1:
            raise ValueError("Final SDK registry replay anchor changed")
        rendered[path] = data.replace(before, after, 1)
    for path, data in rendered.items():
        with path.open("w", encoding="utf-8", newline="") as stream:
            stream.write(data)

    relative_paths = [path.relative_to(root).as_posix() for path in rendered]
    subprocess.run(
        ["git", "-C", str(root), "add", "--", *relative_paths],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
    )
    if _git_value(root, "diff", "--name-only"):
        raise ValueError("Final SDK registry replay left unstaged tracked changes")
    staged = _git_value(root, "diff", "--cached", "--name-only").splitlines()
    if staged != sorted(relative_paths):
        raise ValueError("Final SDK registry replay changed unexpected paths")
    tree = _git_value(root, "write-tree")
    if tree != SDK_VCPKG_TREE:
        raise ValueError("Final SDK registry replay did not reproduce the reviewed child tree")
    return {
        "mode": "reviewed-child-tree-replay",
        "checkout_commit": checkout,
        "tree": tree,
    }


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
    if (git_head(engine) != ENGINE_VCPKG
            or git_head(sdk) not in {SDK_VCPKG_CHECKOUT, SDK_VCPKG}):
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
        "ports/lfc-ui/use-installed-freerdp.cmake",
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
    if (new_lfc.get("baseline"), new_lfc.get("port-version")) != ("0.3.0", 16):
        raise ValueError("Unexpected final-registry lfc-ui baseline")
    if (old_freerdp.get("baseline"), old_freerdp.get("port-version")) != ("3.31.1", 23):
        raise ValueError("Unexpected engine-registry FreeRDP baseline")
    if (new_freerdp.get("baseline"), new_freerdp.get("port-version")) != ("3.31.1", 25):
        raise ValueError("Unexpected final-registry FreeRDP baseline")

    old_manifest = json.loads((engine / "ports/lfc-ui/vcpkg.json").read_text())
    new_manifest = json.loads((sdk / "ports/lfc-ui/vcpkg.json").read_text())
    old_port_version = old_manifest.pop("port-version")
    new_port_version = new_manifest.pop("port-version")
    old_feature = old_manifest["features"].pop("freerdp")
    new_feature = new_manifest["features"].pop("freerdp")
    if old_port_version != 8 or new_port_version != 16 or old_manifest != new_manifest:
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

    old_freerdp_overlay = (engine / "ports/lfc-ui/use-installed-freerdp.cmake").read_text()
    new_freerdp_overlay = (sdk / "ports/lfc-ui/use-installed-freerdp.cmake").read_text()
    expected_freerdp_overlay = old_freerdp_overlay
    overlay_replacements = (
        (
            "            freerdp-shadow)\n",
            "            freerdp-shadow\n"
            "            ainput-server\n"
            "            cliprdr-server\n"
            "            disp-server\n"
            "            rdpgfx-server)\n",
        ),
        (
            "        target_link_libraries(lfc-ui ${_lfc_ui_usage_scope} freerdp-shadow freerdp-server freerdp)\n",
            "        target_link_libraries(lfc-ui ${_lfc_ui_usage_scope}\n"
            "            freerdp-shadow freerdp-server freerdp\n"
            "            ainput-server cliprdr-server disp-server rdpgfx-server)\n"
            "        target_link_libraries(lfc-ui INTERFACE \"$<TARGET_OBJECTS:disp-server>\")\n",
        ),
        (
            "            freerdp-server-proxy freerdp-client freerdp-server freerdp)\n",
            "            freerdp-server-proxy freerdp-client freerdp-server freerdp\n"
            "            disp-server rdpgfx-server)\n"
            "        target_link_libraries(lfc-ui INTERFACE \"$<TARGET_OBJECTS:rdpgfx-server>\")\n",
        ),
    )
    for before_text, after_text in overlay_replacements:
        if expected_freerdp_overlay.count(before_text) != 1:
            raise ValueError("Unexpected original lfc-ui installed FreeRDP overlay")
        expected_freerdp_overlay = expected_freerdp_overlay.replace(
            before_text, after_text, 1
        )
    if new_freerdp_overlay != expected_freerdp_overlay:
        raise ValueError("Unexpected lfc-ui installed FreeRDP OBJECT-target delta")

    old_portfile = (engine / "ports/lfc-ui/portfile.cmake").read_text()
    new_portfile = (sdk / "ports/lfc-ui/portfile.cmake").read_text()
    if old_portfile.replace(
            "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5",
            "29146a706499f83d464dd28fe29301fee06bcb3d",
            1) != new_portfile:
        raise ValueError("lfc-ui source pin changed outside the reviewed FFmpeg revision")

    old_plan = json.loads((engine / "ci/release-plan.json").read_text())
    new_plan = json.loads((sdk / "ci/release-plan.json").read_text())
    old_lfc_source = next(item for item in old_plan["ports"] if item["name"] == "lfc-ui")
    new_lfc_source = next(item for item in new_plan["ports"] if item["name"] == "lfc-ui")
    if old_lfc_source.get("sha") != "85ced5b0f72cb55b9e07b2ab58d27fc43d9420b5":
        raise ValueError("Unexpected engine release-plan lfc-ui source")
    if new_lfc_source.get("sha") != "29146a706499f83d464dd28fe29301fee06bcb3d":
        raise ValueError("Unexpected final release-plan lfc-ui source")
    old_lfc_source["sha"] = new_lfc_source["sha"]
    if old_plan != new_plan:
        raise ValueError("Release plan changed outside the reviewed lfc-ui source revision")

    old_freerdp_manifest = json.loads((engine / "ports/freerdp/vcpkg.json").read_text())
    new_freerdp_manifest = json.loads((sdk / "ports/freerdp/vcpkg.json").read_text())
    old_freerdp_port_version = old_freerdp_manifest.pop("port-version")
    new_freerdp_port_version = new_freerdp_manifest.pop("port-version")
    if (old_freerdp_port_version != 23 or new_freerdp_port_version != 25
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
    native_object_anchor = (
        "if (NOT HAS_SHADOW_SUBSYSTEM)\n"
        "    list(APPEND FEATURE_OPTIONS -DWITH_SHADOW_SUBSYSTEM=OFF -DWITH_SERVER_SHADOW_CLI=OFF)\n"
        "endif()\n\n"
        "vcpkg_find_acquire_program(PKGCONFIG)\n"
    )
    native_object_policy = (
        "if (NOT HAS_SHADOW_SUBSYSTEM)\n"
        "    list(APPEND FEATURE_OPTIONS -DWITH_SHADOW_SUBSYSTEM=OFF -DWITH_SERVER_SHADOW_CLI=OFF)\n"
        "endif()\n\n"
        "# Installed static channel OBJECT libraries are part of the exported SDK link\n"
        "# interface. GCC LTO objects are discoverable by nm through liblto_plugin but\n"
        "# cannot be consumed by the qualified LLD linker used by the final CEF SDK.\n"
        "# Keep Linux static FreeRDP link inputs as native ELF relocatables.\n"
        "if(VCPKG_TARGET_IS_LINUX AND VCPKG_LIBRARY_LINKAGE STREQUAL \"static\")\n"
        "    list(APPEND FEATURE_OPTIONS -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF)\n"
        "endif()\n\n"
        "vcpkg_find_acquire_program(PKGCONFIG)\n"
    )
    if expected_portfile.count(native_object_anchor) != 1:
        raise ValueError("Unexpected original FreeRDP native-object anchor")
    expected_portfile = expected_portfile.replace(
        native_object_anchor, native_object_policy, 1
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
    expected_new_entries = [
        {
            "git-tree": "2c8bdcad32d778ff2ff280db0efe3e1eefabf162",
            "version": "3.31.1",
            "port-version": 25,
        },
        {
            "git-tree": "aceadca1288983390522864e4d6c42b38ae84a6a",
            "version": "3.31.1",
            "port-version": 24,
        },
    ]
    if (not isinstance(old_versions.get("versions"), list)
            or not isinstance(new_versions.get("versions"), list)
            or new_versions["versions"][:2] != expected_new_entries
            or new_versions["versions"][2:] != old_versions["versions"]):
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
        {"git-tree": SDK_LFC_UI_TREE,
         "version": "0.3.0", "port-version": 16},
        {"git-tree": "bbc00cc70e557268570db3e08714d26171c8f06e",
         "version": "0.3.0", "port-version": 15},
        {"git-tree": "cb1a947459fe788d6d697e9e62bb87edec24f3e2",
         "version": "0.3.0", "port-version": 14},
        {"git-tree": "456adaca80fe88da3f23fb7c103f20fab2003fd7",
         "version": "0.3.0", "port-version": 13},
        {"git-tree": "700498a2d6c2a33f652146e804eaeed359247a2d",
         "version": "0.3.0", "port-version": 12},
        {"git-tree": "d635813c8ca3903f7300987e3d24d1c8c6cdea9a",
         "version": "0.3.0", "port-version": 11},
        {"git-tree": "9cc7498e3dd005babec671f17cc7dcea26797c45",
         "version": "0.3.0", "port-version": 10},
        {"git-tree": "cf9f360b1433c1aec5c8eabb4a2fcd3b551627bf",
         "version": "0.3.0", "port-version": 9},
    ]
    if (not isinstance(old_lfc_versions.get("versions"), list)
            or not isinstance(new_lfc_versions.get("versions"), list)
            or new_lfc_versions["versions"][:8] != expected_lfc_entries
            or new_lfc_versions["versions"][8:] != old_lfc_versions["versions"]):
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


def summarize_consumer_sdk_build_failure(log: Path, installed: Path, object_review: dict) -> dict:
    """Return only bounded error class/counts and reviewed OBJECT target names."""
    if not log.is_file() or log.is_symlink() or log.stat().st_size > 32 * 1024**2:
        raise ValueError("Invalid final consumer build log")
    data = log.read_text(encoding="utf-8", errors="replace")
    missing = set()
    for pattern in (
        r"undefined symbol:\s*([^\r\n]+)",
        r"undefined reference to [`']([^`'\r\n]+)[`']",
    ):
        for match in re.finditer(pattern, data):
            name = match.group(1).strip()
            if not name or len(name) > 1024 or len(missing) >= 4096:
                raise ValueError("Invalid undefined-symbol diagnostic")
            missing.add(name)
    result = {
        "consumer_sdk_build_log_sha256": crypto.digest(log),
        "consumer_sdk_build_log_bytes": log.stat().st_size,
        "consumer_sdk_build_undefined_symbol_count": len(missing),
    }
    if not missing:
        result["consumer_sdk_build_error_kind"] = (
            "duplicate-symbols" if "duplicate symbol:" in data
            else "linker-error" if ("ld.lld: error:" in data or "collect2: error:" in data)
            else "build-error"
        )
        return result
    bindings = object_review.get("bindings") if isinstance(object_review, dict) else None
    if not isinstance(bindings, dict) or not bindings or len(bindings) > 256:
        raise ValueError("Invalid OBJECT binding receipt")
    nm = shutil.which("nm") or shutil.which("llvm-nm")
    if not nm:
        raise ValueError("Symbol inspector unavailable")
    prefix = (installed / TRIPLET).resolve()
    providers, matched = set(), set()
    for target, paths in sorted(bindings.items()):
        if (not isinstance(target, str) or re.fullmatch(r"[A-Za-z0-9_+.-]+", target) is None
                or not isinstance(paths, list) or not paths or len(paths) > 256):
            raise ValueError("Invalid OBJECT binding")
        names = set()
        for relative in paths:
            if not isinstance(relative, str) or len(relative) > 4096:
                raise ValueError("Invalid OBJECT path")
            path = (prefix / relative).resolve()
            if not path.is_relative_to(prefix) or not path.is_file() or path.is_symlink():
                raise ValueError("Missing relocated OBJECT")
            for demangle in (False, True):
                command = [nm, "-g", "--defined-only"]
                if demangle:
                    command.append("-C")
                command.append(str(path))
                inspected = subprocess.run(command, capture_output=True, text=True, timeout=30)
                if inspected.returncode or len(inspected.stdout) > 8 * 1024**2:
                    raise ValueError("Symbol inspection failed")
                for line in inspected.stdout.splitlines():
                    item = re.match(r"^\s*(?:[0-9A-Fa-f]+\s+)?[A-Za-z]\s+(.+?)\s*$", line)
                    if item:
                        names.add(item.group(1))
        hits = missing.intersection(names)
        if hits:
            providers.add(target)
            matched.update(hits)
    result.update({
        "consumer_sdk_build_error_kind": "undefined-symbols",
        "consumer_sdk_build_object_provider_targets": sorted(providers),
        "consumer_sdk_build_object_provider_count": len(providers),
        "consumer_sdk_build_object_provider_symbol_count": len(matched),
        "consumer_sdk_build_unmatched_undefined_symbol_count": len(missing - matched),
    })
    return result


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
    sdk_registry = materialize_sdk_registry(registry)
    expected_heads = {
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
    cef_sdk_objects.validate_sources(registry)
    example_review = cef_sdk_example.capture(lfc_ui, registry)
    cef_sdk_protoc.validate_sources(upstream)
    cef_sdk_xz.validate_sources(upstream)
    cef_sdk_source_interfaces.validate_sources(upstream)
    cef_boringssl_isolation.validate_sources(upstream)

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
        "sdk_vcpkg_checkout_commit": sdk_registry["checkout_commit"],
        "sdk_vcpkg_tree": sdk_registry["tree"],
        "sdk_vcpkg_materialization": sdk_registry["mode"],
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
        stage = "consumer-linker"
        consumer_linker = cef_consumer_linker.verify(root)
        summary["consumer_linker_kind"] = consumer_linker["kind"]
        summary["consumer_linker_version"] = consumer_linker["version"]
        summary["consumer_linker_sha256"] = consumer_linker["sha256"]
        summary["consumer_linker_static_gcc_runtime"] = (
            consumer_linker["static_gcc_runtime"]
        )
        summary["consumer_linker_os_needed_count"] = len(
            consumer_linker["needed"]
        )
        stage = "dependency-source-prefetch"
        cef_dependency_source.prefetch(
            registry, upstream, root, clean_environment(), summary
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
        summary["restored_engine_runtime_verified"] = True

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
        summary["restored_platform_requalified"] = True
        shutil.rmtree(requalified)
        requalified_manifest.unlink()

        stage = "qualified-acquisition-port"
        port_profile = cef_combined_port.materialize(
            registry / "ports/cef-static", recipe, source,
            engine_work / "platform-inputs.json", engine_work / "target-prefix",
            platform_sha,
        )
        summary["qualified_port_abi_tracked"] = port_profile["abi_tracked"]
        summary["qualified_port_patch_sha256"] = port_profile["patch_sha256"]
        summary["qualified_port_bindings_sha256"] = port_profile["binding_sha256"]
        summary["qualified_port_isolated_archive_count"] = port_profile["isolated_archives"]

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
        stage = "frozen-dependency-ownership"
        replay_triplets = cef_frozen_dependencies.materialize(
            root / "qualified-triplets", workspace / "triplets" / (TRIPLET + ".cmake"),
            engine_work / "platform-inputs.json", engine_work / "target-prefix",
            platform_sha, upstream / "packages", upstream / "scripts/ports.cmake",
        )
        summary["frozen_dependency_replay_abi_tracked"] = True
        stage = "vcpkg-install"
        install_args = build_support.native_release_options([
            "--triplet=" + TRIPLET,
            "--host-triplet=" + TRIPLET,
            "--overlay-ports=" + str(registry / "ports"),
            "--overlay-triplets=" + str(replay_triplets),
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

        stage = "installed-frozen-dependencies"
        summary.update(cef_frozen_dependencies.verify_installed(
            installed / TRIPLET, engine_work / "platform-inputs.json", platform_sha
        ))
        stage = "installed-freerdp-profile"
        summary.update(cef_freerdp_profile.verify(installed / TRIPLET))

        stage = "installed-isolation-proof"
        cef_combined_port.verify_packaged_isolation(
            installed / TRIPLET, platform_sha, port_profile["binding_sha256"]
        )
        summary["installed_isolation_bytes_verified"] = True

        stage = "installed-cef-boringssl-isolation"
        boringssl_receipt = cef_boringssl_isolation.install(
            installed, source, root / "cef-boringssl-isolation"
        )
        boringssl_proof = cef_boringssl_isolation.verify(
            installed, source, boringssl_receipt
        )
        if (boringssl_proof.get("cef_boringssl_isolation_verified") is not True
                or boringssl_proof.get("cef_cxx_runtime_isolation_verified") is not True
                or boringssl_proof.get("cef_ffmpeg_isolation_verified") is not True
                or boringssl_proof.get("cef_atomic_isolation_verified") is not True):
            raise RuntimeError("Installed CEF runtime isolation proof is incomplete")
        summary.update({
            "installed_cef_boringssl_isolation_verified": True,
            "installed_cef_cxx_runtime_isolation_verified": True,
            "installed_cef_ffmpeg_isolation_verified": True,
            "installed_cef_atomic_isolation_verified": True,
            "cef_boringssl_collision_count":
                boringssl_proof["cef_boringssl_collision_count"],
            "cef_boringssl_affected_archive_count":
                boringssl_proof["cef_boringssl_affected_archive_count"],
            "cef_boringssl_mapping_sha256":
                boringssl_proof["cef_boringssl_mapping_sha256"],
            "cef_cxx_runtime_collision_count":
                boringssl_proof["cef_cxx_runtime_collision_count"],
            "cef_cxx_runtime_affected_archive_count":
                boringssl_proof["cef_cxx_runtime_affected_archive_count"],
            "cef_cxx_runtime_mapping_sha256":
                boringssl_proof["cef_cxx_runtime_mapping_sha256"],
            "cef_ffmpeg_collision_count":
                boringssl_proof["cef_ffmpeg_collision_count"],
            "cef_ffmpeg_affected_archive_count":
                boringssl_proof["cef_ffmpeg_affected_archive_count"],
            "cef_ffmpeg_mapping_sha256":
                boringssl_proof["cef_ffmpeg_mapping_sha256"],
            "cef_atomic_collision_count":
                boringssl_proof["cef_atomic_collision_count"],
            "cef_atomic_affected_archive_count":
                boringssl_proof["cef_atomic_affected_archive_count"],
            "cef_atomic_mapping_sha256":
                boringssl_proof["cef_atomic_mapping_sha256"],
            "cef_runtime_mapping_sha256":
                boringssl_proof["cef_runtime_mapping_sha256"],
        })

        stage = "installed-object-review"
        object_review = cef_sdk_objects.capture(installed)
        summary["installed_object_count"] = len(object_review["objects"])
        summary["installed_object_targets"] = len(object_review["bindings"])
        stage = "installed-protoc-review"
        protoc_review = cef_sdk_protoc.capture(installed, upstream, root / "protoc-install-proof")
        summary["installed_protoc_verified"] = True
        summary["installed_protoc_sha256"] = protoc_review["record"]["sha256"]
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
        stage = "sdk-cef-boringssl-isolation"
        if cef_boringssl_isolation.verify(
                sdk / "installed", source, boringssl_receipt) != boringssl_proof:
            raise RuntimeError("CEF BoringSSL isolation changed during raw export")
        summary["sdk_cef_boringssl_isolation_verified"] = True
        sdk_zip = root / "sdk.zip"
        stage = "sdk-example-review"
        reviewed_sources = cef_sdk_example.verify(sdk, example_review)
        summary["sdk_example_source_verified"] = True
        summary["sdk_example_source_count"] = len(reviewed_sources)
        stage = "sdk-include-review"
        reviewed_headers = cef_sdk_headers.verify(
            sdk, engine_work / "platform-inputs.json", platform_sha
        )
        summary["sdk_include_source_verified"] = True
        summary["sdk_include_source_count"] = len(reviewed_headers)
        stage = "sdk-alias-review"
        reviewed_aliases = cef_sdk_aliases.verify(
            sdk, engine_work / "platform-inputs.json", platform_sha,
            diagnostics=root / "sdk-link-inventory.json", protoc_review=protoc_review,
        )
        summary["sdk_aliases_verified"] = True
        summary["sdk_alias_count"] = len(reviewed_aliases)
        stage = "sdk-documentation-review"
        reviewed_docs = cef_sdk_xz.verify(sdk)
        summary["sdk_xz_documentation_verified"] = True
        summary["sdk_xz_source_count"] = len(reviewed_docs)
        stage = "sdk-source-interface-review"
        reviewed_interfaces = cef_sdk_source_interfaces.verify(sdk)
        summary["sdk_source_interfaces_verified"] = True
        summary["sdk_source_interface_count"] = len(reviewed_interfaces)
        stage = "sdk-source-inventory"
        summary["sdk_source_inventory_count"] = cef_sdk_xz.inventory_sources(
            sdk, examples=reviewed_sources, headers=reviewed_headers, docs=reviewed_docs,
            aliases=reviewed_aliases, diagnostics=root / "sdk-source-inventory.json",
            interfaces=reviewed_interfaces,
        )
        stage = "sdk-object-review"
        reviewed_objects = cef_sdk_objects.verify(sdk / "installed", object_review)
        summary["sdk_objects_verified"] = True
        stage = "sdk-packaging"
        safeio.sdk_zip(sdk, sdk_zip, reviewed_sources=reviewed_sources,
                       reviewed_include_sources=reviewed_headers,
                       reviewed_aliases=reviewed_aliases, reviewed_doc_sources=reviewed_docs,
                       reviewed_interface_sources=reviewed_interfaces, reviewed_objects=reviewed_objects)
        consumer_sdk = root / "consumer-sdk"
        stage = "sdk-relocation"
        safeio.extract_zip(sdk_zip, consumer_sdk)
        cef_sdk_objects.verify(consumer_sdk / "installed", object_review)
        summary["relocated_sdk_objects_verified"] = True
        stage = "relocated-cef-boringssl-isolation"
        if cef_boringssl_isolation.verify(
                consumer_sdk / "installed", source, boringssl_receipt) != boringssl_proof:
            raise RuntimeError("CEF BoringSSL isolation changed during relocation")
        summary["relocated_cef_boringssl_isolation_verified"] = True
        cef_sdk_example.verify(consumer_sdk, example_review)
        summary["relocated_sdk_example_source_verified"] = True
        cef_sdk_headers.verify(consumer_sdk, engine_work / "platform-inputs.json", platform_sha)
        summary["relocated_sdk_include_source_verified"] = True
        cef_sdk_source_interfaces.verify(consumer_sdk)
        summary["relocated_sdk_source_interfaces_verified"] = True
        cef_sdk_xz.verify(consumer_sdk)
        summary["relocated_sdk_xz_documentation_verified"] = True
        cef_sdk_aliases.verify(consumer_sdk, engine_work / "platform-inputs.json", platform_sha,
                               expected=reviewed_aliases, protoc_review=protoc_review)
        summary["relocated_sdk_aliases_verified"] = True
        verify_relocated_metadata(
            consumer_sdk,
            [installed, sdk, upstream / "buildtrees", upstream / "packages"],
        )
        shutil.rmtree(installed)
        shutil.rmtree(export_root)
        if installed.exists() or export_root.exists():
            raise RuntimeError("Producer SDK roots survived relocation boundary")
        summary["producer_sdk_roots_removed"] = True
        stage = "relocated-protoc-proof"
        cef_sdk_protoc.verify(consumer_sdk / "installed", protoc_review, root / "protoc-relocated-proof")
        summary["relocated_protoc_verified"] = True
        summary["relocated_metadata_verified"] = True

        expected_contract = cef_contract.port_contract(cfg, "linux", platform_sha)
        contract_path = (
            consumer_sdk / "installed" / TRIPLET
            / "share/cef-static/build-contract.json"
        )
        if (not contract_path.is_file()
                or crypto.parse(contract_path.read_bytes()) != expected_contract):
            raise RuntimeError("Final SDK CEF build contract differs from the signed plan")

        stage = "relocated-frozen-dependencies"
        cef_frozen_dependencies.verify_installed(
            consumer_sdk / "installed" / TRIPLET,
            engine_work / "platform-inputs.json", platform_sha,
        )
        summary["relocated_frozen_dependencies_verified"] = True
        stage = "relocated-isolation-proof"
        summary["relocated_isolated_archive_count"] = cef_combined_port.verify_packaged_isolation(
            consumer_sdk / "installed" / TRIPLET,
            platform_sha,
            port_profile["binding_sha256"],
            final_archive_sha256=boringssl_receipt["cef_archives"],
        )
        summary["relocated_isolation_bytes_verified"] = True
        cef_freerdp_profile.verify(consumer_sdk / "installed" / TRIPLET)
        summary["relocated_freerdp_profile_verified"] = True

        cef_sdk_objects.verify(consumer_sdk / "installed", object_review)
        stage = "combined-consumer"
        smoke_build = root / "smoke-build"
        consumer_source = cef_combined_smoke.prepare(
            registry / plan["smoke_path"], recipe / "vcpkg/ports/cef-static/smoke.c",
            root / "combined-consumer-source",
        )
        summary["combined_consumer_source_verified"] = True
        summary["combined_consumer_project_sha256"] = crypto.digest(consumer_source / "CMakeLists.txt")
        configure = build_support.consumer_configure_command(
            consumer_source, smoke_build, consumer_sdk, TRIPLET
        )
        configure.append(
            "-DCEF_STATIC_SMOKE_SOURCE=" + str(consumer_source / "smoke.c")
        )
        configure.append(cef_consumer_linker.cmake_flag())
        run(
            configure, cwd=root, env=build_env,
            log=root / "consumer-configure.log", timeout=900,
        )
        # The two final consumers both carry a large static closure. Building
        # the default target with --parallel 2 may overlap their link steps and
        # makes a one-hour timeout ambiguous. Keep both consumers mandatory,
        # but build them one at a time with independent evidence and budgets.
        stage = "combined-consumer-sdk-build"
        consumer_sdk_log = root / "consumer-sdk-build.log"
        try:
            run(
                ["cmake", "--build", smoke_build, "--config", "Release",
                 "--target", "sdk_smoke", "--parallel", "1", "--verbose"],
                cwd=root, env=build_env,
                log=consumer_sdk_log, timeout=3600,
            )
        except BaseException:
            try:
                summary.update(summarize_consumer_sdk_build_failure(
                    consumer_sdk_log, consumer_sdk / "installed", object_review
                ))
            except (OSError, ValueError, TypeError, subprocess.SubprocessError):
                summary["consumer_sdk_build_diagnostic_invalid"] = True
            raise
        summary["combined_sdk_smoke_built"] = True
        stage = "combined-consumer-cef-build"
        run(
            ["cmake", "--build", smoke_build, "--config", "Release",
             "--target", "cef_static_combined_smoke", "--parallel", "1", "--verbose"],
            cwd=root, env=build_env,
            log=root / "consumer-cef-build.log", timeout=3600,
        )
        summary["combined_cef_smoke_built"] = True
        relocated_smokes = [
            path for path in smoke_build.rglob("cef_static_combined_smoke")
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
        proxy_configure.append(cef_consumer_linker.cmake_flag())
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
        # The no-args CLI check must not depend on Xvfb.  The canonical proxy
        # validates argc before CefExecuteProcess, so this probe exercises only
        # the deterministic browser-process usage path.  The real config-driven
        # runtime/listener proof below remains supervised by xvfb-run.
        usage = subprocess.run(
            [str(proxy_exe)],
            cwd=proxy_exe.parent, env=build_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=120,
        )
        (root / "lfc-ui-freerdp-cef-usage.log").write_text(
            usage.stdout, encoding="utf-8"
        )
        summary["lfc_ui_freerdp_cef_usage_returncode"] = usage.returncode
        summary["lfc_ui_freerdp_cef_usage_marker_verified"] = "Usage:" in usage.stdout
        usage_failed = (
            usage.returncode != 2
            or not summary["lfc_ui_freerdp_cef_usage_marker_verified"]
        )
        summary["lfc_ui_freerdp_cef_usage_sanity_verified"] = not usage_failed
        # Keep the usage sanity fail-closed, but defer the failure until after
        # the real config-driven runtime/listener and hidden-root consumer proof.
        # This distinguishes an auxiliary no-args crash from a production-path
        # runtime regression without allowing a failed usage sanity to qualify.
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
                        failure = classify_proxy_runtime_failure(lifecycle_log, code)
                        summary.update(failure)
                        if failure.get("lfc_ui_freerdp_cef_runtime_failure_class") in {
                            "signal-before-log", "signal-unclassified",
                            "early-exit-unclassified",
                        }:
                            summary.update(capture_proxy_startup_backtrace(
                                proxy_exe, proxy_exe.parent, build_env,
                                root / "lfc-ui-freerdp-cef-gdb.log",
                            ))
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
            platform_preflight=platform_preflight, recipe_root=recipe,
        )
        cef_build.validate_platform_preflight(preflight, proof, cfg, "linux")
        final_key, final_contract = cef_build.qualified_contract(
            proof, cfg, "linux"
        )
        if final_key != build_key or final_contract != expected_contract:
            raise RuntimeError("Final strict Linux contract identity changed")
        summary["hidden_root_consumer_verified"] = True

        if usage_failed:
            stage = "lfc-ui-freerdp-cef-usage-sanity"
            raise RuntimeError(
                "Final FreeRDP/CEF executable did not reach its usage path"
            )

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
