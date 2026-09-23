"""One strict Linux CEF qualification iteration on a trusted builder runner.

Private vcpkg output and compiler logs stay on the runner. The only resumable
artifact is encrypted with the builder input recipient. A completed slice is
additionally subjected to the pinned CEF browser/renderer runtime verification.
"""
from __future__ import annotations
import hashlib
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

from . import cef_cache, cef_contract, cef_nss_isolation, crypto, safeio
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

# GitHub's hosted-image version is intentionally not a semantic build input.
# Keep a historical checkpoint identity stable only after the actual host
# proves a reviewed ABI/toolchain fingerprint. New checkpoints record that
# fingerprint so later image rolls can be accepted by content, not image label.
LEGACY_CHECKPOINT_IMAGE_BY_RUN = {
    35779924527: "20260907.300.1",
}
REVIEWED_LEGACY_IMAGE_MIGRATIONS = {
    ("20260907.300.1", "20260920.314.1"): {
        "schema": 1,
        "os_id": "ubuntu",
        "os_version_id": "24.04",
        "machine": "x86_64",
        "glibc": "2.39",
        "gcc14": "14.2.0",
        "gxx14": "14.2.0",
        "binutils": "2.42",
        "pkg_config": "1.8.1",
        "bison": "3.8.2",
        "ninja": "1.11.1",
        "ccache": "4.9.1",
    },
}


def _tool_version(command: list[str], pattern: str) -> str:
    output = subprocess.check_output(
        command, text=True, stderr=subprocess.STDOUT, timeout=30
    ).splitlines()
    if not output:
        raise ValueError("Critical host tool returned no version")
    match = re.search(pattern, output[0])
    if not match:
        raise ValueError("Critical host tool version is unrecognized")
    return match.group(1)


def critical_host_fingerprint() -> dict:
    release = {}
    for raw in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        release[key] = value.strip().strip('"')
    return {
        "schema": 1,
        "os_id": release.get("ID"),
        "os_version_id": release.get("VERSION_ID"),
        "machine": os.uname().machine.lower(),
        "glibc": _tool_version(["ldd", "--version"], r"([0-9]+\.[0-9]+)$"),
        "gcc14": _tool_version(["gcc-14", "-dumpfullversion"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
        "gxx14": _tool_version(["g++-14", "-dumpfullversion"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
        "binutils": _tool_version(["ld", "--version"], r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)$"),
        "pkg_config": _tool_version(["pkg-config", "--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
        "bison": _tool_version(["bison", "--version"], r"([0-9]+\.[0-9]+\.[0-9]+)$"),
        "ninja": _tool_version(["ninja", "--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
        "ccache": _tool_version(["ccache", "--version"], r"([0-9]+\.[0-9]+\.[0-9]+)$"),
    }


def checkpoint_image_identity(selected: dict | None, producer_summary: dict | None,
                              summary: dict) -> str:
    actual = os.environ.get("ImageVersion")
    if not actual:
        raise ValueError("ImageVersion is required for strict CEF qualification")
    current_fingerprint = critical_host_fingerprint()
    if selected is None:
        checkpoint_image = actual
    else:
        checkpoint_image = (
            producer_summary.get("checkpoint_image_identity")
            if isinstance(producer_summary, dict) else None
        )
        producer_fingerprint = (
            producer_summary.get("critical_host_fingerprint")
            if isinstance(producer_summary, dict) else None
        )
        if checkpoint_image is None:
            checkpoint_image = LEGACY_CHECKPOINT_IMAGE_BY_RUN.get(selected["run"])
        if not isinstance(checkpoint_image, str) or not re.fullmatch(r"[0-9.]+", checkpoint_image):
            raise ValueError("Checkpoint producer image identity is unavailable")
        if actual != checkpoint_image:
            if producer_fingerprint is not None:
                if producer_fingerprint != current_fingerprint:
                    raise ValueError("Critical host fingerprint changed; refusing checkpoint reuse")
            else:
                reviewed = REVIEWED_LEGACY_IMAGE_MIGRATIONS.get((checkpoint_image, actual))
                if reviewed != current_fingerprint:
                    raise ValueError("Runner image migration is not reviewed for this host fingerprint")
    summary["runner_image_actual"] = actual
    summary["checkpoint_image_identity"] = checkpoint_image
    summary["critical_host_fingerprint"] = current_fingerprint
    summary["runner_image_migrated"] = actual != checkpoint_image
    return checkpoint_image


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
    elif re.search(r"(?:mold|ld(?:\.lld)?): error: duplicate symbol:", text, re.I):
        category = "linker-duplicate-symbol"
    elif re.search(r"(?:^|\n)[^\n]*\berror:", text, re.I):
        category = "compiler-error"
    else:
        category = "unknown"
    sysroot_flags = re.findall(r"(?:^|\s)--sysroot=([^\s\"']+)", text)
    result = {
        "compile_failure_category": category,
        "compile_failure_timed_out": status.get("timed_out") is True,
        "compile_failure_unsafe_stop": status.get("unsafe_stop") is True,
        "compile_failure_failed_output_count": len(failed),
        "compile_failure_failed_outputs": [Path(name).name for name in failed[-4:]],
        "compile_failure_uses_sysroot": bool(sysroot_flags),
    }
    if sysroot_flags:
        sysroot_name = Path(sysroot_flags[-1].replace("\\", "/")).name
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
    if category == "linker-duplicate-symbol":
        symbols = sorted(set(re.findall(
            r"duplicate symbol:[^\r\n]*?:\s*([A-Za-z_][A-Za-z0-9_]{0,127})\s*$",
            text, re.I | re.M,
        )))
        if symbols:
            result["compile_failure_duplicate_symbols"] = symbols[:32]
        target = re.search(r"^FAILED:\s+([A-Za-z0-9_./+-]+)\s*$", text, re.M)
        if target:
            result["compile_failure_link_target"] = Path(target.group(1)).name
    return result


LEGACY_STATIC_LINUX_UI_MARKER = "# CEF_STATIC_NO_RUNTIME_GTK_V1"
STATIC_GTK_BUILD_MARKER = "# CEF_STATIC_DIRECT_GTK3_V1"
STATIC_GTK_COMPAT_MARKER = "// CEF_STATIC_DIRECT_GTK3_V1"
STATIC_GTK_SIG_DIR = "cef-static-sigs"
STATIC_GTK_DLSYM_SYMBOLS = (
    "gtk_init_check",
    "gtk_style_context_get_padding",
    "gtk_style_context_get_border",
    "gtk_style_context_get_margin",
    "gtk_style_context_get_color",
    "gtk_style_context_get_background_color",
    "gtk_style_context_lookup_color",
    "gtk_im_context_filter_keypress",
    "gtk_file_chooser_set_current_folder",
    "gtk_render_icon",
    "gtk_window_new",
    "gtk_css_provider_load_from_data",
    "gtk_file_chooser_get_files",
    "gtk_icon_theme_lookup_by_gicon_for_scale",
    "gtk_icon_theme_lookup_icon",
    "gtk_icon_theme_lookup_by_gicon",
    "gtk_file_chooser_dialog_new",
    "gtk_tree_store_new",
    "gdk_event_get_event_type",
    "gdk_event_get_time",
)


def _filter_static_gtk_signatures(text: str, provided: set[str]) -> tuple[str, list[str]]:
    missing = []
    names = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", stripped)
        if not match:
            raise ValueError("Unrecognized Chromium GTK signature line")
        name = match.group(1)
        names.append(name)
        if name not in provided:
            missing.append(raw)
    if len(names) != len(set(names)):
        raise ValueError("Duplicate Chromium GTK signature")
    return ("\n".join(missing) + ("\n" if missing else "")), names


def _frozen_static_gtk_symbols(
        manifest: Path, prefix: Path, platform_sha: str) -> tuple[set[str], dict]:
    if (not manifest.is_file() or manifest.is_symlink()
            or hashlib.sha256(manifest.read_bytes()).hexdigest() != platform_sha):
        raise ValueError("Frozen GTK manifest does not match the platform lock")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    modules = value.get("modules") if isinstance(value, dict) else None
    entry = modules.get("gtk+-3.0") if isinstance(modules, dict) else None
    files = value.get("files") if isinstance(value, dict) else None
    archives = value.get("archive_objects") if isinstance(value, dict) else None
    if (not isinstance(entry, dict) or not isinstance(files, dict)
            or not isinstance(archives, dict)):
        raise ValueError("Frozen platform contract lacks static GTK3")
    libraries = entry.get("libraries")
    link_options = entry.get("link_options")
    if not isinstance(libraries, list) or not isinstance(link_options, list):
        raise ValueError("Frozen GTK3 module contract is malformed")
    if "-Wl,--export-dynamic" not in link_options:
        raise ValueError("Static GTK compatibility dlsym requires exported process symbols")

    required = {
        "lib/libgtk-3.a", "lib/libgdk-3.a", "lib/libgdk_pixbuf-2.0.a",
        "lib/libgio-2.0.a", "lib/libgobject-2.0.a", "lib/libglib-2.0.a",
    }
    selected = []
    for relative in libraries:
        if not isinstance(relative, str) or not relative.startswith("lib/"):
            continue
        if not relative.endswith(".a"):
            continue
        if relative not in files or type(archives.get(relative)) is not int:
            raise ValueError("GTK3 links an archive outside the frozen platform contract")
        path = prefix / relative
        if (not path.is_file() or path.is_symlink()
                or not path.resolve().is_relative_to(prefix.resolve())):
            raise ValueError("Frozen GTK3 archive is missing or redirected")
        selected.append((relative, path))
    present = {name for name, _ in selected}
    if not required.issubset(present):
        raise ValueError("Frozen GTK3 closure is missing required static archives")

    nm = shutil.which("nm")
    if not nm:
        raise ValueError("nm is required to bind the static GTK3 ABI")
    symbols: set[str] = set()
    for _, path in selected:
        result = subprocess.run(
            [nm, "-g", "--defined-only", path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120,
        )
        if result.returncode:
            raise RuntimeError("Failed to inspect a frozen GTK3 archive")
        for raw in result.stdout.splitlines():
            match = re.search(r"([A-Za-z_][A-Za-z0-9_$.@]*)$", raw.strip())
            if match:
                symbols.add(match.group(1))
    essentials = {
        "gtk_settings_get_default", "gtk_get_major_version",
        "gdk_display_get_default", "gdk_pixbuf_new", "g_list_model_get_item",
    }
    if not essentials.issubset(symbols):
        raise ValueError("Frozen GTK3 closure does not export the required desktop ABI")
    return symbols, entry


def ensure_static_linux_gtk(
        source: Path, manifest: Path, prefix: Path,
        platform_sha: str, summary: dict) -> None:
    """Preserve GtkUi while binding it to the frozen static GTK3/GLib closure."""
    if git_head(source) != CHROMIUM:
        raise ValueError("Pinned Chromium source revision mismatch before GTK repair")
    manifest = manifest.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    symbols, gtk_entry = _frozen_static_gtk_symbols(manifest, prefix, platform_sha)

    gtk_root = source / "ui/gtk"
    build = gtk_root / "BUILD.gn"
    compat = gtk_root / "gtk_compat.cc"
    gni = source / "build/config/linux/gtk/gtk.gni"
    for path in (build, compat, gni):
        if not path.is_file() or path.is_symlink():
            raise ValueError("Pinned Chromium GTK source is missing or redirected")

    # Migrate the diagnostic no-GTK checkpoint back to Chromium's normal GtkUi.
    original_use_gtk = "  use_gtk = is_linux && !is_castos\n"
    legacy_use_gtk = (
        "  " + LEGACY_STATIC_LINUX_UI_MARKER + "\n"
        "  use_gtk = false\n"
    )
    gni_text = gni.read_text(encoding="utf-8")
    migrated_fallback = False
    if legacy_use_gtk in gni_text:
        if gni_text.count(LEGACY_STATIC_LINUX_UI_MARKER) != 1:
            raise ValueError("Legacy fallback GTK marker is malformed")
        gni_text = gni_text.replace(legacy_use_gtk, original_use_gtk, 1)
        gni.write_text(gni_text, encoding="utf-8", newline="\n")
        migrated_fallback = True
    elif gni_text.count(original_use_gtk) != 1:
        raise ValueError("Pinned Chromium GTK default differs from reviewed source")

    # Keep direct definitions for every ABI symbol that GTK3 actually exports.
    # Generate normal Chromium stubs only for GTK4-only symbols.
    sig_dir = gtk_root / STATIC_GTK_SIG_DIR
    expected_sigs: dict[str, str] = {}
    counts = {}
    for name in ("gtk", "gdk", "gsk", "gdk_pixbuf", "gio"):
        path = gtk_root / (name + ".sigs")
        if not path.is_file() or path.is_symlink():
            raise ValueError("Pinned Chromium GTK signature inventory is incomplete")
        filtered, all_names = _filter_static_gtk_signatures(
            path.read_text(encoding="utf-8"), symbols
        )
        missing_count = len([
            item for item in filtered.splitlines() if item.strip()
        ])
        counts[name] = {"total": len(all_names), "stubbed": missing_count}
        if name in ("gdk_pixbuf", "gio"):
            if filtered:
                raise ValueError("Frozen GTK3 closure lacks a required GLib/GdkPixbuf ABI symbol")
        else:
            if not filtered:
                raise ValueError("Static GTK compatibility inventory unexpectedly has no missing ABI")
            expected_sigs[name + ".sigs"] = filtered
    if sig_dir.exists():
        if sig_dir.is_symlink() or not sig_dir.is_dir():
            raise ValueError("Static GTK signature directory is redirected")
        actual = sorted(p.name for p in sig_dir.iterdir() if p.is_file())
        if actual != sorted(expected_sigs):
            raise ValueError("Static GTK signature inventory changed")
        for name, content in expected_sigs.items():
            path = sig_dir / name
            if path.is_symlink() or path.read_text(encoding="utf-8") != content:
                raise ValueError("Static GTK signature bytes changed")
    else:
        sig_dir.mkdir()
        for name, content in expected_sigs.items():
            (sig_dir / name).write_text(content, encoding="utf-8", newline="\n")

    forced = sorted(set(STATIC_GTK_DLSYM_SYMBOLS) & symbols)
    required_forced = {
        "gtk_init_check", "gtk_style_context_get_padding",
        "gtk_style_context_get_border", "gtk_style_context_get_color",
        "gtk_window_new", "gtk_css_provider_load_from_data",
    }
    if not required_forced.issubset(forced):
        raise ValueError("Frozen GTK3 closure lacks compatibility symbols required by Chromium")
    force_flags = "".join(
        f'      "-Wl,-u,{name}",\n' for name in forced
    )

    build_text = build.read_text(encoding="utf-8")
    ignore_original = (
        "  # We dlopen() GTK, so make sure not to add a link-time dependency on it.\n"
        "  ignore_libs = true\n"
    )
    ignore_patched = (
        "  # " + STATIC_GTK_BUILD_MARKER.lstrip("# ") + "\n"
        "  # Dynamic Chromium keeps dlopen GTK; strict CEF links the frozen GTK3 archives.\n"
        '  ignore_libs = cef_static_platform_manifest == ""\n'
    )
    sig_original = '''  sigs = [
    "gdk_pixbuf.sigs",
    "gdk.sigs",
    "gsk.sigs",
    "gtk.sigs",
    "gio.sigs",
  ]
'''
    sig_patched = '''  if (cef_static_platform_manifest != "") {
    sigs = [
      "cef-static-sigs/gdk.sigs",
      "cef-static-sigs/gsk.sigs",
      "cef-static-sigs/gtk.sigs",
    ]
  } else {
    sigs = [
      "gdk_pixbuf.sigs",
      "gdk.sigs",
      "gsk.sigs",
      "gtk.sigs",
      "gio.sigs",
    ]
  }
'''
    group_original = '''group("gtk_config") {
  public_configs = [ ":gtk_internal_config" ]
}
'''
    group_patched = '''config("cef_static_gtk_link") {
  if (cef_static_platform_manifest != "") {
    ldflags = [
''' + force_flags + '''    ]
  }
}

group("gtk_config") {
  public_configs = [ ":gtk_internal_config" ]
  if (cef_static_platform_manifest != "") {
    public_configs += [ ":cef_static_gtk_link" ]
  }
}
'''
    define_original = '  defines = [ "IS_GTK_IMPL" ]\n'
    define_patched = (
        '  defines = [ "IS_GTK_IMPL" ]\n'
        '  if (cef_static_platform_manifest != "") {\n'
        '    defines += [ "CEF_STATIC_GTK3=1" ]\n'
        '  }\n'
    )
    if STATIC_GTK_BUILD_MARKER in build_text:
        if (build_text.count(STATIC_GTK_BUILD_MARKER) != 1
                or ignore_patched not in build_text
                or sig_patched not in build_text
                or group_patched not in build_text
                or define_patched not in build_text):
            raise ValueError("Existing static GTK3 GN repair differs from the frozen ABI")
    else:
        for anchor in (ignore_original, sig_original, group_original, define_original):
            if build_text.count(anchor) != 1:
                raise ValueError("Pinned Chromium GTK GN anchors differ from reviewed source")
        build_text = build_text.replace(ignore_original, ignore_patched, 1)
        build_text = build_text.replace(sig_original, sig_patched, 1)
        build_text = build_text.replace(group_original, group_patched, 1)
        build_text = build_text.replace(define_original, define_patched, 1)
        build.write_text(build_text, encoding="utf-8", newline="\n")

    compat_text = compat.read_text(encoding="utf-8")
    include_original = '#include "ui/gtk/gtk_stubs.h"\n'
    include_patched = (
        STATIC_GTK_COMPAT_MARKER + "\n"
        "#if !defined(CEF_STATIC_GTK3)\n"
        '#include "ui/gtk/gtk_stubs.h"\n'
        "#endif\n"
    )
    dlopen_original = '''void* DlOpen(const char* library_name, bool check = true) {
  void* library = dlopen(library_name, RTLD_LAZY | RTLD_GLOBAL);
  CHECK(!check || library);
  return library;
}
'''
    dlopen_patched = '''void* DlOpen(const char* library_name, bool check = true) {
#if defined(CEF_STATIC_GTK3)
  (void)library_name;
  (void)check;
  CHECK(false) << "Static GTK3 profile forbids loading a system GTK module";
  return nullptr;
#else
  void* library = dlopen(library_name, RTLD_LAZY | RTLD_GLOBAL);
  CHECK(!check || library);
  return library;
#endif
}
'''
    get_original = '''void* GetLibGtk() {
  if (GtkCheckVersion(4)) {
    return GetLibGtk4();
  }
  return GetLibGtk3();
}
'''
    get_patched = '''void* GetLibGtk() {
#if defined(CEF_STATIC_GTK3)
  return RTLD_DEFAULT;
#else
  if (GtkCheckVersion(4)) {
    return GetLibGtk4();
  }
  return GetLibGtk3();
#endif
}
'''
    load_original = '''bool LoadGtk(ui::LinuxUiBackend backend) {
  static bool loaded = LoadGtkImpl(backend);
  return loaded;
}
'''
    load_patched = '''bool LoadGtk(ui::LinuxUiBackend backend) {
#if defined(CEF_STATIC_GTK3)
  (void)backend;
  return true;
#else
  static bool loaded = LoadGtkImpl(backend);
  return loaded;
#endif
}
'''
    if STATIC_GTK_COMPAT_MARKER in compat_text:
        if (compat_text.count(STATIC_GTK_COMPAT_MARKER) != 1
                or include_patched not in compat_text
                or dlopen_patched not in compat_text
                or get_patched not in compat_text
                or load_patched not in compat_text):
            raise ValueError("Existing static GTK3 compatibility repair is malformed")
    else:
        for anchor in (include_original, dlopen_original, get_original, load_original):
            if compat_text.count(anchor) != 1:
                raise ValueError("Pinned Chromium GTK compatibility anchors differ from reviewed source")
        compat_text = compat_text.replace(include_original, include_patched, 1)
        compat_text = compat_text.replace(dlopen_original, dlopen_patched, 1)
        compat_text = compat_text.replace(get_original, get_patched, 1)
        compat_text = compat_text.replace(load_original, load_patched, 1)
        compat.write_text(compat_text, encoding="utf-8", newline="\n")

    summary["runtime_gtk_backend"] = "static-gtk3"
    summary["runtime_gtk_backend_preserved"] = True
    summary["runtime_gtk_system_dlopen_disabled"] = True
    summary["runtime_gtk_fallback_migrated"] = migrated_fallback
    summary["runtime_gtk_static_archive_count"] = len([
        item for item in gtk_entry["libraries"]
        if isinstance(item, str) and item.startswith("lib/") and item.endswith(".a")
    ])
    summary["runtime_gtk_forced_symbol_count"] = len(forced)
    summary["runtime_gtk_stub_symbol_count"] = sum(
        value["stubbed"] for value in counts.values()
    )


def _bounded_status(path: Path) -> dict | None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024**2:
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def classify_engine_runtime(logs: Path) -> dict:
    """Expose a bounded runtime/link stage, never private output or arguments."""
    # Static GLib/GObject plus Chromium's RTLD_GLOBAL dlopen(GTK) creates two
    # independent GType registries. Match only stable diagnostics and publish
    # only a category; raw runtime logs remain encrypted/private.
    registry_split = False
    try:
        candidates = [
            path for path in logs.rglob("cef-static.log")
            if (path.is_file() and not path.is_symlink()
                and path.stat().st_size <= 64 * 1024**2)
        ][:8]
    except OSError:
        candidates = []
    for path in candidates:
        text = path.read_text(encoding="utf-8", errors="replace")[-8 * 1024**2:]
        if (
            "GLib-GObject: g_value_get_gtype: assertion 'G_VALUE_HOLDS_GTYPE (value)' failed" in text
            and ("can't peek value table for type 'GdkDisplay'" in text
                 or "invalid param spec type 'GParam" in text)
        ):
            registry_split = True
            break
    if registry_split:
        return {
            "runtime_failure_category": "glib-gobject-registry-split",
            "runtime_failure_timed_out": True,
        }
    for name, category in (
        ("validate-static-platform-status.json", "platform-validation"),
        ("gn-gen-status.json", "gn-generation"),
        ("viz-x11-graph-status.json", "viz-graph"),
        ("viz-x11-graph-check-status.json", "viz-graph-check"),
        ("gn-graph-status.json", "gn-graph"),
        ("audit-static-platform-status.json", "platform-audit"),
        ("native-link-edge-status.json", "link-edge-audit"),
        ("engine-build-status.json", "engine-link"),
        ("binary-imports-status.json", "binary-import-audit"),
        ("runtime-libraries-status.json", "runtime-library-audit"),
    ):
        status = _bounded_status(logs / name)
        if status is None or status.get("status") in (None, "success"):
            continue
        result = {
            "runtime_failure_category": category,
            "runtime_failure_timed_out": status.get("status") == "timed_out",
        }
        code = status.get("exit_code")
        if type(code) is int and -255 <= code <= 255:
            result["runtime_failure_exit_code"] = code
        return result
    smoke = _bounded_status(logs / "static-smoke-status.json")
    if smoke is not None and smoke.get("status") != "success":
        status = smoke.get("status")
        category = {
            "timed_out": "smoke-timeout",
            "spawn_failed": "smoke-spawn",
            "failed": "smoke-exit",
            "interrupted": "smoke-interrupted",
        }.get(status, "smoke-runtime")
        result = {
            "runtime_failure_category": category,
            "runtime_failure_timed_out": status == "timed_out",
        }
        code = smoke.get("exit_code")
        if type(code) is int and -255 <= code <= 255:
            result["runtime_failure_exit_code"] = code
        return result
    smoke_runs = _bounded_status(logs / "smoke-runs.json")
    if smoke_runs is not None and smoke_runs.get("status") == "failed":
        return {"runtime_failure_category": "smoke-proof"}
    if not (logs / "runtime-data.json").is_file():
        return {"runtime_failure_category": "runtime-data"}
    if (logs / "engine-build-receipt.json").is_file():
        return {"runtime_failure_category": "receipt-validation"}
    return {"runtime_failure_category": "unknown"}


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
    progress = value.get("progress")
    resumable_runtime_failure = (
        value.get("status") == "failed"
        and value.get("failure_stage") == "engine-runtime"
        and value.get("failure_type") == "RuntimeError"
        and value.get("slice_state_present") is True
        and value.get("slice_exit_code") == 0
        and value.get("ready") is True
        and value.get("runtime_verified") is False
        and isinstance(progress, dict)
        and progress.get("engine_compilation_complete") is True
    )
    reusable_status = (
        value.get("status") == "success"
        or (allow_resumable and (resumable_compile_failure or resumable_runtime_failure))
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
        producer_summary = None
        if selected is not None:
            token = os.environ.get("GITHUB_TOKEN")
            if not token:
                raise ValueError("GITHUB_TOKEN is required to review checkpoint host compatibility")
            producer_summary = verify_producer_summary(Client(token), selected)
        checkpoint_image = checkpoint_image_identity(selected, producer_summary, summary)
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
            recipe_env_restore["ImageVersion"] = checkpoint_image
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
        recipe_env["ImageVersion"] = checkpoint_image
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

        stage = "nss-boringssl-symbol-isolation"
        cef_nss_isolation.install(
            engine_work / "download/chromium/src",
            engine_work / "platform-inputs.json",
            engine_work / "target-prefix",
            platform_sha,
            summary,
        )

        stage = "linux-static-gtk"
        ensure_static_linux_gtk(
            engine_work / "download/chromium/src",
            engine_work / "platform-inputs.json",
            engine_work / "target-prefix",
            platform_sha,
            summary,
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
        cef_nss_isolation.record_receipt(
            engine_work / "download/chromium/src", summary, required=False
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
        elif summary["failure_stage"] == "engine-runtime":
            summary.update(classify_engine_runtime(engine_logs))
        raise
    finally:
        summary_path.write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
