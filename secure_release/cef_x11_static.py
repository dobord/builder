"""Bind Chromium's Xlib loader to the frozen static X11 closure.

The strict Linux profile already freezes X11/XCB archives in the platform
manifest, but pinned Chromium still generates an Xlib loader with dlopen() and
keeps a bare ``-lxcb`` edge.  That admits host shared libraries at runtime even
though GN's graph audit can map the same names to captured archives.

This repair covers both Xlib loaders and WebRTC desktop capture. It also selects
GTK Cairo rendering before GDK can load host GL/Mesa. Xlib uses the generator's
supported direct-link mode and the target
links the captured ``x11``/``xcb`` pkg-config closure.  The Xlib/XCB bridge is
not loaded in this profile; it is only used by Chromium's Vulkan X11 path while
the static CEF profile keeps Vulkan disabled.  Ordinary Chromium builds are
kept on their original dynamic-loading path.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
MARKER = "CEF_STATIC_X11_DIRECT_V1"
FILES = {'ui/gfx/x/BUILD.gn': 'b8e0c438f1dab1b88fd5c43572d80acbe18ca681e8f60b5ef57563bed25585dc',
 'ui/gfx/x/xlib_support.cc': '0d6d01398fd226f0d263912a133f77eef4506f601648c949f4f7087bcccbf81a',
 'tools/generate_library_loader/generate_library_loader.gni': '784f63ef334097754ce6304ea218db36c2fe17eb5011c5d52501ee865de95dc3',
 'third_party/webrtc/modules/desktop_capture/BUILD.gn': '2051a9069681f25a27eba1e788b4406df205e4979ca3864343aabbacea9393d6',
 'ui/gtk/gtk_ui.cc': '004ab865ad14b5ba7779aa00f6af335d57e55729438399fcfc383f3213ad206b'}
PATCHED = {'ui/gfx/x/BUILD.gn': 'f8599a765c0f0d13d58dd6664d0c4a88d704899c713cb6f30eca9445d542a59d',
 'ui/gfx/x/xlib_support.cc': '83dfd7ef41d6fb0596262dce14294f2318bb00868ff41f37f4d1b57c0611e165',
 'tools/generate_library_loader/generate_library_loader.gni': 'f062ab576e4c2502c9aac84afab2a54f6fd68de9307baa8764036d0948d74c70',
 'third_party/webrtc/modules/desktop_capture/BUILD.gn': '2104e63381732dda404a7c0e0e76c4a42f7344ce626cd2dbdf1f6924bda4870b',
 'ui/gtk/gtk_ui.cc': '1af9fd520dec2d49c06356ed2ca2da141672e96517b096db81d594a2709ecbb2'}
LEGACY_PATCHED = {'ui/gfx/x/BUILD.gn': '52c8654c2363e060c642161e562d1625fd1902e1c3208d3e986017ebc2bde01f',
 'ui/gfx/x/xlib_support.cc': '69a6855cf294257a7db2d869b061ef4e5e8ccc199ece68d5f0f9d6818af4561b',
 'tools/generate_library_loader/generate_library_loader.gni': 'f062ab576e4c2502c9aac84afab2a54f6fd68de9307baa8764036d0948d74c70'}


# Run 74 saved this exact compiler-failed source. Admit only its full digest
# for migration: remove the unreachable return after the fatal CHECK, without
# resetting the checkpoint or admitting an arbitrary partially patched file.
COMPILE_FAILURE_PATCHED = {
    "ui/gfx/x/xlib_support.cc": "3640598ee9f7aada1150092347b86f8be5d6193b47278b523df44f5012663bcc",
}


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _one(text: str, before: str, after: str, label: str) -> str:
    if text.count(before) != 1:
        raise ValueError(f"Pinned X11 {label} anchor changed")
    return text.replace(before, after, 1)


def patch_loader_gni(text: str) -> str:
    before = '''    args = [
      "--name",
      invoker.name,
'''
    after = '''    # CEF_STATIC_X11_DIRECT_V1: preserve the upstream default, but let a
    # reviewed caller request the generator's existing DT_NEEDED/direct mode.
    _link_directly = "--link-directly=0"
    if (defined(invoker.link_directly)) {
      if (invoker.link_directly) {
        _link_directly = "--link-directly=1"
      }
    }

    args = [
      "--name",
      invoker.name,
'''
    text = _one(text, before, after, "loader argument")
    old = '''      # Note GYP build exposes a per-target variable to control this, which, if
      # manually set to true, will disable dlopen(). Its not clear this is
      # needed, so here we just leave off. If this can be done globally, we can
      # expose one switch for this value, otherwise we need to add a template
      # param for this.
      "--link-directly=0",
'''
    new = '''      # The default remains dlopen. Only explicitly reviewed targets can opt
      # into the generator's supported direct-link mode.
      _link_directly,
'''
    return _one(text, old, new, "loader direct-link")


def patch_x_build(text: str) -> str:
    text = _one(
        text,
        'import("//build/config/ui.gni")\n',
        'import("//build/config/ui.gni")\nimport("//build/config/linux/pkg_config.gni")\n',
        "BUILD import",
    )
    xlib = '''  functions = [
    "XInitThreads",
    "XOpenDisplay",
    "XCloseDisplay",
    "XFlush",
    "XSynchronize",
    "XSetErrorHandler",
    "XFree",
    "XPending",
  ]
}
'''
    xlib_static = '''  functions = [
    "XInitThreads",
    "XOpenDisplay",
    "XCloseDisplay",
    "XFlush",
    "XSynchronize",
    "XSetErrorHandler",
    "XFree",
    "XPending",
  ]
  # CEF_STATIC_X11_DIRECT_V1: the strict platform manifest owns the X11 ABI.
  link_directly = cef_static_platform_manifest != ""
}
'''
    text = _one(text, xlib, xlib_static, "Xlib loader")
    tail = '''  configs += [ ":x11_private_config" ]
  libs = [ "xcb" ]
}
'''
    tail_static = '''  configs += [ ":x11_private_config" ]
  if (cef_static_platform_manifest != "") {
    # CEF_STATIC_X11_DIRECT_V1: resolve Xlib/XCB from exact captured archives;
    # never let the linker choose a host .so through a bare -l token.
    configs += [ ":cef_x11_static" ]
    defines = [ "CEF_STATIC_X11_DIRECT=1" ]
  } else {
    libs = [ "xcb" ]
  }
}

if (cef_static_platform_manifest != "") {
  pkg_config("cef_x11_static") {
    packages = [
      "x11",
      "xcb",
    ]
  }
}
'''
    text = _one(text, tail, tail_static, "X11 target libraries")
    text = _one(text, 'import("//build/config/ui.gni")\n',
                'import("//build/config/ui.gni")\nimport("//gpu/vulkan/features.gni")\n', "Vulkan feature")
    return _one(text, '    defines = [ "CEF_STATIC_X11_DIRECT=1" ]\n',
                '    defines = [ "CEF_STATIC_X11_DIRECT=1" ]\n'
                '    assert(!enable_vulkan, "Static X11 bridge requires a reviewed Vulkan profile")\n'
                '    deps -= [ ":xlib_xcb_loader" ]\n', "bridge dependency")


def patch_xlib_support(text: str) -> str:
    bridge = '''  auto* xlib_xcb_loader = GetXlibXcbLoader();
  CHECK(xlib_xcb_loader->Load("libX11-xcb.so.1"));

  CHECK(xlib_loader->XInitThreads());
'''
    bridge_static = '''#if !defined(CEF_STATIC_X11_DIRECT)  // CEF_STATIC_X11_DIRECT_V1
  auto* xlib_xcb_loader = GetXlibXcbLoader();
  CHECK(xlib_xcb_loader->Load("libX11-xcb.so.1"));
#endif

  CHECK(xlib_loader->XInitThreads());
'''
    text = _one(text, bridge, bridge_static, "Xlib/XCB load")
    get = '''struct xcb_connection_t* XlibDisplay::GetXcbConnection() {
  return GetXlibXcbLoader()->XGetXCBConnection(display_);
}
'''
    get_static = '''struct xcb_connection_t* XlibDisplay::GetXcbConnection() {
#if defined(CEF_STATIC_X11_DIRECT)  // CEF_STATIC_X11_DIRECT_V1
  // The strict static CEF profile disables Vulkan, the only reviewed caller of
  // this Xlib/XCB bridge. Fail closed instead of reintroducing libX11-xcb.so.
  CHECK(false) << "Xlib/XCB bridge is unavailable in the static no-Vulkan profile";
#else
  return GetXlibXcbLoader()->XGetXCBConnection(display_);
#endif
}
'''
    text = _one(text, get, get_static, "Xlib/XCB accessor")
    include = '#include "library_loaders/xlib_xcb_loader.h"\n'
    text = _one(text, include,
                '#if !defined(CEF_STATIC_X11_DIRECT)\n' + include + '#endif\n',
                "bridge header")
    getter = """XlibXcbLoader* GetXlibXcbLoader() {
  static base::NoDestructor<XlibXcbLoader> xlib_xcb_loader;
  return xlib_xcb_loader.get();
}
"""
    # The entire getter must disappear, not just its callers (-Wunused-function).
    return _one(text, getter,
                '#if !defined(CEF_STATIC_X11_DIRECT)\n' + getter + '#endif\n',
                "bridge getter")


PATCHERS = {
    "ui/gfx/x/BUILD.gn": patch_x_build,
    "ui/gfx/x/xlib_support.cc": patch_xlib_support,
    "tools/generate_library_loader/generate_library_loader.gni": patch_loader_gni,
}



WEBRTC = "6f37672d358475cd17544121a12494da454d85fb"
DESKTOP_FILE = "third_party/webrtc/modules/desktop_capture/BUILD.gn"
GTK_FILE = "ui/gtk/gtk_ui.cc"
X_MODULES = ("x11", "xcomposite", "xdamage", "xext", "xfixes", "xrandr", "xrender", "xtst", "xcb")
OS_NEEDED = frozenset({"libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0",
                       "librt.so.1", "libresolv.so.2", "ld-linux-x86-64.so.2"})


def patch_desktop_capture(text: str) -> str:
    text = _one(text, 'import("//build/config/ui.gni")\n',
                'import("//build/config/ui.gni")\nimport("//build/config/linux/pkg_config.gni")\n',
                "WebRTC platform import")
    original = '''    libs = [
      "X11",
      "Xcomposite",
      "Xdamage",
      "Xext",
      "Xfixes",

      # Xrandr depends on Xrender and needs to be listed before its dependency.
      "Xrandr",

      "Xrender",
      "Xtst",
    ]
'''
    replacement = ('    # CEF_STATIC_DESKTOP_V2: no host -l lookup in the strict target.\n'
                   '    if (cef_static_platform_manifest != "" &&\n'
                   '        current_toolchain == default_toolchain) {\n'
                   '      configs += [ ":cef_static_capture_x11" ]\n'
                   '    } else {\n' +
                   ''.join('  ' + line if line.strip() else line for line in original.splitlines(True)) +
                   '    }\n')
    text = _one(text, original, replacement, "WebRTC X11 libraries")
    return text + '''
# CEF_STATIC_DESKTOP_V2: retain X11 screen/window capture and all extensions.
if (cef_static_platform_manifest != "" &&
    current_toolchain == default_toolchain) {
  pkg_config("cef_static_capture_x11") {
    packages = [ "x11", "xcomposite", "xdamage", "xext", "xfixes",
                 "xrandr", "xrender", "xtst" ]
  }
}
'''


def patch_gtk_software(text: str) -> str:
    # GTK3 initializes GLX while choosing visuals, even in a CPU-only CEF
    # reference run. Use GTK's supported Cairo path before its initialization;
    # this keeps GtkUi, themes, dialogs, fonts and input integration enabled.
    anchor = '  env->SetVar("NO_AT_BRIDGE", "1");\n'
    return _one(text, anchor, anchor + '''#if defined(CEF_STATIC_GTK3)  // CEF_STATIC_DESKTOP_V2
  // Do not load host GL/Mesa through GDK/epoxy in the strict static profile.
  // This governs GTK's own drawing only, not Chromium's ANGLE/Skia features.
  if (!env->SetVar("GDK_GL", "disable")) {
    return false;
  }
#endif
''', "GDK software rendering")


PATCHERS[DESKTOP_FILE] = patch_desktop_capture
PATCHERS[GTK_FILE] = patch_gtk_software


# CEF's linux_gtk_theme_3610.patch is applied before this adapter runs.
# Never regenerate gtk_ui.cc from stock Chromium and silently discard it.
CEF_GTK_THEME_BLOB = "4e7f63878bfa1558167db2e91ad08394b3bd57bb"
CEF_GTK_THEME_SHA256 = "90afaaea63ac37a0ad4f0ca8d07391ccb9eaa6b6db35ac717ff01622cbc5f188"


def cef_gtk_baseline(original: bytes) -> bytes:
    """Reconstruct ONLY the reviewed CEF prerequisite, bound to full-file bytes."""
    if _digest(original) != FILES[GTK_FILE]:
        raise ValueError("Unreviewed Chromium GTK prerequisite original")
    text = original.decode("utf-8")
    include = '#include "base/strings/string_split.h"\n'
    text = _one(text, include, include + '#include "cef/libcef/features/features.h"\n',
                "CEF GTK feature header")
    theme = '''  connect(settings, "notify::gtk-theme-name", &GtkUi::OnThemeChanged);
  connect(settings, "notify::gtk-icon-theme-name", &GtkUi::OnThemeChanged);
  connect(settings, "notify::gtk-application-prefer-dark-theme",
          &GtkUi::OnThemeChanged);
'''
    guarded = '''  // Disable GTK theme change notifications because they are extremely slow.
  // Light/dark theme changes will still be detected via DarkModeManagerLinux.
  // See https://issues.chromium.org/issues/40280130#comment7
#if !BUILDFLAG(ENABLE_CEF)
''' + theme + "#endif\n"
    result = _one(text, theme, guarded, "CEF GTK theme prerequisite").encode("utf-8")
    if _digest(result) != CEF_GTK_THEME_SHA256:
        raise ValueError("CEF GTK prerequisite differs from reviewed complete source")
    return result


def _regular(root: Path, relative: str) -> Path:
    if (not isinstance(relative, str) or relative.startswith("/")
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("Noncanonical static desktop input")
    path = root
    if path.is_symlink():
        raise ValueError("Redirected static desktop root")
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise ValueError("Redirected static desktop input")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Missing static desktop input")
    return path


def _validated_platform(manifest: Path, prefix: Path, expected: str) -> dict:
    if (not re.fullmatch(r"[0-9a-f]{64}", expected)
            or manifest.is_symlink() or not manifest.is_file()
            or _digest(manifest.read_bytes()) != expected):
        raise ValueError("Static desktop platform manifest mismatch")
    value = json.loads(manifest.read_bytes())
    if (not isinstance(value, dict) or value.get("schema") != 1
            or value.get("kind") != "linux-x64-static-platform-build-inputs"
            or value.get("runtime_verified") is not False):
        raise ValueError("Invalid static desktop platform identity")
    modules, files, archives = (value.get(k) for k in ("modules", "files", "archive_objects"))
    if not all(isinstance(v, dict) for v in (modules, files, archives)):
        raise ValueError("Incomplete static desktop inventory")
    selected = set()
    for module in X_MODULES:
        entry = modules.get(module)
        if not isinstance(entry, dict) or not isinstance(entry.get("libraries"), list):
            raise ValueError("Missing frozen desktop module")
        for relative in entry["libraries"]:
            if not isinstance(relative, str):
                raise ValueError("Invalid static desktop library name")
            if relative in {"c", "m", "dl", "pthread", "rt", "resolv"}:
                continue
            if (not isinstance(relative, str) or not relative.startswith("lib/")
                    or not relative.endswith(".a") or type(archives.get(relative)) is not int
                    or archives[relative] <= 0):
                raise ValueError("Uncaptured static desktop library")
            if relative in selected:
                continue
            record = files.get(relative)
            if not isinstance(record, dict):
                raise ValueError("Missing static desktop archive identity")
            path = _regular(prefix, relative)
            with path.open("rb") as stream:
                magic = stream.read(8)
                stream.seek(0)
                sha = hashlib.file_digest(stream, "sha256").hexdigest()
            if (magic != b"!<arch>\n" or path.stat().st_size != record.get("size")
                    or sha != record.get("sha256")):
                raise ValueError("Frozen desktop archive changed")
            selected.add(relative)
    required = {"lib/libX11.a", "lib/libxcb.a", "lib/libXcomposite.a", "lib/libXdamage.a",
                "lib/libXext.a", "lib/libXfixes.a", "lib/libXrandr.a", "lib/libXrender.a", "lib/libXtst.a"}
    if not required <= selected:
        raise ValueError("Frozen desktop closure lacks required archives")
    return {"archives": sorted(selected), "module_count": len(X_MODULES)}


def transform(relative: str, raw: bytes, original: bytes) -> bytes:
    if relative not in PATCHERS or _digest(original) != FILES[relative]:
        raise ValueError("Unreviewed static desktop original")
    baseline = original
    known = {FILES[relative]}
    if relative == GTK_FILE:
        # git show returns stock Chromium, but the restored/fresh CEF workspace
        # already contains the upstream CEF theme patch. Compose our change on
        # that exact prerequisite; stock-only and partial states remain errors.
        baseline = cef_gtk_baseline(original)
        known = {CEF_GTK_THEME_SHA256}
    elif relative in LEGACY_PATCHED:
        known.add(LEGACY_PATCHED[relative])
    if relative in COMPILE_FAILURE_PATCHED:
        known.add(COMPILE_FAILURE_PATCHED[relative])
    output = PATCHERS[relative](baseline.decode("utf-8")).encode("utf-8")
    if _digest(output) != PATCHED[relative]:
        raise ValueError("Static desktop transform differs from reviewed output")
    known.add(PATCHED[relative])
    if _digest(raw) not in known:
        # Only an allowlisted public source path is included, never file text.
        raise ValueError("Unreviewed or partially patched desktop source: " + relative)
    return output


def install(source: Path, manifest: Path, prefix: Path, expected: str) -> dict:
    if source.is_symlink() or prefix.is_symlink() or manifest.is_symlink():
        raise ValueError("Redirected static desktop selection")
    source, prefix = source.resolve(strict=True), prefix.resolve(strict=True)
    platform = _validated_platform(manifest, prefix, expected)
    for repository, revision in ((source, CHROMIUM), (source / "third_party/webrtc", WEBRTC)):
        head = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"],
                                       text=True, timeout=30).strip()
        if head != revision:
            raise ValueError("Static desktop source revision changed")
    staged = {}
    for relative in PATCHERS:
        path = _regular(source, relative)
        repo, revision, name = source, CHROMIUM, relative
        if relative == DESKTOP_FILE:
            repo, revision, name = source / "third_party/webrtc", WEBRTC, "modules/desktop_capture/BUILD.gn"
        original = subprocess.check_output(["git", "-C", str(repo), "show", revision + ":" + name], timeout=30)
        raw = path.read_bytes()
        output = transform(relative, raw, original)
        if raw != output:
            staged[path] = output
    # Validate every complete file before writing. Idempotent files keep mtimes.
    for path, data in staged.items():
        fd, name = tempfile.mkstemp(prefix=".cef-desktop-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(path.stat().st_mode & 0o777)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return {"schema": 2, "status": "success", "kind": "cef-static-desktop",
            "changed_files": len(staged), "verified_files": len(PATCHERS),
            "platform_sha256": expected, "platform_modules": platform["module_count"],
            "platform_archives": len(platform["archives"]), "gtk_rendering": "cairo-software",
            "webrtc_x11_static": True, "runtime_verified": False}


def audit_native(source: Path) -> dict:
    """Check the real ELF, not GN's interpretation of a bare -l name."""
    exe = _regular(source, "out/CEF_Static_Platform_Release_x64/cef_static_smoke")
    result = subprocess.run(["readelf", "-d", str(exe)], capture_output=True, text=True, timeout=60)
    if result.returncode or len(result.stdout) > 256 * 1024:
        raise RuntimeError("Cannot inspect static engine ELF")
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", result.stdout)
    unexpected = set(needed) - OS_NEEDED
    return {"runtime_native_elf_verified": not unexpected,
            "runtime_native_elf_needed_count": len(needed),
            "runtime_native_elf_unexpected_count": len(unexpected)}
