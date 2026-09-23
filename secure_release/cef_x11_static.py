"""Bind Chromium's Xlib loader to the frozen static X11 closure.

The strict Linux profile already freezes X11/XCB archives in the platform
manifest, but pinned Chromium still generates an Xlib loader with dlopen() and
keeps a bare ``-lxcb`` edge.  That admits host shared libraries at runtime even
though GN's graph audit can map the same names to captured archives.

This repair is deliberately narrow: only the two pinned Xlib loader targets are
changed.  Xlib uses the generator's supported direct-link mode and the target
links the captured ``x11``/``xcb`` pkg-config closure.  The Xlib/XCB bridge is
not loaded in this profile; it is only used by Chromium's Vulkan X11 path while
the static CEF profile keeps Vulkan disabled.  Ordinary Chromium builds are
byte-for-byte behaviorally unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
MARKER = "CEF_STATIC_X11_DIRECT_V1"
FILES = {
    "ui/gfx/x/BUILD.gn": "b8e0c438f1dab1b88fd5c43572d80acbe18ca681e8f60b5ef57563bed25585dc",
    "ui/gfx/x/xlib_support.cc": "0d6d01398fd226f0d263912a133f77eef4506f601648c949f4f7087bcccbf81a",
    "tools/generate_library_loader/generate_library_loader.gni": "784f63ef334097754ce6304ea218db36c2fe17eb5011c5d52501ee865de95dc3",
}
PATCHED = {
    "ui/gfx/x/BUILD.gn": "52c8654c2363e060c642161e562d1625fd1902e1c3208d3e986017ebc2bde01f",
    "ui/gfx/x/xlib_support.cc": "69a6855cf294257a7db2d869b061ef4e5e8ccc199ece68d5f0f9d6818af4561b",
    "tools/generate_library_loader/generate_library_loader.gni": "f062ab576e4c2502c9aac84afab2a54f6fd68de9307baa8764036d0948d74c70",
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
    return _one(text, tail, tail_static, "X11 target libraries")


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
  return nullptr;
#else
  return GetXlibXcbLoader()->XGetXCBConnection(display_);
#endif
}
'''
    return _one(text, get, get_static, "Xlib/XCB accessor")


PATCHERS = {
    "ui/gfx/x/BUILD.gn": patch_x_build,
    "ui/gfx/x/xlib_support.cc": patch_xlib_support,
    "tools/generate_library_loader/generate_library_loader.gni": patch_loader_gni,
}


def _validated_platform(manifest: Path, prefix: Path, expected: str) -> dict:
    if (not manifest.is_file() or manifest.is_symlink() or _digest(manifest.read_bytes()) != expected):
        raise ValueError("Static X11 platform manifest mismatch")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    if (value.get("schema") != 1
            or value.get("kind") != "linux-x64-static-platform-build-inputs"
            or value.get("runtime_verified") is not False):
        raise ValueError("Invalid static X11 platform identity")
    modules = value.get("modules")
    files = value.get("files")
    archives = value.get("archive_objects")
    if not all(isinstance(x, dict) for x in (modules, files, archives)):
        raise ValueError("Static X11 platform inventory is incomplete")
    selected: set[str] = set()
    for module in ("x11", "xcb"):
        entry = modules.get(module)
        if not isinstance(entry, dict) or not isinstance(entry.get("libraries"), list):
            raise ValueError("Static X11 platform module is missing: " + module)
        for relative in entry["libraries"]:
            if relative in {"c", "m", "dl", "pthread", "rt", "resolv"}:
                continue
            if (not isinstance(relative, str) or not relative.startswith("lib/")
                    or not relative.endswith(".a") or relative not in files
                    or type(archives.get(relative)) is not int or archives[relative] <= 0):
                raise ValueError("Static X11 module references an uncaptured archive")
            path = prefix / relative
            if (not path.is_file() or path.is_symlink()
                    or not path.resolve().is_relative_to(prefix.resolve())):
                raise ValueError("Static X11 archive is missing or redirected")
            record = files[relative]
            if path.stat().st_size != record.get("size") or _digest(path.read_bytes()) != record.get("sha256"):
                raise ValueError("Static X11 archive bytes changed")
            selected.add(relative)
    if "lib/libX11.a" not in selected or "lib/libxcb.a" not in selected:
        raise ValueError("Frozen X11/XCB closure lacks required direct archives")
    return {"archives": sorted(selected), "module_count": 2}


def install(source: Path, manifest: Path, prefix: Path, expected: str) -> dict:
    source = source.resolve(strict=True)
    manifest = manifest.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()
    if head != CHROMIUM:
        raise ValueError("Pinned Chromium source revision mismatch before X11 repair")
    platform = _validated_platform(manifest, prefix, expected)

    staged: dict[Path, bytes] = {}
    changed = 0
    for relative, patcher in PATCHERS.items():
        path = source / relative
        if (not path.is_file() or path.is_symlink()
                or not path.resolve().is_relative_to(source)):
            raise ValueError("Pinned Chromium X11 source is missing or redirected")
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        if MARKER in text:
            if _digest(raw) != PATCHED[relative]:
                raise ValueError("Existing static X11 repair differs from reviewed bytes: " + relative)
            continue
        if _digest(raw) != FILES[relative]:
            raise ValueError("Pinned Chromium X11 source differs from reviewed bytes: " + relative)
        output = patcher(text).encode("utf-8")
        if MARKER not in output.decode("utf-8"):
            raise AssertionError("Static X11 repair marker missing")
        staged[path] = output
        changed += 1

    for path, data in staged.items():
        fd, name = tempfile.mkstemp(prefix=".cef-x11-", dir=path.parent)
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

    return {
        "schema": 1,
        "status": "success",
        "kind": "cef-static-x11-direct",
        "chromium": CHROMIUM,
        "changed_files": changed,
        "verified_files": len(PATCHERS),
        "platform_sha256": expected,
        "platform_modules": platform["module_count"],
        "platform_archives": len(platform["archives"]),
        "runtime_verified": False,
    }
