"""Verify the declared FreeRDP/FFmpeg SDK without ambient host VAAPI.

The pinned port has no VAAPI feature/dependency. Chromium host build-deps must
not silently supply it. The ABI-tracked triplet fixes FreeRDP's optional VAAPI
switches; this independent installed/relocated check retains requested features
and refuses libva references. It never edits package metadata or runtime rules.
"""
from __future__ import annotations

import re
from pathlib import Path

REQUIRED_ON = frozenset({
    "WITH_FFMPEG", "WITH_DSP_FFMPEG", "WITH_VIDEO_FFMPEG", "WITH_SWSCALE",
    "WITH_CLIENT", "WITH_SERVER", "WITH_PROXY", "WITH_PROXY_APP",
    "WITH_PROXY_MODULES", "WITH_WINPR_TOOLS", "WITH_X11",
})
REQUIRED_OFF = frozenset({"WITH_VAAPI", "WITH_VAAPI_H264_ENCODING"})


def _text(prefix: Path, relative: str) -> str:
    path = prefix
    if path.is_symlink():
        raise ValueError("Redirected FreeRDP target prefix")
    for part in Path(relative).parts:
        path /= part
        if path.is_symlink():
            raise ValueError("Redirected FreeRDP proof input")
    if not path.is_file() or path.stat().st_size > 1024**2:
        raise ValueError("Missing or oversized FreeRDP proof input")
    return path.read_text(encoding="utf-8")


def verify(prefix: Path) -> dict:
    """Validate actual package outputs before export and again after relocation."""
    text = _text(prefix, "include/freerdp3/freerdp/buildflags.h")
    macros = re.findall(r'^#define FREERDP_BUILD_CONFIG "([^"\r\n]*)"$', text, re.M)
    if len(macros) != 1:
        raise RuntimeError("FreeRDP build-configuration proof is absent or ambiguous")
    options = re.findall(r"\b(WITH_[A-Z0-9_]+)=([^\s]+)", macros[0])
    values = dict(options)
    if len(values) != len(options):
        raise RuntimeError("Duplicate FreeRDP build-configuration flags")
    if any(values.get(name) != "ON" for name in REQUIRED_ON):
        raise RuntimeError("Requested FreeRDP/FFmpeg SDK features are not enabled")
    if any(values.get(name) != "OFF" for name in REQUIRED_OFF):
        raise RuntimeError("Undeclared host VAAPI is enabled in the FreeRDP SDK")
    pc = _text(prefix, "lib/pkgconfig/freerdp3.pc")
    # Both the upstream typo (va) and a corrected host dependency (libva) are
    # invalid here. Do not make va.pc aliases or silently delete Requires fields.
    if re.search(r"(?<![A-Za-z0-9_])(?:libva|va|-lva)(?:-(?:drm|x11|wayland))?(?![A-Za-z0-9_])", pc):
        raise RuntimeError("FreeRDP pkg-config reintroduces undeclared VAAPI")
    required_pc = {"libavcodec", "libavutil", "libswresample", "libswscale"}
    # vcpkg fixup may move static Requires.private to Requires; inspect both.
    fields = " ".join(re.findall(r"^Requires(?:\.private)?:\s*(.*)$", pc, re.M))
    modules = set(re.findall(r"[A-Za-z_][A-Za-z0-9_.+-]*", fields))
    if not required_pc <= modules:
        raise RuntimeError("FreeRDP pkg-config lost its declared FFmpeg closure")
    return {"freerdp_ffmpeg_features_verified": True,
            "freerdp_host_vaapi_excluded": True,
            "freerdp_ffmpeg_pkgconfig_verified": True}
