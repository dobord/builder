"""Bounded non-sensitive evidence for strict CEF ELF DT_NEEDED failures.

The strict runtime gate remains authoritative in ``cef_x11_static.audit_native``.
This helper only exposes deterministic executable metadata after that gate fails,
so a resumed checkpoint can identify the exact linker/runtime dependency without
copying build logs into the public iteration summary.
"""
from __future__ import annotations

import re
from pathlib import Path
import subprocess

from .cef_x11_static import OS_NEEDED

_NEEDED = re.compile(r"\(NEEDED\).*Shared library: \[([^\]]+)\]")
_SAFE_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+:-]{0,95}")
_MAX_NEEDED = 64


def classify_readelf(text: str) -> dict:
    """Return bounded DT_NEEDED basenames only; reject arbitrary/path-like text."""
    if not isinstance(text, str) or len(text) > 256 * 1024:
        raise ValueError("Invalid native ELF audit output")
    needed = _NEEDED.findall(text)
    if not needed or len(needed) > _MAX_NEEDED:
        raise ValueError("Invalid native ELF dependency inventory")
    if any(not _SAFE_BASENAME.fullmatch(name) for name in needed):
        raise ValueError("Unsafe native ELF dependency basename")
    unexpected = sorted(set(needed) - OS_NEEDED)
    families = {
        "x11": ("libX", "libxcb"),
        "graphics": ("libGL", "libEGL", "libGLES", "libgbm", "libdrm", "libepoxy"),
        "gtk": ("libgtk", "libgdk", "libglib", "libgobject", "libgio", "libpango", "libcairo", "libatk"),
        "cxx": ("libstdc++", "libgcc_s", "libc++", "libc++abi"),
        "security": ("libnss", "libssl", "libcrypto", "libnspr"),
    }
    counts = {name: sum(any(item.startswith(prefix) for prefix in prefixes)
                        for item in unexpected)
              for name, prefixes in families.items()}
    recognized = sum(counts.values())
    return {
        "runtime_native_elf_unexpected_names": unexpected,
        "runtime_native_elf_unexpected_x11_count": counts["x11"],
        "runtime_native_elf_unexpected_graphics_count": counts["graphics"],
        "runtime_native_elf_unexpected_gtk_count": counts["gtk"],
        "runtime_native_elf_unexpected_cxx_count": counts["cxx"],
        "runtime_native_elf_unexpected_security_count": counts["security"],
        "runtime_native_elf_unexpected_other_count": len(unexpected) - recognized,
    }


def inspect(source: Path, *, expected_needed: int, expected_unexpected: int) -> dict:
    """Read the already-linked reference ELF and cross-check the gate's counts."""
    source = source.resolve(strict=True)
    exe = source / "out/CEF_Static_Platform_Release_x64/cef_static_smoke"
    if exe.is_symlink() or not exe.is_file() or not exe.resolve().is_relative_to(source):
        raise ValueError("Invalid native ELF evidence target")
    result = subprocess.run(["readelf", "-d", str(exe)], capture_output=True,
                            text=True, timeout=60)
    if result.returncode or (result.stderr and len(result.stderr) > 64 * 1024):
        raise RuntimeError("Cannot collect native ELF dependency evidence")
    evidence = classify_readelf(result.stdout)
    needed = _NEEDED.findall(result.stdout)
    if len(needed) != expected_needed:
        raise RuntimeError("Native ELF dependency inventory changed during evidence collection")
    if len(evidence["runtime_native_elf_unexpected_names"]) != expected_unexpected:
        raise RuntimeError("Native ELF unexpected dependency count changed during evidence collection")
    return evidence
