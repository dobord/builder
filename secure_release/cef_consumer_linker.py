"""Validate the independent LLD used to link final relocated Linux consumers.

The qualified Chromium/CEF native link uses LLD.  The exported SDK intentionally
leaves linker choice to consumers, so strict qualification must make that choice
explicit instead of inheriting GNU ld.bfd from GCC.  Keep the build-time linker
outside the SDK and prove the exact Ubuntu LLD major through the GCC driver before
any expensive checkpoint restore.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile

from . import cef_sdk_example as checked, crypto

GXX = Path("/usr/bin/g++-14")
LLD_DIR = Path("/usr/lib/llvm-18/bin")
LLD = LLD_DIR / "ld.lld"
LLD_MAJOR = 18


def driver_flags(lld_dir: Path = LLD_DIR) -> str:
    """GCC driver flags that select the reviewed LLD directory explicitly."""
    return f"-B{lld_dir.as_posix()} -fuse-ld=lld"


def cmake_flag(lld_dir: Path = LLD_DIR) -> str:
    """One cache argument for executable links; compile commands are unchanged."""
    return "-DCMAKE_EXE_LINKER_FLAGS=" + driver_flags(lld_dir)


def _verify(root: Path, *, gxx: Path, lld_dir: Path, major: int) -> dict:
    root = root.resolve()
    checked.require(root.is_dir() and not root.is_symlink(),
                    "Consumer linker proof root is invalid")
    gxx = gxx.absolute()
    lld_dir = lld_dir.absolute()
    lld = lld_dir / "ld.lld"
    resolved_lld = lld.resolve(strict=True)
    checked.require(gxx.resolve(strict=True).is_file() and os.access(gxx, os.X_OK),
                    "Pinned GCC consumer driver is unavailable")
    checked.require(resolved_lld.is_file() and os.access(lld, os.X_OK)
                    and resolved_lld.is_relative_to(lld_dir.resolve(strict=True)),
                    "Pinned LLD consumer linker is unavailable")
    version = subprocess.check_output(
        [str(lld), "--version"], text=True, timeout=30
    ).strip()
    checked.require(
        re.fullmatch(r"(?:Ubuntu )?LLD " + str(major) + r"\.[0-9.]+(?: .*|)", version)
        is not None,
        "Consumer LLD major changed",
    )
    with tempfile.TemporaryDirectory(prefix="cef-consumer-lld-", dir=root) as name:
        work = Path(name)
        source = work / "probe.cc"
        source.write_text(
            '#include <cstdio>\nint main(){std::puts("lld-probe");}\n',
            encoding="utf-8",
        )
        selected = subprocess.run(
            [str(gxx), f"-B{lld_dir}", "-fuse-ld=lld", "-Wl,--version", str(source)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=60,
        )
        checked.require(
            selected.returncode == 0 and str(lld) in selected.stdout
            and version in selected.stdout,
            "GCC did not select the pinned LLD",
        )
        executable = work / "probe"
        linked = subprocess.run(
            [str(gxx), f"-B{lld_dir}", "-fuse-ld=lld", "-Wl,--fatal-warnings",
             str(source), "-o", str(executable)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=60,
        )
        checked.require(
            linked.returncode == 0 and executable.is_file()
            and not executable.is_symlink(),
            "Pinned LLD cannot link the consumer probe",
        )
        ran = subprocess.run(
            [str(executable)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=30,
        )
        checked.require(
            ran.returncode == 0 and ran.stdout == "lld-probe\n",
            "Pinned LLD consumer probe did not execute",
        )
    return {
        "kind": "lld",
        "major": major,
        "version": version,
        "sha256": crypto.digest(lld),
        "directory": lld_dir.as_posix(),
        "driver": gxx.as_posix(),
    }


def verify(root: Path) -> dict:
    return _verify(root, gxx=GXX, lld_dir=LLD_DIR, major=LLD_MAJOR)
