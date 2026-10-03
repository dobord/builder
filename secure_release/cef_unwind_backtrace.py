"""Keep Chromium stack capture off glibc's runtime-loaded libgcc_s path.

Run 81 links an OS-only ELF, yet both processes map libgcc_s.so.1. Chromium's
WarmUpBacktrace -> CollectStackTrace calls glibc backtrace, whose unwind-link
opens libgcc_s regardless of the executable's already linked LLVM unwinder.
Use that in-tree unwinder directly only for the strict Linux default toolchain.
Keep stack frames, frame-pointer fallback, signal handling and normal builds.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
BLOBS = {
    "base/BUILD.gn": "ddcc03bf9bec0c0b8d32eabbf01cddd269c887b7",
    "base/debug/stack_trace_posix.cc": "1f52ee3e355b1af95566402f1bfebbff3104ff15",
}
HEADER = Path(__file__).with_suffix(".h")
HEADER_TARGET = "base/debug/cef_static_backtrace.h"
MARKER = "CEF_STATIC_UNWIND_BACKTRACE_V1"

GN_SELECTION = '''
# CEF_STATIC_UNWIND_BACKTRACE_V1: private flag, not a global compiler define.
# Only stack_trace_posix.cc includes this header; preserve unrelated objects.
_cef_static_backtrace = false
if (is_linux) {
  import("//build/config/linux/pkg_config.gni")
  import("//build/config/unwind.gni")
  _cef_static_backtrace = cef_static_platform_manifest != "" &&
                          current_toolchain == default_toolchain
  if (_cef_static_backtrace) {
    assert(use_custom_libunwind,
           "Static backtrace requires the selected in-tree unwinder")
  }
}
buildflag_header("cef_static_backtrace_buildflags") {
  header = "cef_static_backtrace_buildflags.h"
  header_dir = "base/debug"
  flags = [ "CEF_STATIC_UNWIND_BACKTRACE=$_cef_static_backtrace" ]
}

'''
GN_TARGET = 'component("base") {\n'
GN_DEPS = '  deps = [\n    ":check_version_internal",\n'
GN_SOURCES = '    sources += [ "debug/stack_trace_posix.cc" ]\n'
GN_SOURCES_NEW = '''    sources += [
      "debug/stack_trace_posix.cc",
      "debug/cef_static_backtrace.h",
    ]
'''
CPP_INCLUDE = '#include "base/debug/debugging_buildflags.h"\n'
# The pinned file includes debugging_buildflags.h twice. Use a unique context.
CPP_INCLUDE_ANCHOR = CPP_INCLUDE + '#include "base/memory/raw_ptr.h"\n'
CPP_INCLUDE_NEW = CPP_INCLUDE + '''#include "base/debug/cef_static_backtrace_buildflags.h"
#if BUILDFLAG(CEF_STATIC_UNWIND_BACKTRACE)
#include "base/debug/cef_static_backtrace.h"
#endif
#include "base/memory/raw_ptr.h"
'''
CPP_BRANCH = '''  return base::debug::TraceStackFramePointers(trace, 0);
#elif defined(HAVE_BACKTRACE)
'''
CPP_BRANCH_NEW = '''  return base::debug::TraceStackFramePointers(trace, 0);
#elif BUILDFLAG(CEF_STATIC_UNWIND_BACKTRACE)  // CEF_STATIC_UNWIND_BACKTRACE_V1
  // glibc backtrace() opens libgcc_s even with libunwind already linked. Use
  // the selected static unwinder directly; retain WarmUpBacktrace and frames.
  return cef_static_backtrace::Capture(trace);
#elif defined(HAVE_BACKTRACE)
'''


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _one(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("Pinned static backtrace context changed")
    return text.replace(old, new, 1)


def edits(relative: str) -> tuple[tuple[str, str], ...]:
    if relative == "base/BUILD.gn":
        return (
            (GN_TARGET, GN_SELECTION + GN_TARGET),
            (GN_DEPS, '  deps = [\n    ":cef_static_backtrace_buildflags",\n    ":check_version_internal",\n'),
            (GN_SOURCES, GN_SOURCES_NEW),
        )
    if relative == "base/debug/stack_trace_posix.cc":
        return ((CPP_INCLUDE_ANCHOR, CPP_INCLUDE_NEW), (CPP_BRANCH, CPP_BRANCH_NEW))
    raise ValueError("Unreviewed static backtrace file")


def transform(relative: str, raw: bytes) -> bytes:
    if relative not in BLOBS:
        raise ValueError("Unreviewed static backtrace file")
    changes = edits(relative)
    original = raw.decode("utf-8")
    if blob(raw) != BLOBS[relative]:
        # Reconstruct and validate the COMPLETE original, not just markers.
        for old, new in reversed(changes):
            original = _one(original, new, old)
    if blob(original.encode("utf-8")) != BLOBS[relative]:
        raise ValueError("Unreviewed or partial static backtrace source")
    output = original
    for old, new in changes:
        output = _one(output, old, new)
    changed = output.encode("utf-8")
    if raw not in (original.encode("utf-8"), changed):
        raise ValueError("Partial static backtrace source")
    return changed


def _regular(root: Path, relative: str) -> Path:
    path = root
    if root.is_symlink():
        raise ValueError("Redirected static backtrace root")
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Redirected static backtrace input")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Missing static backtrace input")
    return path


def check_source(source: Path) -> dict:
    hashes = {}
    for relative in BLOBS:
        data = transform(relative, _regular(source, relative).read_bytes())
        hashes[relative] = hashlib.sha256(data).hexdigest()
    return hashes


def install(source: Path) -> dict:
    if source.is_symlink():
        raise ValueError("Redirected static backtrace root")
    source = source.resolve(strict=True)
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"],
                                   text=True, timeout=30).strip()
    if head != CHROMIUM:
        raise ValueError("Static backtrace Chromium revision changed")
    header = HEADER.read_bytes()
    if hashlib.sha256(header).hexdigest() != HEADER_SHA256:
        raise ValueError("Static backtrace header policy changed")
    staged = []
    for relative in BLOBS:
        path = _regular(source, relative)
        raw = path.read_bytes()
        changed = transform(relative, raw)
        if changed != raw:
            staged.append((path, changed))
    target = source / HEADER_TARGET
    # All ancestors have been checked by stack_trace_posix.cc above.
    if target.is_symlink():
        raise ValueError("Redirected static backtrace header")
    if target.exists():
        if not target.is_file() or target.read_bytes() != header:
            raise ValueError("Unowned or changed static backtrace header")
    else:
        staged.append((target, header))
    # Validate all inputs before replacing anything. Write the owned header first
    # so an interrupted source edit never refers to a missing header.
    staged.sort(key=lambda item: item[0] != target)
    for path, data in staged:
        fd, name = tempfile.mkstemp(prefix=".cef-backtrace-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(path.stat().st_mode & 0o777 if path.exists() else 0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return {"schema": 1, "kind": "cef-static-backtrace", "verified_files": 3,
            "changed_files": len(staged), "header_sha256": HEADER_SHA256,
            "backend": "in-tree-unwind-backtrace", "runtime_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-source", type=Path, required=True)
    args = parser.parse_args()
    check_source(args.check_source)
    print("CEF_STATIC_BACKTRACE_SOURCE_VERIFIED")


HEADER_SHA256 = "53dee27d56988b86a0d76fc8ce1dd57265d68a4c7313a1a792e4674a2ac2ac20"

if __name__ == "__main__":
    main()
