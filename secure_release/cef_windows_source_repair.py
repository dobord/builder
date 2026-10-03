"""Four reviewed Windows source corrections, bound to a new build contract.

The baseline CEF checkout and native checkpoint codec stay unchanged. Only the
exact legacy producer below may cross into this profile, after authenticated
restore under its OLD contract. New checkpoints carry the NEW contract and a
verified source marker covering all four files. Neither receipts nor fixtures
constitute runtime proof.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time

from .crypto import canonical, parse

CHROMIUM = "79460ebecaa5625e57a5fb679a735659e73dc687"
HEADER = "download/chromium/src/net/websockets/websocket_handshake_challenge.h"
MARKER = "cef-windows-source-repair.json"
BEFORE = "e9c2a8404032abb4080a5f6855ca396a5ecee841f017e932d49b9bbc2574e184"
AFTER = "38eb8b609bea01c37e3799feaba074c79f189568ff9b7df8c6943707433ef713"
PAINT_HEADER = "download/chromium/src/ui/gfx/paint_vector_icon.h"
PAINT_BEFORE = "8e9d9819abc21afcd225345eb0ae679731b909e6f23fc4c2dc04ce1f66c6a58d"
PAINT_AFTER = "89e65e86fa4d5de9a72567de96c41659b6610e02cb50a063942e458e0fda70cd"
AUTOFILL_SOURCE = "download/chromium/src/components/autofill/core/common/form_field_data.cc"
AUTOFILL_BEFORE = "0edba08fcad529c1980260493296da86db429684b98fdaf7765ae8c083397e32"
AUTOFILL_AFTER = "fd5dcc844aa6250b7b5bb702965e7abeba4cb57f655aec2ff43f078be471b490"
ATOMIC_SOURCE = "download/chromium/src/third_party/blink/renderer/platform/wtf/text/atomic_string.cc"
ATOMIC_BEFORE = "a4c0cc1f34fd6b692337331b8192096e77ada0a13a3b6c6598770bbb8711a871"
ATOMIC_AFTER = "554274d3e6d39eb924fa276f1a747e26f54453a00c1e644dde9a1b7cc8cb5b42"
# Ordered, closed set of corrections; no caller-selected paths or patches.
CORRECTIONS = (
    (HEADER, BEFORE, AFTER, (
        (b"#include <string_view>\n",
         b"#include <string>\n#include <string_view>\n"),
    )),
    (PAINT_HEADER, PAINT_BEFORE, PAINT_AFTER, (
        (b'#include "base/component_export.h"\n',
         b'#include <string>\n\n#include "base/component_export.h"\n'),
    )),
    (AUTOFILL_SOURCE, AUTOFILL_BEFORE, AUTOFILL_AFTER, (
        (b'#include "base/notreached.h"\n',
         b'#include "base/no_destructor.h"\n#include "base/notreached.h"\n'),
        (b'    static const std::optional<AutocompleteParsingResult> kNoParsingResult =\n'
         b'        std::nullopt;\n',
         b'    static const base::NoDestructor<std::optional<AutocompleteParsingResult>>\n'
         b'        kNoParsingResult(std::nullopt);\n'),
        (b'!e.contains(kNotRefillRelated) ? f.parsed_autocomplete_ : kNoParsingResult,',
         b'!e.contains(kNotRefillRelated) ? f.parsed_autocomplete_ : *kNoParsingResult,'),
    )),
    (ATOMIC_SOURCE, ATOMIC_BEFORE, ATOMIC_AFTER, (
        (b'#include "third_party/blink/renderer/platform/wtf/text/case_map.h"\n',
         b'#include "third_party/blink/renderer/platform/wtf/text/case_map.h"\n'
         b'#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"\n'),
    )),
)
BASE_KEY = "60a369f6b051ba651cb301af299e7dadcc99608d0db6894bccab87b953817602"
LEGACY = {
    "run": 37007852614, "attempt": 1,
    "producer_sha": "312f6ca48ab6a26982a4bb21ec0e1514af38e859",
    "artifact_id": 11237383883,
    "artifact_sha256": "3a3788d8b2c6ed29daeba5ac357f751aa374a6b05ba9aab94591001165ea402f",
    "summary_artifact_id": 11237488572,
    "summary_artifact_sha256": "343ce6fe1876f7cf5bf295ad626c2f88a52973667dc6d92797421d004af518e3",
    "build_key": BASE_KEY,
}


def profile() -> dict:
    return {
        "schema": 2, "id": "windows-blink-iterator-v4",
        "chromium_commit": CHROMIUM,
        "corrections": [
            {"path": path.removeprefix("download/chromium/src/"),
             "before_sha256": before, "after_sha256": after}
            for path, before, after, _ in CORRECTIONS
        ],
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def build_key(base_key: str) -> str:
    if base_key != BASE_KEY:
        raise ValueError("Windows source repair requires the reviewed baseline")
    return hashlib.sha256(canonical({
        "schema": 2, "base_build_key": base_key, "source_repair": profile(),
    })).hexdigest()


def restore_contract(selected: dict | None, base_key: str) -> tuple[str, str]:
    current = build_key(base_key)
    if selected is None:
        return current, "fresh"
    if not isinstance(selected, dict):
        raise ValueError("Invalid Windows source repair checkpoint")
    # Canonical comparison distinguishes booleans from integer identifiers.
    if canonical(selected) == canonical(LEGACY):
        return BASE_KEY, "legacy"
    if selected.get("build_key") == current:
        return current, "resume"
    raise ValueError("No reviewed Windows source repair checkpoint transition")


def verify_summary(value: dict, selected: dict) -> None:
    _, origin = restore_contract(selected, BASE_KEY)
    if origin == "legacy":
        if "source_repair" in value:
            raise ValueError("Legacy Windows checkpoint claims a repaired profile")
        return
    if (value.get("base_build_key") != BASE_KEY
            or value.get("source_repair_verified") is not True
            or canonical(value.get("source_repair")) != canonical(profile())):
        raise ValueError("Windows checkpoint lacks the exact source repair proof")


def normalized(raw: bytes) -> tuple[bytes, bytes]:
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    text = raw.replace(b"\r\n", b"\n")
    if b"\r" in text or (newline == b"\r\n" and b"\n" in raw.replace(b"\r\n", b"")):
        raise ValueError("Unreviewed Windows header newline encoding")
    return text, newline


def transform(raw: bytes, relative: str = HEADER) -> bytes:
    correction = next((item for item in CORRECTIONS if item[0] == relative), None)
    if correction is None:
        raise ValueError("Unreviewed Windows header correction path")
    _, before, after, edits = correction
    text, newline = normalized(raw)
    digest = hashlib.sha256(text).hexdigest()
    if digest == after:
        return raw
    if digest != before:
        raise ValueError("Unreviewed Windows header; refusing source correction")
    changed = text
    for anchor, replacement in edits:
        if changed.count(anchor) != 1:
            raise ValueError("Windows source correction anchor mismatch")
        changed = changed.replace(anchor, replacement, 1)
    if hashlib.sha256(changed).hexdigest() != after:
        raise ValueError("Windows source correction digest mismatch")
    return changed.replace(b"\n", newline)


def _object_snapshot(info) -> tuple:
    # CPython 3.12 win32_xstat copies birthtime to ctime; fstat retains
    # ChangeTime. Compare the same birthtime field ACROSS the APIs instead.
    # Keep ctime in the full snapshots checked WITHIN each API below.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns,
            getattr(info, "st_birthtime_ns", info.st_ctime_ns))


def _snapshot(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _path(work: Path, relative: str) -> Path:
    current = work
    for part in relative.split("/"):
        current = current / part
        info = current.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("Redirected Windows source repair path")
    if not current.resolve(strict=True).is_relative_to(work):
        raise ValueError("Windows source repair escaped workspace")
    return current


def _read(work: Path, relative: str, limit: int = 65536) -> tuple[Path, bytes, object]:
    path = _path(work, relative)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or not 0 < before.st_size <= limit):
        raise ValueError("Invalid Windows source repair input")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if _object_snapshot(opened) != _object_snapshot(before):
            raise ValueError("Windows source repair input changed before read")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(data) != before.st_size or _snapshot(after) != _snapshot(opened)
            or _snapshot(path.lstat()) != _snapshot(before)):
        raise ValueError("Windows source repair input changed during read")
    return path, data, before


def apply(work: Path, contract: str, origin: str) -> str:
    if origin not in {"fresh", "legacy", "resume"} or contract != build_key(BASE_KEY):
        raise ValueError("Invalid Windows source repair invocation")
    if not work.is_absolute() or work != work.resolve(strict=True):
        raise ValueError("Noncanonical Windows source repair workspace")
    expected = canonical({"schema": 1, "kind": "cef-windows-source-repair",
                          "build_key": contract, "source_repair": profile()})
    marker = work / MARKER
    # Validate the complete set BEFORE writing any source. A bad later
    # file must not cause a seemingly valid partial source transition.
    inputs = []
    for relative, _, _, _ in CORRECTIONS:
        path, original, before = _read(work, relative)
        inputs.append((relative, path, original, before, transform(original, relative)))
    if origin == "resume":
        _, data, _ = _read(work, MARKER, 8192)
        if (canonical(parse(data)) != expected
                or any(original != changed for _, _, original, _, changed in inputs)):
            raise ValueError("Repaired Windows checkpoint source/marker mismatch")
        return "already-applied"
    # No v1, v2 or v3 checkpoint was qualified. Only the exact legacy producer may
    # transition; reject old markers and partially applied source sets.
    if os.path.lexists(marker) or any(original == changed for _, _, original, _, changed in inputs):
        raise ValueError("Unexpected source correction in baseline checkpoint")
    for relative, path, original, before, changed in inputs:
        fd, name = tempfile.mkstemp(prefix=".cef-header-", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(changed)
            temporary.chmod(stat.S_IMODE(before.st_mode))
            # Retime only this changed INPUT, never existing objects/deps or
            # already-corrected headers. Ninja invalidates its dependents.
            new_time = max(time.time_ns(), before.st_mtime_ns + 1_000_000)
            os.utime(temporary, ns=(new_time, new_time))
            if _path(work, relative) != path or _snapshot(path.lstat()) != _snapshot(before):
                raise ValueError("Windows source repair input changed before replacement")
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    # Publish the marker only after ALL corrections verify. An interrupted
    # transition fails closed; it cannot produce a qualified checkpoint.
    for relative, _, _, before, changed in inputs:
        _, result, after = _read(work, relative)
        if result != changed or after.st_mtime_ns <= before.st_mtime_ns:
            raise ValueError("Windows header correction or input clock verification failed")
    with marker.open("xb") as stream:
        stream.write(expected + b"\n")
    return "applied"
