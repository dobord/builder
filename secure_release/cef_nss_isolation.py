"""Fail-closed NSS/BoringSSL symbol isolation for resumed static CEF builds."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

ARCHIVE_RELATIVE = "lib/cef-nss/libcef_nss.a"
MARKER = b"# cef-nss-boringssl-isolation-wrapper-v1"
OUT_NAME = "CEF_Static_Platform_Release_x64"
SYMBOL_RENAMES = {
    "SHA256_Update": "CEF_NSS_SHA256_Update",
    "SHA224_Update": "CEF_NSS_SHA224_Update",
    "SHA512_Update": "CEF_NSS_SHA512_Update",
    "SHA384_Update": "CEF_NSS_SHA384_Update",
    "SHA1_Update": "CEF_NSS_SHA1_Update",
    "MD5_Update": "CEF_NSS_MD5_Update",
    "HMAC_Init": "CEF_NSS_HMAC_Init",
    "HMAC_Update": "CEF_NSS_HMAC_Update",
    "CMAC_Init": "CEF_NSS_CMAC_Init",
    "CMAC_Update": "CEF_NSS_CMAC_Update",
}


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _wrapper_text(archive: Path, expected: str, objcopy: Path, nm: Path) -> str:
    renames = json.dumps(SYMBOL_RENAMES, sort_keys=True)
    return f'''#!/usr/bin/env python3
# cef-nss-boringssl-isolation-wrapper-v1
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE_ARCHIVE = Path({json.dumps(str(archive))})
EXPECTED_SHA256 = {json.dumps(expected)}
OBJCOPY = Path({json.dumps(str(objcopy))})
NM = Path({json.dumps(str(nm))})
RENAMES = {renames}
REAL_NINJA = Path(__file__).with_name("ninja.cef-real")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def has_symbol(text, name):
    return re.search(r"(?:^|[ \\t])" + re.escape(name) + r"$", text, re.M) is not None


def repair(out):
    if (not SOURCE_ARCHIVE.is_file() or SOURCE_ARCHIVE.is_symlink()
            or digest(SOURCE_ARCHIVE) != EXPECTED_SHA256):
        raise RuntimeError("Frozen cef-nss archive changed before symbol isolation")
    root = out / ".cef-nss-isolation"
    root.mkdir(parents=True, exist_ok=True)
    mapping = root / "redefine-syms.txt"
    mapping.write_text("".join(f"{{old}} {{new}}\\n" for old, new in sorted(RENAMES.items())),
                       encoding="ascii")
    before = subprocess.check_output([str(NM), "-g", str(SOURCE_ARCHIVE)],
                                     text=True, timeout=120)
    for old, new in RENAMES.items():
        if not has_symbol(before, old) or has_symbol(before, new):
            raise RuntimeError("Unexpected cef-nss symbol inventory: " + old)
    target = root / "libcef_nss_isolated.a"
    temporary = root / ".libcef_nss_isolated.a.new"
    temporary.unlink(missing_ok=True)
    subprocess.run([str(OBJCOPY), "--redefine-syms=" + str(mapping),
                    str(SOURCE_ARCHIVE), str(temporary)],
                   check=True, timeout=300)
    after = subprocess.check_output([str(NM), "-g", str(temporary)],
                                    text=True, timeout=120)
    for old, new in RENAMES.items():
        if has_symbol(after, old) or not has_symbol(after, new):
            raise RuntimeError("cef-nss symbol isolation incomplete: " + old)
    os.replace(temporary, target)

    old_path = str(SOURCE_ARCHIVE)
    new_path = str(target)
    replacements = 0
    for ninja in sorted(out.rglob("*.ninja")):
        data = ninja.read_text(encoding="utf-8")
        count = data.count(old_path)
        if not count:
            continue
        updated = data.replace(old_path, new_path)
        temporary_ninja = ninja.with_name(ninja.name + ".cef-nss-new")
        temporary_ninja.write_text(updated, encoding="utf-8")
        os.replace(temporary_ninja, ninja)
        replacements += count
    if replacements <= 0:
        raise RuntimeError("Generated Ninja graph contains no frozen cef-nss archive")
    receipt = {{
        "schema": 1,
        "kind": "cef-nss-boringssl-symbol-isolation",
        "source_sha256": EXPECTED_SHA256,
        "derived_sha256": digest(target),
        "redefined_symbols": sorted(RENAMES),
        "ninja_replacements": replacements,
    }}
    (root / "receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\\n",
                                       encoding="utf-8")


def selected_out(argv):
    if "-t" in argv or "cef_static_smoke" not in argv:
        return None
    try:
        index = argv.index("-C")
        value = argv[index + 1]
    except (ValueError, IndexError):
        return None
    path = Path(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


out = selected_out(sys.argv[1:])
if out is not None:
    repair(out)
os.execv(str(REAL_NINJA), [str(REAL_NINJA), *sys.argv[1:]])
'''


def install(source: Path, manifest: Path, prefix: Path, expected_manifest: str,
            summary: dict) -> None:
    source = source.resolve(strict=True)
    manifest = manifest.resolve(strict=True)
    prefix = prefix.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest):
        raise ValueError("Invalid platform manifest digest for NSS isolation")
    if _digest(manifest) != expected_manifest:
        raise ValueError("Platform manifest changed before NSS isolation")
    value = json.loads(manifest.read_text(encoding="utf-8"))
    record = value.get("files", {}).get(ARCHIVE_RELATIVE)
    if (not isinstance(record, dict) or set(record) != {"size", "sha256"}
            or type(record.get("size")) is not int
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256")))):
        raise ValueError("Frozen platform manifest lacks cef-nss archive identity")
    archive = prefix / ARCHIVE_RELATIVE
    if (not archive.is_file() or archive.is_symlink()
            or archive.stat().st_size != record["size"]
            or _digest(archive) != record["sha256"]):
        raise ValueError("Frozen cef-nss archive does not match platform manifest")

    llvm = source / "third_party/llvm-build/Release+Asserts/bin"
    objcopy = llvm / "llvm-objcopy"
    nm = llvm / "llvm-nm"
    for tool in (objcopy, nm):
        if not tool.is_file() or tool.is_symlink() or not os.access(tool, os.X_OK):
            raise ValueError("Pinned Chromium LLVM tool is unavailable: " + tool.name)

    ninja = source / "third_party/ninja/ninja"
    real = ninja.with_name("ninja.cef-real")
    if real.exists():
        if not real.is_file() or real.is_symlink():
            raise ValueError("Invalid preserved real Ninja binary")
        if ninja.is_file() and not ninja.is_symlink():
            head = ninja.open("rb").read(len(MARKER) + 80)
            if MARKER not in head and _digest(ninja) != _digest(real):
                raise ValueError("Ninja changed after NSS isolation was installed")
        else:
            raise ValueError("Ninja wrapper is missing after checkpoint restore")
    else:
        if not ninja.is_file() or ninja.is_symlink():
            raise ValueError("Pinned Ninja binary is unavailable")
        ninja.rename(real)

    wrapper = _wrapper_text(archive, record["sha256"], objcopy, nm)
    temporary = ninja.with_name("ninja.cef-nss-new")
    temporary.write_text(wrapper, encoding="utf-8", newline="\n")
    mode = stat.S_IMODE(real.stat().st_mode)
    temporary.chmod(mode | stat.S_IXUSR)
    os.replace(temporary, ninja)
    summary["nss_boringssl_isolation_installed"] = True
    summary["nss_boringssl_source_sha256"] = record["sha256"]
    summary["nss_boringssl_symbol_count"] = len(SYMBOL_RENAMES)


def record_receipt(source: Path, summary: dict, *, required: bool = False) -> bool:
    receipt_path = source / "out" / OUT_NAME / ".cef-nss-isolation" / "receipt.json"
    if not receipt_path.is_file():
        if required:
            raise RuntimeError("NSS/BoringSSL isolation receipt is missing")
        return False
    value = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected_symbols = sorted(SYMBOL_RENAMES)
    if (value.get("schema") != 1
            or value.get("kind") != "cef-nss-boringssl-symbol-isolation"
            or value.get("source_sha256") != summary.get("nss_boringssl_source_sha256")
            or value.get("redefined_symbols") != expected_symbols
            or type(value.get("ninja_replacements")) is not int
            or value["ninja_replacements"] <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("derived_sha256")))):
        raise RuntimeError("NSS/BoringSSL isolation receipt is invalid")
    summary["nss_boringssl_isolation_verified"] = True
    summary["nss_boringssl_derived_sha256"] = value["derived_sha256"]
    summary["nss_boringssl_ninja_replacements"] = value["ninja_replacements"]
    return True
