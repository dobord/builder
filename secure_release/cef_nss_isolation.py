"""Fail-closed NSS/BoringSSL symbol isolation for resumed static CEF builds."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

ARCHIVE_RELATIVE = "lib/cef-nss/libcef_nss.a"
MARKER = b"# cef-nss-boringssl-isolation-wrapper-v2"
OUT_NAME = "CEF_Static_Platform_Release_x64"
FAILURE_STAGES = frozenset({
    "source-validate",
    "symbol-inventory",
    "objcopy",
    "symbol-verify",
    "ninja-rewrite",
})
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
    stages = json.dumps(sorted(FAILURE_STAGES))
    return f'''#!/usr/bin/env python3
# cef-nss-boringssl-isolation-wrapper-v2
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
FAILURE_STAGES = frozenset({stages})
REAL_NINJA = Path(__file__).with_name("ninja.cef-real")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def has_symbol(text, name):
    return re.search(r"(?:^|[ \\t])" + re.escape(name) + r"$", text, re.M) is not None


def write_status(root, status, stage, error_type=None):
    if stage not in FAILURE_STAGES and stage != "complete":
        raise RuntimeError("Invalid NSS isolation status stage")
    value = {{
        "schema": 1,
        "kind": "cef-nss-boringssl-symbol-isolation-status",
        "status": status,
        "stage": stage,
    }}
    if error_type is not None:
        value["error_type"] = error_type
    path = root / "status.json"
    temporary = root / ".status.json.new"
    temporary.write_text(json.dumps(value, sort_keys=True) + "\\n", encoding="utf-8")
    os.replace(temporary, path)


def graph_path_pairs(out, target):
    pairs = [
        (str(SOURCE_ARCHIVE), str(target)),
        (os.path.relpath(SOURCE_ARCHIVE, out), os.path.relpath(target, out)),
    ]
    return list(dict.fromkeys(pairs))


def repair(out):
    root = out / ".cef-nss-isolation"
    root.mkdir(parents=True, exist_ok=True)
    stage = "source-validate"
    write_status(root, "running", stage)
    try:
        if (not SOURCE_ARCHIVE.is_file() or SOURCE_ARCHIVE.is_symlink()
                or digest(SOURCE_ARCHIVE) != EXPECTED_SHA256):
            raise RuntimeError("Frozen cef-nss archive changed before symbol isolation")
        mapping = root / "redefine-syms.txt"
        mapping.write_text("".join(f"{{old}} {{new}}\\n" for old, new in sorted(RENAMES.items())),
                           encoding="ascii")

        stage = "symbol-inventory"
        write_status(root, "running", stage)
        before = subprocess.check_output([str(NM), "-g", str(SOURCE_ARCHIVE)],
                                         text=True, timeout=120)
        for old, new in RENAMES.items():
            if not has_symbol(before, old) or has_symbol(before, new):
                raise RuntimeError("Unexpected cef-nss symbol inventory: " + old)

        stage = "objcopy"
        write_status(root, "running", stage)
        target = root / "libcef_nss_isolated.a"
        temporary = root / ".libcef_nss_isolated.a.new"
        temporary.unlink(missing_ok=True)
        subprocess.run([str(OBJCOPY), "--redefine-syms=" + str(mapping),
                        str(SOURCE_ARCHIVE), str(temporary)],
                       check=True, timeout=300)

        stage = "symbol-verify"
        write_status(root, "running", stage)
        after = subprocess.check_output([str(NM), "-g", str(temporary)],
                                        text=True, timeout=120)
        for old, new in RENAMES.items():
            if has_symbol(after, old) or not has_symbol(after, new):
                raise RuntimeError("cef-nss symbol isolation incomplete: " + old)
        os.replace(temporary, target)

        stage = "ninja-rewrite"
        write_status(root, "running", stage)
        references = 0
        graphs = 0
        pairs = [
            (old_path.encode("utf-8"), new_path.encode("utf-8"))
            for old_path, new_path in graph_path_pairs(out, target)
        ]
        for ninja in sorted(out.rglob("*.ninja")):
            graphs += 1
            data = ninja.read_bytes()
            updated = data
            file_changes = 0
            for old_path, new_path in pairs:
                count = updated.count(old_path)
                if count:
                    updated = updated.replace(old_path, new_path)
                    file_changes += count
            file_references = sum(updated.count(new_path) for _, new_path in pairs)
            references += file_references
            if not file_changes:
                continue
            temporary_ninja = ninja.with_name(ninja.name + ".cef-nss-new")
            temporary_ninja.write_bytes(updated)
            os.replace(temporary_ninja, ninja)
        if graphs <= 0:
            raise RuntimeError("Generated Ninja graph is missing")
        if references <= 0:
            raise RuntimeError("Generated Ninja graph contains no frozen or isolated cef-nss archive")
        receipt = {{
            "schema": 1,
            "kind": "cef-nss-boringssl-symbol-isolation",
            "source_sha256": EXPECTED_SHA256,
            "derived_sha256": digest(target),
            "redefined_symbols": sorted(RENAMES),
            "ninja_replacements": references,
        }}
        (root / "receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\\n",
                                           encoding="utf-8")
        write_status(root, "success", "complete")
    except Exception as error:
        error_type = type(error).__name__
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{{0,63}}", error_type):
            error_type = "Exception"
        write_status(root, "failed", stage, error_type)
        raise


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
    compile(wrapper, "<cef-nss-isolation-wrapper>", "exec")
    temporary = ninja.with_name("ninja.cef-nss-new")
    temporary.write_text(wrapper, encoding="utf-8", newline="\n")
    mode = stat.S_IMODE(real.stat().st_mode)
    temporary.chmod(mode | stat.S_IXUSR)
    os.replace(temporary, ninja)
    summary["nss_boringssl_isolation_installed"] = True
    summary["nss_boringssl_wrapper_validated"] = True
    summary["nss_boringssl_source_sha256"] = record["sha256"]
    summary["nss_boringssl_symbol_count"] = len(SYMBOL_RENAMES)


def _read_status(root: Path) -> dict | None:
    path = root / "status.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    keys = set(value)
    if (value.get("schema") != 1
            or value.get("kind") != "cef-nss-boringssl-symbol-isolation-status"
            or value.get("status") not in {"running", "failed", "success"}
            or not isinstance(value.get("stage"), str)
            or value["stage"] not in FAILURE_STAGES | {"complete"}):
        raise RuntimeError("NSS/BoringSSL isolation status is invalid")
    if value["status"] == "failed":
        if (keys != {"schema", "kind", "status", "stage", "error_type"}
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}",
                                    str(value.get("error_type")))):
            raise RuntimeError("NSS/BoringSSL isolation failure status is invalid")
    elif keys != {"schema", "kind", "status", "stage"}:
        raise RuntimeError("NSS/BoringSSL isolation status fields are invalid")
    return value


def record_receipt(source: Path, summary: dict, *, required: bool = False) -> bool:
    root = source / "out" / OUT_NAME / ".cef-nss-isolation"
    receipt_path = root / "receipt.json"
    status = _read_status(root)
    if not receipt_path.is_file():
        if status is not None:
            summary["nss_boringssl_isolation_failure_stage"] = status["stage"]
            if status["status"] == "failed":
                summary["nss_boringssl_isolation_failure_type"] = status["error_type"]
            else:
                summary["nss_boringssl_isolation_failure_type"] = "Interrupted"
        if required:
            raise RuntimeError("NSS/BoringSSL isolation receipt is missing")
        return False
    if (status is None or status.get("status") != "success"
            or status.get("stage") != "complete"):
        raise RuntimeError("NSS/BoringSSL isolation did not reach a successful status")
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
