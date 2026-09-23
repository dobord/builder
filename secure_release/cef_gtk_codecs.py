"""Namespace the frozen GTK image-codec closure without changing its ABI inputs.

GTK/GdkPixbuf and Chromium/PDFium must not accidentally share JPEG/TIFF internals.
Rename ALL provider globals and the matching references in EVERY captured
platform archive. Frozen vcpkg files remain untouched; derived archives and
provenance live in the native output tree. No shared-library or linker-error
suppression fallback is permitted. This is build evidence, not runtime proof.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile

SCHEMA = 1
DIRECTORY = ".cef-gtk-codecs-v1"
NAMESPACE = "CEF_GTK_CODEC_"
OWNERS = {"lib/libjpeg.a": "jpeg_std_error", "lib/libtiff.a": "TIFFOpen"}
SYMBOL = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@]*\Z")
ANCHOR = 'os.execv(str(REAL_NINJA), [str(REAL_NINJA), *sys.argv[1:]])\n'


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative == PurePosixPath(relative).as_posix()
            and not relative.startswith("/")
            and all(p not in ("", ".", "..") for p in relative.split("/")),
            "Noncanonical codec input path")
    path = root
    require(not root.is_symlink(), "Redirected codec root")
    for part in relative.split("/"):
        path /= part
        require(not path.is_symlink(), "Redirected codec input")
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()),
            "Missing codec input")
    return path


def platform(manifest: Path, prefix: Path, expected: str) -> dict:
    require(not manifest.is_symlink() and manifest.is_file()
            and re.fullmatch(r"[0-9a-f]{64}", expected) is not None
            and digest(manifest) == expected, "Codec platform manifest mismatch")
    value = json.loads(manifest.read_bytes())
    require(isinstance(value, dict) and value.get("schema") == 1
            and value.get("kind") == "linux-x64-static-platform-build-inputs"
            and value.get("runtime_verified") is False, "Invalid codec platform identity")
    require(isinstance(value.get("archive_objects"), dict)
            and isinstance(value.get("files"), dict)
            and isinstance(value.get("modules"), dict), "Missing codec platform inventory")
    gtk = value["modules"].get("gtk+-3.0", {})
    require(set(OWNERS) <= set(gtk.get("libraries", [])),
            "Static GTK must retain both frozen JPEG and TIFF")
    for name, count in value["archive_objects"].items():
        require(name.startswith("lib/") and name.endswith(".a")
                and type(count) is int and count > 0, "Invalid codec archive inventory")
        record = value["files"].get(name, {})
        path = regular(prefix, name)
        require(path.stat().st_size == record.get("size")
                and digest(path) == record.get("sha256"), "Frozen codec closure changed")
        with path.open("rb") as stream:
            require(stream.read(8) == b"!<arch>\n", "Codec input is not a regular archive")
    return value


def symbols(nm: Path, archive: Path) -> Counter:
    result = subprocess.run([str(nm), "-P", "-g", "--no-demangle", str(archive)],
                            capture_output=True, text=True, timeout=120)
    require(result.returncode == 0 and len(result.stdout) <= 64 * 1024**2,
            "Cannot inspect static codec symbols")
    found: Counter = Counter()
    for line in result.stdout.splitlines():
        if not line.strip() or line.endswith(":"):
            continue  # POSIX nm archive member headings.
        fields = line.split()
        require(len(fields) >= 2 and SYMBOL.fullmatch(fields[0]) is not None
                and re.fullmatch(r"[A-Za-z?]", fields[1]) is not None,
                "Unrecognized static codec symbol record")
        found[(fields[0], fields[1])] += 1
    return found


def defined(table: Counter) -> set[str]:
    return {name for name, kind in table if kind not in {"U", "w", "v"}}


def rewrite_graph(data: bytes, pairs: list[tuple[bytes, bytes]]) -> tuple[bytes, set[int]]:
    """Replace complete Ninja path tokens, never similarly named archive paths."""
    references = set()
    for index, (old, new) in enumerate(pairs):
        pattern = rb"(?<![^\s\"'])" + re.escape(old) + rb"(?![^\s\"':])"
        data = re.sub(pattern, lambda _: new, data)
        target = rb"(?<![^\s\"'])" + re.escape(new) + rb"(?![^\s\"':])"
        if re.search(target, data):
            references.add(index)
    return data, references


def verify_derived(root: Path, identity: dict) -> dict:
    receipt_path = regular(root, "receipt.json")
    require(receipt_path.stat().st_size <= 4 * 1024**2, "Oversized codec receipt")
    receipt = json.loads(receipt_path.read_bytes())
    require(receipt.get("schema") == SCHEMA and receipt.get("identity") == identity
            and receipt.get("kind") == "cef-static-gtk-codec-namespace"
            and isinstance(receipt.get("archives"), dict), "Codec derivation identity changed")
    mapping = regular(root, "redefine-syms.txt")
    require(digest(mapping) == receipt.get("mapping_sha256"), "Codec mapping changed")
    require(set(OWNERS) <= set(receipt["archives"]), "Codec derivation lacks providers")
    expected_files = {"receipt.json", "redefine-syms.txt", "status.json"}
    for name, record in receipt["archives"].items():
        require(name in identity["sources"] and record.get("source_sha256") == identity["sources"][name],
                "Unbound codec derivation source")
        target = regular(root, record["file"])
        require(digest(target) == record["sha256"], "Derived codec archive changed")
        expected_files.add(record["file"])
    require(all(not p.is_symlink() and p.is_file() and p.name in expected_files
                for p in root.iterdir()), "Unexpected codec derivation payload")
    return receipt


def repair(out: Path, manifest: Path, prefix: Path, expected: str,
           nm: Path, objcopy: Path) -> dict:
    require(out.is_dir() and not out.is_symlink(), "Invalid native codec output root")
    out = out.resolve(strict=True)
    value = platform(manifest, prefix, expected)
    for tool in (nm, objcopy):
        require(tool.is_file() and not tool.is_symlink() and os.access(tool, os.X_OK),
                "Pinned codec tool is unavailable")
    identity = {
        "platform_sha256": expected, "policy_sha256": digest(Path(__file__)),
        "nm_sha256": digest(nm), "objcopy_sha256": digest(objcopy),
        "sources": {name: value["files"][name]["sha256"]
                    for name in sorted(value["archive_objects"])},
    }
    root = out / DIRECTORY
    require(not root.is_symlink(), "Redirected codec derivation")
    if root.exists():
        receipt = verify_derived(root, identity)
    else:
        tables = {name: symbols(nm, regular(prefix, name)) for name in identity["sources"]}
        owned: set[str] = set()
        for name, anchor in OWNERS.items():
            exports = defined(tables[name])
            require(anchor in exports and not owned.intersection(exports),
                    "Ambiguous codec provider definitions")
            owned.update(exports)
        require(owned, "Empty codec provider ABI")
        renamed = {name: NAMESPACE + name for name in sorted(owned)}
        for name, table in tables.items():
            require(not {n for n, _ in table}.intersection(renamed.values()),
                    "Codec namespace already exists in frozen inputs")
            if name not in OWNERS:
                require(not defined(table).intersection(owned),
                        "Codec symbol is also defined outside its providers")
        affected = {name: table for name, table in tables.items()
                    if {symbol for symbol, _ in table}.intersection(owned)}
        require("lib/libgdk_pixbuf-2.0.a" in affected,
                "Static image loader has no bound codec references")
        with tempfile.TemporaryDirectory(prefix=".cef-codec-stage-", dir=out) as folder:
            stage = Path(folder) / "payload"
            stage.mkdir()
            mapping = stage / "redefine-syms.txt"
            mapping.write_text("".join(f"{a} {b}\n" for a, b in renamed.items()), encoding="ascii")
            records = {}
            for name, before in affected.items():
                filename = hashlib.sha256(name.encode()).hexdigest()[:16] + ".a"
                target = stage / filename
                subprocess.run([str(objcopy), "--redefine-syms=" + str(mapping),
                                str(regular(prefix, name)), str(target)],
                               check=True, capture_output=True, timeout=300)
                after = symbols(nm, target)
                wanted: Counter = Counter()
                for (symbol, kind), count in before.items():
                    wanted[(renamed.get(symbol, symbol), kind)] += count
                require(after == wanted, "Codec definitions/references were not coherently renamed")
                records[name] = {"file": filename, "source_sha256": identity["sources"][name],
                                 "sha256": digest(target)}
            receipt = {"schema": SCHEMA, "kind": "cef-static-gtk-codec-namespace",
                       "identity": identity, "mapping_sha256": digest(mapping),
                       "renamed_symbols": len(renamed), "archives": records,
                       "runtime_verified": False}
            (stage / "receipt.json").write_bytes(canonical(receipt))
            stage.rename(root)
        verify_derived(root, identity)

    # Revalidate frozen bytes even when a derivation was reused; no mutation of
    # vcpkg's manifest or dependency archives is permitted by this repair.
    platform(manifest, prefix, expected)
    pairs = []
    owners = set()
    for name, record in receipt["archives"].items():
        old, new = prefix / name, root / record["file"]
        for a, b in ((str(old), str(new)), (os.path.relpath(old, out), os.path.relpath(new, out))):
            require(not any(c.isspace() or c in "$\"'" for c in a + b), "Unescaped Ninja codec path")
            if name in OWNERS:
                owners.add(len(pairs))
            pairs.append((a.encode(), b.encode()))
    changes, seen = [], set()
    for graph in sorted(out.rglob("*.ninja")):
        require(not graph.is_symlink(), "Redirected Ninja graph")
        data = graph.read_bytes()
        updated, references = rewrite_graph(data, pairs)
        seen.update(references)
        if updated != data:
            changes.append((graph, updated))
    for name in OWNERS:
        target = root / receipt["archives"][name]["file"]
        alternatives = {i for i in owners if pairs[i][1] in
                        {str(target).encode(), os.path.relpath(target, out).encode()}}
        require(seen.intersection(alternatives), "Ninja graph does not link both isolated image codecs")
    for graph, data in changes:
        temporary = graph.with_name(graph.name + ".cef-codecs-new")
        require(not temporary.exists() and not temporary.is_symlink(), "Stale codec graph transaction")
        try:
            temporary.write_bytes(data)
            os.replace(temporary, graph)
        finally:
            temporary.unlink(missing_ok=True)
    return {"schema": SCHEMA, "status": "success", "kind": "cef-static-gtk-codec-status",
            "receipt_sha256": digest(root / "receipt.json"), "graph_paths": len(seen)}


def attach(wrapper: str, source: Path, manifest: Path, prefix: Path,
           expected: str, summary: dict) -> str:
    """Add the verified codec hook to the NSS wrapper generated by this checkout."""
    value = json.loads(manifest.read_bytes())
    if "gtk+-3.0" not in value.get("modules", {}):
        return wrapper  # The standalone NSS-only contract remains unchanged.
    value = platform(manifest, prefix, expected)
    require(wrapper.count(ANCHOR) == 1, "NSS wrapper exec boundary changed")
    script = Path(__file__).resolve()
    llvm = source / "third_party/llvm-build/Release+Asserts/bin"
    command = [str(script), "--manifest", str(manifest), "--prefix", str(prefix),
               "--sha256", expected, "--nm", str(llvm / "llvm-nm"),
               "--objcopy", str(llvm / "llvm-objcopy")]
    hook = ("if out is not None:\n"
            f"    if digest(Path({str(script)!r})) != {digest(script)!r}:\n"
            "        raise RuntimeError('GTK codec policy changed after installation')\n"
            f"    subprocess.run([sys.executable, *{command!r}, '--out', str(out)], check=True)\n")
    summary["gtk_codec_namespace_installed"] = True
    summary["gtk_codec_policy_sha256"] = digest(script)
    summary["gtk_codec_platform_sha256"] = expected
    summary["gtk_codec_inputs_sha256"] = hashlib.sha256(canonical({
        name: value["files"][name]["sha256"] for name in sorted(value["archive_objects"])
    })).hexdigest()
    return wrapper.replace(ANCHOR, hook + ANCHOR)


def record_receipt(source: Path, summary: dict, *, required: bool) -> bool:
    if summary.get("gtk_codec_namespace_installed") is not True:
        return False
    root = source / "out/CEF_Static_Platform_Release_x64" / DIRECTORY
    status_path = root / "status.json"
    if not status_path.is_file() or status_path.is_symlink():
        if required:
            raise RuntimeError("Missing GTK codec namespace evidence")
        return False
    status = json.loads(status_path.read_bytes())
    if status.get("status") != "success":
        summary["gtk_codec_namespace_failure"] = True
        if required:
            raise RuntimeError("GTK codec namespace did not complete")
        return False
    receipt_path = regular(root, "receipt.json")
    require(digest(receipt_path) == status.get("receipt_sha256"), "GTK codec receipt changed")
    receipt = json.loads(receipt_path.read_bytes())
    require(receipt["identity"]["policy_sha256"] == summary.get("gtk_codec_policy_sha256"),
            "GTK codec policy provenance changed")
    require(receipt["identity"]["platform_sha256"] == summary.get("gtk_codec_platform_sha256")
            and hashlib.sha256(canonical(receipt["identity"]["sources"])).hexdigest()
                == summary.get("gtk_codec_inputs_sha256"), "GTK codec input provenance changed")
    verify_derived(root, receipt["identity"])
    summary["gtk_codec_namespace_verified"] = True
    summary["gtk_codec_namespace_symbols"] = receipt["renamed_symbols"]
    summary["gtk_codec_namespace_archives"] = len(receipt["archives"])
    summary["gtk_codec_namespace_receipt_sha256"] = digest(receipt_path)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("out", "manifest", "prefix", "nm", "objcopy"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    root = args.out / DIRECTORY
    # Fail closed rather than reporting a previous successful invocation.
    if root.exists():
        require(not root.is_symlink(), "Redirected codec output")
        (root / "status.json").unlink(missing_ok=True)
    status = repair(args.out, args.manifest, args.prefix, args.sha256, args.nm, args.objcopy)
    (root / "status.json").write_bytes(canonical(status))


if __name__ == "__main__":
    main()
