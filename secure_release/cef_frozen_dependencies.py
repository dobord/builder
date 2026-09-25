"""Replay exact qualified platform archives inside their owning vcpkg packages.

A new source build is not guaranteed to reproduce the checkpoint's archive
bytes. Never change the engine manifest or turn its SHA256 checks into ABI
claims. An ABI-tracked post-portfile hook reuses the authenticated, requalified
archives BEFORE vcpkg installs/owns the package. Built headers must match the
frozen headers byte-for-byte; metadata and other package contents stay intact.
No writes to the frozen prefix or to an already installed package are allowed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import subprocess
import tempfile

if __package__:
    from . import cef_harfbuzz_boundary
else:  # Executed by the explicitly ABI-tracked vcpkg post-portfile hook.
    import cef_harfbuzz_boundary

TRIPLET = "x64-linux-static-release"
PORTS_BLOB = "244769fb406f1248c8d3b7cce0f8ff5075777d7f"
RECEIPT = "cef-frozen-platform-replay.json"


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def clean_path(path: Path) -> Path:
    path = path.absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)),
            "Redirected frozen dependency path")
    return path


def member(root: Path, name: str) -> Path:
    require(isinstance(name, str) and name == PurePosixPath(name).as_posix()
            and not name.startswith("/") and "\\" not in name
            and all(p not in ("", ".", "..") for p in name.split("/")),
            "Invalid frozen dependency member")
    path = clean_path(root / name)
    require(path.is_relative_to(root.absolute()), "Escaped frozen dependency member")
    return path


def checked(path: Path, record: dict) -> None:
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_size == record["size"] and sha(path) == record["sha256"],
            "Frozen dependency bytes differ: " + path.name)


def manifest_at(path: Path, expected: str) -> dict:
    path = clean_path(path)
    require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None
            and path.is_file() and path.stat().st_size <= 16 * 1024**2
            and sha(path) == expected, "Frozen dependency manifest identity changed")
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict) and value.get("schema") == 1
            and value.get("kind") == "linux-x64-static-platform-build-inputs"
            and value.get("runtime_verified") is False
            and isinstance(value.get("files"), dict)
            and isinstance(value.get("archive_objects"), dict)
            and 0 < len(value["archive_objects"]) <= 256,
            "Invalid frozen dependency inventory")
    for name, record in value["files"].items():
        member(path.parent, name)
        require(isinstance(record, dict) and set(record) == {"sha256", "size"}
                and isinstance(record["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None
                and type(record["size"]) is int and record["size"] >= 0,
                "Invalid frozen dependency file identity")
    for name, count in value["archive_objects"].items():
        require(name.startswith("lib/") and name.endswith(".a")
                and name in value["files"] and type(count) is int and count > 0,
                "Invalid frozen dependency archive identity")
    return value


def read_spec(path: Path, expected: str) -> tuple[dict, dict]:
    path = clean_path(path)
    require(path.is_file() and path.stat().st_size <= 65536 and sha(path) == expected,
            "Frozen dependency replay specification changed")
    spec = json.loads(path.read_bytes())
    require(isinstance(spec, dict) and set(spec) == {
        "schema", "kind", "manifest", "platform_sha256", "prefix", "packages", "triplet"
    } and spec["schema"] == 1 and spec["kind"] == "cef-frozen-dependency-replay"
        and spec["triplet"] == TRIPLET, "Invalid frozen replay specification")
    for key in ("prefix", "packages", "manifest"):
        require(isinstance(spec[key], str) and Path(spec[key]).is_absolute(),
                "Nonabsolute frozen replay input")
        clean_path(Path(spec[key]))
    prefix, packages = Path(spec["prefix"]), Path(spec["packages"])
    require(not prefix.is_relative_to(packages) and not packages.is_relative_to(prefix),
            "Frozen and package roots overlap")
    return spec, manifest_at(Path(spec["manifest"]), spec["platform_sha256"])


def exports(path: Path) -> set[str]:
    result = subprocess.run(["nm", "-P", "-g", "--defined-only", str(path)],
                            capture_output=True, text=True, timeout=120)
    require(result.returncode == 0 and len(result.stdout) <= 64 * 1024**2,
            "Cannot verify frozen dependency symbol surface")
    names = set()
    for line in result.stdout.splitlines():
        if not line.strip() or line.endswith(":"):
            continue
        fields = line.split()
        require(len(fields) >= 2 and re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$@]*", fields[0])
                is not None, "Unrecognized frozen dependency symbol")
        names.add(fields[0])
    return names


# Failure evidence is outside the package/prefix. It is collected only by the
# existing encrypted diagnostic collector, NEVER installed/exported or printed.
SYMBOL_EVIDENCE = "symbol-evidence"
EVIDENCE_LIMIT = 16 * 1024**2
_SYMBOL = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@]*\Z")


def elf_details(archive: Path, names: set[str]) -> dict:
    """Describe a rejected difference; visibility never authorizes a replay."""
    result = subprocess.run(["readelf", "--wide", "--symbols", str(archive)],
                            capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, LC_ALL="C"))
    require(result.returncode == 0 and len(result.stdout) <= 128 * 1024**2,
            "Cannot inspect rejected frozen symbol metadata")
    details: dict[str, set[tuple[str, str, str]]] = {n: set() for n in names}
    for line in result.stdout.splitlines():
        fields = line.split()
        if (len(fields) == 8 and fields[0].endswith(":")
                and fields[0][:-1].isdigit() and fields[-1] in names
                and fields[6] != "UND"):
            kind, binding, visibility = fields[3:6]
            require(all(re.fullmatch(r"[A-Z0-9_]+", f) for f in (kind, binding, visibility)),
                    "Unknown rejected ELF symbol metadata")
            details[fields[-1]].add((kind, binding, visibility))
    return {name: [{"type": t, "binding": b, "visibility": v}
                   for t, b, v in sorted(entries)] for name, entries in sorted(details.items())}


def record_mismatch(spec_path: Path, spec: dict, port: str, archives: list[dict],
                    headers: int, features: str, version: str) -> None:
    """Write exact differences before failing, without replacing any archive."""
    require(len(features) <= 4096 and (not features or re.fullmatch(
        r"[a-z0-9-]+(?:;[a-z0-9-]+)*", features)), "Invalid replay feature evidence")
    require(len(version) <= 128 and (not version or re.fullmatch(
        r"[A-Za-z0-9_.+:#-]+", version)), "Invalid replay version evidence")
    directory = clean_path(spec_path.parent / SYMBOL_EVIDENCE)
    for field in ("prefix", "packages"):
        other = Path(spec[field])
        require(not directory.is_relative_to(other) and not other.is_relative_to(directory),
                "Symbol evidence overlaps protected inputs")
    value = {"schema": 1, "kind": "cef-frozen-symbol-mismatch", "port": port,
             "triplet": TRIPLET, "platform_sha256": spec["platform_sha256"],
             "spec_sha256": sha(spec_path), "policy_sha256": sha(Path(__file__)),
             "headers_verified": headers, "features": sorted(set(features.split(";"))) if features else [],
             "version": version, "archives": archives, "runtime_verified": False}
    data = canonical(value)
    require(len(data) <= EVIDENCE_LIMIT, "Oversized frozen symbol evidence")
    directory.mkdir(mode=0o700, exist_ok=True)
    target = member(directory, port + ".json")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def mismatch_summary(overlay: Path, platform_sha: str) -> dict:
    """Release only fixed counters/validated package labels, never symbol names."""
    directory = clean_path(overlay / SYMBOL_EVIDENCE)
    if not directory.exists():
        return {}
    require(directory.is_dir(), "Invalid frozen symbol evidence directory")
    spec_path = clean_path(overlay / "frozen-dependencies.json")
    spec_sha = sha(spec_path)
    spec, inventory = read_spec(spec_path, spec_sha)
    require(spec["platform_sha256"] == platform_sha, "Frozen evidence platform changed")
    paths = sorted(directory.iterdir())
    require(0 < len(paths) <= 256, "Invalid frozen symbol report count")
    reports, archive_count, candidate_count = [], 0, 0
    weak_count, hidden_count, visible_count, cpp_count = 0, 0, 0, 0
    complete = True
    first_archive = None
    for path in paths:
        clean_path(path)
        require(path.is_file() and path.stat().st_size <= EVIDENCE_LIMIT,
                "Invalid frozen symbol evidence file")
        value = json.loads(path.read_bytes())
        require(isinstance(value, dict) and value.get("schema") == 1
                and value.get("kind") == "cef-frozen-symbol-mismatch"
                and value.get("platform_sha256") == platform_sha
                and value.get("policy_sha256") == sha(Path(__file__))
                and value.get("spec_sha256") == spec_sha
                and value.get("runtime_verified") is False and value.get("triplet") == TRIPLET
                and len(str(value.get("port"))) <= 128
                and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", str(value.get("port")))
                and path.name == value["port"] + ".json"
                and isinstance(value.get("archives"), list) and value["archives"],
                "Unbound frozen symbol evidence")
        reports.append(value["port"])
        for record in value["archives"]:
            name = record.get("archive", "")
            member(directory, name)
            require(name in inventory["archive_objects"] and len(Path(name).name) <= 128
                    and record.get("frozen_sha256") == inventory["files"][name]["sha256"]
                    and re.fullmatch(r"[A-Za-z0-9_.+-]+", Path(name).name)
                    and all(re.fullmatch(r"[0-9a-f]{64}", str(record.get(k)))
                            for k in ("built_sha256", "frozen_sha256"))
                    and isinstance(record.get("built_only"), dict) and record["built_only"],
                    "Invalid frozen archive symbol evidence")
            first_archive = first_archive or Path(name).name
            archive_count += 1
            for symbol, entries in record["built_only"].items():
                require(_SYMBOL.fullmatch(symbol) and isinstance(entries, list),
                        "Invalid frozen symbol evidence record")
                candidate_count += 1
                cpp_count += int(symbol.startswith("_Z"))
                complete &= bool(entries)
                for entry in entries:
                    require(isinstance(entry, dict) and set(entry) == {"type", "binding", "visibility"}
                            and all(isinstance(v, str) and re.fullmatch(r"[A-Z0-9_]+", v)
                                    for v in entry.values()), "Invalid ELF evidence fields")
                weak_count += int(any(e["binding"] == "WEAK" for e in entries))
                hidden_count += int(any(e["visibility"] in {"HIDDEN", "INTERNAL"} for e in entries))
                visible_count += int(any(e["binding"] == "GLOBAL" and e["visibility"] in
                                         {"DEFAULT", "PROTECTED"} for e in entries))
    return {"frozen_symbol_evidence_verified": True,
            "frozen_symbol_failure_category": "unproven-symbol-coverage",
            "frozen_symbol_first_port": reports[0], "frozen_symbol_first_archive": first_archive,
            "frozen_symbol_mismatched_archives": archive_count,
            "frozen_symbol_built_only_count": candidate_count,
            "frozen_symbol_weak_count": weak_count, "frozen_symbol_hidden_count": hidden_count,
            "frozen_symbol_visible_global_count": visible_count,
            "frozen_symbol_cpp_mangled_count": cpp_count,
            "frozen_symbol_elf_metadata_complete": complete}


def replay(spec_path: Path, spec_sha: str, package: Path, port: str, triplet: str,
           *, features: str = "", version: str = "", installed: Path | None = None) -> dict:
    spec, value = read_spec(spec_path, spec_sha)
    require(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", port) is not None
            and triplet == spec["triplet"], "Invalid frozen replay package identity")
    package = clean_path(package)
    require(package == Path(spec["packages"]) / (port + "_" + triplet)
            and package.is_dir(), "Replay is only permitted in the owning package staging directory")
    prefix = Path(spec["prefix"])
    selected = [n for n in value["archive_objects"] if member(package, n).exists()]
    if not selected:
        return {"archives": 0, "replaced": 0, "headers": 0}
    # Refuse a different ABI surface rather than transplanting headers too.
    headers = []
    for name, record in value["files"].items():
        if name in value["archive_objects"] or name.endswith(".pc"):
            continue
        candidate = member(package, name)
        if candidate.exists():
            checked(candidate, record)
            checked(member(prefix, name), record)
            headers.append(name)
    records, staged, mismatches = {}, [], []
    receipt = member(package, "share/" + port + "/" + RECEIPT)
    require(not receipt.exists(), "Package already contains a frozen replay receipt")
    for name in selected:
        source, target = member(prefix, name), member(package, name)
        checked(source, value["files"][name])
        require(target.is_file() and target.stat().st_nlink == 1,
                "Invalid built dependency archive")
        with source.open("rb") as stream:
            require(stream.read(8) == b"!<arch>\n", "Frozen dependency is not a regular archive")
        with target.open("rb") as stream:
            require(stream.read(8) == b"!<arch>\n", "Built dependency is not a regular archive")
        built_names, frozen_names = exports(target), exports(source)
        records[name] = {"sha256": value["files"][name]["sha256"], "built_sha256": sha(target)}
        if not built_names <= frozen_names:
            mismatches.append({"archive": name, "built_sha256": records[name]["built_sha256"],
                "frozen_sha256": records[name]["sha256"],
                "built_export_count": len(built_names), "frozen_export_count": len(frozen_names),
                "built_only": elf_details(target, built_names - frozen_names),
                "frozen_only": elf_details(source, frozen_names - built_names)})
    boundary_proof = None
    if mismatches:
        # No general weak/C++ exemption. Only the complete pinned HarfBuzz
        # boundary may be proved using headers, both ELF sets, external
        # references and a live C-linker probe. Every other mismatch still fails.
        if (port == "harfbuzz" and len(mismatches) == 1
                and mismatches[0]["archive"] == cef_harfbuzz_boundary.ARCHIVE):
            try:
                require(installed is not None, "HarfBuzz consumer prefix was not supplied")
                boundary_proof = cef_harfbuzz_boundary.verify(
                    package=package, prefix=prefix, inventory=value,
                    version=version, features=features, installed=installed,
                    output=spec_path.parent / "harfbuzz-boundary-proof",
                )
            except Exception:
                record_mismatch(spec_path, spec, port, mismatches, len(headers), features, version)
                raise
        else:
            record_mismatch(spec_path, spec, port, mismatches, len(headers), features, version)
            raise ValueError("Frozen dependency would lose a built feature symbol: "
                             + Path(mismatches[0]["archive"]).name)
    # Validate all selected bytes and headers before the first replacement.
    # vcpkg has not installed or recorded ownership of this staging tree yet.
    try:
        for name in selected:
            target = member(package, name)
            if records[name]["built_sha256"] == records[name]["sha256"]:
                continue
            fd, filename = tempfile.mkstemp(prefix=".cef-frozen-", dir=target.parent)
            os.close(fd)
            temporary = Path(filename)
            staged.append((target, temporary))
            shutil.copyfile(member(prefix, name), temporary)
            checked(temporary, value["files"][name])
            temporary.chmod(target.stat().st_mode & 0o777)
        for target, temporary in staged:
            os.replace(temporary, target)
        for name in selected:
            checked(member(package, name), value["files"][name])
        receipt.parent.mkdir(parents=True, exist_ok=True)
        with receipt.open("xb") as stream:
            stream.write(canonical({"schema": 1, "kind": "cef-frozen-dependency-replay",
                "port": port, "triplet": triplet, "platform_sha256": spec["platform_sha256"],
                "archives": records, "headers_verified": len(headers), "runtime_verified": False,
                **({"harfbuzz_boundary": boundary_proof} if boundary_proof is not None else {})}))
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)
    return {"archives": len(selected), "replaced": len(staged), "headers": len(headers)}


def _quote(path: Path) -> str:
    value = path.absolute().as_posix()
    require(not any(c in value for c in '\n\r";$'), "Unquotable replay path")
    return '"' + value + '"'


def materialize(destination: Path, base_triplet: Path, manifest: Path, prefix: Path,
                expected: str, packages: Path, ports_script: Path) -> Path:
    """Create a local, explicit ABI universe before any package ABI is computed."""
    for path in (destination, base_triplet, prefix, packages, ports_script):
        clean_path(path)
    value = manifest_at(manifest, expected)
    raw = ports_script.read_bytes()
    require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == PORTS_BLOB,
            "Pinned vcpkg post-portfile ordering changed")
    require(base_triplet.name == TRIPLET + ".cmake" and base_triplet.is_file()
            and not destination.exists(), "Invalid frozen replay triplet destination")
    for name, record in value["files"].items():
        checked(member(prefix, name), record)
    spec = {"schema": 1, "kind": "cef-frozen-dependency-replay", "triplet": TRIPLET,
            "manifest": str(manifest.absolute()), "platform_sha256": expected,
            "prefix": str(prefix.absolute()), "packages": str(packages.absolute())}
    destination.mkdir()
    data = canonical(spec)
    spec_path = destination / "frozen-dependencies.json"
    spec_path.write_bytes(data)
    policy = Path(__file__).resolve()
    boundary = Path(cef_harfbuzz_boundary.__file__).resolve()
    interface = cef_harfbuzz_boundary.INTERFACE
    require(sha(interface) == cef_harfbuzz_boundary.INTERFACE_SHA256,
            "Public HarfBuzz interface policy changed")
    hook = destination / "frozen-dependencies.cmake"
    hook.write_text(
        '# Frozen archive reuse before vcpkg installs its owning package.\n'
        f'file(SHA256 {_quote(policy)} _cef_policy_sha)\n'
        f'if(NOT _cef_policy_sha STREQUAL "{sha(policy)}")\n'
        '  message(FATAL_ERROR "Frozen replay policy changed")\nendif()\n' +
        ''.join(f'file(SHA256 {_quote(p)} _cef_boundary_sha)\n'
                f'if(NOT _cef_boundary_sha STREQUAL "{sha(p)}")\n'
                '  message(FATAL_ERROR "HarfBuzz boundary input changed")\nendif()\n'
                for p in (boundary, interface)) +
        f'execute_process(COMMAND {_quote(Path(sys.executable))} {_quote(policy)}\n'
        f'  --spec {_quote(spec_path)} --sha256 "{hashlib.sha256(data).hexdigest()}"\n'
        '  --package "${CURRENT_PACKAGES_DIR}" --port "${PORT}" --triplet "${TARGET_TRIPLET}"\n'
        '  --features "${FEATURES}" --version "${VERSION}"\n'
        '  --installed "${CURRENT_INSTALLED_DIR}"\n'
        '  COMMAND_ERROR_IS_FATAL ANY)\n', encoding="utf-8", newline="\n")
    triplet = destination / base_triplet.name
    triplet.write_text(
        '# ABI-tracked reuse of the runtime-qualified platform, not a binary cache.\n'
        f'include({_quote(base_triplet)})\n'
        f'list(APPEND VCPKG_POST_PORTFILE_INCLUDES {_quote(hook)})\n'
        'list(APPEND VCPKG_HASH_ADDITIONAL_FILES\n' +
        ''.join('  ' + _quote(p) + '\n' for p in (base_triplet, manifest, spec_path, policy, hook, boundary, interface)) + ')\n',
        encoding="utf-8", newline="\n")
    return destination


def verify_installed(prefix: Path, manifest: Path, expected: str) -> dict:
    """Check exact archives, headers and owning-port receipts after installation/relocation."""
    value = manifest_at(manifest, expected)
    clean_path(prefix)
    # Revalidate the source-defined metadata alias after install and relocation.
    # The archive/header rules below still prohibit all redirected link inputs.
    alias = prefix / "lib/pkgconfig/libcrypt.pc"
    if alias.is_symlink():
        require(cef_harfbuzz_boundary.verified_metadata_alias(alias, prefix, value),
                "Installed libxcrypt metadata alias changed")
    owners = {}
    boundary_fields = {}
    for receipt in sorted((prefix / "share").glob("*/" + RECEIPT)):
        clean_path(receipt)
        require(receipt.is_file() and receipt.stat().st_size <= 1024**2,
                "Invalid packaged replay receipt")
        record = json.loads(receipt.read_bytes())
        port = receipt.parent.name
        require(record.get("schema") == 1 and record.get("kind") == "cef-frozen-dependency-replay"
                and record.get("platform_sha256") == expected and record.get("port") == port
                and record.get("triplet") == TRIPLET and record.get("runtime_verified") is False
                and isinstance(record.get("archives"), dict) and record["archives"],
                "Packaged frozen replay identity changed")
        if "harfbuzz_boundary" in record:
            proof = record["harfbuzz_boundary"]
            archive = record["archives"].get(cef_harfbuzz_boundary.ARCHIVE, {})
            require(port == "harfbuzz" and isinstance(proof, dict)
                    and proof.get("schema") == 1
                    and proof.get("kind") == "harfbuzz-14.2.1-closed-c-boundary"
                    and proof.get("public_link_verified") is True
                    and proof.get("runtime_verified") is False
                    and proof.get("interface_sha256") == cef_harfbuzz_boundary.INTERFACE_SHA256
                    and proof.get("policy_sha256") == sha(Path(cef_harfbuzz_boundary.__file__))
                    and proof.get("frozen_sha256") == archive.get("sha256")
                    and proof.get("built_sha256") == archive.get("built_sha256")
                    and all(type(proof.get(k)) is int and proof[k] >= 0 for k in (
                        "public_functions", "private_built_only", "private_frozen_only", "reference_archives"))
                    and proof["public_functions"] > 400 and proof["reference_archives"] > 0,
                    "Installed HarfBuzz C boundary proof changed")
            boundary_fields = {"frozen_harfbuzz_c_link_verified": True,
                               "frozen_harfbuzz_public_functions": proof["public_functions"]}
        for name, info in record["archives"].items():
            require(name in value["archive_objects"] and name not in owners
                    and info.get("sha256") == value["files"][name]["sha256"],
                    "Duplicate or changed replay ownership")
            owners[name] = port
    require(set(owners) == set(value["archive_objects"]), "Incomplete frozen dependency replay")
    for name, record in value["files"].items():
        if not name.endswith(".pc"):
            checked(member(prefix, name), record)
    # The actual vcpkg file lists, not merely our receipts, establish ownership.
    lists = list((prefix.parent / "vcpkg/info").glob("*_" + TRIPLET + ".list"))
    listed = {}
    for path in lists:
        clean_path(path)
        port = path.name.split("_", 1)[0]
        for name in path.read_text().splitlines():
            if name.startswith(TRIPLET + "/") and name[len(TRIPLET) + 1:] in owners:
                relative = name[len(TRIPLET) + 1:]
                require(relative not in listed, "Duplicate vcpkg dependency owner")
                listed[relative] = port
    require(listed == owners, "Frozen dependencies lost vcpkg package ownership")
    return {"frozen_dependency_archives_verified": len(owners),
            "frozen_dependency_owners_verified": len(set(owners.values())), **boundary_fields}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--triplet", required=True)
    parser.add_argument("--features", default="")
    parser.add_argument("--version", default="")
    parser.add_argument("--installed", type=Path)
    args = parser.parse_args()
    result = replay(args.spec, args.sha256, args.package, args.port, args.triplet,
                    features=args.features, version=args.version, installed=args.installed)
    if result["archives"]:
        print("CEF_FROZEN_DEPENDENCY_REPLAY " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
