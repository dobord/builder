"""Namespace CEF's Chromium/BoringSSL symbols away from vcpkg OpenSSL.

The final combined SDK intentionally links Chromium's BoringSSL and FreeRDP's
OpenSSL into one executable. Static ELF cannot contain two global providers for
the same SSL/X509/PEM API names. Derive the complete collision set from the
pinned installed archives, rewrite ONLY CEF-owned archives in place with the
pinned Chromium llvm-objcopy, and bind every byte through a transport receipt.

OpenSSL archives, FreeRDP archives/objects, CEF public headers, runtime policy,
and success gates remain unchanged.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile

from . import safeio

TRIPLET = "x64-linux-static-release"
OPENSSL_VERSION = "3.6.3"
OPENSSL_PORT_BLOB = "82e2a0232b25f0e52397e80ff2ab93040055b11d"
CEF_VERSION = "152.0.6"
CEF_PORT_VERSION = 15
NAMESPACE = "CEF_CHROMIUM_BSSL_"
OPENSSL_ARCHIVES = ("lib/libssl.a", "lib/libcrypto.a")
CEF_CONFIG = "share/cef-static/cef-static-config.cmake"
CEF_ARCHIVE = re.compile(r"lib/cef-static/(?:cef_objects|cef_[0-9]{4}_[0-9a-f]{12})\.a\Z")
SYMBOL = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@]*\Z")
MAX_CEF_ARCHIVES = 4096
MAX_COLLISIONS = 8192
MAX_SOURCE_ARCHIVE_BYTES = 1024**3
MAX_NM_OUTPUT_BYTES = 2 * 1024**3
MAX_NM_ERROR_BYTES = 16 * 1024**2
MAX_NM_RECORDS = 20_000_000
MAX_NM_LINE_BYTES = 8192
ANCHORS = frozenset({"SSL_new", "SSL_use_certificate", "PEM_read_PrivateKey"})


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def regular(root: Path, relative: str) -> Path:
    require(isinstance(relative, str)
            and relative == PurePosixPath(relative).as_posix()
            and not relative.startswith("/")
            and all(part not in ("", ".", "..") for part in relative.split("/")),
            "Invalid BoringSSL isolation path")
    path = root
    require(not root.is_symlink(), "Redirected BoringSSL isolation root")
    for part in relative.split("/"):
        path /= part
        require(not path.is_symlink(), "Redirected BoringSSL isolation path")
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()),
            "Missing BoringSSL isolation input")
    return path


def validate_sources(upstream: Path) -> None:
    path = regular(upstream, "ports/openssl/vcpkg.json")
    raw = path.read_bytes()
    require(git_blob(raw) == OPENSSL_PORT_BLOB,
            "Pinned OpenSSL port manifest changed")
    value = json.loads(raw)
    require(value.get("name") == "openssl"
            and value.get("version") == OPENSSL_VERSION,
            "Pinned OpenSSL version changed")


def _tools(source: Path) -> tuple[Path, Path]:
    root = source / "third_party/llvm-build/Release+Asserts/bin"
    nm, objcopy = root / "llvm-nm", root / "llvm-objcopy"
    for tool in (nm, objcopy):
        require(tool.is_file() and not tool.is_symlink()
                and os.access(tool, os.X_OK),
                "Pinned Chromium LLVM tool is unavailable")
    return nm, objcopy


def _archive_limit(archive: Path) -> int:
    return (
        safeio.MAX_BYTES
        if archive.name == "cef_objects.a"
        else MAX_SOURCE_ARCHIVE_BYTES
    )


def _archive_size(archive: Path, *, limit: int | None = None) -> int:
    require(archive.is_file() and not archive.is_symlink(),
            "Invalid static archive for BoringSSL isolation")
    if limit is None:
        limit = _archive_limit(archive)
    require(type(limit) is int
            and MAX_SOURCE_ARCHIVE_BYTES <= limit <= safeio.MAX_BYTES,
            "Invalid static archive byte budget for BoringSSL isolation")
    size = archive.stat().st_size
    require(8 <= size <= limit,
            "Invalid static archive for BoringSSL isolation")
    with archive.open("rb") as stream:
        require(stream.read(8) == b"!<arch>\n",
                "BoringSSL isolation input is not a regular archive")
    return size


def _symbol_records(nm: Path, archive: Path, *, archive_limit: int | None = None):
    """Stream bounded llvm-nm output through disk, never one giant Python string."""
    _archive_size(archive, limit=archive_limit)
    with tempfile.TemporaryDirectory(prefix=".cef-bssl-nm-") as folder:
        root = Path(folder)
        stdout = root / "stdout"
        stderr = root / "stderr"
        with stdout.open("wb") as out, stderr.open("wb") as err:
            result = subprocess.run(
                [str(nm), "-P", "-g", "--no-demangle", str(archive)],
                stdout=out, stderr=err, timeout=900,
            )
        require(
            result.returncode == 0
            and stdout.stat().st_size <= MAX_NM_OUTPUT_BYTES
            and stderr.stat().st_size <= MAX_NM_ERROR_BYTES,
            "Cannot inspect static symbols for BoringSSL isolation",
        )
        count = 0
        with stdout.open("rb") as stream:
            for raw in stream:
                require(len(raw) <= MAX_NM_LINE_BYTES,
                        "Oversized BoringSSL symbol record")
                line = raw.rstrip(b"\r\n")
                if not line.strip() or line.rstrip().endswith(b":"):
                    continue
                fields = line.split()
                require(len(fields) >= 2,
                        "Unrecognized BoringSSL symbol record")
                try:
                    name = fields[0].decode("ascii")
                    kind = fields[1].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        "Unrecognized BoringSSL symbol record"
                    ) from exc
                require(
                    SYMBOL.fullmatch(name) is not None
                    and re.fullmatch(r"[A-Za-z?]", kind) is not None,
                    "Unrecognized BoringSSL symbol record",
                )
                count += 1
                require(count <= MAX_NM_RECORDS,
                        "BoringSSL symbol inventory exceeds bounded records")
                yield name, kind


def _symbols(
    nm: Path, archive: Path, *, archive_limit: int | None = None
) -> Counter:
    return Counter(_symbol_records(nm, archive, archive_limit=archive_limit))


def _defined(table: Counter) -> set[str]:
    return {name for name, kind in table if kind not in {"U", "w", "v"}}


def _profile_symbols(
    nm: Path,
    archive: Path,
    *,
    watch: set[str],
    reverse: dict[str, str] | None = None,
    forbidden: set[str] | None = None,
    forbidden_prefix: str | None = None,
    archive_limit: int | None = None,
) -> tuple[dict[str, int | str], Counter]:
    reverse = reverse or {}
    forbidden = forbidden or set()
    digestor = hashlib.sha256()
    relevant: Counter = Counter()
    count = 0
    for name, kind in _symbol_records(
            nm, archive, archive_limit=archive_limit):
        if name in forbidden or (
            forbidden_prefix is not None and name.startswith(forbidden_prefix)
        ):
            raise ValueError("BoringSSL isolation namespace already exists")
        if name in watch:
            relevant[(name, kind)] += 1
        normalized = reverse.get(name, name).encode("ascii")
        digestor.update(len(normalized).to_bytes(4, "big"))
        digestor.update(normalized)
        digestor.update(kind.encode("ascii"))
        count += 1
    return {
        "count": count,
        "sha256": digestor.hexdigest(),
    }, relevant


def _cef_archives(prefix: Path) -> list[tuple[str, Path]]:
    config = regular(prefix, CEF_CONFIG)
    text = config.read_text(encoding="utf-8")
    names = re.findall(
        r'\$\{_cef_static_prefix\}/(lib/cef-static/(?:cef_objects|cef_[0-9]{4}_[0-9a-f]{12})\.a)"',
        text,
    )
    unique = list(dict.fromkeys(names))
    require(names and len(unique) == len(names)
            and 1 < len(unique) <= MAX_CEF_ARCHIVES,
            "CEF static target archive inventory is ambiguous")
    archives = [(name, regular(prefix, name)) for name in unique]
    sizes = [_archive_size(path) for _, path in archives]
    require(sum(sizes) <= safeio.MAX_BYTES,
            "CEF static archive closure exceeds SDK byte budget")
    return archives


def _status_records(installed: Path) -> list[dict[str, str]]:
    status = regular(installed, "vcpkg/status")
    require(status.stat().st_size <= 32 * 1024**2,
            "Oversized vcpkg status database")
    text = status.read_text(encoding="utf-8")
    records: list[dict[str, str]] = []
    for block in re.split(r"\r?\n\r?\n+", text.strip()):
        if not block:
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line.startswith((" ", "\t")):
                continue
            require(": " in line, "Malformed vcpkg status record")
            key, value = line.split(": ", 1)
            require(key and key not in fields,
                    "Duplicate vcpkg status field")
            fields[key] = value
        records.append(fields)
    require(records, "Empty vcpkg status database")
    return records


def _installed_identity(installed: Path, package: str, version: str,
                        port_version: int) -> None:
    candidates = []
    for fields in _status_records(installed):
        if (fields.get("Package") == package
                and fields.get("Architecture") == TRIPLET
                and fields.get("Status") == "install ok installed"
                and fields.get("Feature") in (None, "core")):
            candidates.append(fields)
    require(len(candidates) == 1,
            "Expected one installed package identity for BoringSSL isolation")
    fields = candidates[0]
    raw_version = fields.get("Version")
    port_field = fields.get("Port-Version")
    valid_version = raw_version in {
        version,
        version + "#" + str(port_version),
    }
    valid_port = (
        port_field is None
        or (port_field.isdigit() and int(port_field) == port_version)
    )
    require(valid_version and valid_port,
            "Installed package version changed for BoringSSL isolation")


def _owner(installed: Path, package: str, version: str, port_version: int,
           required: set[str]) -> None:
    require(required, "Empty package ownership proof")
    _installed_identity(installed, package, version, port_version)
    info = installed / "vcpkg/info"
    require(info.is_dir() and not info.is_symlink(),
            "Missing vcpkg package ownership inventory")
    lists = sorted(info.glob("*_" + TRIPLET + ".list"))
    require(0 < len(lists) <= 4096,
            "Invalid vcpkg package ownership inventory")
    owners: dict[str, list[Path]] = {name: [] for name in required}
    total = 0
    for listing in lists:
        require(listing.is_file() and not listing.is_symlink(),
                "Redirected vcpkg package ownership list")
        size = listing.stat().st_size
        total += size
        require(size <= 32 * 1024**2 and total <= 128 * 1024**2,
                "Oversized vcpkg package ownership inventory")
        lines = set(listing.read_text(encoding="utf-8").splitlines())
        for name in required.intersection(lines):
            owners[name].append(listing)
    require(all(len(value) == 1 for value in owners.values()),
            "Static archive lost its unique vcpkg package owner")
    unique = {value[0] for value in owners.values()}
    require(len(unique) == 1,
            "Static archives are split across vcpkg package owners")
    owner = next(iter(unique))
    require(owner.name.startswith(package + "_")
            and owner.name.endswith("_" + TRIPLET + ".list"),
            "Static archive owner package changed")


def _ownership(installed: Path, cef_names: list[str]) -> None:
    _owner(
        installed, "cef-static", CEF_VERSION, CEF_PORT_VERSION,
        {TRIPLET + "/" + name for name in cef_names},
    )
    _owner(
        installed, "openssl", OPENSSL_VERSION, 0,
        {TRIPLET + "/" + name for name in OPENSSL_ARCHIVES},
    )


def _mapping_bytes(symbols: list[str]) -> bytes:
    return "".join(
        name + " " + NAMESPACE + name + "\n" for name in symbols
    ).encode("ascii")


def _archive_hashes(archives: list[tuple[str, Path]]) -> dict[str, str]:
    return {name: digest(path) for name, path in archives}


def install(installed: Path, source: Path, diagnostics: Path) -> dict:
    """Rewrite CEF-owned collision symbols after vcpkg install, before export."""
    installed = installed.resolve(strict=True)
    regular(installed, "vcpkg/status")
    prefix = installed / TRIPLET
    require(prefix.is_dir() and not prefix.is_symlink(),
            "Invalid installed triplet for BoringSSL isolation")
    nm, objcopy = _tools(source)
    cef = _cef_archives(prefix)
    cef_names = [name for name, _ in cef]
    _ownership(installed, cef_names)

    providers = [(name, regular(prefix, name)) for name in OPENSSL_ARCHIVES]
    provider_hashes = {name: digest(path) for name, path in providers}
    openssl_defined: set[str] = set()
    openssl_names: set[str] = set()
    for _, path in providers:
        table = _symbols(nm, path)
        openssl_defined.update(_defined(table))
        openssl_names.update(name for name, _ in table)

    collisions: set[str] = set()
    source_hashes = _archive_hashes(cef)
    profiles: dict[str, dict[str, int | str]] = {}
    candidates: dict[str, Counter] = {}
    for name, path in cef:
        profile, relevant = _profile_symbols(
            nm, path, watch=openssl_defined, forbidden_prefix=NAMESPACE
        )
        profiles[name] = profile
        candidates[name] = relevant
        collisions.update(
            symbol for (symbol, kind), count in relevant.items()
            if count and kind not in {"U", "w", "v"}
        )

    ordered = sorted(collisions)
    require(ANCHORS <= collisions
            and 1 <= len(ordered) <= MAX_COLLISIONS,
            "Unexpected Chromium/OpenSSL collision inventory")
    require(all(SYMBOL.fullmatch(name) is not None and len(name) <= 512
                for name in ordered),
            "Invalid Chromium/OpenSSL collision symbol")
    renamed = {name: NAMESPACE + name for name in ordered}
    require(not set(renamed.values()).intersection(openssl_names),
            "BoringSSL isolation namespace already exists")

    diagnostics.mkdir(parents=True, exist_ok=False)
    mapping = diagnostics / "redefine-syms.txt"
    mapping.write_bytes(_mapping_bytes(ordered))
    mapping.chmod(0o600)
    mapping_sha = digest(mapping)

    affected: dict[str, dict] = {}
    try:
        reverse = {new: old for old, new in renamed.items()}
        watched = collisions | set(renamed.values())
        for name, path in cef:
            relevant = Counter(
                {
                    (symbol, kind): count
                    for (symbol, kind), count in candidates[name].items()
                    if symbol in collisions
                }
            )
            if not relevant:
                continue
            old_mode = stat.S_IMODE(path.stat().st_mode)
            fd, temp_name = tempfile.mkstemp(
                prefix=".cef-bssl-", suffix=".a", dir=path.parent
            )
            os.close(fd)
            temporary = Path(temp_name)
            try:
                temporary.unlink()
                subprocess.run(
                    [str(objcopy), "--redefine-syms=" + str(mapping),
                     str(path), str(temporary)],
                    check=True, timeout=600,
                )
                temporary.chmod(old_mode)
                after_profile, after = _profile_symbols(
                    nm,
                    temporary,
                    watch=watched,
                    reverse=reverse,
                    forbidden=collisions,
                    archive_limit=_archive_limit(path),
                )
                require(
                    after_profile == profiles[name],
                    "CEF archive global symbol table changed outside namespace mapping",
                )
                for (old, kind), count in relevant.items():
                    require(
                        after.get((renamed[old], kind), 0) == count,
                        "CEF BoringSSL symbol isolation is incomplete",
                    )
                source_sha = source_hashes[name]
                derived_sha = digest(temporary)
                os.replace(temporary, path)
                affected[name] = {
                    "source_sha256": source_sha,
                    "sha256": derived_sha,
                    "renamed_occurrences": sum(relevant.values()),
                    "global_symbol_count": profiles[name]["count"],
                    "global_symbol_sha256": profiles[name]["sha256"],
                }
            finally:
                temporary.unlink(missing_ok=True)
    finally:
        mapping.unlink(missing_ok=True)

    require(affected, "No CEF archive was transformed for BoringSSL isolation")
    final_hashes = _archive_hashes(cef)
    require(set(final_hashes) == set(source_hashes)
            and all(final_hashes[name] != source_hashes[name]
                    for name in affected)
            and all(final_hashes[name] == source_hashes[name]
                    for name in set(source_hashes) - set(affected)),
            "Unexpected CEF archive mutation during BoringSSL isolation")
    for _, path in providers:
        require(digest(path) == provider_hashes[
            path.relative_to(prefix).as_posix()
        ], "OpenSSL provider changed during CEF BoringSSL isolation")

    receipt = {
        "schema": 1,
        "kind": "cef-chromium-boringssl-isolation",
        "namespace": NAMESPACE,
        "mapping_sha256": mapping_sha,
        "collision_count": len(ordered),
        "symbols": ordered,
        "openssl": {
            "version": OPENSSL_VERSION,
            "archives": provider_hashes,
        },
        "cef_archives": final_hashes,
        "affected": affected,
        "nm_sha256": digest(nm),
        "objcopy_sha256": digest(objcopy),
    }
    (diagnostics / "receipt.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return receipt


def verify(installed: Path, source: Path, receipt: dict) -> dict:
    """Recheck exact transformed bytes after raw export and relocation."""
    require(isinstance(receipt, dict)
            and receipt.get("schema") == 1
            and receipt.get("kind") == "cef-chromium-boringssl-isolation"
            and receipt.get("namespace") == NAMESPACE
            and receipt.get("openssl", {}).get("version") == OPENSSL_VERSION,
            "Missing CEF BoringSSL isolation receipt")
    symbols = receipt.get("symbols")
    require(isinstance(symbols, list)
            and symbols == sorted(set(symbols))
            and ANCHORS <= set(symbols)
            and len(symbols) == receipt.get("collision_count")
            and 1 <= len(symbols) <= MAX_COLLISIONS
            and hashlib.sha256(_mapping_bytes(symbols)).hexdigest()
                == receipt.get("mapping_sha256"),
            "Invalid CEF BoringSSL isolation mapping")
    installed = installed.resolve(strict=True)
    prefix = installed / TRIPLET
    require(prefix.is_dir() and not prefix.is_symlink(),
            "Missing relocated triplet for CEF BoringSSL isolation")
    nm, objcopy = _tools(source)
    require(digest(nm) == receipt.get("nm_sha256")
            and digest(objcopy) == receipt.get("objcopy_sha256"),
            "BoringSSL isolation tool identity changed")

    cef = _cef_archives(prefix)
    names = [name for name, _ in cef]
    require(set(names) == set(receipt.get("cef_archives", {})),
            "CEF archive inventory changed in SDK transport")
    _ownership(installed, names)
    for name, path in cef:
        require(digest(path) == receipt["cef_archives"][name],
                "CEF BoringSSL-isolated archive changed in transport")

    providers = receipt.get("openssl", {}).get("archives")
    require(isinstance(providers, dict)
            and set(providers) == set(OPENSSL_ARCHIVES),
            "OpenSSL provider receipt changed")
    for name in OPENSSL_ARCHIVES:
        require(digest(regular(prefix, name)) == providers[name],
                "OpenSSL provider changed in SDK transport")

    affected = receipt.get("affected")
    require(isinstance(affected, dict)
            and affected and set(affected) <= set(names),
            "CEF BoringSSL affected archive receipt changed")
    for name, record in affected.items():
        require(isinstance(record, dict)
                and set(record) == {
                    "source_sha256", "sha256", "renamed_occurrences",
                    "global_symbol_count", "global_symbol_sha256",
                }
                and record["sha256"] == receipt["cef_archives"][name]
                and record["source_sha256"] != record["sha256"]
                and type(record["renamed_occurrences"]) is int
                and record["renamed_occurrences"] > 0
                and type(record["global_symbol_count"]) is int
                and 0 < record["global_symbol_count"] <= MAX_NM_RECORDS
                and isinstance(record["global_symbol_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}",
                                 record["global_symbol_sha256"]) is not None,
                "Invalid CEF BoringSSL affected archive receipt")
    return {
        "cef_boringssl_isolation_verified": True,
        "cef_boringssl_collision_count": len(symbols),
        "cef_boringssl_affected_archive_count": len(affected),
        "cef_boringssl_mapping_sha256": receipt["mapping_sha256"],
    }
