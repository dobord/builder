"""Namespace CEF's Chromium runtime away from final consumer runtimes.

The final combined SDK intentionally links Chromium's BoringSSL beside vcpkg
OpenSSL and Chromium's libc++/libc++abi beside a GCC-built consumer closure.
Static ELF cannot contain duplicate global providers. Derive BOTH complete
collision sets from the pinned CEF archives and the actual final providers,
rewrite ONLY CEF-owned definitions and references in one llvm-objcopy mapping,
and bind every byte through one transport receipt.

OpenSSL, GCC runtime archives, FreeRDP archives/objects, CEF public headers,
runtime policy, and success gates remain unchanged.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import heapq
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import tempfile

from . import cef_crel, safeio

TRIPLET = "x64-linux-static-release"
OPENSSL_VERSION = "3.6.3"
OPENSSL_PORT_BLOB = "82e2a0232b25f0e52397e80ff2ab93040055b11d"
CEF_VERSION = "152.0.6"
CEF_PORT_VERSION = 15
NAMESPACE = "CEF_CHROMIUM_BSSL_"
CXX_NAMESPACE = "CEF_CHROMIUM_CXX_"
FFMPEG_NAMESPACE = "CEF_CHROMIUM_FFMPEG_"
ATOMIC_NAMESPACE = "CEF_CHROMIUM_ATOMIC_"
OPENSSL_ARCHIVES = ("lib/libssl.a", "lib/libcrypto.a")
FFMPEG_VERSION = "8.1.2"
FFMPEG_PORT_VERSION = 4
FFMPEG_ARCHIVES = (
    "lib/libavcodec.a",
    "lib/libavdevice.a",
    "lib/libavfilter.a",
    "lib/libavformat.a",
    "lib/libavutil.a",
    "lib/libswresample.a",
    "lib/libswscale.a",
)
GXX = Path("/usr/bin/g++-14")
GCC_ROOT = Path("/usr/lib/gcc/x86_64-linux-gnu/14")
GCC_RUNTIME_ARCHIVES = ("libstdc++.a", "libgcc.a", "libgcc_eh.a")
GCC_ATOMIC_ARCHIVE = "libatomic.a"
CEF_CONFIG = "share/cef-static/cef-static-config.cmake"
CEF_ARCHIVE = re.compile(r"lib/cef-static/(?:cef_objects|cef_[0-9]{4}_[0-9a-f]{12})\.a\Z")
SYMBOL = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@]*\Z")
MAX_CEF_ARCHIVES = 4096
MAX_COLLISIONS = 8192
MAX_CXX_COLLISIONS = 8192
MAX_FFMPEG_COLLISIONS = 8192
MAX_ATOMIC_COLLISIONS = 4096
MAX_SOURCE_ARCHIVE_BYTES = 1024**3
MAX_NM_OUTPUT_BYTES = 2 * 1024**3
MAX_NM_ERROR_BYTES = 16 * 1024**2
MAX_NM_RECORDS = 20_000_000
MAX_NM_LINE_BYTES = 8192
PROFILE_CHUNK_RECORDS = 100_000
ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_SECTION = struct.Struct("<IIQQQQIIQQ")
AR_HEADER_BYTES = 60
INIT_ARRAY_ALIGNMENT = 8
MAX_ARCHIVE_MEMBERS = 2_000_000
MAX_INIT_ARRAY_SECTIONS = 2_000_000
ANCHORS = frozenset({"SSL_new", "SSL_use_certificate", "PEM_read_PrivateKey"})
CXX_ANCHORS = frozenset({
    "_ZNSt9type_infoD0Ev",
    "_ZN10__cxxabiv117__class_type_infoD0Ev",
    "_ZNSt9exceptionD0Ev",
})
FFMPEG_ANCHORS = frozenset({
    "av_dynamic_hdr_plus_alloc",
    "av_dynamic_hdr_plus_create_side_data",
    "av_dynamic_hdr_plus_from_t35",
    "av_dynamic_hdr_plus_to_t35",
})
ATOMIC_ANCHORS = frozenset({
    "__atomic_load",
    "__atomic_store",
    "__atomic_load_16",
    "__atomic_store_16",
    "__atomic_compare_exchange_16",
})


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


def _ar_elf_payloads(archive: Path, *, archive_limit: int | None = None):
    """Yield bounded regular-archive ELF member payloads in physical order."""
    archive_size = _archive_size(archive, limit=archive_limit)
    with archive.open("rb") as stream:
        require(stream.read(8) == b"!<arch>\n",
                "CEF startup-alignment input is not a regular archive")
        member_index = 0
        while True:
            header = stream.read(AR_HEADER_BYTES)
            if not header:
                break
            require(len(header) == AR_HEADER_BYTES and header[58:] == b"\x60\n",
                    "Malformed CEF archive member header")
            raw_size = header[48:58].strip()
            require(raw_size.isdigit(), "Malformed CEF archive member size")
            size = int(raw_size)
            require(0 <= size <= archive_size - stream.tell() - (size & 1),
                    "CEF archive member exceeds SDK byte budget")
            # Archive indexes/name tables can be large. Only materialize ELF
            # members; keep declared sizes inside the already validated file.
            magic = stream.read(min(4, size))
            if magic == b"\x7fELF":
                payload = magic + stream.read(size - len(magic))
                require(len(payload) == size, "Truncated CEF archive member")
            else:
                stream.seek(size - len(magic), os.SEEK_CUR)
                payload = b""
            if size & 1:
                require(stream.read(1) == b"\n", "Malformed CEF archive padding")
            member_index += 1
            require(member_index <= MAX_ARCHIVE_MEMBERS,
                    "CEF archive has too many members")
            if payload.startswith(b"\x7fELF"):
                yield member_index, payload


def _elf_init_array_sections(payload: bytes):
    """Return (.init_array*, size, alignment) records from one ELF64 object."""
    require(len(payload) >= ELF64_HEADER.size, "Truncated CEF ELF member")
    header = ELF64_HEADER.unpack_from(payload, 0)
    ident = header[0]
    require(ident[:7] == b"\x7fELF\x02\x01\x01",
            "CEF startup-alignment audit requires little-endian ELF64")
    e_shoff = header[6]
    e_ehsize = header[8]
    e_shentsize = header[11]
    e_shnum = header[12]
    e_shstrndx = header[13]
    require(
        e_ehsize == ELF64_HEADER.size
        and e_shentsize == ELF64_SECTION.size
        and 1 <= e_shnum <= 65535
        and 0 < e_shstrndx < e_shnum
        and e_shoff + e_shnum * e_shentsize <= len(payload),
        "Invalid CEF ELF section table",
    )
    sections = [
        ELF64_SECTION.unpack_from(payload, e_shoff + i * e_shentsize)
        for i in range(e_shnum)
    ]
    shstr = sections[e_shstrndx]
    names_offset, names_size = shstr[4], shstr[5]
    require(names_offset + names_size <= len(payload),
            "Invalid CEF ELF section-name table")
    names = payload[names_offset:names_offset + names_size]

    def section_name(offset: int) -> str:
        require(0 <= offset < len(names), "Invalid CEF ELF section-name offset")
        end = names.find(b"\0", offset)
        require(end >= 0, "Unterminated CEF ELF section name")
        try:
            return names[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("Non-ASCII CEF ELF section name") from error

    for values in sections:
        name = section_name(values[0])
        size = values[5]
        alignment = values[8]
        if (name == ".init_array" or name.startswith(".init_array.")) and size:
            require(
                alignment >= 1 and alignment & (alignment - 1) == 0,
                "Invalid CEF init-array section alignment",
            )
            yield name, size, alignment


def _init_array_profile(
    archive: Path, *, archive_limit: int | None = None
) -> list[tuple[int, str, int, int]]:
    records: list[tuple[int, str, int, int]] = []
    for member_index, payload in _ar_elf_payloads(
        archive, archive_limit=archive_limit
    ):
        for name, size, alignment in _elf_init_array_sections(payload):
            records.append((member_index, name, size, alignment))
            require(len(records) <= MAX_INIT_ARRAY_SECTIONS,
                    "CEF init-array inventory exceeds bounded sections")
    return records


def _normalized_init_array_profile(records):
    return [
        (member, name, size, min(alignment, INIT_ARRAY_ALIGNMENT))
        for member, name, size, alignment in records
    ]


def _profile_sha256(records) -> str:
    raw = "".join(
        f"{member}\t{name}\t{size}\t{alignment}\n"
        for member, name, size, alignment in records
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _gcc_runtime() -> tuple[dict, list[tuple[str, Path]]]:
    """Bind the exact GCC14 static runtime archives used by final consumers."""
    resolved_driver = GXX.resolve(strict=True)
    require(
        resolved_driver.is_file() and os.access(GXX, os.X_OK),
        "Pinned GCC14 consumer driver is unavailable",
    )
    version = subprocess.check_output(
        [str(GXX), "-dumpfullversion"], text=True, timeout=30
    ).strip()
    require(
        re.fullmatch(r"14\.[0-9.]+", version) is not None,
        "Pinned GCC14 consumer version changed",
    )
    root = GCC_ROOT.resolve(strict=True)
    providers: list[tuple[str, Path]] = []
    archives: dict[str, dict[str, str]] = {}
    for name in GCC_RUNTIME_ARCHIVES:
        raw = subprocess.check_output(
            [str(GXX), "-print-file-name=" + name], text=True, timeout=30
        ).strip()
        path = Path(raw)
        require(
            path.is_absolute() and path.name == name,
            "GCC static runtime archive lookup changed",
        )
        resolved = path.resolve(strict=True)
        require(
            resolved.is_file() and resolved.is_relative_to(root),
            "GCC static runtime archive escaped pinned GCC14 root",
        )
        _archive_size(resolved)
        providers.append((name, resolved))
        archives[name] = {
            "path": resolved.as_posix(),
            "sha256": digest(resolved),
        }
    receipt = {
        "driver": GXX.as_posix(),
        "driver_sha256": digest(resolved_driver),
        "version": version,
        "root": root.as_posix(),
        "archives": archives,
    }
    return receipt, providers


def _gcc_atomic() -> tuple[dict, list[tuple[str, Path]]]:
    """Bind the exact GCC14 libatomic provider pulled by final static proxy links."""
    raw = subprocess.check_output(
        [str(GXX), "-print-file-name=" + GCC_ATOMIC_ARCHIVE],
        text=True, timeout=30,
    ).strip()
    path = Path(raw)
    require(
        path.is_absolute() and path.name == GCC_ATOMIC_ARCHIVE,
        "GCC libatomic archive lookup changed",
    )
    root = GCC_ROOT.resolve(strict=True)
    resolved = path.resolve(strict=True)
    require(
        resolved.is_file() and resolved.is_relative_to(root),
        "GCC libatomic archive escaped pinned GCC14 root",
    )
    _archive_size(resolved)
    receipt = {
        "name": GCC_ATOMIC_ARCHIVE,
        "path": resolved.as_posix(),
        "sha256": digest(resolved),
    }
    return receipt, [(GCC_ATOMIC_ARCHIVE, resolved)]


def _ffmpeg_runtime(
    installed: Path,
    prefix: Path,
    *,
    expected: dict | None = None,
    require_status: bool = True,
) -> tuple[dict, list[tuple[str, Path]]]:
    """Bind the complete pinned vcpkg FFmpeg static provider set and ownership."""
    required = {TRIPLET + "/" + name for name in FFMPEG_ARCHIVES}
    owner = _owner(
        installed,
        "ffmpeg",
        FFMPEG_VERSION,
        FFMPEG_PORT_VERSION,
        required,
        expected=None if expected is None else expected.get("ownership"),
        require_status=require_status,
    )
    providers = [(name, regular(prefix, name)) for name in FFMPEG_ARCHIVES]
    archives = {name: digest(path) for name, path in providers}
    result = {
        "version": FFMPEG_VERSION,
        "port_version": FFMPEG_PORT_VERSION,
        "ownership": owner,
        "archives": archives,
    }
    if expected is not None:
        require(result == expected,
                "FFmpeg static runtime provider changed in SDK transport")
    return result, providers


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


def _profile_records(
    records,
    *,
    watch: set[str],
    reverse: dict[str, str] | None = None,
    forbidden: set[str] | None = None,
    forbidden_prefixes: tuple[str, ...] = (),
) -> tuple[dict[str, int | str], Counter]:
    """Canonicalize the complete global-symbol multiset with bounded memory."""
    reverse = reverse or {}
    forbidden = forbidden or set()
    relevant: Counter = Counter()
    count = 0
    canonical_bytes = 0
    with tempfile.TemporaryDirectory(prefix=".cef-bssl-profile-") as folder:
        root = Path(folder)
        chunks: list[Path] = []
        pending: list[bytes] = []

        def flush() -> None:
            if not pending:
                return
            pending.sort()
            path = root / f"{len(chunks):06d}.symbols"
            with path.open("wb") as stream:
                stream.writelines(pending)
            chunks.append(path)
            pending.clear()

        for name, kind in records:
            if name in forbidden or any(
                name.startswith(prefix) for prefix in forbidden_prefixes
            ):
                raise ValueError("CEF runtime isolation namespace already exists")
            if name in watch:
                relevant[(name, kind)] += 1
            normalized = reverse.get(name, name)
            require(SYMBOL.fullmatch(normalized) is not None,
                    "Invalid normalized BoringSSL symbol")
            record = (normalized + "\t" + kind + "\n").encode("ascii")
            canonical_bytes += len(record)
            require(canonical_bytes <= MAX_NM_OUTPUT_BYTES,
                    "Canonical BoringSSL symbol inventory exceeds byte budget")
            pending.append(record)
            count += 1
            require(count <= MAX_NM_RECORDS,
                    "BoringSSL symbol inventory exceeds bounded records")
            if len(pending) >= PROFILE_CHUNK_RECORDS:
                flush()
        flush()

        digestor = hashlib.sha256()
        streams = [path.open("rb") for path in chunks]
        try:
            for record in heapq.merge(*streams):
                digestor.update(record)
        finally:
            for stream in streams:
                stream.close()

    return {
        "count": count,
        "sha256": digestor.hexdigest(),
    }, relevant


def _profile_symbols(
    nm: Path,
    archive: Path,
    *,
    watch: set[str],
    reverse: dict[str, str] | None = None,
    forbidden: set[str] | None = None,
    forbidden_prefixes: tuple[str, ...] = (),
    archive_limit: int | None = None,
) -> tuple[dict[str, int | str], Counter]:
    return _profile_records(
        _symbol_records(nm, archive, archive_limit=archive_limit),
        watch=watch,
        reverse=reverse,
        forbidden=forbidden,
        forbidden_prefixes=forbidden_prefixes,
    )


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
                        port_version: int) -> dict[str, object]:
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
    return {
        "package": package,
        "version": version,
        "port_version": port_version,
        "triplet": TRIPLET,
    }


def _owner(
    installed: Path,
    package: str,
    version: str,
    port_version: int,
    required: set[str],
    *,
    expected: dict | None = None,
    require_status: bool = True,
) -> dict:
    require(required, "Empty package ownership proof")
    status = installed / "vcpkg/status"
    if require_status or status.exists():
        identity = _installed_identity(
            installed, package, version, port_version
        )
    else:
        require(expected is not None,
                "Missing installed package identity receipt")
        identity = {
            "package": package,
            "version": version,
            "port_version": port_version,
            "triplet": TRIPLET,
        }
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
    result = {
        "package": package,
        "version": version,
        "port_version": port_version,
        "triplet": TRIPLET,
        "owner": owner.name,
        "owner_sha256": digest(owner),
        "required_count": len(required),
    }
    if expected is not None:
        require(result == expected,
                "Static archive ownership receipt changed in transport")
    return result


def _ownership(
    installed: Path,
    cef_names: list[str],
    *,
    expected: dict | None = None,
    require_status: bool = True,
) -> dict:
    if expected is not None:
        require(
            isinstance(expected, dict)
            and set(expected) == {"cef-static", "openssl"},
            "Invalid BoringSSL ownership receipt",
        )
    result = {
        "cef-static": _owner(
            installed, "cef-static", CEF_VERSION, CEF_PORT_VERSION,
            {TRIPLET + "/" + name for name in cef_names},
            expected=None if expected is None else expected["cef-static"],
            require_status=require_status,
        ),
        "openssl": _owner(
            installed, "openssl", OPENSSL_VERSION, 0,
            {TRIPLET + "/" + name for name in OPENSSL_ARCHIVES},
            expected=None if expected is None else expected["openssl"],
            require_status=require_status,
        ),
    }
    if expected is not None:
        require(result == expected,
                "BoringSSL package ownership changed in SDK transport")
    return result


def _domain_mapping_bytes(symbols: list[str], prefix: str) -> bytes:
    return "".join(
        name + " " + prefix + name + "\n" for name in symbols
    ).encode("ascii")


def _mapping_bytes(
    symbols: list[str],
    cxx_symbols: list[str],
    ffmpeg_symbols: list[str],
    atomic_symbols: list[str],
) -> bytes:
    pairs = {
        **{name: NAMESPACE + name for name in symbols},
        **{name: CXX_NAMESPACE + name for name in cxx_symbols},
        **{name: FFMPEG_NAMESPACE + name for name in ffmpeg_symbols},
        **{name: ATOMIC_NAMESPACE + name for name in atomic_symbols},
    }
    require(
        len(pairs)
        == len(symbols) + len(cxx_symbols) + len(ffmpeg_symbols)
           + len(atomic_symbols),
        "Overlapping CEF runtime isolation collision sets",
    )
    return "".join(
        name + " " + pairs[name] + "\n" for name in sorted(pairs)
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
    ownership_receipt = _ownership(installed, cef_names)

    providers = [(name, regular(prefix, name)) for name in OPENSSL_ARCHIVES]
    provider_hashes = {name: digest(path) for name, path in providers}
    openssl_defined: set[str] = set()
    openssl_names: set[str] = set()
    for _, path in providers:
        table = _symbols(nm, path)
        openssl_defined.update(_defined(table))
        openssl_names.update(name for name, _ in table)

    gcc_runtime, gcc_providers = _gcc_runtime()
    gcc_defined: set[str] = set()
    gcc_names: set[str] = set()
    for _, path in gcc_providers:
        table = _symbols(nm, path)
        gcc_defined.update(_defined(table))
        gcc_names.update(name for name, _ in table)

    atomic_runtime, atomic_providers = _gcc_atomic()
    atomic_defined: set[str] = set()
    atomic_names: set[str] = set()
    for _, path in atomic_providers:
        table = _symbols(nm, path)
        atomic_defined.update(_defined(table))
        atomic_names.update(name for name, _ in table)

    ffmpeg_runtime, ffmpeg_providers = _ffmpeg_runtime(
        installed, prefix, require_status=True
    )
    ffmpeg_defined: set[str] = set()
    ffmpeg_names: set[str] = set()
    for _, path in ffmpeg_providers:
        table = _symbols(nm, path)
        ffmpeg_defined.update(_defined(table))
        ffmpeg_names.update(name for name, _ in table)

    collisions: set[str] = set()
    cxx_collisions: set[str] = set()
    ffmpeg_collisions: set[str] = set()
    atomic_collisions: set[str] = set()
    source_hashes = _archive_hashes(cef)
    relocation_receipt = cef_crel.install(cef, objcopy)
    relocation_affected = set(relocation_receipt["archives"])
    require(all(record["source_sha256"] == source_hashes[name]
                for name, record in relocation_receipt["archives"].items()),
            "CEF relocation source identity changed")
    init_profiles: dict[str, list[tuple[int, str, int, int]]] = {
        name: _init_array_profile(path) for name, path in cef
    }
    profiles: dict[str, dict[str, int | str]] = {}
    candidates: dict[str, Counter] = {}
    watch = openssl_defined | gcc_defined | ffmpeg_defined | atomic_defined
    for name, path in cef:
        profile, relevant = _profile_symbols(
            nm,
            path,
            watch=watch,
            forbidden_prefixes=(
                NAMESPACE, CXX_NAMESPACE, FFMPEG_NAMESPACE, ATOMIC_NAMESPACE
            ),
        )
        profiles[name] = profile
        candidates[name] = relevant
        for (symbol, kind), count in relevant.items():
            if not count or kind in {"U", "w", "v"}:
                continue
            if symbol in openssl_defined:
                collisions.add(symbol)
            if symbol in gcc_defined:
                cxx_collisions.add(symbol)
            if symbol in ffmpeg_defined:
                ffmpeg_collisions.add(symbol)
            if symbol in atomic_defined:
                atomic_collisions.add(symbol)

    domains = (collisions, cxx_collisions, ffmpeg_collisions, atomic_collisions)
    require(
        sum(len(domain) for domain in domains)
        == len(set().union(*domains)),
        "CEF runtime collision belongs to multiple provider namespaces",
    )
    ordered = sorted(collisions)
    cxx_ordered = sorted(cxx_collisions)
    ffmpeg_ordered = sorted(ffmpeg_collisions)
    atomic_ordered = sorted(atomic_collisions)
    require(ANCHORS <= collisions
            and 1 <= len(ordered) <= MAX_COLLISIONS,
            "Unexpected Chromium/OpenSSL collision inventory")
    require(CXX_ANCHORS <= cxx_collisions
            and 1 <= len(cxx_ordered) <= MAX_CXX_COLLISIONS,
            "Unexpected Chromium/GCC runtime collision inventory")
    require(FFMPEG_ANCHORS <= ffmpeg_collisions
            and 1 <= len(ffmpeg_ordered) <= MAX_FFMPEG_COLLISIONS,
            "Unexpected Chromium/FFmpeg collision inventory")
    require(ATOMIC_ANCHORS <= atomic_collisions
            and 1 <= len(atomic_ordered) <= MAX_ATOMIC_COLLISIONS,
            "Unexpected Chromium/libatomic collision inventory")
    require(all(SYMBOL.fullmatch(name) is not None and len(name) <= 512
                for name in ordered + cxx_ordered
                + ffmpeg_ordered + atomic_ordered),
            "Invalid Chromium runtime collision symbol")
    renamed = {name: NAMESPACE + name for name in ordered}
    renamed.update({name: CXX_NAMESPACE + name for name in cxx_ordered})
    renamed.update({name: FFMPEG_NAMESPACE + name for name in ffmpeg_ordered})
    renamed.update({name: ATOMIC_NAMESPACE + name for name in atomic_ordered})
    require(
        not set(renamed.values()).intersection(
            openssl_names | gcc_names | ffmpeg_names | atomic_names
        ),
        "CEF runtime isolation namespace already exists",
    )

    diagnostics.mkdir(parents=True, exist_ok=False)
    mapping = diagnostics / "redefine-syms.txt"
    mapping.write_bytes(
        _mapping_bytes(
            ordered, cxx_ordered, ffmpeg_ordered, atomic_ordered
        )
    )
    mapping.chmod(0o600)
    mapping_sha = digest(mapping)
    boringssl_mapping_sha = hashlib.sha256(
        _domain_mapping_bytes(ordered, NAMESPACE)
    ).hexdigest()
    cxx_mapping_sha = hashlib.sha256(
        _domain_mapping_bytes(cxx_ordered, CXX_NAMESPACE)
    ).hexdigest()
    ffmpeg_mapping_sha = hashlib.sha256(
        _domain_mapping_bytes(ffmpeg_ordered, FFMPEG_NAMESPACE)
    ).hexdigest()
    atomic_mapping_sha = hashlib.sha256(
        _domain_mapping_bytes(atomic_ordered, ATOMIC_NAMESPACE)
    ).hexdigest()

    affected: dict[str, dict] = {}
    boringssl_affected: set[str] = set()
    cxx_affected: set[str] = set()
    ffmpeg_affected: set[str] = set()
    atomic_affected: set[str] = set()
    init_array_affected: set[str] = set()
    init_array_normalized_sections = 0
    try:
        reverse = {new: old for old, new in renamed.items()}
        all_collisions = (
            collisions | cxx_collisions | ffmpeg_collisions | atomic_collisions
        )
        watched = all_collisions | set(renamed.values())
        for name, path in cef:
            relevant = Counter(
                {
                    (symbol, kind): count
                    for (symbol, kind), count in candidates[name].items()
                    if symbol in all_collisions
                }
            )
            init_profile = init_profiles[name]
            over_aligned = [
                record for record in init_profile
                if record[3] > INIT_ARRAY_ALIGNMENT
            ]
            if not relevant and not over_aligned and name not in relocation_affected:
                continue
            if over_aligned:
                init_array_affected.add(name)
                init_array_normalized_sections += len(over_aligned)
            if any(symbol in collisions for symbol, _ in relevant):
                boringssl_affected.add(name)
            if any(symbol in cxx_collisions for symbol, _ in relevant):
                cxx_affected.add(name)
            if any(symbol in ffmpeg_collisions for symbol, _ in relevant):
                ffmpeg_affected.add(name)
            if any(symbol in atomic_collisions for symbol, _ in relevant):
                atomic_affected.add(name)
            old_mode = stat.S_IMODE(path.stat().st_mode)
            fd, temp_name = tempfile.mkstemp(
                prefix=".cef-bssl-", suffix=".a", dir=path.parent
            )
            os.close(fd)
            temporary = Path(temp_name)
            try:
                temporary.unlink()
                alignment_names = sorted({
                    section_name for _, section_name, _, alignment in over_aligned
                    if alignment > INIT_ARRAY_ALIGNMENT
                })
                subprocess.run(
                    [str(objcopy), "--redefine-syms=" + str(mapping),
                     *[
                         "--set-section-alignment="
                         + section_name + "=" + str(INIT_ARRAY_ALIGNMENT)
                         for section_name in alignment_names
                     ],
                     str(path), str(temporary)],
                    check=True, timeout=600,
                )
                temporary.chmod(old_mode)
                after_profile, after = _profile_symbols(
                    nm,
                    temporary,
                    watch=watched,
                    reverse=reverse,
                    forbidden=all_collisions,
                    archive_limit=_archive_limit(path),
                )
                require(
                    after_profile == profiles[name],
                    "CEF archive global symbol table changed outside namespace mapping",
                )
                normalized_init_profile = _normalized_init_array_profile(init_profile)
                final_init_profile = _init_array_profile(
                    temporary, archive_limit=_archive_limit(path)
                )
                require(
                    final_init_profile == normalized_init_profile,
                    "CEF init-array alignment normalization is incomplete",
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
                    "init_array_sections_normalized": len(over_aligned),
                    "init_array_source_profile_sha256": _profile_sha256(init_profile),
                    "init_array_final_profile_sha256": _profile_sha256(final_init_profile),
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
        ], "OpenSSL provider changed during CEF runtime isolation")
    current_gcc_runtime, _ = _gcc_runtime()
    require(
        current_gcc_runtime == gcc_runtime,
        "GCC static runtime provider changed during CEF runtime isolation",
    )
    current_atomic_runtime, _ = _gcc_atomic()
    require(
        current_atomic_runtime == atomic_runtime,
        "GCC libatomic provider changed during CEF runtime isolation",
    )
    current_ffmpeg_runtime, _ = _ffmpeg_runtime(
        installed, prefix, require_status=True
    )
    require(
        current_ffmpeg_runtime == ffmpeg_runtime,
        "FFmpeg provider changed during CEF runtime isolation",
    )

    receipt = {
        "schema": 1,
        "kind": "cef-chromium-boringssl-isolation",
        "namespace": NAMESPACE,
        "cxx_namespace": CXX_NAMESPACE,
        "ffmpeg_namespace": FFMPEG_NAMESPACE,
        "atomic_namespace": ATOMIC_NAMESPACE,
        "mapping_sha256": mapping_sha,
        "boringssl_mapping_sha256": boringssl_mapping_sha,
        "cxx_mapping_sha256": cxx_mapping_sha,
        "ffmpeg_mapping_sha256": ffmpeg_mapping_sha,
        "atomic_mapping_sha256": atomic_mapping_sha,
        "collision_count": len(ordered),
        "symbols": ordered,
        "cxx_collision_count": len(cxx_ordered),
        "cxx_symbols": cxx_ordered,
        "ffmpeg_collision_count": len(ffmpeg_ordered),
        "ffmpeg_symbols": ffmpeg_ordered,
        "atomic_collision_count": len(atomic_ordered),
        "atomic_symbols": atomic_ordered,
        "openssl": {
            "version": OPENSSL_VERSION,
            "archives": provider_hashes,
        },
        "gcc_runtime": gcc_runtime,
        "atomic_runtime": atomic_runtime,
        "ffmpeg_runtime": ffmpeg_runtime,
        "cef_archives": final_hashes,
        "ownership": ownership_receipt,
        "affected": affected,
        "relocation_compatibility": relocation_receipt,
        "boringssl_affected_archives": sorted(boringssl_affected),
        "cxx_affected_archives": sorted(cxx_affected),
        "ffmpeg_affected_archives": sorted(ffmpeg_affected),
        "atomic_affected_archives": sorted(atomic_affected),
        "init_array_alignment": INIT_ARRAY_ALIGNMENT,
        "init_array_affected_archives": sorted(init_array_affected),
        "init_array_normalized_section_count": init_array_normalized_sections,
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
            and receipt.get("cxx_namespace") == CXX_NAMESPACE
            and receipt.get("ffmpeg_namespace") == FFMPEG_NAMESPACE
            and receipt.get("atomic_namespace") == ATOMIC_NAMESPACE
            and receipt.get("openssl", {}).get("version") == OPENSSL_VERSION,
            "Missing CEF runtime isolation receipt")
    symbols = receipt.get("symbols")
    cxx_symbols = receipt.get("cxx_symbols")
    ffmpeg_symbols = receipt.get("ffmpeg_symbols")
    atomic_symbols = receipt.get("atomic_symbols")
    require(isinstance(symbols, list)
            and symbols == sorted(set(symbols))
            and ANCHORS <= set(symbols)
            and len(symbols) == receipt.get("collision_count")
            and 1 <= len(symbols) <= MAX_COLLISIONS,
            "Invalid CEF BoringSSL isolation mapping")
    require(isinstance(cxx_symbols, list)
            and cxx_symbols == sorted(set(cxx_symbols))
            and CXX_ANCHORS <= set(cxx_symbols)
            and len(cxx_symbols) == receipt.get("cxx_collision_count")
            and 1 <= len(cxx_symbols) <= MAX_CXX_COLLISIONS,
            "Invalid CEF C++ runtime isolation mapping")
    require(isinstance(ffmpeg_symbols, list)
            and ffmpeg_symbols == sorted(set(ffmpeg_symbols))
            and FFMPEG_ANCHORS <= set(ffmpeg_symbols)
            and len(ffmpeg_symbols) == receipt.get("ffmpeg_collision_count")
            and 1 <= len(ffmpeg_symbols) <= MAX_FFMPEG_COLLISIONS,
            "Invalid CEF FFmpeg isolation mapping")
    require(isinstance(atomic_symbols, list)
            and atomic_symbols == sorted(set(atomic_symbols))
            and ATOMIC_ANCHORS <= set(atomic_symbols)
            and len(atomic_symbols) == receipt.get("atomic_collision_count")
            and 1 <= len(atomic_symbols) <= MAX_ATOMIC_COLLISIONS,
            "Invalid CEF libatomic isolation mapping")
    domains = [
        set(symbols), set(cxx_symbols), set(ffmpeg_symbols), set(atomic_symbols)
    ]
    require(
        sum(len(domain) for domain in domains)
        == len(set().union(*domains)),
        "CEF runtime isolation collision domains overlap in receipt",
    )
    require(
        hashlib.sha256(
            _mapping_bytes(
                symbols, cxx_symbols, ffmpeg_symbols, atomic_symbols
            )
        ).hexdigest() == receipt.get("mapping_sha256")
        and hashlib.sha256(_domain_mapping_bytes(symbols, NAMESPACE)).hexdigest()
            == receipt.get("boringssl_mapping_sha256")
        and hashlib.sha256(
            _domain_mapping_bytes(cxx_symbols, CXX_NAMESPACE)
        ).hexdigest() == receipt.get("cxx_mapping_sha256")
        and hashlib.sha256(
            _domain_mapping_bytes(ffmpeg_symbols, FFMPEG_NAMESPACE)
        ).hexdigest() == receipt.get("ffmpeg_mapping_sha256")
        and hashlib.sha256(
            _domain_mapping_bytes(atomic_symbols, ATOMIC_NAMESPACE)
        ).hexdigest() == receipt.get("atomic_mapping_sha256"),
        "Invalid combined CEF runtime isolation mapping",
    )
    installed = installed.resolve(strict=True)
    prefix = installed / TRIPLET
    require(prefix.is_dir() and not prefix.is_symlink(),
            "Missing relocated triplet for CEF BoringSSL isolation")
    nm, objcopy = _tools(source)
    require(digest(nm) == receipt.get("nm_sha256")
            and digest(objcopy) == receipt.get("objcopy_sha256"),
            "CEF runtime isolation tool identity changed")
    current_gcc_runtime, _ = _gcc_runtime()
    require(
        current_gcc_runtime == receipt.get("gcc_runtime"),
        "GCC static runtime provider changed in SDK transport",
    )
    current_atomic_runtime, _ = _gcc_atomic()
    require(
        current_atomic_runtime == receipt.get("atomic_runtime"),
        "GCC libatomic provider changed in SDK transport",
    )
    current_ffmpeg_runtime, _ = _ffmpeg_runtime(
        installed,
        prefix,
        expected=receipt.get("ffmpeg_runtime"),
        require_status=False,
    )
    require(
        current_ffmpeg_runtime == receipt.get("ffmpeg_runtime"),
        "FFmpeg provider changed in SDK transport",
    )

    cef = _cef_archives(prefix)
    names = [name for name, _ in cef]
    require(set(names) == set(receipt.get("cef_archives", {})),
            "CEF archive inventory changed in SDK transport")
    ownership = receipt.get("ownership")
    _ownership(
        installed,
        names,
        expected=ownership,
        require_status=False,
    )
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
    boringssl_affected = receipt.get("boringssl_affected_archives")
    cxx_affected = receipt.get("cxx_affected_archives")
    ffmpeg_affected = receipt.get("ffmpeg_affected_archives")
    atomic_affected = receipt.get("atomic_affected_archives")
    init_array_affected = receipt.get("init_array_affected_archives")
    init_array_count = receipt.get("init_array_normalized_section_count")
    cef_crel.verify_receipt(receipt)
    relocation_affected = set(receipt["relocation_compatibility"]["archives"])
    require(receipt.get("init_array_alignment") == INIT_ARRAY_ALIGNMENT,
            "CEF init-array alignment policy changed")
    require(isinstance(affected, dict)
            and affected and set(affected) <= set(names),
            "CEF runtime affected archive receipt changed")
    require(
        isinstance(boringssl_affected, list)
        and boringssl_affected == sorted(set(boringssl_affected))
        and set(boringssl_affected) <= set(affected)
        and boringssl_affected,
        "CEF BoringSSL affected archive receipt changed",
    )
    require(
        isinstance(cxx_affected, list)
        and cxx_affected == sorted(set(cxx_affected))
        and set(cxx_affected) <= set(affected)
        and cxx_affected,
        "CEF C++ runtime affected archive receipt changed",
    )
    require(
        isinstance(ffmpeg_affected, list)
        and ffmpeg_affected == sorted(set(ffmpeg_affected))
        and set(ffmpeg_affected) <= set(affected)
        and ffmpeg_affected,
        "CEF FFmpeg affected archive receipt changed",
    )
    require(
        isinstance(atomic_affected, list)
        and atomic_affected == sorted(set(atomic_affected))
        and set(atomic_affected) <= set(affected)
        and atomic_affected,
        "CEF libatomic affected archive receipt changed",
    )
    require(
        isinstance(init_array_affected, list)
        and init_array_affected == sorted(set(init_array_affected))
        and set(init_array_affected) <= set(affected)
        and type(init_array_count) is int
        and 0 <= init_array_count <= MAX_INIT_ARRAY_SECTIONS
        and set(affected) == (
            set(boringssl_affected) | set(cxx_affected)
            | set(ffmpeg_affected) | set(atomic_affected)
            | set(init_array_affected) | relocation_affected
        ),
        "CEF init-array affected archive receipt changed",
    )
    for name, record in affected.items():
        require(isinstance(record, dict)
                and set(record) == {
                    "source_sha256", "sha256", "renamed_occurrences",
                    "init_array_sections_normalized",
                    "init_array_source_profile_sha256",
                    "init_array_final_profile_sha256",
                    "global_symbol_count", "global_symbol_sha256",
                }
                and record["sha256"] == receipt["cef_archives"][name]
                and record["source_sha256"] != record["sha256"]
                and type(record["renamed_occurrences"]) is int
                and record["renamed_occurrences"] >= 0
                and type(record["init_array_sections_normalized"]) is int
                and record["init_array_sections_normalized"] >= 0
                and (record["renamed_occurrences"] > 0
                     or record["init_array_sections_normalized"] > 0
                     or name in relocation_affected)
                and isinstance(record["init_array_source_profile_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", record["init_array_source_profile_sha256"])
                    is not None
                and isinstance(record["init_array_final_profile_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", record["init_array_final_profile_sha256"])
                    is not None
                and type(record["global_symbol_count"]) is int
                and 0 <= record["global_symbol_count"] <= MAX_NM_RECORDS
                and (record["global_symbol_count"] > 0 or name in relocation_affected)
                and isinstance(record["global_symbol_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}",
                                 record["global_symbol_sha256"]) is not None,
                "Invalid CEF BoringSSL affected archive receipt")
        profile = _init_array_profile(prefix / name)
        require(
            _profile_sha256(profile) == record["init_array_final_profile_sha256"]
            and all(alignment <= INIT_ARRAY_ALIGNMENT
                    for _, _, _, alignment in profile),
            "CEF init-array alignment changed in transport",
        )
    return {
        "cef_relocation_compatibility_verified": True,
        "cef_crel_affected_archive_count": len(relocation_affected),
        "cef_crel_converted_section_count": sum(
            item["crel_sections"] for item in receipt["relocation_compatibility"]["archives"].values()
        ),
        "cef_boringssl_isolation_verified": True,
        "cef_boringssl_collision_count": len(symbols),
        "cef_boringssl_affected_archive_count": len(boringssl_affected),
        "cef_boringssl_mapping_sha256":
            receipt["boringssl_mapping_sha256"],
        "cef_cxx_runtime_isolation_verified": True,
        "cef_cxx_runtime_collision_count": len(cxx_symbols),
        "cef_cxx_runtime_affected_archive_count": len(cxx_affected),
        "cef_cxx_runtime_mapping_sha256": receipt["cxx_mapping_sha256"],
        "cef_ffmpeg_isolation_verified": True,
        "cef_ffmpeg_collision_count": len(ffmpeg_symbols),
        "cef_ffmpeg_affected_archive_count": len(ffmpeg_affected),
        "cef_ffmpeg_mapping_sha256": receipt["ffmpeg_mapping_sha256"],
        "cef_atomic_isolation_verified": True,
        "cef_atomic_collision_count": len(atomic_symbols),
        "cef_atomic_affected_archive_count": len(atomic_affected),
        "cef_atomic_mapping_sha256": receipt["atomic_mapping_sha256"],
        "cef_init_array_alignment_verified": True,
        "cef_init_array_affected_archive_count": len(init_array_affected),
        "cef_init_array_normalized_section_count": init_array_count,
        "cef_runtime_mapping_sha256": receipt["mapping_sha256"],
    }
