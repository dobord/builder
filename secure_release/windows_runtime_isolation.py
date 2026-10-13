"""Namespace the source-built Windows engine away from final static providers.

Only generated CEF engine archives are rewritten. Definitions AND references
use one complete collision map; COFF section bytes and global symbol counts are
checked before accepting derivatives. Provider archives and public APIs stay
intact. Publication binds the actual relocated archive bytes to this receipt.
"""
from collections import Counter
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

from . import cef_boringssl_isolation as checked, crypto, safeio

TRIPLET = "x64-windows-static-release"
NAMESPACE = "CEF_CHROMIUM_RUNTIME_"
PROFILE = {"schema": 1, "kind": "windows-coff-runtime-isolation",
           "namespace": NAMESPACE, "method": "complete-final-provider-collisions",
           "coff_rewrite": "symbol-names-and-appended-strings-only"}
ENGINE = re.compile(r"lib/cef-static/(?:cef_objects|cef_[0-9]{4}_[0-9a-f]{12})\.lib\Z")
ANCHORS = {"SSL_new", "SSL_use_certificate", "PEM_read_PrivateKey"}
MAX_SYMBOLS = 20_000_000
MAX_COLLISIONS = 65536


def _tools(source: Path) -> tuple[Path, Path]:
    paths = source / "third_party/llvm-build/Release+Asserts/bin"
    nm, librarian = paths / "llvm-nm.exe", paths / "lld-link.exe"
    if not all(t.is_file() for t in (nm, librarian)):
        paths = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "LLVM/bin"
        nm, librarian = paths / "llvm-nm.exe", paths / "lld-link.exe"
        for tool in (nm, librarian):
            result = subprocess.check_output([str(tool), "--version"], text=True, timeout=30)
            checked.require(re.search(r"(?:LLVM version|LLD) 20\.1\.8\b", result) is not None,
                            "Reviewed Windows LLVM runtime-isolation tool changed")
    checked.require(all(safeio.regular(t) for t in (nm, librarian)), "Missing Windows LLVM isolation tools")
    return nm, librarian


def symbols(nm: Path, archive: Path) -> Counter:
    checked._archive_size(archive, limit=safeio.MAX_BYTES)
    with tempfile.TemporaryDirectory(prefix="windows-coff-symbols-") as folder:
        root = Path(folder)
        with (root / "out").open("wb") as out, (root / "err").open("wb") as err:
            result = subprocess.run([str(nm), "-P", "-g", "--no-demangle", str(archive)],
                                    stdout=out, stderr=err, timeout=1800)
        checked.require(result.returncode == 0 and (root / "out").stat().st_size <= 2 * 1024**3
                        and (root / "err").stat().st_size <= 16 * 1024**2,
                        "Cannot inspect Windows runtime symbols")
        table = Counter()
        count = 0
        with (root / "out").open("rb") as stream:
            for raw in stream:
                checked.require(len(raw) <= 8192, "Oversized Windows symbol record")
                line = raw.rstrip(b"\r\n")
                if not line.strip() or line.rstrip().endswith(b":"):
                    continue
                fields = line.split()
                checked.require(len(fields) >= 2, "Invalid Windows symbol record")
                name, kind = fields[0].decode("ascii"), fields[1].decode("ascii")
                checked.require((re.fullmatch(r"[\x21-\x7e]+", name) is not None
                                 or re.fullmatch(r"\x7f[A-Za-z0-9_.-]+_NULL_THUNK_DATA", name) is not None)
                                and re.fullmatch(r"[A-Za-z?]", kind) is not None,
                                "Invalid Windows symbol identity: " + repr(line[:256]))
                table[name, kind] += 1
                count += 1
                checked.require(count <= MAX_SYMBOLS, "Windows symbol inventory exceeds limit")
        return table


def _defined(table: Counter) -> set[str]:
    # COFF's DEL-prefixed null-thunk records are linker metadata, not runtime
    # providers. Retain their exact symbols/payloads without namespacing OS ABI.
    return {name for name, kind in table if kind not in {"U", "w", "v"} and not name.startswith("\x7f")}


def _sections(archive: Path) -> str:
    """Bind ordered regular COFF section payloads independently of symbol tables."""
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        checked.require(stream.read(8) == b"!<arch>\n", "Expected regular COFF archive")
        member = 0
        while header := stream.read(60):
            checked.require(len(header) == 60 and header[58:] == b"`\n", "Malformed COFF archive header")
            field = header[48:58].strip()
            checked.require(field.isdigit(), "Invalid COFF member size")
            size = int(field)
            name = header[:16].rstrip(b" ")
            checked.require(0 <= size <= safeio.MAX_BYTES, "COFF member size exceeds limit")
            if name in (b"/", b"//", b"/SYM64/"):
                stream.seek(size, os.SEEK_CUR)
            else:
                checked.require(size <= 256 * 1024**2, "COFF object exceeds limit")
                payload = stream.read(size)
                checked.require(len(payload) == size and len(payload) >= 20, "Truncated COFF object")
                member += 1
                checked.require(member <= 2_000_000, "Too many COFF objects")
                if payload[:4] == b"\0\0\xff\xff" and struct.unpack_from("<H", payload, 4)[0] == 0:
                    # Native OS import members are not runtime providers; all bytes must survive.
                    digest.update(b"import\0" + hashlib.sha256(payload).digest())
                else:
                    if payload[:4] == b"\0\0\xff\xff":
                        checked.require(len(payload) >= 56 and struct.unpack_from("<H", payload, 4)[0] == 2
                                        and struct.unpack_from("<H", payload, 6)[0] == 0x8664,
                                        "Invalid Windows bigobj input")
                        count, symptr, symcount = struct.unpack_from("<III", payload, 44)
                        start, symbol_size = 56, 20
                    else:
                        machine, count, _, symptr, symcount, optional, _ = struct.unpack_from("<HHIIIHH", payload)
                        checked.require(machine == 0x8664 and optional == 0, "Expected x64 regular COFF object")
                        start, symbol_size = 20, 18
                    checked.require(0 < count <= 1_000_000 and start + 40 * count <= len(payload), "Invalid COFF sections")
                    strings = symptr + symbol_size * symcount
                    for index in range(count):
                        offset = start + index * 40
                        section = payload[offset:offset + 8].rstrip(b"\0")
                        if section.startswith(b"/"):
                            checked.require(section[1:].isdigit(), "Invalid COFF long section name")
                            pos = strings + int(section[1:])
                            end = payload.find(b"\0", pos)
                            checked.require(strings <= pos < end <= len(payload), "Invalid COFF section string")
                            section = payload[pos:end]
                        length, position = struct.unpack_from("<II", payload, offset + 16)
                        characteristics = struct.unpack_from("<I", payload, offset + 36)[0]
                        checked.require(length <= safeio.MAX_BYTES and
                                        (position == 0 or position + length <= len(payload)),
                                        "COFF section payload escapes object")
                        checked.require(position != 0 or length == 0 or characteristics & 0x80,
                                        "Initialized COFF section lacks file payload")
                        # LLVM may materialize zero bytes for virtual COFF BSS.
                        # Bind its extent/flags and prove any stored payload is zero.
                        data = payload[position:position + length] if position else b""
                        digest.update(struct.pack("<III", index, length, characteristics) + section + b"\0")
                        if characteristics & 0x80:
                            checked.require(not any(data), "COFF BSS unexpectedly contains initialized bytes")
                            digest.update(hashlib.sha256(b"coff-zero-initialized-bss").digest())
                        else:
                            digest.update(hashlib.sha256(data).digest())
            if size & 1:
                checked.require(stream.read(1) == b"\n", "Invalid COFF archive padding")
    return digest.hexdigest()


def _ownership(installed: Path, names: set[str]) -> None:
    listings = list((installed / "vcpkg/info").glob("*_" + TRIPLET + ".list"))
    checked.require(0 < len(listings) <= 4096, "Missing Windows SDK ownership")
    owners = Counter()
    for path in listings:
        checked.require(safeio.regular(path) and path.stat().st_size <= 8 * 1024**2, "Invalid Windows owner record")
        for line in path.read_text(encoding="utf-8").splitlines():
            if line in names:
                owners[line] += 1
    checked.require(set(owners) == names and all(n == 1 for n in owners.values()), "Ambiguous Windows runtime ownership")


def _member_mapping(payload: bytes, mapping: dict) -> dict:
    if payload[:4] == b"\0\0\xff\xff":
        if struct.unpack_from("<H", payload, 4)[0] == 0:
            return {}  # Copy native import payloads byte-for-byte.
        _, pointer, count = struct.unpack_from("<III", payload, 44)
        width = 20
    else:
        pointer, count = struct.unpack_from("<II", payload, 8)
        width = 18
    strings = pointer + count * width
    checked.require(strings <= len(payload), "COFF symbol table escapes object")
    result = {}
    index = 0
    while index < count:
        entry = pointer + index * width
        name = payload[entry:entry + 8]
        if name == b"\0" * 8:
            index += 1 + payload[entry + width - 1]
            checked.require(index <= count, "Invalid unnamed COFF symbol boundary")
            continue
        if name[:4] == b"\0" * 4:
            offset = strings + struct.unpack_from("<I", name, 4)[0]
            end = payload.find(b"\0", offset)
            checked.require(strings <= offset < end <= len(payload), "Invalid COFF symbol string")
            name = payload[offset:end]
        else:
            name = name.rstrip(b"\0")
        if name.isascii() and name.decode("ascii") in mapping:
            old = name.decode("ascii")
            result[old] = mapping[old]
        index += 1 + payload[entry + width - 1]
        checked.require(index <= count, "Invalid COFF auxiliary symbol count")
    return result


def _rename_member(payload: bytes, mapping: dict) -> bytes:
    """Keep NASM weak/auxiliary records intact; change only symbol name fields.

    COFF names are inline eight-byte fields or offsets in an appendable string
    table. Symbol values, classes, auxiliary records, relocations, initialized
    sections and BSS headers are preserved byte-for-byte.
    """
    if payload[:4] == b"\0\0\xff\xff":
        checked.require(struct.unpack_from("<H", payload, 4)[0] == 2, "Cannot rename native import metadata")
        _, pointer, count = struct.unpack_from("<III", payload, 44)
        width = 20
    else:
        pointer, count = struct.unpack_from("<II", payload, 8)
        width = 18
    strings = pointer + count * width
    checked.require(strings + 4 <= len(payload), "Missing COFF string table")
    size = struct.unpack_from("<I", payload, strings)[0]
    checked.require(size >= 4 and strings + size <= len(payload), "Invalid COFF string table size")
    result = bytearray(payload[:strings + size])
    offsets = {}
    index = 0
    while index < count:
        entry = pointer + index * width
        name = payload[entry:entry + 8]
        if name == b"\0" * 8:
            index += 1 + payload[entry + width - 1]
            checked.require(index <= count, "Invalid unnamed COFF symbol boundary")
            continue
        if name[:4] == b"\0" * 4:
            offset = struct.unpack_from("<I", name, 4)[0]
            checked.require(4 <= offset < size, "Invalid COFF symbol-name offset")
            end = payload.find(b"\0", strings + offset, strings + size)
            checked.require(end >= 0, "Unterminated COFF symbol name")
            name = payload[strings + offset:end]
        else:
            name = name.rstrip(b"\0")
        old = name.decode("ascii") if name.isascii() else None
        if old in mapping:
            new = mapping[old].encode("ascii")
            if new not in offsets:
                offsets[new] = len(result) - strings
                result.extend(new + b"\0")
            struct.pack_into("<II", result, entry, 0, offsets[new])
        index += 1 + payload[entry + width - 1]
        checked.require(index <= count, "Invalid COFF auxiliary symbol boundary")
    checked.require(len(result) - strings < 2**32, "COFF string table exceeds offset range")
    struct.pack_into("<I", result, strings, len(result) - strings)
    result.extend(payload[strings + size:])
    return bytes(result)


def _rewrite_members(librarian: Path, archive: Path, output: Path,
                     mapping: dict, diagnostics: Path) -> None:
    """Rewrite symbol fields in regular objects; copy native imports byte-for-byte."""
    with tempfile.TemporaryDirectory(prefix="coff-members-", dir=diagnostics) as folder:
        root = Path(folder)
        members = []
        with archive.open("rb") as stream, (diagnostics / "objcopy.log").open("ab") as log:
            checked.require(stream.read(8) == b"!<arch>\n", "Expected regular Windows engine archive")
            while header := stream.read(60):
                checked.require(len(header) == 60 and header[58:] == b"`\n", "Invalid Windows archive member")
                size = int(header[48:58].strip())
                if header[:16].rstrip(b" ") in (b"/", b"//", b"/SYM64/"):
                    stream.seek(size, os.SEEK_CUR)
                else:
                    checked.require(20 <= size <= 256 * 1024**2, "Invalid Windows object size")
                    payload = stream.read(size)
                    checked.require(len(payload) == size, "Truncated Windows object")
                    path = root / f"member{len(members):06d}.obj"
                    subset = _member_mapping(payload, mapping)
                    path.write_bytes(_rename_member(payload, subset) if subset else payload)
                    members.append(path)
                if size & 1:
                    checked.require(stream.read(1) == b"\n", "Invalid Windows archive padding")
            # The reviewed LLVM COFF librarian stores explicit inputs in reverse order.
            response = root / "members.rsp"
            response.write_text("".join(subprocess.list2cmdline([str(p)]) + "\n" for p in reversed(members)), encoding="utf-8")
            command = [str(librarian)]
            if "lld-link" in librarian.name:
                command.append("/lib")
            command += ["/nologo", "/out:" + str(output), "@" + str(response)]
            result = subprocess.run(command, stdout=log, stderr=log, timeout=1800)
            checked.require(result.returncode == 0, "Windows COFF archive reconstruction failed")


def install(installed: Path, source: Path, diagnostics: Path, *, tools=None) -> dict:
    prefix = installed / TRIPLET
    nm, librarian = tools or _tools(source)
    paths = sorted(p for p in (prefix / "lib").rglob("*.lib") if safeio.regular(p))
    engine = [p for p in paths if ENGINE.fullmatch(p.relative_to(prefix).as_posix())]
    providers = [p for p in paths if p not in engine]
    checked.require(0 < len(engine) <= 4096 and 0 < len(providers) <= 4096, "Invalid Windows runtime closure")
    required = {"lib/libssl.lib", "lib/libcrypto.lib"}
    checked.require(required <= {p.relative_to(prefix).as_posix() for p in providers}, "Missing Windows OpenSSL providers")
    _ownership(installed, {TRIPLET + "/" + p.relative_to(prefix).as_posix() for p in paths})
    diagnostics.mkdir(mode=0o700)
    provider_defs = set()
    provider_hashes = {}
    print("WINDOWS_COFF_ISOLATION phase=scan", flush=True)
    for path in providers:
        provider_defs.update(_defined(symbols(nm, path)))
        provider_hashes[path.relative_to(prefix).as_posix()] = crypto.digest(path)
    engine_defs = set()
    for path in engine:
        engine_defs.update(_defined(symbols(nm, path)))
    collisions = sorted(engine_defs & provider_defs)
    checked.require(ANCHORS <= set(collisions) and 0 < len(collisions) <= MAX_COLLISIONS,
                    "Incomplete Windows runtime collision closure")
    checked.require(not any(n.startswith("cef_") or n.startswith(NAMESPACE) for n in collisions),
                    "Windows runtime mapping would change public CEF APIs")
    targets = {NAMESPACE + name for name in collisions}
    checked.require(not targets.intersection(engine_defs | provider_defs), "Windows runtime namespace already exists")
    mapping = dict(zip(collisions, (NAMESPACE + n for n in collisions)))
    mapping_file = diagnostics / "symbols.map"
    # The receipt validator reconstructs canonical ASCII/LF bytes. Text-mode
    # newline translation on Windows must not change their signed digest.
    mapping_file.write_bytes("".join(f"{old} {new}\n" for old, new in mapping.items()).encode("ascii"))
    records = {}
    for index, path in enumerate(engine):
        print(f"WINDOWS_COFF_ISOLATION phase=archive index={index + 1} count={len(engine)}", flush=True)
        original = crypto.digest(path)
        before = symbols(nm, path)
        section_hash = _sections(path)
        if any(name in mapping for name, kind in before):
            output = diagnostics / path.name
            _rewrite_members(librarian, path, output, mapping, diagnostics)
            expected = Counter()
            for (name, kind), count in before.items():
                expected[mapping.get(name, name), kind] += count
            actual = symbols(nm, output)
            if actual != expected:
                with (diagnostics / "objcopy.log").open("a", encoding="utf-8") as log:
                    log.write("\nSYMBOL_PROFILE_MISMATCH " + path.name + "\n")
                    for label, delta in (("missing", expected - actual), ("extra", actual - expected)):
                        for (name, kind), count in sorted(delta.items())[:20]:
                            log.write(f"{label} {name!r} {kind} {count}\n")
            checked.require(actual == expected,
                            "Windows runtime rewrite lost symbol definitions or references")
            checked.require(_sections(output) == section_hash,
                            "Windows runtime rewrite changed ordered COFF section bytes, extents or flags")
            checked.require(crypto.digest(path) == original, "Windows engine archive changed during isolation")
            output.replace(path)
        records[path.relative_to(prefix).as_posix()] = {
            "input_sha256": original, "output_sha256": crypto.digest(path), "sections_sha256": section_hash}
    checked.require(all(crypto.digest(checked.regular(prefix, name)) == digest for name, digest in provider_hashes.items()),
                    "Windows final providers changed during engine isolation")
    receipt = {**PROFILE, "status": "success", "collisions": collisions,
               "mapping_sha256": crypto.digest(mapping_file), "archives": records, "providers": provider_hashes,
               "tools": {"nm_sha256": crypto.digest(nm), "librarian_sha256": crypto.digest(librarian)}}
    (prefix / "share/cef-static/windows-runtime-isolation.json").write_bytes(crypto.canonical(receipt))
    print("WINDOWS_COFF_ISOLATION phase=verified", flush=True)
    return receipt


def validate_archive(archive: Path, receipt: dict) -> None:
    checked.require(isinstance(receipt, dict) and set(receipt) == set(PROFILE) | {
        "status", "collisions", "mapping_sha256", "archives", "providers", "tools"}
        and all(receipt[k] == v for k, v in PROFILE.items()) and receipt["status"] == "success",
        "Missing Windows runtime isolation receipt")
    names = receipt["collisions"]
    checked.require(isinstance(names, list) and 0 < len(names) <= MAX_COLLISIONS
                    and all(isinstance(n, str) and re.fullmatch(r"[\x21-\x7e]+", n) for n in names)
                    and names == sorted(set(names)) and ANCHORS <= set(names), "Invalid Windows runtime map")
    mapping = "".join(f"{n} {NAMESPACE}{n}\n" for n in names).encode("ascii")
    checked.require(hashlib.sha256(mapping).hexdigest() == receipt["mapping_sha256"], "Windows runtime map digest changed")
    records = receipt["archives"]
    providers = receipt["providers"]
    checked.require(isinstance(records, dict) and 0 < len(records) <= 4096
                    and all(ENGINE.fullmatch(n) for n in records) and isinstance(providers, dict)
                    and 0 < len(providers) <= 4096 and {"lib/libssl.lib", "lib/libcrypto.lib"} <= set(providers),
                    "Invalid Windows runtime archive receipt")
    for record in records.values():
        checked.require(set(record) == {"input_sha256", "output_sha256", "sections_sha256"}, "Invalid Windows engine record")
        checked.require(all(re.fullmatch(r"[0-9a-f]{64}", v) for v in record.values()), "Invalid Windows engine digest")
    checked.require(set(receipt["tools"]) == {"nm_sha256", "librarian_sha256"}
                    and all(re.fullmatch(r"[0-9a-f]{64}", v) for v in receipt["tools"].values()), "Invalid Windows tool record")
    with zipfile.ZipFile(archive) as sdk:
        root = "installed/" + TRIPLET + "/"
        members = {i.filename: i for i in sdk.infolist()}
        actual = {n[len(root):] for n in members if n.startswith(root) and ENGINE.fullmatch(n[len(root):])}
        checked.require(actual == set(records), "Windows engine inventory changed during export")
        stored = root + "share/cef-static/windows-runtime-isolation.json"
        checked.require(stored in members and members[stored].file_size <= 8 * 1024**2
                        and crypto.parse(sdk.read(stored)) == receipt, "Installed Windows runtime receipt differs")
        expected = {n: r["output_sha256"] for n, r in records.items()} | providers
        for name, digest in expected.items():
            checked.require(re.fullmatch(r"lib/[A-Za-z0-9_+./-]+\.lib", name) is not None
                            and ".." not in name and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                            and root + name in members, "Invalid Windows provider identity")
            with sdk.open(root + name) as stream:
                checked.require(hashlib.file_digest(stream, "sha256").hexdigest() == digest,
                                "Windows runtime/provider bytes changed during export")
