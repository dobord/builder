"""Encrypted runner-local CI diagnostics for builder workflows."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
from typing import Iterable

from . import crypto

MAX_SINGLE_FILE = 128 * 1024**2
MAX_TOTAL_BYTES = 2 * 1024**3
MAX_FILES = 20000
MAX_DEPTH = 12

_SKIP_DIRS = {
    ".git", ".svn", "__pycache__", "node_modules",
    "downloads", "download", "packages", "package",
    "installed", "vcpkg_installed", "target-prefix",
    "restored-checkpoint", "cef-strict-checkpoint-encrypted",
    "cef-strict-cache", "builder-encrypted-logs",
    "obj", "gen",
}
_SKIP_SUFFIXES = {
    ".a", ".o", ".obj", ".so", ".dll", ".dylib", ".exe",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".enc",
    ".pem", ".key", ".p12", ".pfx",
}
_LOG_SUFFIXES = {
    ".log", ".out", ".err", ".txt", ".json", ".yaml", ".yml",
    ".xml", ".trx", ".rsp", ".stdout", ".stderr", ".trace",
}
_LOG_NAMES = {
    "cmakecache.txt", "cmakeconfigurelog.yaml", ".ninja_log",
    "compile_commands.json", "lasttest.log", "lasttestsfailed.log",
}
_FORBIDDEN_NAME = re.compile(
    r"(?:credential|secret|token|private[-_. ]?key)", re.I
)


def _decode_key_b64(value: str) -> str:
    raw = base64.b64decode(value.strip(), validate=True)
    if not raw or len(raw) > 1024 * 1024:
        raise ValueError("invalid encoded key length")
    return raw.decode("utf-8")


def _encode_key_b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def github_context() -> dict:
    def number(name: str) -> int:
        raw = os.environ.get(name, "")
        return int(raw) if raw.isdigit() else 0

    return {
        "schema": 1,
        "kind": "builder-encrypted-ci-logs",
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "local"),
        "job": os.environ.get("GITHUB_JOB", "local"),
        "run_id": number("GITHUB_RUN_ID"),
        "run_attempt": number("GITHUB_RUN_ATTEMPT"),
        "sha": os.environ.get("GITHUB_SHA", "local"),
    }


def _safe_label(root: Path, index: int) -> str:
    name = re.sub(r"[^A-Za-z0-9_.+-]+", "-", root.name or "root").strip("-")
    return f"{index:02d}-{name or 'root'}"


def _eligible(path: Path) -> bool:
    name = path.name
    lower = name.lower()
    if _FORBIDDEN_NAME.search(name):
        return False
    if path.suffix.lower() in _SKIP_SUFFIXES:
        return False
    return lower in _LOG_NAMES or path.suffix.lower() in _LOG_SUFFIXES


def iter_logs(root: Path) -> Iterable[Path]:
    root = root.resolve(strict=True)
    for current, dirs, files in os.walk(root, followlinks=False):
        here = Path(current)
        try:
            relative = here.relative_to(root)
        except ValueError:
            continue
        if len(relative.parts) >= MAX_DEPTH:
            dirs[:] = []
        else:
            dirs[:] = [
                name for name in dirs
                if name not in _SKIP_DIRS
                and not _FORBIDDEN_NAME.search(name)
                and not (here / name).is_symlink()
            ]
        for name in files:
            path = here / name
            if not _eligible(path) or path.is_symlink():
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            if not path.is_file() or st.st_size > MAX_SINGLE_FILE:
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_relative_to(root):
                continue
            yield path


def _manifest_entry(path: Path, root: Path, archive_name: str) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "archive_name": archive_name,
        "relative_path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": digest,
    }


def collect(
    roots: list[Path], target: Path, public_key: str, context: dict
) -> dict:
    if target.exists():
        raise ValueError("encrypted log target already exists")
    if context.get("schema") != 1 or context.get("kind") != "builder-encrypted-ci-logs":
        raise ValueError("invalid encrypted log context")
    recipient = crypto.fingerprint(public_key)
    target.parent.mkdir(parents=True, exist_ok=True)

    selected: list[tuple[Path, Path, str]] = []
    total = 0
    seen: set[Path] = set()
    for index, requested in enumerate(roots):
        try:
            root = requested.resolve(strict=True)
        except (FileNotFoundError, OSError):
            continue
        if not root.is_dir() or root.is_symlink():
            continue
        label = _safe_label(root, index)
        for path in iter_logs(root):
            resolved = path.resolve()
            if resolved in seen:
                continue
            size = path.stat().st_size
            if len(selected) >= MAX_FILES or total + size > MAX_TOTAL_BYTES:
                raise ValueError("encrypted log collection exceeds bounded limits")
            seen.add(resolved)
            arcname = f"logs/{label}/{path.relative_to(root).as_posix()}"
            selected.append((path, root, arcname))
            total += size

    manifest = {
        "schema": 1,
        "kind": "builder-encrypted-ci-log-manifest",
        "context": context,
        "recipient": recipient,
        "file_count": len(selected),
        "plain_bytes": total,
        "files": [
            _manifest_entry(path, root, arcname)
            for path, root, arcname in selected
        ],
    }

    fd, temp_name = tempfile.mkstemp(
        prefix=".builder-logs-", suffix=".tar.gz", dir=target.parent
    )
    os.close(fd)
    plain = Path(temp_name)
    try:
        with tarfile.open(plain, "w:gz", compresslevel=6) as archive:
            payload = crypto.canonical(manifest) + b"\n"
            info = tarfile.TarInfo("manifest.json")
            info.size = len(payload)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(payload))
            for path, _, arcname in selected:
                archive.add(path, arcname=arcname, recursive=False)
        crypto.encrypt_file(plain, target, public_key, context)
    finally:
        plain.unlink(missing_ok=True)

    print(
        "BUILDER_ENCRYPTED_LOGS_CREATED"
        f" files={manifest['file_count']} bytes={manifest['plain_bytes']}"
        f" recipient={recipient}",
        flush=True,
    )
    return manifest


def _validate_member(member: tarfile.TarInfo, destination: Path) -> None:
    if member.issym() or member.islnk() or member.isdev():
        raise ValueError("encrypted log archive contains unsupported member")
    name = member.name.replace("\\", "/")
    path = Path(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("encrypted log archive contains unsafe path")
    resolved = (destination / path).resolve()
    if not resolved.is_relative_to(destination.resolve()):
        raise ValueError("encrypted log archive escapes destination")
    if member.size > MAX_SINGLE_FILE:
        raise ValueError("encrypted log member exceeds bounded size")


def decrypt_archive(source: Path, destination: Path, private_key: str) -> dict:
    if destination.exists():
        raise ValueError("decryption destination already exists")
    with source.open("rb") as stream:
        header = crypto.read_header(stream)
    context = header.get("context")
    if (not isinstance(context, dict)
            or context.get("schema") != 1
            or context.get("kind") != "builder-encrypted-ci-logs"):
        raise ValueError("unexpected encrypted log context")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".builder-log-decrypt-", dir=destination.parent
    ) as folder:
        root = Path(folder)
        plain = root / "logs.tar.gz"
        crypto.decrypt_file(source, plain, private_key, context)
        destination.mkdir()
        total = 0
        count = 0
        try:
            with tarfile.open(plain, "r:gz") as archive:
                members = archive.getmembers()
                for member in members:
                    _validate_member(member, destination)
                    if member.isfile():
                        total += member.size
                        count += 1
                        if total > MAX_TOTAL_BYTES or count > MAX_FILES + 1:
                            raise ValueError("encrypted log archive exceeds bounded limits")
                archive.extractall(destination, members=members)
        except Exception:
            import shutil
            shutil.rmtree(destination, ignore_errors=True)
            raise

    manifest_path = destination / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("encrypted log manifest is missing")
    manifest = crypto.parse(manifest_path.read_bytes())
    if (not isinstance(manifest, dict)
            or manifest.get("schema") != 1
            or manifest.get("kind") != "builder-encrypted-ci-log-manifest"
            or manifest.get("context") != context):
        raise ValueError("invalid encrypted log manifest")
    return manifest


def roots_from_environment() -> list[Path]:
    raw = os.environ.get("BUILDER_ENCRYPTED_LOG_ROOTS", "")
    roots = [Path(line.strip()) for line in raw.splitlines() if line.strip()]
    if not roots:
        runner = os.environ.get("RUNNER_TEMP")
        if runner:
            roots.append(Path(runner))
    return roots


def _write_key(path: Path, value: str, mode: int) -> None:
    if path.exists():
        raise ValueError("key output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_encode_key_b64(value) + "\n", encoding="ascii")
    try:
        path.chmod(mode)
    except OSError:
        pass


def command_keygen(args) -> int:
    private, public = crypto.generate("encrypt")
    prefix = Path(args.prefix)
    private_path = Path(str(prefix) + ".private.b64")
    public_path = Path(str(prefix) + ".public.b64")
    _write_key(private_path, private, 0o600)
    _write_key(public_path, public, 0o644)
    print("private_key_file=" + str(private_path))
    print("public_key_file=" + str(public_path))
    print("public_fingerprint=" + crypto.fingerprint(public))
    return 0


def command_collect(args) -> int:
    encoded = os.environ.get("BUILDER_ENCRYPTED_LOGS_PUBLIC_KEY_B64", "").strip()
    if not encoded:
        print(
            "BUILDER_ENCRYPTED_LOGS_PUBLIC_KEY_MISSING; encrypted artifact skipped",
            flush=True,
        )
        return 0
    public = _decode_key_b64(encoded)
    collect(roots_from_environment(), Path(args.output), public, github_context())
    return 0


def command_decrypt(args) -> int:
    encoded = Path(args.private_key_file).read_text(encoding="ascii").strip()
    private = _decode_key_b64(encoded)
    manifest = decrypt_archive(Path(args.input), Path(args.output_dir), private)
    print(
        "BUILDER_ENCRYPTED_LOGS_DECRYPTED"
        f" files={manifest.get('file_count', 0)}"
        f" repository={manifest.get('context', {}).get('repository', '')}"
    )
    return 0


def command_inspect(args) -> int:
    with Path(args.input).open("rb") as stream:
        header = crypto.read_header(stream)
    print(json.dumps(
        {
            "recipient": header.get("recipient"),
            "context": header.get("context"),
        },
        sort_keys=True,
        indent=2,
    ))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--prefix", required=True)
    keygen.set_defaults(func=command_keygen)

    collect_cmd = sub.add_parser("collect")
    collect_cmd.add_argument("--output", required=True)
    collect_cmd.set_defaults(func=command_collect)

    decrypt = sub.add_parser("decrypt")
    decrypt.add_argument("--input", required=True)
    decrypt.add_argument("--private-key-file", required=True)
    decrypt.add_argument("--output-dir", required=True)
    decrypt.set_defaults(func=command_decrypt)

    inspect = sub.add_parser("inspect")
    inspect.add_argument("--input", required=True)
    inspect.set_defaults(func=command_inspect)

    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
