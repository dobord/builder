#!/usr/bin/env python3
"""Decrypt builder encrypted-log artifacts with OpenSSL 3, without Tink Python."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secure_release.openssl_tink_logs import (  # noqa: E402
    MAX_CIPHERTEXT_BYTES,
    OpenSSLBackend,
    decrypt_archive,
)

SAFE_ENC_NAME = re.compile(r"[A-Za-z0-9_.+-]{1,240}\.enc\Z")


def read_private_key(path: Path) -> str:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("private key must be a regular file")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if os.name != "nt" and mode & 0o077:
            print(
                "WARNING: private key is group/world-accessible; run: chmod 600 "
                + str(path),
                file=sys.stderr,
            )
    except OSError:
        pass
    data = path.read_text(encoding="utf-8").strip()
    if not data or len(data) > 2 * 1024 * 1024:
        raise ValueError("invalid private key file size")
    return data


def validate_ciphertext(path: Path) -> Path:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("ciphertext must be a regular file")
    if not 0 < path.stat().st_size <= MAX_CIPHERTEXT_BYTES:
        raise ValueError("ciphertext size is outside the local diagnostic limit")
    return path


def extract_one_enc(archive_path: Path, directory: Path) -> Path:
    archive_path = archive_path.expanduser().resolve(strict=True)
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ValueError("artifact ZIP must be a regular file")
    with zipfile.ZipFile(archive_path) as archive:
        candidates = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            leaf = Path(name).name
            if info.flag_bits & 1:
                raise ValueError("password-encrypted ZIP entries are not supported")
            if leaf.endswith(".enc"):
                if name != leaf or not SAFE_ENC_NAME.fullmatch(leaf):
                    raise ValueError("unsafe encrypted-log member name")
                if not 0 < info.file_size <= MAX_CIPHERTEXT_BYTES:
                    raise ValueError("encrypted-log member size is outside the local limit")
                candidates.append(info)
        if len(candidates) != 1:
            raise ValueError(
                f"expected exactly one .enc encrypted-log member, found {len(candidates)}"
            )
        target = directory / candidates[0].filename
        with archive.open(candidates[0]) as source, target.open("xb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
    return validate_ciphertext(target)


def decrypt_input(
    input_path: Path,
    private_key: str,
    output: Path,
    openssl_library: str | None,
) -> dict:
    suffix = input_path.suffix.lower()
    if suffix == ".enc":
        return decrypt_archive(
            validate_ciphertext(input_path), output, private_key,
            openssl_library=openssl_library,
        )
    if suffix == ".zip":
        with tempfile.TemporaryDirectory(prefix=".builder-openssl-artifact-") as folder:
            cipher = extract_one_enc(input_path, Path(folder))
            return decrypt_archive(
                cipher, output, private_key, openssl_library=openssl_library
            )
    raise ValueError("input must be a raw .enc file or a GitHub artifact .zip")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version", action="store_true",
        help="Print the detected OpenSSL version and exit",
    )
    parser.add_argument(
        "--input", type=Path,
        help="Downloaded GitHub artifact ZIP or raw .enc file",
    )
    parser.add_argument(
        "--private-key", type=Path,
        help="Base64 transport key or decoded Tink JSON key file",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Fresh directory for authenticated plaintext logs",
    )
    parser.add_argument(
        "--openssl-library",
        help="Optional explicit OpenSSL 3 libcrypto path; normally auto-detected",
    )
    args = parser.parse_args()

    if args.version:
        print(OpenSSLBackend(args.openssl_library).version)
        return 0
    if args.input is None or args.private_key is None or args.output is None:
        parser.error(
            "--input, --private-key and --output are required unless --version is used"
        )

    output = args.output.expanduser().resolve()
    if output.exists():
        raise ValueError("output directory already exists; choose a fresh path")
    manifest = decrypt_input(
        args.input.expanduser(),
        read_private_key(args.private_key),
        output,
        args.openssl_library,
    )
    context = manifest.get("context", {}) if isinstance(manifest, dict) else {}
    safe = {
        "status": "decrypted",
        "backend": "OpenSSL",
        "output": str(output),
        "file_count": manifest.get("file_count", 0) if isinstance(manifest, dict) else 0,
        "repository": context.get("repository", ""),
        "run_id": context.get("run_id", ""),
        "run_attempt": context.get("run_attempt", ""),
        "job": context.get("job", ""),
    }
    print(json.dumps(safe, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
