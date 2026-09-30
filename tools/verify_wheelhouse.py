#!/usr/bin/env python3
"""Verify the vendored offline wheelhouse against the exact lockfile hashes."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WHEELHOUSE = ROOT / "vendor" / "wheels"
LOCK = ROOT / "requirements.lock"

EXPECTED = {
    "absl_py-2.3.1-py3-none-any.whl":
        "eeecf07f0c2a93ace0772c92e596ace6d3d3996c042b2128459aaae2a76de11d",
    "bazel_runfiles-1.6.3-py3-none-any.whl":
        "76a6c2d1e9cc2b8fc9ae657901aff0dbf4da46ee1eeab67cce8fd907e3196857",
    "protobuf-6.33.5-cp310-abi3-win_amd64.whl":
        "3093804752167bcab3998bec9f1048baae6e29505adaf1afd14a37bddede533c",
    "protobuf-6.33.5-cp39-abi3-manylinux2014_x86_64.whl":
        "cbf16ba3350fb7b889fca858fb215967792dc125b35c7976ca4818bee3521cf0",
    "tink-1.16.1-cp312-cp312-win_amd64.whl":
        "99766688b84b362516488fbf371b4f801c5b2833a86cc8b70f58d607a636d951",
    "tink-1.16.1-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl":
        "af3519dfa01704e9f1ae1020db6076dcff89b5f799deba08a1adf901d977fc4e",
    "tink-1.16.1-cp313-cp313-win_amd64.whl":
        "33818c06bd17397de1e3a122fb2db7aa2658eed06d01f299ce004d7ff3612b98",
    "tink-1.16.1-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl":
        "a33da9474ee43a21e0c7261ad8af1a3b394d1607db2d79a0a21e3d5305285e68",
}


def main() -> int:
    if not WHEELHOUSE.is_dir():
        print(f"missing wheelhouse: {WHEELHOUSE}", file=sys.stderr)
        return 1

    lock = LOCK.read_text("utf-8")
    missing_pins = [
        digest for digest in EXPECTED.values()
        if f"--hash=sha256:{digest}" not in lock
    ]
    if missing_pins:
        print("requirements.lock does not contain every vendored wheel hash", file=sys.stderr)
        return 1

    actual = {p.name for p in WHEELHOUSE.glob("*.whl") if p.is_file()}
    expected = set(EXPECTED)
    if actual != expected:
        print(f"wheelhouse mismatch; missing={sorted(expected - actual)} extra={sorted(actual - expected)}",
              file=sys.stderr)
        return 1

    for name, expected_hash in sorted(EXPECTED.items()):
        path = WHEELHOUSE / name
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            print(f"SHA256 mismatch: {name}", file=sys.stderr)
            return 1

    print("Offline wheelhouse verified: exact filenames and SHA256 pins match requirements.lock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
