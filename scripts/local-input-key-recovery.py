"""Temporary owner-requested encrypted transfer of the existing INPUT key."""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_release import crypto

RECIPIENT_B64 = "ewogICJwcmltYXJ5S2V5SWQiOiAxOTc5NzEwNDAzLAogICJrZXkiOiBbCiAgICB7CiAgICAgICJrZXlEYXRhIjogewogICAgICAgICJ0eXBlVXJsIjogInR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkhwa2VQdWJsaWNLZXkiLAogICAgICAgICJ2YWx1ZSI6ICJFZ1lJQVJBQkdBSWFJQWpqK29tNlJVNjF3NEFtK2dPVHllVEZPbDJXa2ZXV2JlYnVYNXNhMHRGZCIsCiAgICAgICAgImtleU1hdGVyaWFsVHlwZSI6ICJBU1lNTUVUUklDX1BVQkxJQyIKICAgICAgfSwKICAgICAgInN0YXR1cyI6ICJFTkFCTEVEIiwKICAgICAgImtleUlkIjogMTk3OTcxMDQwMywKICAgICAgIm91dHB1dFByZWZpeFR5cGUiOiAiVElOSyIKICAgIH0KICBdCn0="
RECIPIENT_SHA256 = "e84ef0e99332ba58a7586d1850defe4ee0233f011f604f72e2c159dcb62ecb59"
BRANCH = "temporary/input-key-recovery-20261001"


def context(environment: dict[str, str]) -> dict:
    if (environment.get("GITHUB_REPOSITORY") != "dobord/builder"
            or environment.get("GITHUB_REF") != "refs/heads/" + BRANCH
            or re.fullmatch(r"[0-9a-f]{40}", environment.get("GITHUB_SHA", "")) is None):
        raise ValueError("Invalid recovery repository, branch, or revision")
    run = int(environment["GITHUB_RUN_ID"])
    attempt = int(environment["GITHUB_RUN_ATTEMPT"])
    if run <= 0 or attempt <= 0:
        raise ValueError("Invalid recovery run identity")
    return {"schema": 1, "purpose": "builder-local-input-key-recovery-v1",
            "repository": environment["GITHUB_REPOSITORY"], "branch": BRANCH,
            "run": run, "attempt": attempt, "builder_sha": environment["GITHUB_SHA"]}


def main() -> None:
    binding = context(dict(os.environ))
    public = crypto.unb64(RECIPIENT_B64).decode("utf-8")
    if crypto.fingerprint(public) != RECIPIENT_SHA256:
        raise ValueError("Recovery recipient identity changed")
    private = os.environ.pop("BUILDER_INPUT_PRIVATE_KEY", "")
    if not private or len(private.encode("utf-8")) > 65536:
        raise ValueError("INPUT key is absent or exceeds the recovery bound")
    try:
        crypto.public_text(private)
    except Exception:
        raise ValueError("INPUT key is not a valid private encryption keyset") from None
    root = Path(os.environ["RUNNER_TEMP"]) / "local-input-key-recovery"
    root.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".input-key-", dir=root) as folder:
        source = Path(folder) / "input-private.json"
        with open(source, "x", encoding="utf-8", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
            stream.write(private)
        crypto.encrypt_file(source, root / "input-key.enc", public, binding)
    print("ENCRYPTED_INPUT_KEY_RECOVERY_READY")


if __name__ == "__main__":
    main()
