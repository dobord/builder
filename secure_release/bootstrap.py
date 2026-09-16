"""Run locally, never in Actions: generate keys and provision GitHub via gh stdin."""
from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
from . import crypto
from .protocol import SOURCE, BUILDER, BIN, IDS, sha, validate_plan


def gh(args: list[str], data: bytes | None = None) -> bytes:
    result = subprocess.run(["gh", *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise RuntimeError("GitHub CLI operation failed; check authentication and administrator permissions")
    return result.stdout


def api(path: str):
    return crypto.parse(gh(["api", "-H", "X-GitHub-Api-Version: 2026-03-10", path]))


def variable(repo: str, name: str, value: str):
    gh(["variable", "set", name, "--repo", repo, "--body", value])


def secret(repo: str, name: str, value: str):
    if not value or len(value.encode()) > 45000:
        raise ValueError("invalid secret size")
    gh(["secret", "set", name, "--repo", repo], value.encode())


def protect_directory(path: Path):
    if path.exists():
        raise ValueError("key directory already exists; refusing to overwrite")
    path = path.absolute()
    if any((p / ".git").exists() for p in (path.parent, *path.parents)):
        raise ValueError("key directory must be outside all Git worktrees")
    path.mkdir(mode=0o700, parents=False)
    if os.name == "nt":
        identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
        import csv
        sid = next(csv.reader([identity.stdout.strip()]))[1]
        if not sid.startswith("S-1-"):
            raise ValueError("cannot determine Windows SID")
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", "*" + sid + ":(OI)(CI)F"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate(directory: Path):
    protect_directory(directory)
    for role, kind in (("artifact", "encrypt"), ("builder-input", "encrypt"), ("request-signing", "sign")):
        private, public = crypto.generate(kind)
        for suffix, data in (("private", private), ("public", public)):
            path = directory / f"{role}-{suffix}.json"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(data)
    print("Three independent keypairs generated locally. Back up the protected directory securely.")


def configure(directory: Path, revision: str, with_tokens: bool):
    revision = sha(revision)
    for repo in (SOURCE, BUILDER, BIN):
        metadata = api(f"repos/{repo}")
        if metadata["id"] != IDS[repo] or not metadata.get("permissions", {}).get("admin"):
            raise ValueError("canonical repository administrator access required")
        if repo != BUILDER and not metadata["private"]:
            raise ValueError("source and destination must remain private")
    for repo in (SOURCE, BUILDER, BIN):
        variable(repo, "RELEASE_ENABLED", "false")
    variable(BIN, "PUBLISH_ENABLED", "false")
    if api(f"repos/{BUILDER}/commits/main")["sha"] != revision:
        raise ValueError("reviewed builder commit must be current main")
    record = api(f"repos/{SOURCE}/contents/ci/release-plan.json?ref=main")
    plan = crypto.parse(crypto.unb64(record["content"].replace("\n", "")))
    validate_plan(plan)
    def load(name):
        path = directory / (name + ".json")
        if not path.is_file() or path.stat().st_size > 45000:
            raise ValueError("key file missing or oversized")
        return path.read_text("utf-8")
    artifact_private = load("artifact-private")
    artifact_public = load("artifact-public")
    input_private = load("builder-input-private")
    input_public = load("builder-input-public")
    signing_private = load("request-signing-private")
    signing_public = load("request-signing-public")
    if (crypto.fingerprint(crypto.public_text(artifact_private)) != crypto.fingerprint(artifact_public)
            or crypto.fingerprint(crypto.public_text(input_private)) != crypto.fingerprint(input_public)):
        raise ValueError("keypair mismatch")
    crypto.verify(crypto.sign({"purpose": "local-key-check"}, signing_private), signing_public)
    for repo in (SOURCE, BUILDER, BIN):
        variable(repo, "BUILDER_COMMIT_SHA", revision)
        secret(repo, "ARTIFACT_ENCRYPTION_PUBLIC_KEY", artifact_public)
    secret(SOURCE, "REQUEST_SIGNING_PRIVATE_KEY", signing_private)
    secret(SOURCE, "BUILDER_INPUT_PUBLIC_KEY", input_public)
    secret(BUILDER, "BUILDER_INPUT_PRIVATE_KEY", input_private)
    secret(BUILDER, "REQUEST_VERIFY_PUBLIC_KEY", signing_public)
    secret(BIN, "REQUEST_VERIFY_PUBLIC_KEY", signing_public)
    secret(BIN, "ARTIFACT_DECRYPTION_PRIVATE_KEY", artifact_private)
    source_repos = sorted({SOURCE, *(p["repository"] for p in plan["ports"])})
    secret(BUILDER, "SOURCE_ALLOWLIST", ",".join(source_repos))
    if with_tokens:
        prompts = ((SOURCE, "BUILDER_DISPATCH_TOKEN", "Selected repository: builder; Actions write"),
                   (BUILDER, "SOURCE_READ_TOKEN", "Selected source repositories from the private plan; Contents read, Actions read"),
                   (BUILDER, "BIN_DISPATCH_TOKEN", "Selected repository: vcpkg-bin; Actions write"),
                   (BIN, "BUILDER_READ_TOKEN", "Selected repository: builder; Actions read"))
        for repo, name, scope in prompts:
            print(f"{name}: {scope}")
            value = getpass.getpass("Paste fine-grained PAT (hidden): ").strip()
            secret(repo, name, value)
            del value
    print("Keys and approved revision installed. RELEASE_ENABLED and PUBLISH_ENABLED remain false.")
    print("No release was started. Review green synthetic CI and the private setup guide before enabling.")


def main():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise RuntimeError("production key generation is forbidden in Actions")
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate"); gen.add_argument("--directory", type=Path, required=True)
    setup = sub.add_parser("configure")
    setup.add_argument("--directory", type=Path, required=True)
    setup.add_argument("--builder-sha", required=True)
    setup.add_argument("--prompt-tokens", action="store_true")
    args = parser.parse_args()
    if args.command == "generate":
        generate(args.directory.expanduser().resolve())
    else:
        configure(args.directory.expanduser().resolve(), args.builder_sha, args.prompt_tokens)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Setup stopped ({type(error).__name__}); no secret values are printed. Existing keys are never overwritten.", file=sys.stderr)
        sys.exit(1)
