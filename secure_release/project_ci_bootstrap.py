"""LOCAL-only dedicated project-CI keys and gh-stdin provisioning."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import subprocess

from . import crypto, project_ci as ci


def outside_worktree(directory):
    directory = directory.expanduser().resolve()
    for parent in (directory, *directory.parents):
        if (parent / ".git").exists():
            raise ValueError("key directory must be outside Git worktrees")
    return directory


def generate(directory):
    directory = outside_worktree(directory)
    directory.mkdir(mode=0o700)
    for role, kind in (("signing", "sign"), ("input", "encrypt")):
        private, public = crypto.generate(kind)
        for suffix, text in (("private", private), ("public", public)):
            path = directory / f"ci-{role}-{suffix}.json"
            with path.open("x", encoding="utf-8") as output:
                os.chmod(path, 0o600)
                output.write(text)
    print("PROJECT_CI_KEYS_GENERATED; retain the protected offline backup")


def gh(arguments, *, data=None):
    result = subprocess.run(["gh", *arguments], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError("GitHub provisioning failed")
    return result.stdout


def configure(directory, revision, policy_file):
    directory = outside_worktree(directory)
    if not ci.SHA.fullmatch(revision):
        raise ValueError("reviewed full builder SHA required")
    builder = crypto.parse(gh(["api", "repos/dobord/builder"]))
    policy = crypto.parse(policy_file.read_bytes())
    if (set(policy) != {"repository", "repository_id", "authorizer_branch", "approval_boundaries"} or
            not re.fullmatch(r"dobord/[A-Za-z0-9_.-]+", policy["repository"]) or
            policy["authorizer_branch"] != "main" or not 1 <= len(policy["approval_boundaries"]) <= 10):
        raise ValueError("invalid source policy")
    for pattern in policy["approval_boundaries"]:
        re.compile(pattern)
    source = crypto.parse(gh(["api", "repos/" + policy["repository"]]))
    branch = crypto.parse(gh(["api", "repos/dobord/builder/branches/main"]))
    if (builder["id"] != ci.BUILDER_ID or source["id"] != policy["repository_id"] or
            not source["private"] or branch["commit"]["sha"] != revision):
        raise ValueError("unapproved repository or builder revision")
    # Repository-scoped signing secrets would be available to a new same-repo
    # PR workflow that omits the protected environment. Require environment-only
    # signing/dispatch credentials and verify its main-only deployment policy.
    environment = crypto.parse(gh(["api", f"repos/{policy['repository']}/environments/encrypted-builder-ci"]))
    deployment = environment.get("deployment_branch_policy") or {}
    branches = crypto.parse(gh(["api", f"repos/{policy['repository']}/environments/encrypted-builder-ci/deployment-branch-policies"]))
    reviewers = [rule for rule in environment["protection_rules"] if rule["type"] == "required_reviewers"]
    if (not deployment.get("custom_branch_policies") or
            [(item["name"], item["type"]) for item in branches["branch_policies"]] != [("main", "branch")] or
            not reviewers or not reviewers[0].get("reviewers")):
        raise ValueError("source authorizer environment is not protected")
    existing = crypto.parse(gh(["api", f"repos/{policy['repository']}/actions/secrets"]))
    if {item["name"] for item in existing["secrets"]} & {"PROJECT_CI_SIGNING_PRIVATE_KEY_B64", "BUILDER_DISPATCH_TOKEN"}:
        raise ValueError("privileged CI credentials must not be repository scoped")
    def load(role):
        path = directory / (role + ".json")
        if path.is_symlink() or (os.name != "nt" and path.stat().st_mode & 0o077):
            raise ValueError("unprotected key backup")
        return path.read_text()
    signing_private, signing_public = load("ci-signing-private"), load("ci-signing-public")
    input_private, input_public = load("ci-input-private"), load("ci-input-public")
    if (crypto.public_text(signing_private) != signing_public or
            crypto.fingerprint(crypto.public_text(input_private)) != crypto.fingerprint(input_public)):
        raise ValueError("key backup mismatch")
    settings = {
        policy["repository"]: {"PROJECT_CI_SIGNING_PRIVATE_KEY_B64": crypto.b64(signing_private.encode()),
                                "PROJECT_CI_INPUT_PUBLIC_KEY_B64": crypto.b64(input_public.encode())},
        ci.BUILDER: {"PROJECT_CI_INPUT_PRIVATE_KEY_B64": crypto.b64(input_private.encode()),
                     "PROJECT_CI_INPUT_PUBLIC_KEY_B64": crypto.b64(input_public.encode()),
                     "PROJECT_CI_VERIFY_PUBLIC_KEY_B64": crypto.b64(signing_public.encode()),
                     "PROJECT_CI_SOURCE_POLICY": crypto.canonical(policy).decode()}}
    for repo, secrets in settings.items():
        for name, value in secrets.items():
            arguments = ["secret", "set", name, "--repo", repo]
            if repo == policy["repository"] and name == "PROJECT_CI_SIGNING_PRIVATE_KEY_B64":
                arguments.extend(["--env", "encrypted-builder-ci"])
            gh(arguments, data=value.encode())
        gh(["variable", "set", "PROJECT_CI_BUILDER_SHA", "--repo", repo, "--body", revision])
    gh(["variable", "set", "PROJECT_CI_BUILDER_REF", "--repo", policy["repository"], "--body", "main"])
    gh(["variable", "set", "PROJECT_CI_ENABLED", "--repo", ci.BUILDER, "--body", "false"])
    print("PROJECT_CI_CONFIGURED_DISABLED; review protected environment, tokens and runner before activation")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("generate", "configure"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--builder-sha")
    parser.add_argument("--source-policy", type=Path)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise SystemExit("LOCAL_CONFIGURATION_ONLY")
    try:
        if args.stage == "generate":
            generate(args.directory)
        else:
            if args.source_policy is None:
                raise ValueError("operator-reviewed source policy required")
            configure(args.directory, args.builder_sha or "", args.source_policy)
    except Exception:
        raise SystemExit("PROJECT_CI_CONFIGURATION_FAILED; no key material is printed") from None


if __name__ == "__main__":
    main()
