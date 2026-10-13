"""Builder-owned recipe admission and bounded matrix expansion regressions."""
import json
import os
import contextlib
import io
import argparse
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from secure_release import project_ci as ci, project_ci_operator as operator
from tests.test_project_ci import payload
from tests.test_project_ci_operator import operator_payload


def synthetic_recipes():
    """An independently supplied test contract; never candidate-provided pins."""
    result = {}
    for profile, count in zip(ci.SUITES["release"], (20, 5, 5, 6, 3)):
        recipe = {"jobs": {"synthetic": {"runs-on": "${{ matrix.os }}", "strategy": {
            "matrix": {"include": [{"os": "ubuntu-24.04", "case": index} for index in range(count)]}},
            "steps": [{"run": "exit 0"}]}}}
        result[profile] = yaml.safe_dump(recipe).encode()
    return result


class RecipeContractTests(unittest.TestCase):
    def test_local_release_package_rejects_replacements_before_crypto_or_publication(self):
        raw = synthetic_recipes()
        pins = {profile: ci.digest_bytes(data) for profile, data in raw.items()}
        policy = {"repository": "dobord/synthetic", "repository_id": 1, "authorizer_branch": "main",
                  "operator_origin": "local-operator", "operator_id": 5323024, "request_schemas": [2]}
        changes = [dict(raw, ci=raw["ci"].replace(b"exit 0", b"exit 1")),
                   dict(raw, performance=raw["performance"].replace(b"ubuntu-24.04", b"windows-2022")),
                   {profile: data for profile, data in raw.items() if profile != "nightly-stress"}]
        def reply(path, token):
            if path.endswith(policy["repository"]):
                return {"id": 1, "full_name": policy["repository"]}
            if "/releases/tags/" in path:
                return {"draft": False, "prerelease": False, "tag_name": "v0.4.0", "published_at": "2026-01-01"}
            if "/git/ref/tags/" in path:
                return {"object": {"type": "commit", "sha": "e" * 40}}
            if "/git/ref/heads/main" in path:
                return {"object": {"type": "commit", "sha": "a" * 40}}
            raise AssertionError(path)
        with tempfile.TemporaryDirectory() as tmp:
            for index, changed in enumerate(changes):
                args = argparse.Namespace(work=Path(tmp) / f"private-{index}", policy=Path(tmp) / "policy.json",
                                          pr=0, suite="release", builder_sha="b" * 40, builder_ref="refs/tags/synthetic",
                                          baseline_tag="v0.4.0", source_sha="a" * 40, base_sha="a" * 40,
                                          input_public=Path(tmp) / "input-public.json", signing_private=Path(tmp) / "signing-private.json")
                def command(argv, **kwargs):
                    if argv[0] == "gh":
                        return subprocess.CompletedProcess(argv, 0, b"5323024\n", b"")
                    profile = argv[-1].rsplit("/", 1)[-1].removesuffix(".yml")
                    if profile not in changed:
                        return subprocess.CompletedProcess(argv, 1, b"", b"")
                    if "cat-file" in argv:
                        return subprocess.CompletedProcess(argv, 0, str(len(changed[profile])).encode(), b"")
                    kwargs["stdout"].write(changed[profile])
                    return subprocess.CompletedProcess(argv, 0, b"", b"")
                def private(path):
                    return json.dumps(policy) if path == args.policy else "SYNTHETIC_PRIVATE_KEY"
                with self.subTest(index=index), patch.object(operator, "private_directory", side_effect=lambda path, create=False: path.mkdir() if create else None), patch.object(ci, "RELEASE_RECIPE_DIGESTS", pins), patch.object(operator, "protected_file", side_effect=private), patch.object(operator, "public_file", return_value="PUBLIC_SYNTHETIC_KEY"), patch.object(operator, "builder_ref"), patch.object(ci, "api_json", side_effect=reply), patch.object(operator.subprocess, "run", side_effect=command), patch.object(ci, "checked"), patch.object(operator.crypto, "fingerprint"), patch.object(operator.crypto, "encrypt_file") as encrypt, patch.object(operator.crypto, "sign") as sign, patch.object(operator, "publish_input") as publish, patch.object(yaml, "safe_load") as parse, self.assertRaises(ValueError):
                    operator.package(args, "synthetic")
                encrypt.assert_not_called()
                sign.assert_not_called()
                publish.assert_not_called()
                parse.assert_not_called()

    def test_release_contract_checks_all_five_before_any_yaml_expansion(self):
        raw = synthetic_recipes()
        pins = {profile: ci.digest_bytes(data) for profile, data in raw.items()}
        with patch.object(ci, "RELEASE_RECIPE_DIGESTS", pins):
            self.assertEqual(len(ci.expand_recipes("release", raw)), 39)
            cases = []
            replacement = dict(raw)
            replacement["performance"] = replacement["performance"].replace(b"exit 0", b"exit 1")
            cases.append(replacement)  # Same lane count, different qualification.
            platform = dict(raw)
            platform["vcpkg-port"] = platform["vcpkg-port"].replace(b"ubuntu-24.04", b"windows-2022")
            cases.append(platform)
            missing = dict(raw)
            del missing["nightly-stress"]
            cases.append(missing)
            for changed in cases:
                with self.subTest(profiles=set(changed)), patch.object(yaml, "safe_load") as parse, patch.object(ci, "expand_recipe") as expand, self.assertRaises(ValueError):
                    ci.expand_recipes("release", changed)
                parse.assert_not_called()
                expand.assert_not_called()

    def test_recipe_reader_rejects_missing_profile_and_same_count_replacement(self):
        raw = synthetic_recipes()
        pins = {profile: ci.digest_bytes(data) for profile, data in raw.items()}
        with tempfile.TemporaryDirectory() as tmp, patch.object(ci, "RELEASE_RECIPE_DIGESTS", pins):
            root = Path(tmp)
            directory = root / "ci/builder"
            directory.mkdir(parents=True)
            for profile, data in raw.items():
                (directory / (profile + ".yml")).write_bytes(data)
            self.assertEqual(len(ci.recipes(root, "release")), 39)
            (directory / "ci.yml").write_bytes(raw["ci"].replace(b"ubuntu-24.04", b"macos-14"))
            with self.assertRaises(ValueError):
                ci.recipes(root, "release")
            (directory / "ci.yml").write_bytes(raw["ci"])
            (directory / "performance.yml").unlink()
            with self.assertRaises(ValueError):
                ci.recipes(root, "release")

    def test_cartesian_cardinality_is_rejected_before_product_is_called(self):
        recipe = {"jobs": {"synthetic": {"runs-on": "ubuntu-24.04", "strategy": {
            "matrix": {f"axis_{index}": list(range(10)) for index in range(12)}}, "steps": []}}}
        with patch.object(ci.itertools, "product") as product, self.assertRaises(ValueError):
            ci.expand_recipe("ci", recipe)
        product.assert_not_called()

    def test_matrix_shapes_types_and_row_bounds_fail_closed(self):
        matrices = ([], "bad", {"a": "string"}, {"a": []}, {"a": list(range(101))},
                    {"include": []}, {"include": [{}] * 101}, {"include": ["not-a-row"]},
                    {"include": [{"a": {"nested": "value"}}]}, {"include": [{}], "a": [1]},
                    {1: [1]}, {"a": [None]}, {"a": [float("inf")]},
                    {f"axis_{index}": [1] for index in range(17)})
        for matrix in matrices:
            recipe = {"jobs": {"synthetic": {"runs-on": "ubuntu-24.04", "strategy": {"matrix": matrix}}}}
            with self.subTest(matrix=matrix), self.assertRaises(ValueError):
                ci.expand_recipe("ci", recipe)
        for recipe in ([], {}, {"jobs": []}, {"jobs": {"bad": []}},
                       {"jobs": {"bad": {"strategy": [], "runs-on": "ubuntu-24.04"}}},
                       {"jobs": {"bad": {"runs-on": 7}}}):
            with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                ci.expand_recipe("ci", recipe)

    def test_cumulative_job_and_profile_limits_are_enforced_before_expansion(self):
        job = {"runs-on": "ubuntu-24.04", "strategy": {"matrix": {"a": list(range(60))}}}
        with patch.object(ci.itertools, "product", wraps=ci.itertools.product) as product, self.assertRaises(ValueError):
            ci.expand_recipe("ci", {"jobs": {"first": job, "second": job}})
        self.assertEqual(product.call_count, 1)
        raw = {profile: yaml.safe_dump({"jobs": {"synthetic": job}}).encode() for profile in ci.SUITES["ci"]}
        with patch.object(ci.itertools, "product", wraps=ci.itertools.product) as product, self.assertRaises(ValueError):
            ci.expand_recipes("ci", raw)
        self.assertEqual(product.call_count, 1)


class OperatorPolicyTests(unittest.TestCase):
    def test_opaque_source_policy_preserves_short_values_and_never_falls_back(self):
        policy = {"request_schemas": [2], "operator_id": 5323024, "repository_id": 1}
        encoded = ci.crypto.b64(json.dumps(policy).encode())
        with patch.dict(os.environ, {"CI_SOURCE_POLICY_B64": encoded, "CI_SOURCE_POLICY": "{}"}):
            self.assertEqual(ci.source_policy(), policy)
        for encoded in ("NOT_BASE64!", ci.crypto.b64(b"[]"), ci.crypto.b64(b"broken-json")):
            with patch.dict(os.environ, {"CI_SOURCE_POLICY_B64": encoded, "CI_SOURCE_POLICY": json.dumps(policy)}), self.assertRaises(ValueError):
                ci.source_policy()

    @unittest.skipUnless(os.name == "posix", "local client uses POSIX file ownership")
    def test_dispatch_and_wait_cli_accept_owner_controlled_0644_signing_public(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = root / "signing-public.json"
            public.write_text("PUBLIC_SYNTHETIC_KEY")
            public.chmod(0o644)
            state = {"request_digest": "a" * 64}
            operator.save(root / "state.json", state)
            for stage in ("dispatch", "wait"):
                args = ["project-ci-operator", stage, "--work", str(root), "--signing-public", str(public)]
                console = io.StringIO()
                with patch.object(operator.sys, "argv", args), patch.object(operator, "token", return_value="synthetic"), patch.object(operator, "validate_state") as verify, patch.object(operator, stage, return_value="https://github.com/dobord/builder/actions/runs/10") as execute, contextlib.redirect_stdout(console):
                    operator.main()
                verify.assert_called_once_with(state, "PUBLIC_SYNTHETIC_KEY")
                execute.assert_called_once()
                self.assertNotIn("PUBLIC_SYNTHETIC_KEY", console.getvalue())

    def test_schema_policy_denies_prepare_and_local_package_before_any_api(self):
        request = "OPAQUE_SYNTHETIC_CIPHERTEXT"
        env = {"GITHUB_REPOSITORY": ci.BUILDER, "GITHUB_REPOSITORY_ID": str(ci.BUILDER_ID),
               "GITHUB_SHA": "a" * 40, "CI_BUILDER_SHA": "a" * 40, "GITHUB_EVENT_NAME": "workflow_dispatch",
               "GITHUB_RUN_ATTEMPT": "1", "CI_REQUEST": request, "CI_REQUEST_DIGEST": ci.digest_bytes(request.encode()),
               "CI_REQUEST_SCHEMA": "1", "CI_SOURCE_POLICY": json.dumps({"request_schemas": [2]})}
        with patch.dict(os.environ, env), patch.object(ci, "api_json") as api, patch.object(ci, "pages") as pages, self.assertRaises(ValueError):
            ci.prepare()
        api.assert_not_called()
        pages.assert_not_called()
        policy = {"repository": "dobord/synthetic", "repository_id": 1, "operator_origin": "local-operator",
                  "operator_id": 5323024, "request_schemas": [1]}
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(work=Path(tmp) / "private", policy=Path(tmp) / "policy.json")
            args.policy.write_text(json.dumps(policy))
            args.policy.chmod(0o600)
            with patch.object(operator, "private_directory"), patch.object(operator, "protected_file", return_value=json.dumps(policy)), patch.object(operator, "builder_ref") as builder, patch.object(ci, "api_json") as api, self.assertRaises(ValueError):
                operator.package(args, "synthetic")
            builder.assert_not_called()
            api.assert_not_called()

    def test_local_client_rejects_non_posix_ownership_without_reading_files(self):
        with patch.object(operator.os, "name", "nt"):
            for reader in (operator.protected_file, operator.public_file, operator.private_directory):
                with self.subTest(reader=reader), self.assertRaisesRegex(ValueError, "POSIX-local"):
                    reader(None)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits and ownership do not establish Windows ACL protection")
    def test_public_files_accept_0644_but_private_files_reject_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "public.json"
            path.write_text("PUBLIC_SYNTHETIC_KEY")
            path.chmod(0o644)
            self.assertEqual(operator.public_file(path), "PUBLIC_SYNTHETIC_KEY")
            with self.assertRaises(ValueError):
                operator.protected_file(path)
            for mode in (0o664, 0o646):
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    operator.public_file(path)
            path.chmod(0o644)
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                operator.public_file(link)
            with self.assertRaises(ValueError):
                operator.public_file(Path(tmp))
            with path.open("r+b") as stream:
                stream.truncate(1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                operator.public_file(path)

    def test_schema_policy_rejects_disallowed_or_malformed_lists_before_api(self):
        policy = {"repository": "dobord/synthetic", "repository_id": 1,
                  "authorizer_branch": "main", "approval_boundaries": [], "request_schemas": [2]}
        for schemas in ([2], [], [True], [3], "2", [1, 1]):
            current = dict(policy, request_schemas=schemas)
            with self.subTest(schemas=schemas), patch.dict(os.environ, {"CI_SOURCE_POLICY": json.dumps(current)}), patch.object(ci, "api_json") as api, patch.object(ci, "pages") as pages, self.assertRaises(ValueError):
                ci.verify_source_policy(payload(), "synthetic")
            api.assert_not_called()
            pages.assert_not_called()
        with self.assertRaises(ValueError):
            ci.verify_request_schema(dict(policy, request_schemas=[1]), 2)
        ci.verify_request_schema(policy, 2)
        ci.verify_request_schema({key: value for key, value in policy.items() if key != "request_schemas"}, 1)

    def test_schema2_pr_base_branch_must_be_the_authorizer_branch(self):
        value = dict(operator_payload(), pr=151, suite="release")
        policy = {"repository": value["source"], "repository_id": value["source_id"],
                  "authorizer_branch": "main", "approval_boundaries": [], "operator_id": 5323024,
                  "operator_origin": "local-operator", "request_schemas": [2]}
        pr = {"head": {"sha": value["source_sha"], "repo": {"id": 1}},
              "base": {"sha": value["base_sha"], "repo": {"id": 1}, "ref": "main"}, "state": "open"}
        def reply(path, token):
            if path.endswith(value["source"]):
                return {"id": 1, "full_name": value["source"]}
            if "/releases/tags/" in path:
                return {"draft": False, "prerelease": False, "tag_name": "v0.4.0", "published_at": "2026-01-01"}
            if "/git/ref/tags/" in path:
                return {"object": {"type": "commit", "sha": value["baseline_sha"]}}
            if "/pulls/" in path:
                return pr
            raise AssertionError(path)
        with patch.dict(os.environ, {"CI_SOURCE_POLICY": json.dumps(policy), "GITHUB_ACTOR_ID": "5323024"}), patch.object(ci, "api_json", side_effect=reply):
            ci.verify_source_policy(value, "synthetic")
            pr["base"]["ref"] = "other"
            with self.assertRaises(ValueError):
                ci.verify_source_policy(value, "synthetic")


if __name__ == "__main__":
    unittest.main()
