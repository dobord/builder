"""Owner baseline exceptions are exact, independent policy, not request privileges."""
import copy
import json
import os
import unittest
from unittest.mock import patch

from secure_release import project_ci as ci, project_ci_operator as operator
from tests.test_project_ci import payload
from tests.test_project_ci_operator import operator_payload


def fixture():
    value = dict(operator_payload(), suite="release", pr=0)
    value.update(base_sha=value["source_sha"], baseline_sha=value["source_sha"])
    value["baseline_tag"] = "owner-approved-" + value["baseline_sha"]
    approval = {"candidate_sha": value["source_sha"], "baseline_sha": value["baseline_sha"],
                "suites": ["performance", "release"], "approved_by": value["operator_id"],
                "reason": "Owner approved resetting the synthetic release baseline"}
    policy = {"repository": value["source"], "repository_id": value["source_id"],
              "operator_origin": "local-operator", "operator_id": value["operator_id"],
              "request_schemas": [2], "authorizer_branch": "main", "approval_boundaries": [],
              "baseline_exceptions": [approval]}
    return value, policy


class BaselineExceptionTests(unittest.TestCase):
    def reply(self, value):
        def api(path, token):
            self.assertEqual(token, "SYNTHETIC")
            prefix = "repos/" + value["source"]
            if path == prefix:
                return {"id": value["source_id"], "full_name": value["source"]}
            if path == prefix + "/git/commits/" + value["baseline_sha"]:
                return {"sha": value["baseline_sha"]}
            if path == prefix + "/git/ref/heads/main":
                return {"object": {"type": "commit", "sha": value["source_sha"]}}
            raise AssertionError("Unexpected API endpoint: " + path)
        return api

    def test_explicit_schema2_marker_is_structurally_valid_but_not_authorization(self):
        value, _ = fixture()
        ci.validate_payload(value)
        for change in ({"baseline_tag": "v0.4.0"}, {"schema": 1}, {"suite": "ci"},
                       {"baseline_tag": "owner-approved-" + "0" * 40}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                ci.validate_payload(dict(value, **change))
        legacy = dict(payload(), suite="release")
        legacy["baseline_tag"] = "owner-approved-" + legacy["baseline_sha"]
        with self.assertRaises(ValueError):
            ci.validate_payload(legacy)

    def test_exact_policy_revalidates_baseline_commit_and_current_main(self):
        value, policy = fixture()
        env = {"CI_SOURCE_POLICY": json.dumps(policy), "GITHUB_ACTOR_ID": "5323024"}
        with patch.dict(os.environ, env), patch.object(ci, "api_json", side_effect=self.reply(value)) as api:
            ci.verify_source_policy(value, "SYNTHETIC")
        self.assertEqual(api.call_count, 3)

    def test_missing_mismatched_malformed_or_duplicate_approval_fails_closed(self):
        value, policy = fixture()
        policies = [dict(policy, baseline_exceptions=[])]
        absent = dict(policy)
        absent.pop("baseline_exceptions")
        policies.append(absent)
        for change in ({"candidate_sha": "0" * 40}, {"baseline_sha": "0" * 40},
                       {"approved_by": 7}, {"approved_by": True}, {"reason": ""},
                       {"reason": "bad\nreason"}, {"reason": "x" * 1025},
                       {"suites": ["ci"]}, {"suites": ["release", "release"]},
                       {"suites": []}, {"extra": True}):
            policies.append(dict(policy, baseline_exceptions=[dict(policy["baseline_exceptions"][0], **change)]))
        policies.extend([dict(policy, baseline_exceptions=None),
                         dict(policy, baseline_exceptions=policy["baseline_exceptions"] * 2),
                         dict(policy, baseline_exceptions=policy["baseline_exceptions"] * 9)])
        for invalid in policies:
            with self.subTest(policy=invalid), patch.dict(os.environ, {
                    "CI_SOURCE_POLICY": json.dumps(invalid), "GITHUB_ACTOR_ID": "5323024"}), \
                    patch.object(ci, "api_json", side_effect=self.reply(value)) as api, self.assertRaises(ValueError):
                ci.verify_source_policy(value, "SYNTHETIC")
            self.assertEqual(api.call_count, 1)  # Only repository identity, never source execution.

    def test_exception_does_not_bypass_actor_source_identity_or_current_main(self):
        value, policy = fixture()
        env = {"CI_SOURCE_POLICY": json.dumps(policy), "GITHUB_ACTOR_ID": "5323024"}
        for change in ({"source_id": 7}, {"source": "dobord/foreign"},
                       {"operator_id": 7}, {"base_sha": "0" * 40}):
            with self.subTest(change=change), patch.dict(os.environ, env), \
                    patch.object(ci, "api_json", side_effect=self.reply(value)), self.assertRaises(ValueError):
                ci.verify_source_policy(dict(value, **change), "SYNTHETIC")
        for suffix, replacement in (("/git/commits/" + value["baseline_sha"], {"sha": "0" * 40}),
                                    ("/git/ref/heads/main", {"object": {"type": "commit", "sha": "0" * 40}})):
            reply = self.reply(value)
            with self.subTest(suffix=suffix), patch.dict(os.environ, env), \
                    patch.object(ci, "api_json", side_effect=lambda path, token: replacement if path.endswith(suffix) else reply(path, token)), \
                    self.assertRaises(ValueError):
                ci.verify_source_policy(value, "SYNTHETIC")
        with patch.dict(os.environ, dict(env, GITHUB_ACTOR_ID="7")), \
                patch.object(ci, "api_json") as api, self.assertRaises(ValueError):
            ci.verify_source_policy(value, "SYNTHETIC")
        api.assert_not_called()

    def test_local_resolver_requires_same_approval_as_independent_builder(self):
        value, policy = fixture()
        with patch.object(ci, "api_json", side_effect=self.reply(value)) as api:
            self.assertEqual(operator.baseline(policy, value["baseline_tag"], "SYNTHETIC",
                                             source_sha=value["source_sha"], suite="release"), value["baseline_sha"])
        self.assertEqual(api.call_count, 1)
        for change in ({"source_sha": "0" * 40}, {"suite": "ci"}):
            args = dict(source_sha=value["source_sha"], suite="release")
            args.update(change)
            with patch.object(ci, "api_json") as api, self.assertRaises(ValueError):
                operator.baseline(policy, value["baseline_tag"], "SYNTHETIC", **args)
            api.assert_not_called()
        independent = copy.deepcopy(policy)
        independent.pop("baseline_exceptions")
        with patch.dict(os.environ, {"CI_SOURCE_POLICY": json.dumps(independent), "GITHUB_ACTOR_ID": "5323024"}), \
                patch.object(ci, "api_json", side_effect=self.reply(value)), self.assertRaises(ValueError):
            ci.verify_source_policy(value, "SYNTHETIC")


if __name__ == "__main__":
    unittest.main()
