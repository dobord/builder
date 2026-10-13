"""Synthetic admission regressions; never query private package identities."""
import unittest
from unittest.mock import patch

from secure_release import project_dependency_review as review


class DependencyReviewTests(unittest.TestCase):
    def test_pinned_actions_and_fetchcontent_are_commit_queries(self):
        files = {"ci/builder/ci.yml": b"jobs:\n  test:\n    steps:\n      - uses: actions/checkout@" + b"a" * 40 + b"\n",
                 "CMakeLists.txt": b"FetchContent_Declare(test URL https://github.com/example/public/archive/" + b"b" * 40 + b".tar.gz)"}
        with patch.object(review, "public_commit", side_effect=lambda repo, ref: ref), patch.object(review, "action_version", return_value="4.2.2"):
            queries = review.inventory(files, {})
        self.assertEqual(queries, {review.query_key({"commit": "a" * 40}), review.query_key({"commit": "b" * 40}),
                                  review.query_key({"package": {"ecosystem": "GitHub Actions", "name": "actions/checkout"}, "version": "4.2.2"})})

    def test_action_semver_mapping_is_required_for_commit_pins(self):
        refs = [{"ref": "refs/tags/v4.2.2", "object": {"type": "commit", "sha": "a" * 40}}]
        with patch.object(review, "public_json", return_value=refs):
            self.assertEqual(review.action_version("actions/checkout", "a" * 40), "4.2.2")
        with patch.object(review, "public_json", return_value=[]), self.assertRaises(ValueError):
            review.action_version("actions/checkout", "b" * 40)

    def test_mutable_action_and_unknown_manifest_fail_closed(self):
        for files in ({"ci/builder/ci.yml": b"jobs:\n  test:\n    steps:\n      - uses: actions/checkout@main\n"},
                      {"package-lock.json": b"{}"},
                      {"requirements.txt": b"example>=1.0\n"}):
            with self.subTest(files=files), self.assertRaises(ValueError):
                review.inventory(files, {})

    def test_vcpkg_baseline_is_resolved_and_unknown_package_rejected(self):
        manifest = b'{"name":"synthetic","builtin-baseline":"' + b"a" * 40 + b'","dependencies":["zlib"]}'
        baseline = {"default": {"zlib": {"baseline": "1.3.1", "port-version": 0}}}
        with patch.object(review, "public_json", return_value=baseline):
            queries = review.inventory({"vcpkg.json": manifest}, {})
        self.assertEqual(queries, {review.query_key({"package": {"ecosystem": "OSS-Fuzz", "name": "zlib"}, "version": "1.3.1"})})
        with patch.object(review, "public_json", return_value=baseline), self.assertRaises(ValueError):
            review.inventory({"vcpkg.json": manifest.replace(b'zlib', b'unknown-package')}, {})

    def test_only_introduced_dependencies_are_scanned_and_receipt_is_bound(self):
        before = {review.query_key({"commit": "a" * 40})}
        after = before | {review.query_key({"commit": "b" * 40})}
        with patch.object(review, "public_json", return_value={}) as request:
            receipt = review.check(before, after, "c" * 40, "d" * 40)
        self.assertEqual(request.call_args.kwargs["data"], {"commit": "b" * 40})
        self.assertEqual(receipt["source_sha"], "d" * 40)
        self.assertEqual(receipt["introduced_count"], 1)

    def test_vulnerability_threshold_and_missing_data_fail_closed(self):
        query = {review.query_key({"commit": "a" * 40})}
        for response in ({"vulns": [{"id": "SYNTHETIC", "database_specific": {"severity": "MODERATE"}}]},
                         {"vulns": [{"id": "SYNTHETIC"}]}, {"vulns": None}, [],
                         {"unexpected": "field"}):
            with self.subTest(response=response), patch.object(review, "public_json", return_value=response), self.assertRaises(ValueError):
                review.check(set(), query, "b" * 40, "c" * 40)
        with patch.object(review, "public_json", side_effect=ValueError("unavailable")), self.assertRaises(ValueError):
            review.check(set(), query, "b" * 40, "c" * 40)
        with patch.object(review, "public_json", return_value={"vulns": [{"id": "SYNTHETIC", "database_specific": {"severity": "LOW"}}]}):
            self.assertEqual(review.check(set(), query, "b" * 40, "c" * 40)["result"], "success")

    def test_gitlink_without_public_module_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            review.inventory({}, {"third-party/example": "a" * 40})

    def test_private_upstream_and_moving_branch_never_reach_network(self):
        with patch.object(review, "public_json") as network:
            for repository, revision in (("dobord/private", "a" * 40), ("actions/checkout", "main")):
                with self.subTest(repository=repository), self.assertRaises(ValueError):
                    review.public_commit(repository, revision)
            network.assert_not_called()

    def test_non_pr_qualification_cannot_compare_candidate_against_itself(self):
        candidate = {review.query_key({"commit": "a" * 40})}
        payload = {"pr": 0, "source_sha": "b" * 40, "base_sha": "b" * 40}
        with patch.object(review, "snapshot", return_value=candidate), patch.object(review, "check", return_value={}) as check:
            review.verify("synthetic", payload, {})
            self.assertEqual(check.call_args.args[:2], (set(), candidate))


if __name__ == "__main__":
    unittest.main()
