"""Synthetic admission regressions; never query private package identities."""
import unittest
import hashlib
import json
import urllib.error
from unittest.mock import patch

from secure_release import project_dependency_review as review


class DependencyReviewTests(unittest.TestCase):
    def test_http_denial_records_only_bounded_rate_limit_evidence(self):
        from secure_release import project_ci

        url = 'https://api.github.com/repos/actions/checkout/git/ref/tags/v4'
        headers = {'X-RateLimit-Remaining': '0', 'X-RateLimit-Limit': '60',
                   'Retry-After': '59', 'Authorization': 'PUBLIC_SYNTHETIC_SECRET'}
        with patch.object(review.urllib.request, 'build_opener') as build:
            build.return_value.open.side_effect = urllib.error.HTTPError(url, 403, 'private', headers, None)
            with self.assertRaises(review.DependencyTransportError) as caught:
                review.public_json(url)
        report = project_ci.prepare_failure_record(caught.exception)
        self.assertEqual(report['dependency_transport']['rate_limit'],
                         {'remaining': 0, 'limit': 60, 'retry_after_seconds': 59})
        self.assertNotIn(url, json.dumps(report))
        self.assertNotIn('PUBLIC_SYNTHETIC_SECRET', json.dumps(report))
        build.return_value.open.assert_called_once()

    def test_malformed_or_excessive_rate_limit_headers_are_not_retained(self):
        from secure_release import project_ci

        url = 'https://api.github.com/repos/actions/checkout/git/ref/tags/v4'
        for value in ('-1', '1234567890123456789', 'PUBLIC_SYNTHETIC_SECRET', '3.2', ' 0', True):
            with self.subTest(value=value), patch.object(review.urllib.request, 'build_opener') as build:
                build.return_value.open.side_effect = urllib.error.HTTPError(
                    url, 403, 'private', {'X-RateLimit-Remaining': value}, None)
                with self.assertRaises(review.DependencyTransportError) as caught:
                    review.public_json(url)
                report = project_ci.prepare_failure_record(caught.exception)
                self.assertNotIn('rate_limit', report['dependency_transport'])

    def test_forged_transport_counters_are_validated_again_at_diagnostic_boundary(self):
        from secure_release import project_ci

        error = review.DependencyTransportError('github-api', 'http', 403,
            {'remaining': True, 'limit': 'PUBLIC_SYNTHETIC_SECRET', 'retry_after_seconds': 86401,
             'Authorization': 'PUBLIC_SYNTHETIC_SECRET'})
        report = project_ci.prepare_failure_record(error)
        self.assertNotIn('rate_limit', report['dependency_transport'])
        self.assertNotIn('PUBLIC_SYNTHETIC_SECRET', json.dumps(report))
        self.assertEqual(review.bounded_rate_limit(None), {})

    def test_metadata_transport_retries_transient_gateway_failure(self):
        url = 'https://api.github.com/repos/actions/checkout/git/ref/tags/v4'
        with patch.object(review.urllib.request, 'build_opener') as build, patch('time.sleep') as delay:
            opener = build.return_value
            response = unittest.mock.MagicMock()
            response.__enter__.return_value.read.return_value = b'{"object": {}}'
            opener.open.side_effect = [urllib.error.HTTPError(url, 503, 'private', {}, None), response]
            self.assertEqual(review.public_json(url), {'object': {}})
            self.assertEqual(opener.open.call_count, 2)
            delay.assert_called_once()

    def test_metadata_transport_keeps_denials_fail_closed_without_exposing_details(self):
        from secure_release import project_ci

        url = 'https://api.github.com/repos/actions/checkout/git/ref/tags/v4'
        with patch.object(review.urllib.request, 'build_opener') as build:
            opener = build.return_value
            opener.open.side_effect = urllib.error.HTTPError(url, 403, 'private body', {}, None)
            with self.assertRaisesRegex(ValueError, '^dependency data unavailable$') as error:
                review.public_json(url)
            opener.open.assert_called_once()
        report = project_ci.prepare_failure_record(error.exception)
        self.assertEqual(report['dependency_transport'], {'endpoint': 'github-api', 'failure': 'http', 'status': 403})
        self.assertNotIn(url, json.dumps(report))
        self.assertNotIn('private body', json.dumps(report))

    def test_metadata_transport_fails_closed_after_bounded_timeouts(self):
        url = 'https://api.github.com/repos/actions/checkout/git/ref/tags/v4'
        with patch.object(review.urllib.request, 'build_opener') as build, patch('time.sleep') as delay:
            opener = build.return_value
            opener.open.side_effect = urllib.error.URLError(TimeoutError('private reason'))
            with self.assertRaisesRegex(ValueError, '^dependency data unavailable$'):
                review.public_json(url)
            self.assertEqual(opener.open.call_count, 3)
            self.assertEqual(delay.call_count, 2)

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
                         {"vulns": [{"id": "SYNTHETIC", "affected": [{"ecosystem_specific": {"severity": "MEDIUM"}}]}]},
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

    def test_security_overlay_changes_resolved_version_and_rejects_tampering(self):
        manifest = b'{"name":"synthetic","builtin-baseline":"' + b"a" * 40 + b'","dependencies":["libvpx"]}'
        overlay = {"portfile.cmake": b"# PUBLIC SYNTHETIC TEMPLATE\n", "vcpkg.json": b'{"name":"libvpx","version":"1.17.0"}'}
        files = {"vcpkg.json": manifest, "vcpkg-configuration.json": b'{"overlay-ports":["packaging/vcpkg/overlays"]}'}
        files.update({review.OVERLAY_ROOT + name: raw for name, raw in overlay.items()})
        pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in overlay.items()}
        versions = {"default": {"libvpx": {"baseline": "1.16.0", "port-version": 2}}}
        with patch.dict(review.OVERLAY_PINS, pins, clear=True), patch.object(review, "public_json", side_effect=lambda *a, **kw: json.loads(json.dumps(versions))):
            queries = review.inventory(files, {})
            self.assertIn(review.query_key({"package": {"ecosystem": "OSS-Fuzz", "name": "libvpx"}, "version": "1.17.0"}), queries)
            self.assertNotIn(review.query_key({"package": {"ecosystem": "OSS-Fuzz", "name": "libvpx"}, "version": "1.16.0"}), queries)
            for modification in ({review.OVERLAY_ROOT + "portfile.cmake": b"# TAMPERED\n"},
                                 {review.OVERLAY_ROOT + "extra.cmake": b"# EXTRA\n"},
                                 {"vcpkg-configuration.json": b"{}"}):
                with self.subTest(modification=modification), self.assertRaises(ValueError):
                    review.inventory(dict(files, **modification), {})

    def test_non_pr_qualification_cannot_compare_candidate_against_itself(self):
        candidate = {review.query_key({"commit": "a" * 40})}
        payload = {"pr": 0, "source_sha": "b" * 40, "base_sha": "b" * 40}
        with patch.object(review, "snapshot", return_value=candidate), patch.object(review, "check", return_value={}) as check:
            review.verify("synthetic", payload, {})
            self.assertEqual(check.call_args.args[:2], (set(), candidate))


if __name__ == "__main__":
    unittest.main()
