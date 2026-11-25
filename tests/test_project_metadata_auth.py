"""Public-only metadata credentials never cross the trusted prepare boundary."""
import io
import contextvars
import json
import os
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from secure_release import project_ci as ci, project_dependency_review as review
from tests import public_dependency_metadata as smoke


URL = 'https://api.github.com/repos/actions/checkout/git/ref/tags/v4'
TOKEN = 'PUBLIC_SYNTHETIC_READ_ONLY_TOKEN'


class MetadataAuthenticationTests(unittest.TestCase):
    def test_exhausted_anonymous_quota_does_not_block_authenticated_prepare_metadata(self):
        def request(req, **kwargs):
            if req.get_header('Authorization') != 'Bearer ' + TOKEN:
                raise urllib.error.HTTPError(URL, 403, 'SYNTHETIC',
                    {'X-RateLimit-Remaining': '0', 'X-RateLimit-Limit': '60'}, None)
            return io.BytesIO(b'{"object":{"type":"commit","sha":"' + b'a' * 40 + b'"}}')
        def snapshot(root, revision, env, **kwargs):
            self.assertNotIn(TOKEN, json.dumps(env))
            result = review.public_json(URL)
            return {review.query_key({'commit': result['object']['sha']})}
        payload = {'pr': 1, 'base_sha': 'b' * 40, 'source_sha': 'c' * 40}
        with patch.object(review.urllib.request, 'build_opener') as build:
            build.return_value.open.side_effect = request
            with self.assertRaises(review.DependencyTransportError) as caught:
                review.public_json(URL)
            self.assertEqual(caught.exception.status, 403)
            self.assertEqual(caught.exception.rate_limit, {'remaining': 0, 'limit': 60})
            with patch.object(review, 'snapshot', side_effect=snapshot):
                receipt = review.verify('SYNTHETIC', payload, {'PATH': '/bin'}, github_token=TOKEN)
            self.assertEqual(receipt['result'], 'success')
            self.assertEqual(receipt['inventory_count'], 1)
            # Authentication is lexical, not a process-global environment edit.
            with self.assertRaises(review.DependencyTransportError):
                review.public_json(URL)

    def test_credentials_are_not_sent_to_osv_or_raw_content(self):
        urls = ('https://api.osv.dev/v1/query',
                'https://raw.githubusercontent.com/microsoft/vcpkg/' + 'a' * 40 + '/versions/baseline.json')
        with review.github_metadata_credentials(TOKEN), patch.object(review.urllib.request, 'build_opener') as build:
            def request(req, **kwargs):
                self.assertIsNone(req.get_header('Authorization'))
                return io.BytesIO(b'{}')
            build.return_value.open.side_effect = request
            for url in urls:
                self.assertEqual(review.public_json(url, data={} if 'osv' in url else None), {})

    def test_only_exact_public_github_metadata_paths_can_receive_credentials(self):
        urls = ('https://api.github.com/repos/dobord/private/git/ref/tags/v4',
                'https://api.github.com/user', URL + '?access_token=bad', URL + '#fragment',
                URL.replace('api.github.com', 'api.github.com:443'),
                URL.replace('api.github.com', 'api.github.com.evil.example'),
                URL.replace('api.github.com', 'user@api.github.com'),
                URL.replace('/git/ref/', '/git/%72ef/'),
                URL.replace('/git/ref/tags/v4', '/contents/private'),
                'https://api.github.com/repositories/1/git/matching-refs/tags',
                URL.replace('/git/ref/tags/v4', '/git/ref/tags/main'))
        with review.github_metadata_credentials(TOKEN), patch.object(review.urllib.request, 'build_opener') as build:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    review.public_json(url)
            build.assert_not_called()
            with self.assertRaises(ValueError):
                review.public_json(URL, data={})
            build.assert_not_called()

    def test_authenticated_metadata_never_redirects_or_retries_denial(self):
        with review.github_metadata_credentials(TOKEN), patch.object(review.urllib.request, 'build_opener') as build:
            build.return_value.open.side_effect = urllib.error.HTTPError(URL, 403, 'SYNTHETIC', {}, None)
            with self.assertRaises(review.DependencyTransportError):
                review.public_json(URL)
            build.return_value.open.assert_called_once()
            handler = build.call_args.args[0]
            req = urllib.request.Request(URL, headers={'Authorization': 'Bearer ' + TOKEN})
            for target in (URL, 'https://api.osv.dev/v1/query', 'https://evil.example/'):
                with self.subTest(target=target):
                    self.assertIsNone(handler.redirect_request(req, None, 302, 'SYNTHETIC', {}, target))

    def test_all_three_metadata_paths_are_authenticated_and_contexts_are_isolated(self):
        urls = (URL, 'https://api.github.com/repos/actions/checkout/git/matching-refs/tags',
                'https://api.github.com/repos/actions/checkout/git/tags/' + 'a' * 40,
                'https://api.github.com/repositories/203863565/git/matching-refs/tags')
        with review.github_metadata_credentials(TOKEN), patch.object(review.urllib.request, 'build_opener') as build:
            headers = []
            def request(req, **kwargs):
                headers.append(req.get_header('Authorization'))
                return io.BytesIO(b'{}')
            build.return_value.open.side_effect = request
            for url in urls:
                review.public_json(url)
            contextvars.Context().run(review.public_json, URL)
            self.assertEqual(headers, ['Bearer ' + TOKEN] * 4 + [None])

    def test_transferred_upstream_uses_reviewed_id_without_following_redirect(self):
        commit = 'f' * 40
        with patch.object(review, 'public_json', return_value={'object': {'type': 'commit', 'sha': commit}}) as request:
            self.assertEqual(review.public_commit('mymindstorm/setup-emsdk', 'v9999.123'), commit)
            request.assert_called_once_with('https://api.github.com/repositories/203863565/git/ref/tags/v9999.123')

    def test_ambient_tokens_are_never_discovered_by_scanner(self):
        with patch.dict(os.environ, {'BUILDER_READ_TOKEN': TOKEN, 'SOURCE_READ_TOKEN': TOKEN,
                                     'GITHUB_TOKEN': TOKEN}), patch.object(review.urllib.request, 'build_opener') as build:
            build.return_value.open.return_value = io.BytesIO(b'{}')
            review.public_json(URL)
            self.assertIsNone(build.return_value.open.call_args.args[0].get_header('Authorization'))

    def test_credential_scope_is_restored_on_exception_and_rejects_header_injection(self):
        with self.assertRaisesRegex(RuntimeError, 'SYNTHETIC'):
            with review.github_metadata_credentials(TOKEN):
                raise RuntimeError('SYNTHETIC')
        with patch.object(review.urllib.request, 'build_opener') as build:
            def request(req, **kwargs):
                self.assertIsNone(req.get_header('Authorization'))
                return io.BytesIO(b'{}')
            build.return_value.open.side_effect = request
            review.public_json(URL)
        for token in ('', 'bad\r\nInjected: header', 'bad token', 'x' * 16385, 1):
            with self.subTest(token_type=type(token).__name__), self.assertRaises(ValueError):
                with review.github_metadata_credentials(token):
                    self.fail('invalid credential accepted')

    def test_source_subprocess_environment_excludes_metadata_credentials(self):
        env = ci.build_environment({'PATH': '/bin', 'BUILDER_READ_TOKEN': TOKEN,
                                    'SOURCE_READ_TOKEN': 'SOURCE_SYNTHETIC', 'GITHUB_TOKEN': TOKEN})
        self.assertEqual(env, {'PATH': '/bin'})

    def test_hosted_smoke_requires_existing_token_and_exact_public_tag_identity(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError), patch.object(review, 'public_commit') as request:
            smoke.main()
        request.assert_not_called()
        with patch.dict(os.environ, {'BUILDER_READ_TOKEN': TOKEN}), patch.object(review, 'public_commit', return_value='0' * 40), self.assertRaises(ValueError):
            smoke.main()


if __name__ == '__main__':
    unittest.main()
