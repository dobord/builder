"""Bounded, atomic transport retries; digest and policy failures stay fatal."""
import hashlib
import http.client
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

from secure_release.github import Client


DATA = b"complete immutable artifact"
DIGEST = hashlib.sha256(DATA).hexdigest()
ENDPOINT = "/repos/dobord/builder/actions/artifacts/301/zip"


class Response:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def read(self, size):
        value = next(self.chunks, b"")
        if isinstance(value, BaseException):
            raise value
        return value


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.target = Path(self.folder.name) / "artifact.zip"
        self.partial = self.target.with_suffix(".zip.part")
        self.api = Client("disposable-test-credential")
        self.sleep = mock.patch("secure_release.github.time.sleep").start()
        self.addCleanup(mock.patch.stopall)

    def download(self):
        self.api.download(ENDPOINT, self.target, DIGEST, max_size=1024)

    def test_partial_timeout_restarts_from_zero_with_same_digest(self):
        stalled = Response([DATA[:7], TimeoutError("read timed out")])
        complete = Response([DATA])
        with mock.patch.object(self.api, "request", side_effect=[stalled, complete]) as request:
            self.download()
        self.assertEqual(request.call_args_list, [mock.call("GET", ENDPOINT)] * 2)
        self.assertEqual(self.target.read_bytes(), DATA)
        self.assertFalse(self.partial.exists())
        self.assertTrue(stalled.closed and complete.closed)
        self.sleep.assert_called_once_with(1)

    def test_repeated_timeouts_are_bounded_and_never_replace_existing_output(self):
        self.target.write_bytes(b"previous complete artifact")
        responses = [Response([b"partial", TimeoutError()]) for _ in range(3)]
        with mock.patch.object(self.api, "request", side_effect=responses) as request:
            with self.assertRaises(TimeoutError):
                self.download()
        self.assertEqual(request.call_count, 3)
        self.assertEqual(self.target.read_bytes(), b"previous complete artifact")
        self.assertFalse(self.partial.exists())
        self.assertTrue(all(value.closed for value in responses))
        self.assertEqual(self.sleep.call_args_list, [mock.call(1), mock.call(2)])

    def test_timeout_does_not_allow_corruption_on_retry_or_publish_partial_output(self):
        self.target.write_bytes(b"previous verified bytes")
        responses = iter([Response([b"partial", TimeoutError()]), Response([b"wrong complete bytes"])])
        def request(*args):
            self.assertFalse(self.partial.exists())
            self.assertEqual(self.target.read_bytes(), b"previous verified bytes")
            return next(responses)
        with mock.patch.object(self.api, "request", side_effect=request) as opened:
            with self.assertRaisesRegex(ValueError, "download digest mismatch"):
                self.download()
        self.assertEqual(opened.call_count, 2)
        self.assertEqual(self.target.read_bytes(), b"previous verified bytes")
        self.assertFalse(self.partial.exists())

    def test_digest_size_and_local_file_errors_are_not_retried(self):
        for contents, expected in ((b"incorrect", "digest mismatch"), (b"x" * 1025, "too large")):
            with self.subTest(expected=expected), mock.patch.object(self.api, "request", return_value=Response([contents])) as request:
                with self.assertRaisesRegex(ValueError, expected):
                    self.download()
                self.assertEqual(request.call_count, 1)
                self.assertFalse(self.target.exists())
                self.assertFalse(self.partial.exists())
        self.partial.write_bytes(b"not owned by this download")
        response = Response([DATA])
        with mock.patch.object(self.api, "request", return_value=response) as request:
            with self.assertRaises(FileExistsError):
                self.download()
        self.assertEqual(request.call_count, 1)
        self.assertEqual(self.partial.read_bytes(), b"not owned by this download")
        self.assertTrue(response.closed)

    def test_connection_and_truncated_response_retries_but_other_url_errors_do_not(self):
        for error in (ConnectionResetError(), http.client.IncompleteRead(b"short"),
                      urllib.error.URLError(TimeoutError())):
            with self.subTest(error=type(error).__name__), mock.patch.object(self.api, "request", side_effect=[error, Response([DATA])]) as request:
                self.download()
                self.assertEqual(request.call_count, 2)
                self.target.unlink()
        for error in (urllib.error.URLError("certificate verification failed"),
                      urllib.error.HTTPError(ENDPOINT, 403, "forbidden", {}, None)):
            with mock.patch.object(self.api, "request", side_effect=error) as request:
                with self.assertRaises(urllib.error.URLError):
                    self.download()
                self.assertEqual(request.call_count, 1)

    def test_redirect_reacquired_without_forwarding_credentials(self):
        location = "https://artifact.example/immutable-signed-artifact"
        redirect = urllib.error.HTTPError(ENDPOINT, 302, "redirect", {"Location": location}, None)
        with mock.patch.object(self.api, "request", side_effect=[redirect, redirect]) as request, \
             mock.patch("secure_release.github.urllib.request.urlopen", side_effect=[Response([b"partial", TimeoutError()]), Response([DATA])]) as signed:
            self.download()
        self.assertEqual(request.call_count, 2)
        for call in signed.call_args_list:
            req = call.args[0]
            self.assertEqual(req.full_url, location)
            self.assertNotIn("authorization", {key.lower() for key in req.headers})
        self.assertEqual(self.target.read_bytes(), DATA)

    def test_unsafe_redirect_and_invalid_digest_are_fatal_without_retry(self):
        error = urllib.error.HTTPError(ENDPOINT, 302, "redirect", {"Location": "http://artifact.example/plaintext"}, None)
        with mock.patch.object(self.api, "request", side_effect=error) as request, \
             mock.patch("secure_release.github.urllib.request.urlopen") as signed:
            with self.assertRaisesRegex(ValueError, "unsafe download location"):
                self.download()
        self.assertEqual(request.call_count, 1)
        signed.assert_not_called()
        with mock.patch.object(self.api, "request") as request:
            with self.assertRaisesRegex(ValueError, "artifact digest required"):
                self.api.download(ENDPOINT, self.target, "0")
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
