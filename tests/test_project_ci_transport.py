"""Bounded HTTP reads with public synthetic bytes, never a transport fallback."""
import io
import json
import unittest
from unittest.mock import patch

from secure_release import project_ci as ci


class FragmentedResponse(io.BytesIO):
    def __init__(self, raw, *, fragment=65537, length=None):
        super().__init__(raw)
        self.fragment = fragment
        self.headers = {} if length is None else {"Content-Length": length}
        self.requests = []

    def read(self, size=-1):
        self.requests.append(size)
        return super().read(min(size, self.fragment))


class ApiTransportTests(unittest.TestCase):
    def fetch(self, response, **kwargs):
        with patch.object(ci.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            return ci.api("repos/dobord/synthetic/git/blobs/" + "a" * 40, "SYNTHETIC", **kwargs)

    def test_large_blob_json_is_read_through_short_reads(self):
        raw = json.dumps({"content": "A" * (17 * 1024**2)}).encode()
        response = FragmentedResponse(raw, length=str(len(raw)))
        self.assertEqual(json.loads(self.fetch(response, limit=len(raw))), json.loads(raw))
        self.assertGreater(len(response.requests), 2)
        self.assertLessEqual(max(response.requests), 1024**2)
        self.assertTrue(response.closed)

    def test_no_length_and_empty_response_require_eof(self):
        for raw in (b"", b"[]", b"PUBLIC_SYNTHETIC_BYTES"):
            response = FragmentedResponse(raw, fragment=1)
            with self.subTest(size=len(raw)):
                self.assertEqual(self.fetch(response, limit=len(raw) + 1), raw)
                self.assertEqual(len(response.requests), len(raw) + 1)

    def test_invalid_or_oversized_declared_lengths_fail_before_read(self):
        for length in ("-1", "1.0", " 2", "2, 2", "garbage", "9" * 100, "11"):
            response = FragmentedResponse(b"[]", length=length)
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.fetch(response, limit=10)
            self.assertEqual(response.requests, [])
            self.assertTrue(response.closed)

    def test_early_eof_or_excess_body_fails_even_for_valid_json(self):
        for length in ("1", "3"):
            response = FragmentedResponse(b"[]", fragment=1, length=length)
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, "length mismatch"):
                self.fetch(response, limit=10)
        with self.assertRaisesRegex(ValueError, "too large"):
            self.fetch(FragmentedResponse(b"01234567890", fragment=2), limit=10)

    def test_total_read_deadline_is_bounded(self):
        response = FragmentedResponse(b"[]", fragment=1)
        with patch.object(ci.time, "monotonic", side_effect=[0, 0, 181]), self.assertRaisesRegex(ValueError, "timed out"):
            self.fetch(response, limit=10)
        self.assertTrue(response.closed)

    def test_read_error_does_not_retry_or_use_another_transport(self):
        response = FragmentedResponse(b"[]")
        with patch.object(response, "read", side_effect=OSError("SYNTHETIC")), patch.object(ci.urllib.request, "urlopen") as fallback, self.assertRaises(OSError):
            self.fetch(response, limit=10)
        fallback.assert_not_called()
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
