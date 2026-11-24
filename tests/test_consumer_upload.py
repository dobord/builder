"""Synthetic destination API: these tests never publish a real release."""
import copy
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest import mock

from secure_release import consumer_upload, crypto
from tests.test_consumer_publication import fixture


class FakeAPI:
    def __init__(self, expected):
        self.expected = expected
        self.release = None
        self.assets = []
        self.content = {}
        self.writes = []
        self.uploads = 0
        self.fail_after = None
        self.corrupt = False
        self.moved = False
        self.repository_id = expected["repository_id"]

    def get(self, path):
        prefix = "/repos/dobord/synthetic-consumer"
        if path == prefix:
            return {"id": self.repository_id, "full_name": "dobord/synthetic-consumer", "private": True}
        if "/git/ref/tags/" in path:
            return {"object": {"type": "tag", "sha": "9" * 40 if self.moved else self.expected["tag_object"]}}
        if "/releases/tags/" in path:
            if self.release is None:
                raise urllib.error.HTTPError("https://api.github.com", 404, "missing", {}, None)
            return copy.deepcopy(self.release)
        if "/releases?" in path:
            return [] if self.release is None else [copy.deepcopy(self.release)]
        if path.endswith("/assets?per_page=100"):
            return copy.deepcopy(self.assets)
        if self.release and path.endswith("/releases/100"):
            return copy.deepcopy(self.release)
        raise AssertionError("unexpected synthetic API path")

    def json(self, method, path, payload):
        self.writes.append((method, copy.deepcopy(payload)))
        if method == "POST":
            self.release = dict(payload, id=100)
        elif method == "PATCH":
            self.release.update(payload)
        else:
            raise AssertionError("unexpected synthetic write")
        return copy.deepcopy(self.release)

    def upload_asset(self, repository, release_id, path):
        if self.fail_after is not None and self.uploads >= self.fail_after:
            raise RuntimeError("synthetic interruption")
        self.uploads += 1
        data = path.read_bytes()
        asset = {"id": 1000 + self.uploads, "name": path.name, "size": len(data),
                 "state": "uploaded", "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        self.assets.append(asset)
        self.content[asset["id"]] = data
        return copy.deepcopy(asset)

    def request(self, method, path, *, accept):
        if method != "GET" or accept != "application/octet-stream":
            raise AssertionError("remote bytes must be fetched explicitly")
        data = self.content[int(path.rsplit("/", 1)[1])]
        return io.BytesIO(bytes([data[0] ^ 1]) + data[1:] if self.corrupt else data)


class ConsumerUpload(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.expected = fixture()
        name = self.expected["archive"]["name"]
        names = {name, name + ".asc", "SHA256SUMS", "SHA256SUMS.asc",
                 "provenance.json", "provenance.json.asc", "release-approval.json", "release-approval.json.asc"}
        self.manifest = {}
        for asset in sorted(names):
            data = ("synthetic asset " + asset).encode()
            (self.root / asset).write_bytes(data)
            self.manifest[asset] = hashlib.sha256(data).hexdigest()
        self.expected["archive"]["sha256"] = self.manifest[name]
        approval = crypto.canonical(self.expected)
        (self.root / "release-approval.json").write_bytes(approval)
        self.manifest["release-approval.json"] = hashlib.sha256(approval).hexdigest()
        self.api = FakeAPI(self.expected)

    def publish(self):
        return consumer_upload.publish_release(
            self.api, "dobord/synthetic-consumer", self.root, self.expected, self.manifest)

    def test_complete_remote_bytes_are_verified_before_publication_and_identical_retry_is_noop(self):
        self.assertEqual(self.publish(), 100)
        self.assertFalse(self.api.release["draft"])
        self.assertEqual(len(self.api.assets), 8)
        before = (copy.deepcopy(self.api.writes), self.api.uploads)
        self.assertEqual(self.publish(), 100)
        self.assertEqual((self.api.writes, self.api.uploads), before)

    def test_interrupted_draft_resumes_missing_assets_without_overwrite(self):
        self.api.fail_after = 2
        with self.assertRaises(RuntimeError):
            self.publish()
        self.assertTrue(self.api.release["draft"])
        self.assertEqual(len(self.api.assets), 2)
        first = copy.deepcopy(self.api.assets)
        self.api.fail_after = None
        self.publish()
        self.assertEqual(self.api.assets[:2], first)
        self.assertEqual(self.api.uploads, 8)
        self.assertFalse(self.api.release["draft"])

    def test_incomplete_published_release_is_not_silently_repaired(self):
        self.publish()
        self.api.assets.pop()
        before = copy.deepcopy(self.api.writes)
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.writes, before)
        self.assertEqual(self.api.uploads, 8)

    def test_false_remote_digest_or_bytes_never_publish(self):
        self.api.corrupt = True
        with self.assertRaises(ValueError):
            self.publish()
        self.assertTrue(self.api.release["draft"])
        self.assertFalse(any(method == "PATCH" for method, _ in self.api.writes))

    def test_wrong_destination_or_tag_precedes_every_write(self):
        for mutation in ("destination", "tag"):
            with self.subTest(mutation=mutation):
                self.api = FakeAPI(self.expected)
                if mutation == "destination":
                    self.api.repository_id += 1
                else:
                    self.api.moved = True
                with self.assertRaises(ValueError):
                    self.publish()
                self.assertEqual(self.api.writes, [])
                self.assertEqual(self.api.uploads, 0)

    def test_conflicting_existing_asset_or_body_is_never_overwritten(self):
        self.api.fail_after = 1
        with self.assertRaises(RuntimeError):
            self.publish()
        self.api.fail_after = None
        original = copy.deepcopy(self.api.assets)
        self.api.assets[0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.uploads, 1)
        self.api.assets = original
        self.api.release["body"] = "foreign draft"
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.uploads, 1)

    def test_unapproved_file_manifest_or_changed_local_bytes_precede_writes(self):
        (self.root / "unexpected").write_bytes(b"synthetic")
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.writes, [])
        (self.root / "unexpected").unlink()
        (self.root / "SHA256SUMS").write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.writes, [])

    def test_tag_moving_during_upload_blocks_finalization(self):
        upload = self.api.upload_asset
        def move(*args):
            result = upload(*args)
            self.api.moved = True
            return result
        with mock.patch.object(self.api, "upload_asset", side_effect=move), self.assertRaises(ValueError):
            self.publish()
        self.assertTrue(self.api.release["draft"])
        self.assertFalse(any(method == "PATCH" for method, _ in self.api.writes))

    def test_storage_redirect_never_forwards_authorization_or_accepts_foreign_hosts(self):
        asset = {"id": 101}
        content = b"synthetic remote content"
        digest = hashlib.sha256(content).hexdigest()
        for location in ("http://release-assets.githubusercontent.com/asset",
                         "https://foreign.example.invalid/asset",
                         "https://user@release-assets.githubusercontent.com/asset"):
            error = urllib.error.HTTPError("https://api.github.com", 302, "redirect", {"Location": location}, None)
            with self.subTest(location=location), \
                    mock.patch.object(self.api, "request", side_effect=error), \
                    mock.patch.object(consumer_upload.urllib.request, "build_opener") as opener, \
                    self.assertRaises(ValueError):
                consumer_upload._remote_bytes(self.api, "/repos/dobord/synthetic-consumer", asset, digest, len(content))
            opener.assert_not_called()
        error = urllib.error.HTTPError(
            "https://api.github.com", 302, "redirect",
            {"Location": "https://release-assets.githubusercontent.com/synthetic"}, None)
        with mock.patch.object(self.api, "request", side_effect=error), \
                mock.patch.object(consumer_upload.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(content)
            consumer_upload._remote_bytes(self.api, "/repos/dobord/synthetic-consumer", asset, digest, len(content))
        request = opener.return_value.open.call_args.args[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 120)
