import copy
import hashlib
import io
import tarfile
import tempfile
from pathlib import Path
import unittest
import os
import time
import uuid
import sys
import zipfile
import urllib.error
from datetime import datetime, timezone
from unittest import mock

from secure_release import consumer_publisher as publisher, crypto, consumer_ci, safeio
from secure_release import consumer_presentation
from tests.test_consumer_publication import fixture
from tests import test_consumer_publication as signatures
from tests.test_consumer_ci import request as request_fixture, policy as qualification_policy
from tests.test_consumer_upload import FakeAPI


def policy():
    return {
        "schema": 1, "repository": "dobord/synthetic", "repository_id": 100,
        "operator_id": 5323024, "source_sha": "2" * 40, "base_sha": "3" * 40,
        "qualifier_sha": "4" * 40, "run": 21, "tag": "0.9.1",
        "archive_name": "synthetic-0.9.1-linux-x86_64-static.tar.gz",
        "archive_sha256": "6" * 64, "consumer_policy_sha256": "8" * 64,
        "signer_fingerprint": "A" * 40,
        "acceptance": {kind: ["synthetic-check"] for kind in ("dataplane", "client", "supplier")},
    }


class ConsumerPublisherContracts(unittest.TestCase):
    def test_original_artifact_transport_binds_bytes_size_and_redirect_credentials(self):
        data = b"fresh synthetic API artifact"
        digest = hashlib.sha256(data).hexdigest()
        api = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api.request.return_value = io.BytesIO(data)
            publisher.download_original(api, "/fixed-artifact", root / "valid.zip", digest)
            self.assertEqual((root / "valid.zip").read_bytes(), data)
            api.request.return_value = io.BytesIO(data + b"tamper")
            with self.assertRaises(ValueError):
                publisher.download_original(api, "/fixed-artifact", root / "tampered.zip", digest)
            api.request.return_value = io.BytesIO(data)
            with mock.patch.object(consumer_ci, "MAX_PREPARED", len(data) - 1), self.assertRaises(ValueError):
                publisher.download_original(api, "/fixed-artifact", root / "oversized.zip", digest)
            location = "https://results-receiver.actions.githubusercontent.com/synthetic"
            api.request.side_effect = urllib.error.HTTPError(
                "https://api.github.com", 302, "redirect", {"Location": location}, None)
            opener = mock.Mock()
            opener.open.return_value = io.BytesIO(data)
            with mock.patch.object(publisher.urllib.request, "build_opener", return_value=opener):
                publisher.download_original(api, "/fixed-artifact", root / "redirect.zip", digest)
            sent = opener.open.call_args.args[0]
            self.assertEqual(sent.full_url, location)
            self.assertNotIn("Authorization", sent.headers)
            for location in ("http://results-receiver.actions.githubusercontent.com/synthetic",
                             "https://storage.example.invalid/synthetic",
                             "https://user:password@results-receiver.actions.githubusercontent.com/synthetic"):
                api.request.side_effect = urllib.error.HTTPError(
                    "https://api.github.com", 302, "redirect", {"Location": location}, None)
                with self.subTest(location=location), self.assertRaises(ValueError):
                    publisher.download_original(api, "/fixed-artifact", root / "denied.zip", digest)
            self.assertFalse((root / "denied.zip").exists())

    def test_diagnostic_io_failure_keeps_fixed_marker_and_never_prints_exception_data(self):
        with mock.patch.object(sys, "argv", ["publisher", "verify"]), \
                mock.patch.object(publisher, "verify", side_effect=ValueError("sensitive-input-not-for-logs")), \
                mock.patch.object(publisher, "work_root", side_effect=PermissionError("private-path")):
            with self.assertRaises(SystemExit) as stopped:
                publisher.main()
        self.assertEqual(str(stopped.exception), "CONSUMER_PUBLISHER_FAILED verify")

    def test_protected_policy_requires_every_acceptance_kind_and_exact_identity(self):
        publisher.validate_policy(policy())
        for field, value in (("run", True), ("tag", "../0.9.1"), ("repository", "other/synthetic"),
                             ("archive_sha256", "bad"), ("source_sha", "bad"),
                             ("signer_fingerprint", "0" * 39), ("acceptance", {})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                publisher.validate_policy(dict(policy(), **{field: value}))
        for checks in ([], ["same", "same"], ["../escape"], ["pass"] * 129):
            changed = copy.deepcopy(policy())
            changed["acceptance"]["dataplane"] = checks
            with self.subTest(checks=checks[:2]), self.assertRaises(ValueError):
                publisher.validate_policy(changed)

    def test_expected_approval_is_derived_from_qualified_data_not_approval_fields(self):
        p = policy()
        qualified = {"source": p["repository"], "source_id": p["repository_id"],
                     "operator_id": p["operator_id"], "source_sha": p["source_sha"],
                     "base_sha": p["base_sha"], "builder_sha": p["qualifier_sha"]}
        expected = publisher.expected_approval(p, qualified, "5" * 64, "1" * 40,
                                               {kind: "7" * 64 for kind in p["acceptance"]})
        self.assertEqual(expected, fixture())
        with self.assertRaises(ValueError):
            publisher.expected_approval(p, dict(qualified, source_sha="9" * 40),
                                        "5" * 64, "1" * 40, expected["acceptance"])

    def test_source_tag_api_bytes_require_both_raw_payload_and_signature(self):
        tag = {"verification": {"payload": "payload\n", "signature": "signature\n"}}
        self.assertEqual(publisher.raw_tag(tag), b"payload\nsignature\n")
        for changed in ({}, {"verification": {"verified": True}},
                        {"verification": {"payload": "x", "signature": ""}}):
            with self.assertRaises(ValueError):
                publisher.raw_tag(changed)

    def test_result_extraction_has_exact_inventory_and_preserves_archive_bytes(self):
        data = b"fresh synthetic archive bytes"
        p = policy()
        p["archive_sha256"] = hashlib.sha256(data).hexdigest()
        result = {"schema": 1, "source_sha": p["source_sha"], "builder_sha": p["qualifier_sha"],
                  "lane": "static", "status": "success"}
        members = {p["archive_name"]: data, "result.json": crypto.canonical(result),
                   "SHA256SUMS": (p["archive_sha256"] + "  " + p["archive_name"] + "\n").encode(),
                   "ctest.txt": b"synthetic pass\n", "dataplane-limits.txt": b"separate gate\n"}
        for mutation in ("valid", "extra", "duplicate", "wrong-archive", "wrong-result",
                         "boolean-schema", "link", "metadata"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "result.tar.gz"
                values = dict(members)
                if mutation == "extra":
                    values["untrusted.py"] = b"do not execute"
                if mutation == "wrong-archive":
                    values[p["archive_name"]] = b"wrong"
                if mutation == "wrong-result":
                    values["result.json"] = b"{}"
                if mutation == "boolean-schema":
                    values["result.json"] = crypto.canonical(dict(result, schema=True))
                with tarfile.open(source, "w:gz") as archive:
                    for name, content in values.items():
                        item = tarfile.TarInfo(name)
                        item.size = len(content)
                        if mutation == "metadata":
                            item.pax_headers = {"synthetic": "x" * 20000}
                        if mutation == "link" and name == "ctest.txt":
                            item.type = tarfile.SYMTYPE
                            item.linkname = "/etc/passwd"
                            item.size = 0
                        archive.addfile(item, io.BytesIO(content))
                    if mutation == "duplicate":
                        item = tarfile.TarInfo("ctest.txt")
                        item.size = 1
                        archive.addfile(item, io.BytesIO(b"x"))
                target = root / "candidate"
                target.mkdir(mode=0o700)
                if mutation == "valid":
                    publisher.extract_original_result(source, target, p)
                    self.assertEqual((target / p["archive_name"]).read_bytes(), data)
                    self.assertEqual(list(target.iterdir()), [target / p["archive_name"]])
                else:
                    with self.assertRaises(ValueError):
                        publisher.extract_original_result(source, target, p)

    def test_workflow_has_no_write_token_or_decryption_keys_outside_their_stage(self):
        import yaml
        value = yaml.load((Path(__file__).resolve().parents[1] /
                           ".github/workflows/publish-consumer-release.yml").read_text(), Loader=yaml.BaseLoader)
        job = value["jobs"]["publish"]
        self.assertEqual(value["permissions"], {})
        self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
        self.assertIn("github.sha == vars.CONSUMER_RELEASE_BUILDER_SHA", job["if"])
        self.assertIn("github.run_attempt == 1", job["if"])
        self.assertNotIn("CONSUMER_RELEASE_PUBLISH_TOKEN", job["env"])
        for step in job["steps"]:
            env = step.get("env", {})
            if step.get("run") == "python -m secure_release.consumer_publisher publish":
                self.assertEqual(env["CONSUMER_RELEASE_PUBLISH_TOKEN"], "${{ secrets.BIN_PUBLISH_TOKEN }}")
                self.assertFalse(any("PRIVATE_KEY" in name for name in env))
            else:
                self.assertFalse(any("PUBLISH_TOKEN" in name for name in env))
            if step.get("run") != "python -m secure_release.consumer_publisher verify":
                self.assertNotIn("CONSUMER_PUBLISH_PRIVATE_KEY_B64", env)
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")

    def test_dispatch_guard_rejects_wrong_pin_actor_attempt_ref_and_disabled_mode(self):
        sha = "f" * 40
        env = {"CONSUMER_RELEASE_BUILDER_SHA": sha, "GITHUB_ACTIONS": "true",
               "GITHUB_REPOSITORY": consumer_ci.ci.BUILDER,
               "GITHUB_REPOSITORY_ID": str(consumer_ci.ci.BUILDER_ID),
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_ACTOR_ID": "5323024", "GITHUB_SHA": sha,
               "GITHUB_REF": "refs/tags/consumer-publisher-" + sha,
               "GITHUB_WORKFLOW_REF": consumer_ci.ci.BUILDER + "/.github/workflows/" +
                   publisher.WORKFLOW + "@refs/tags/consumer-publisher-" + sha,
               "CONSUMER_RELEASE_ENABLED": "true"}
        with mock.patch.dict(os.environ, env), mock.patch.object(publisher.os, "name", "posix"):
            self.assertEqual(publisher.guard(), sha)
            for key, value in (("GITHUB_SHA", "a" * 40), ("GITHUB_ACTOR_ID", "100"),
                               ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_REF", "refs/heads/main"),
                               ("CONSUMER_RELEASE_ENABLED", "false"), ("GITHUB_ACTIONS", "false")):
                with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}), self.assertRaises(ValueError):
                    publisher.guard()


class TagAPI(FakeAPI):
    def __init__(self, expected, raw):
        super().__init__(expected)
        self.tag_raw = raw
        self.tag_exists = False
        self.tag_created = False
        self.latest = None

    def get(self, path):
        if path.endswith("/releases/latest"):
            return {"id": self.latest, "tag_name": self.expected["tag"] if self.latest else "0.9.0"}
        if "/git/ref/tags/" in path and not self.tag_exists:
            raise urllib.error.HTTPError("https://api.github.com", 404, "missing", {}, None)
        if "/git/tags/" in path:
            payload, _, signature = self.tag_raw.partition(b"-----BEGIN PGP SIGNATURE-----")
            return {"sha": publisher.tag_object(self.tag_raw),
                    "verification": {"payload": payload.decode(),
                                     "signature": (b"-----BEGIN PGP SIGNATURE-----" + signature).decode()}}
        return super().get(path)

    def json(self, method, path, payload):
        if payload.get("make_latest") == "true":
            self.latest = 100
        if path.endswith("/git/tags"):
            self.writes.append((method, copy.deepcopy(payload)))
            self.tag_created = True
            stamp = int(datetime.strptime(payload["tagger"]["date"], "%Y-%m-%dT%H:%M:%SZ")
                        .replace(tzinfo=timezone.utc).timestamp())
            raw = (f"object {payload['object']}\ntype commit\ntag {payload['tag']}\n"
                   f"tagger {payload['tagger']['name']} <{payload['tagger']['email']}> {stamp} +0000\n\n"
                   + payload["message"]).encode()
            if raw != self.tag_raw:
                raise ValueError("synthetic Git API changed signed bytes")
            return {"sha": publisher.tag_object(raw)}
        if path.endswith("/git/refs"):
            self.writes.append((method, copy.deepcopy(payload)))
            self.tag_exists = True
            return {"object": {"type": "tag", "sha": payload["sha"]}}
        return super().json(method, path, payload)


class ConsumerPublisherCryptography(unittest.TestCase):
    run_gpg = classmethod(signatures.ConsumerPublicationSignatures.run_gpg.__func__)

    @classmethod
    def setUpClass(cls):
        signatures.ConsumerPublicationSignatures.setUpClass.__func__(cls)

    @classmethod
    def sign(cls, data):
        return cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file",
                           cls.tool_home + "/synthetic-passphrase",
                           "--armor", "--detach-sign", "--output", "-", data=data)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.selected = qualification_policy()
        self.qualified = request_fixture()
        self.selected["repository"] = self.qualified["source"] = "dobord/synthetic-consumer"
        self.input_private, input_public = crypto.generate("encrypt")
        self.publisher_private, publisher_public = crypto.generate("encrypt")
        signing_private, signing_public = crypto.generate("sign")
        self.sealed_qualification = crypto.seal_message(
            crypto.canonical(crypto.sign(self.qualified, signing_private)), input_public,
            consumer_ci.context("request", self.qualified))
        digest = hashlib.sha256(self.sealed_qualification.encode()).hexdigest()
        self.policy = policy()
        self.policy.update(repository=self.qualified["source"], repository_id=self.qualified["source_id"],
                           source_sha=self.qualified["source_sha"], base_sha=self.qualified["base_sha"],
                           qualifier_sha=self.qualified["builder_sha"], signer_fingerprint=self.fingerprint,
                           consumer_policy_sha256=hashlib.sha256(crypto.canonical(self.selected)).hexdigest())
        data = b"synthetic opaque archive; never execute or rebuild"
        self.policy["archive_sha256"] = hashlib.sha256(data).hexdigest()
        payload = (f"object {self.qualified['source_sha']}\ntype commit\ntag 0.9.1\n"
                   "tagger Synthetic Approver <signer@example.invalid> 1 +0000\n\nRelease\n").encode()
        self.tag = payload + self.sign(payload)
        identity = {"source_sha": self.policy["source_sha"], "builder_sha": self.policy["qualifier_sha"],
                    "run": self.policy["run"], "attempt": 1, "archive_sha256": self.policy["archive_sha256"]}
        receipts = {kind: crypto.canonical(dict(identity, schema=1, purpose="consumer-release-acceptance",
                                               kind=kind, checks={"synthetic-check": "pass"}))
                    for kind in self.policy["acceptance"]}
        receipt_hashes = publisher.receipt_digests(self.policy, receipts)
        self.expected = publisher.expected_approval(
            self.policy, self.qualified, digest, publisher.tag_object(self.tag), receipt_hashes)
        original = self.root / "original"
        original.mkdir()
        (original / self.policy["archive_name"]).write_bytes(data)
        (original / "result.json").write_bytes(crypto.canonical(
            {"schema": 1, "source_sha": self.policy["source_sha"], "builder_sha": self.policy["qualifier_sha"],
             "lane": "static", "status": "success"}))
        (original / "SHA256SUMS").write_bytes(
            (self.policy["archive_sha256"] + "  " + self.policy["archive_name"] + "\n").encode())
        (original / "ctest.txt").write_text("synthetic pass\n")
        (original / "dataplane-limits.txt").write_text("independent acceptance required\n")
        tar = self.root / "result.tar.gz"
        safeio.pack_tar(original, tar)
        context = consumer_ci.context("publisher-results", self.qualified)
        context.update(run=21, attempt=1, request_digest=digest, lane="static")
        cipher = self.root / "publisher-results.enc"
        crypto.encrypt_file(tar, cipher, publisher_public, context)
        self.zip = self.root / "original.zip"
        with zipfile.ZipFile(self.zip, "w") as z:
            z.write(cipher, "publisher-results.enc")
            z.writestr("results.enc", b"master-log result not consumed")
            z.writestr("diagnostics.enc", b"master-log diagnostics not consumed")
        artifact = {"id": 17, "sha256": crypto.digest(self.zip)}
        self.artifact = dict(id=17, name="consumer-output-static-21-1", expired=False,
                             size_in_bytes=self.zip.stat().st_size, digest="sha256:" + artifact["sha256"])
        prov = publisher.provenance(self.policy, self.qualified, artifact, receipt_hashes, self.selected,
                                    digest, self.expected["tag_object"])
        staging = self.root / "signing"
        staging.mkdir()
        (staging / self.policy["archive_name"]).write_bytes(data)
        (staging / "provenance.json").write_bytes(prov)
        raw_approval = crypto.canonical(self.expected)
        (staging / "release-approval.json").write_bytes(raw_approval)
        checksums = publisher.checksum_bytes(staging, self.expected)
        self.bundle = {"qualification_request": self.sealed_qualification,
                       "qualification_request_id": self.qualified["request_id"],
                       "approval": crypto.b64(raw_approval), "approval_signature": crypto.b64(self.sign(raw_approval)),
                       "tag": crypto.b64(self.tag), "receipts": {k: crypto.b64(v) for k, v in receipts.items()},
                       "signatures": {k: crypto.b64(self.sign(v)) for k, v in
                                      (("archive", data), ("provenance", prov), ("checksums", checksums))}}
        self.input_public = input_public
        self.sha = "f" * 40
        self.env = {"RUNNER_TEMP": str(self.root), "GITHUB_OUTPUT": str(self.root / "step-output"),
                    "CONSUMER_RELEASE_POLICY_B64": crypto.b64(crypto.canonical(self.policy)),
                    "CONSUMER_POLICY_B64": crypto.b64(crypto.canonical(self.selected)),
                    "CONSUMER_INPUT_PRIVATE_KEY_B64": crypto.b64(self.input_private.encode()),
                    "CONSUMER_VERIFY_PUBLIC_KEY_B64": crypto.b64(signing_public.encode()),
                    "CONSUMER_PUBLISH_PRIVATE_KEY_B64": crypto.b64(self.publisher_private.encode()),
                    "CONSUMER_RELEASE_VERIFY_PUBLIC_KEY_B64": crypto.b64(self.public),
                    "BUILDER_READ_TOKEN": "synthetic-read-only"}
        self.api = TagAPI(self.expected, self.tag)

    def transport(self, bundle=None, *, expired=False):
        request_id = str(uuid.uuid4())
        now = int(time.time())
        sealed = crypto.seal_message(crypto.canonical(
            {"created": now - 120 if expired else now, "expires": now - 1 if expired else now + 3600,
             "bundle": bundle or self.bundle}), self.input_public, publisher.bundle_context(request_id, self.sha))
        return {"CONSUMER_RELEASE_REQUEST_ID": request_id, "CONSUMER_RELEASE_REQUEST": sealed,
                "CONSUMER_RELEASE_REQUEST_DIGEST": hashlib.sha256(sealed.encode()).hexdigest()}

    def verify(self, bundle=None, *, expired=False):
        def download(api, resource, target, digest):
            if crypto.digest(self.zip) != digest:
                raise ValueError("synthetic original artifact digest mismatch")
            target.write_bytes(self.zip.read_bytes())
        with mock.patch.dict(os.environ, dict(self.env, **self.transport(bundle, expired=expired))), \
                mock.patch.object(publisher, "guard", return_value=self.sha), \
                mock.patch.object(publisher.approval, "resolve_qualification", return_value=self.qualified), \
                mock.patch.object(consumer_ci.ci, "pages", return_value=[self.artifact]), \
                mock.patch.object(publisher, "download_original", side_effect=download):
            publisher.verify()

    def publish(self):
        output = (self.root / "step-output").read_text().strip().split("=", 1)[1]
        # Model a fresh workflow step, not a machine without its toolchain/OS
        # environment. Never retain ambient application or credential variables.
        env = {k: v for k, v in os.environ.items()
               if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"}}
        env.update({k: v for k, v in self.env.items() if "PRIVATE_KEY" not in k})
        env.update(CONSUMER_RELEASE_STAGING_DIGEST=output, CONSUMER_RELEASE_PUBLISH_TOKEN="synthetic-writer")
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(publisher, "guard", return_value=self.sha), \
                mock.patch.object(publisher, "recheck_qualification") as recheck, \
                mock.patch.object(publisher, "Client", return_value=self.api):
            publisher.publish()
        self.assertEqual(recheck.call_count, 2)

    def test_real_ciphertext_signatures_receipts_and_remote_bytes_reach_publication(self):
        self.verify()
        self.publish()
        self.assertFalse(self.api.release["draft"])
        self.assertEqual(len(self.api.assets), 8)
        self.assertTrue(self.api.tag_created and self.api.tag_exists)
        before = copy.deepcopy(self.api.writes)
        self.publish()
        self.assertEqual(self.api.writes, before)

    def presentation_bundle(self):
        notes = "### Added\n\n- Independently synthetic release notes.\n"
        settings = {"notes_sha256": hashlib.sha256(notes.encode()).hexdigest(), "make_latest": True}
        self.policy["presentation"] = settings
        self.env["CONSUMER_RELEASE_POLICY_B64"] = crypto.b64(crypto.canonical(self.policy))
        original, signing = self.root / "original", self.root / "signing"
        raw = {self.policy["archive_name"]: (original / self.policy["archive_name"]).read_bytes(),
               self.policy["archive_name"] + ".asc": crypto.unb64(self.bundle["signatures"]["archive"]),
               "release-approval.json": crypto.unb64(self.bundle["approval"]),
               "release-approval.json.asc": crypto.unb64(self.bundle["approval_signature"]),
               "provenance.json": (signing / "provenance.json").read_bytes(),
               "provenance.json.asc": crypto.unb64(self.bundle["signatures"]["provenance"]),
               "SHA256SUMS": publisher.checksum_bytes(signing, self.expected),
               "SHA256SUMS.asc": crypto.unb64(self.bundle["signatures"]["checksums"])}
        manifest = {name: hashlib.sha256(value).hexdigest() for name, value in raw.items()}
        intent = consumer_presentation.intent(settings, self.expected, manifest, notes)
        self.bundle["presentation"] = {"notes": notes, "signature": crypto.b64(self.sign(intent))}
        return manifest

    def test_signed_presentation_survives_staging_and_sets_latest_without_asset_changes(self):
        manifest = self.presentation_bundle()
        self.verify()
        self.publish()
        self.assertEqual(self.api.latest, 100)
        self.assertIn("Independently synthetic release notes.", self.api.release["body"])
        self.assertEqual({a["name"]: a["digest"].removeprefix("sha256:") for a in self.api.assets}, manifest)
        before = copy.deepcopy(self.api.writes)
        self.publish()
        self.assertEqual(self.api.writes, before)

    def test_presentation_policy_or_signature_mismatch_never_reaches_publication(self):
        self.presentation_bundle()
        for mutation in ("notes", "signature", "missing"):
            bundle = copy.deepcopy(self.bundle)
            if mutation == "notes":
                bundle["presentation"]["notes"] += "Unapproved suffix."
            elif mutation == "signature":
                bundle["presentation"]["signature"] = bundle["approval_signature"]
            else:
                del bundle["presentation"]
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                env = self.env
                self.env = dict(env, RUNNER_TEMP=directory)
                try:
                    with self.assertRaises(ValueError):
                        self.verify(bundle)
                finally:
                    self.env = env
            self.assertEqual(self.api.writes, [])

    def test_publication_fixture_keeps_system_tool_environment_but_not_ambient_credentials(self):
        self.verify()
        observed = {}
        expected_path = os.environ.get("PATH")
        def capture():
            observed.update(os.environ)
            publisher.recheck_qualification(None, None, None, None)
            publisher.recheck_qualification(None, None, None, None)
        with mock.patch.dict(os.environ, {"SYSTEMROOT": "synthetic-system-root",
                                          "UNRELATED_SECRET": "do-not-forward"}), \
                mock.patch.object(publisher, "publish", side_effect=capture):
            self.publish()
        self.assertEqual(observed.get("PATH"), expected_path)
        self.assertEqual(observed.get("SYSTEMROOT"), "synthetic-system-root")
        self.assertNotIn("UNRELATED_SECRET", observed)
        self.assertFalse(any("PRIVATE_KEY" in key for key in observed))

    def test_wrong_signer_missing_receipt_bad_tag_and_expired_transport_never_write(self):
        for mutation in ("signer", "receipt", "tag", "expired", "qualification", "artifact"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.bundle)
                with tempfile.TemporaryDirectory() as directory:
                    env = dict(self.env, RUNNER_TEMP=directory)
                    if mutation == "signer":
                        value = dict(self.policy, signer_fingerprint="0" * 40)
                        env["CONSUMER_RELEASE_POLICY_B64"] = crypto.b64(crypto.canonical(value))
                    if mutation == "receipt":
                        value = crypto.parse(crypto.unb64(changed["receipts"]["supplier"]))
                        value["checks"]["synthetic-check"] = "skipped"
                        changed["receipts"]["supplier"] = crypto.b64(crypto.canonical(value))
                    if mutation == "tag":
                        changed["tag"] = crypto.b64(self.tag + b"unsigned suffix")
                    old_qualified, old_artifact = self.qualified, self.artifact
                    if mutation == "qualification":
                        self.qualified = dict(self.qualified, source_sha="9" * 40)
                    if mutation == "artifact":
                        self.artifact = dict(self.artifact, digest="sha256:" + "0" * 64)
                    old_env = self.env
                    self.env = env
                    try:
                        with self.assertRaises(ValueError):
                            self.verify(changed, expired=mutation == "expired")
                    finally:
                        self.env, self.qualified, self.artifact = old_env, old_qualified, old_artifact
                self.assertEqual(self.api.writes, [])

    def test_asset_or_verified_state_tamper_precedes_destination_credential_use(self):
        self.verify()
        assets = self.root / "consumer-publication/assets"
        original = (assets / "provenance.json").read_bytes()
        (assets / "provenance.json").write_bytes(b"tamper")
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.writes, [])
        (assets / "provenance.json").write_bytes(original)
        record = self.root / "consumer-publication/verified.json"
        record.write_bytes(record.read_bytes() + b"\n")
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.writes, [])

    def test_pinned_signer_not_registered_with_github_still_requires_exact_raw_tag(self):
        payload = publisher.tag_payload(self.tag, self.expected)
        remote = dict(payload, verification={"verified": False, "payload": None, "signature": None},
                      object={"sha": payload["object"], "type": "commit"})
        self.assertEqual(publisher.raw_tag(remote), self.tag)
        self.assertEqual(publisher.approval.verify_source_tag(
            publisher.raw_tag(remote), self.expected["tag"], self.expected["source_sha"],
            self.expected["tag_object"], self.public, self.fingerprint), self.expected["tag_object"])


if __name__ == "__main__":
    unittest.main()
