"""Fresh synthetic signing keys only; never execute a consumer archive."""
import copy
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import consumer_signing as signing, consumer_publisher as publisher, crypto
from tests import test_consumer_publication as signatures
from tests import test_consumer_publisher as publisher_tests
from tests.test_consumer_ci import request as request_fixture, policy as qualification_policy


class SigningCleanupContracts(unittest.TestCase):
    def test_agent_cleanup_failure_does_not_replace_the_original_exception(self):
        fingerprint = "A" * 40
        def run(argv, **kwargs):
            if argv[0] == "gpgconf":
                raise OSError("synthetic cleanup failure")
            listing = ("sec:-:255:22:\nfpr:::::::::" + fingerprint + ":\n").encode()
            return subprocess.CompletedProcess(argv, 0, stdout=listing)
        private = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic mock input only\n"
        # This test targets cleanup, not the independently tested MSYS path
        # adapter. Its subprocess mock must never masquerade as cygpath output.
        with mock.patch.object(signing.approval, "_tool_home",
                               side_effect=lambda root, env: root.as_posix()), \
                mock.patch.object(signing.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(ValueError, "^original synthetic assertion$"):
                with signing.isolated_signer(private, b"synthetic-only", fingerprint):
                    raise ValueError("original synthetic assertion")


class IsolatedSigningCryptography(unittest.TestCase):
    run_gpg = classmethod(signatures.ConsumerPublicationSignatures.run_gpg.__func__)

    @classmethod
    def setUpClass(cls):
        signatures.ConsumerPublicationSignatures.setUpClass.__func__(cls)
        cls.private = cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file",
                                 cls.tool_home + "/synthetic-passphrase",
                                 "--armor", "--export-secret-keys", cls.fingerprint)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.selected = qualification_policy()
        self.qualified = request_fixture()
        self.selected["repository"] = self.qualified["source"] = "dobord/synthetic-consumer"
        self.policy = publisher_tests.policy()
        self.policy.update(repository=self.qualified["source"], repository_id=self.qualified["source_id"],
                           source_sha=self.qualified["source_sha"], base_sha=self.qualified["base_sha"],
                           qualifier_sha=self.qualified["builder_sha"], signer_fingerprint=self.fingerprint,
                           consumer_policy_sha256=hashlib.sha256(crypto.canonical(self.selected)).hexdigest())
        self.archive = self.root / "archive.tar.gz"
        self.archive.write_bytes(b"fresh opaque synthetic artifact; never execute")
        self.policy["archive_sha256"] = crypto.digest(self.archive)
        identity = {"source_sha": self.policy["source_sha"], "builder_sha": self.policy["qualifier_sha"],
                    "run": self.policy["run"], "attempt": 1, "archive_sha256": self.policy["archive_sha256"]}
        receipts = {kind: crypto.b64(crypto.canonical(dict(identity, schema=1,
                    purpose="consumer-release-acceptance", kind=kind, checks={"synthetic-check": "pass"})))
                    for kind in self.policy["acceptance"]}
        self.plan = {"schema": 1, "qualified": self.qualified, "qualification_request": "synthetic-opaque-request",
                     "qualification_request_id": self.qualified["request_id"],
                     "artifact": {"id": 17, "sha256": "c" * 64}, "receipts": receipts,
                     "notes": None, "existing": None, "tag_time": 1}

    def test_real_isolated_signer_produces_verified_exact_publisher_bundle(self):
        with signing.isolated_signer(self.private, b"synthetic-test-only\n", self.fingerprint) as signer:
            bundle = signing.sign_bundle(self.plan, self.policy, self.selected, self.archive,
                                         self.root / "assets", signer, self.public)
        data = publisher.decode_bundle(bundle)
        self.assertEqual((self.root / "assets" / self.policy["archive_name"]).read_bytes(),
                         self.archive.read_bytes())
        self.assertTrue(data["tag"].startswith(b"object " + self.policy["source_sha"].encode()))
        self.assertEqual(len(list((self.root / "assets").iterdir())), 8)

    def test_existing_signature_bytes_are_preserved_and_only_presentation_is_signed(self):
        with signing.isolated_signer(self.private, b"synthetic-test-only\n", self.fingerprint) as signer:
            original = signing.sign_bundle(self.plan, self.policy, self.selected, self.archive,
                                           self.root / "first", signer, self.public)
        self.plan["existing"] = {key: original[key] for key in ("approval", "approval_signature", "tag", "signatures")}
        notes = "### Added\n\n- Synthetic automatic presentation.\n"
        self.plan["notes"] = notes
        self.policy["presentation"] = {"notes_sha256": hashlib.sha256(notes.encode()).hexdigest(),
                                       "make_latest": True}
        with signing.isolated_signer(self.private, b"synthetic-test-only\n", self.fingerprint) as signer:
            counted = mock.Mock(side_effect=signer)
            updated = signing.sign_bundle(self.plan, self.policy, self.selected, self.archive,
                                           self.root / "second", counted, self.public)
            self.assertEqual(counted.call_count, 1)
        for key in ("approval", "approval_signature", "tag", "signatures"):
            self.assertEqual(updated[key], original[key])
        for first in (self.root / "first").iterdir():
            self.assertEqual(first.read_bytes(), (self.root / "second" / first.name).read_bytes())
        self.assertEqual(updated["presentation"]["notes"], notes)

    def test_bad_source_receipts_or_artifact_fail_before_signing_callback(self):
        for mutation in ("source", "receipt", "archive"):
            with self.subTest(mutation=mutation):
                plan = copy.deepcopy(self.plan)
                archive = self.root / ("bad-" + mutation)
                archive.write_bytes(self.archive.read_bytes())
                if mutation == "source":
                    plan["qualified"]["source_sha"] = "0" * 40
                elif mutation == "receipt":
                    del plan["receipts"]["supplier"]
                else:
                    archive.write_bytes(b"substitution")
                signer = mock.Mock()
                with self.assertRaises(ValueError):
                    signing.sign_bundle(plan, self.policy, self.selected, archive,
                                         self.root / ("output-" + mutation), signer, self.public)
                signer.assert_not_called()

    def test_direct_context_has_independent_pins_and_rejects_boolean_run(self):
        first = signing.protocol_context("input", 10, "a" * 40, "b" * 40, self.policy)
        self.assertNotEqual(first, signing.protocol_context("result", 10, "a" * 40, "b" * 40, self.policy))
        with self.assertRaises(ValueError):
            signing.protocol_context("input", True, "a" * 40, "b" * 40, self.policy)

    def test_automatic_signing_requires_independently_pinned_receipt_digests_not_only_pass_labels(self):
        self.policy["automation"] = {"builder_sha": "a" * 40, "signer_sha": "b" * 40,
            "signer_recipient": "c" * 64, "operator_verify_sha256": "d" * 64,
            "receipt_sha256": {kind: "0" * 64 for kind in self.policy["acceptance"]}}
        signer = mock.Mock()
        with self.assertRaisesRegex(ValueError, "acceptance is not independently approved"):
            signing.sign_bundle(self.plan, self.policy, self.selected, self.archive,
                                 self.root / "unapproved", signer, self.public)
        signer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
