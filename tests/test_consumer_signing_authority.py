"""Defense-in-depth contracts before opening isolated private signing authority."""
from pathlib import Path
import hashlib
import unittest
from unittest import mock

from secure_release import consumer_signing as signing, consumer_publisher as publisher, crypto
from tests import test_consumer_signing as signing_tests
from tests import test_consumer_publication as signature_tests
from tests import test_consumer_publisher as publisher_tests


class SharedReceiptAuthority(unittest.TestCase):
    def test_shared_verifier_enforces_auto_receipt_hashes_not_just_pass_labels(self):
        policy = publisher_tests.policy()
        policy["automation"] = {"builder_sha": "a" * 40, "signer_sha": "b" * 40,
            "signer_recipient": "c" * 64, "operator_verify_sha256": "d" * 64,
            "receipt_sha256": {kind: "0" * 64 for kind in policy["acceptance"]}}
        identity = {"source_sha": policy["source_sha"], "builder_sha": policy["qualifier_sha"],
                    "run": policy["run"], "attempt": 1, "archive_sha256": policy["archive_sha256"]}
        receipts = {kind: crypto.canonical(dict(identity, schema=1, purpose="consumer-release-acceptance",
                    kind=kind, checks={"synthetic-check": "pass"})) for kind in policy["acceptance"]}
        with self.assertRaisesRegex(ValueError, "acceptance is not independently approved"):
            publisher.receipt_digests(policy, receipts)


class ExistingReleaseAuthority(unittest.TestCase):
    run_gpg = classmethod(signature_tests.ConsumerPublicationSignatures.run_gpg.__func__)

    @classmethod
    def setUpClass(cls):
        signing_tests.IsolatedSigningCryptography.setUpClass.__func__(cls)

    def setUp(self):
        signing_tests.IsolatedSigningCryptography.setUp(self)

    def test_existing_release_is_preverified_without_loading_any_private_signer(self):
        with signing.isolated_signer(self.private, b"synthetic-test-only\n", self.fingerprint) as signer:
            bundle = signing.sign_bundle(self.plan, self.policy, self.selected, self.archive,
                                         self.root / "first", signer, self.public)
        self.plan["existing"] = {key: bundle[key] for key in
                                 ("approval", "approval_signature", "tag", "signatures")}
        notes = "Synthetic presentation\n"
        self.policy["presentation"] = {"notes_sha256": hashlib.sha256(notes.encode()).hexdigest(),
                                       "make_latest": True}
        self.plan["notes"] = notes
        with mock.patch.object(signing, "isolated_signer", side_effect=AssertionError("private authority opened")):
            signing.verify_existing_bundle(self.plan, self.policy, self.selected, self.archive,
                                           self.root / "prechecked", self.public)
        self.plan["existing"]["signatures"]["archive"] = crypto.b64(b"not a signature")
        with mock.patch.object(signing, "isolated_signer", side_effect=AssertionError("private authority opened")), \
                self.assertRaises(ValueError):
            signing.verify_existing_bundle(self.plan, self.policy, self.selected, self.archive,
                                           self.root / "rejected", self.public)


if __name__ == "__main__":
    unittest.main()
