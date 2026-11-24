import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from secure_release import consumer_publication, crypto


def fixture():
    return {
        "schema": 1, "purpose": "consumer-release-publication",
        "repository_id": 100, "tag": "0.9.1", "tag_object": "1" * 40,
        "source_sha": "2" * 40, "base_sha": "3" * 40, "builder_sha": "4" * 40,
        "run": 21, "attempt": 1, "request_digest": "5" * 64,
        "archive": {"name": "synthetic-0.9.1-linux-x86_64-static.tar.gz", "sha256": "6" * 64},
        "acceptance": {key: "7" * 64 for key in ("dataplane", "client", "supplier")},
    }


class ConsumerPublicationContracts(unittest.TestCase):
    def test_approval_binds_every_publication_input(self):
        expected = fixture()
        self.assertEqual(consumer_publication.check_approval(crypto.canonical(expected), expected), expected)
        for key in expected:
            with self.subTest(key=key):
                changed = copy.deepcopy(expected)
                del changed[key]
                with self.assertRaises(ValueError):
                    consumer_publication.check_approval(crypto.canonical(changed), expected)
        for key, different in {
            "repository_id": 101, "tag_object": "8" * 40, "source_sha": "9" * 40,
            "run": 22, "attempt": 2, "request_digest": "0" * 64,
            "archive": {"name": expected["archive"]["name"], "sha256": "8" * 64},
        }.items():
            with self.subTest(key=key):
                changed = dict(expected, **{key: different})
                with self.assertRaises(ValueError):
                    consumer_publication.check_approval(crypto.canonical(changed), expected)

    def test_malformed_or_partial_approval_is_not_a_publishable_intent(self):
        good = fixture()
        for override in (
            {"schema": True}, {"repository_id": True}, {"run": True},
            {"purpose": "verified-candidate-only"}, {"tag": "../0.9.1"},
            {"archive": {"name": "../archive.tar.gz", "sha256": "1" * 64}},
            {"acceptance": {"dataplane": "7" * 64, "client": "NOT RUN", "supplier": "7" * 64}},
            {"acceptance": {"dataplane": "7" * 64, "client": "7" * 64}}, {"extra": "unapproved"},
        ):
            with self.subTest(override=override):
                changed = dict(good, **override)
                with self.assertRaises(ValueError):
                    consumer_publication.check_approval(crypto.canonical(changed), changed)
        for malformed in (b'{}', b' ' + crypto.canonical(good), b'x' * 8193):
            with self.assertRaises(ValueError):
                consumer_publication.check_approval(malformed, good)


@unittest.skipUnless(all(shutil.which(name) for name in ("gpg", "gpgv", "gpgconf")),
                     "OpenPGP verification tools required")
class ConsumerPublicationSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="synthetic-release-signature-")
        cls.addClassCleanup(cls.temp.cleanup)
        home = Path(cls.temp.name)
        cls.home = home
        cls.addClassCleanup(
            subprocess.run, ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        # A file avoids empty-argument loss in Windows/MSYS tool invocation.
        # This passphrase protects only a disposable synthetic test signer.
        cls.passphrase = home / "synthetic-passphrase"
        cls.passphrase.write_bytes(b"synthetic-test-only\n")
        cls.passphrase.chmod(0o600)
        cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file", str(cls.passphrase),
                    "--quick-generate-key", "Synthetic Approver <signer@example.invalid>", "ed25519", "sign", "1d")
        listing = cls.run_gpg("--with-colons", "--list-keys").decode()
        cls.fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.public = cls.run_gpg("--armor", "--export", cls.fingerprint)
        cls.raw = crypto.canonical(fixture())
        cls.signature = cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file", str(cls.passphrase),
                                    "--armor", "--detach-sign", "--output", "-", data=cls.raw)

    @classmethod
    def run_gpg(cls, *args, data=None):
        if any(not arg for arg in args):
            raise RuntimeError("synthetic OpenPGP invocation has an empty argument")
        result = subprocess.run(["gpg", "--no-options", "--batch", "--homedir", str(cls.home), *args],
                                input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode:
            stage = next((name for name in ("--quick-generate-key", "--list-keys", "--export", "--detach-sign")
                          if name in args), "unknown-stage")
            # Never print raw tool output, paths or key material, even though
            # these tests use freshly generated synthetic-only signing data.
            reason = next((code for text, code in (
                (b"invalid option", "unsupported-option"), (b"no pinentry", "pinentry-unavailable"),
                (b"can't connect to the agent", "agent-unavailable"),
                (b"no such file", "file-unavailable"), (b"invalid value", "invalid-value"),
                (b"key generation failed", "key-generation-failed"),
            ) if text in result.stderr.lower()), "unclassified-tool-error")
            raise RuntimeError(f"synthetic OpenPGP {stage} failed: {reason} (exit {result.returncode})")
        return result.stdout

    def test_only_pinned_signer_can_authenticate_exact_approval(self):
        self.assertEqual(
            consumer_publication.verify_signed_approval(
                self.raw, self.signature, self.public, self.fingerprint, fixture()),
            fixture())
        with self.assertRaises(ValueError):
            consumer_publication.verify_signed_approval(
                self.raw, self.signature, self.public, "0" * 40, fixture())

    def test_setup_never_relies_on_empty_tool_arguments(self):
        with self.assertRaisesRegex(RuntimeError, "empty argument"):
            self.run_gpg("--passphrase", "")

    def test_valid_signature_for_different_canonical_approval_is_rejected(self):
        modified = dict(fixture(), run=22)
        raw = crypto.canonical(modified)
        with self.assertRaises(ValueError):
            consumer_publication.verify_signed_approval(
                raw, self.signature, self.public, self.fingerprint, modified)
        with self.assertRaises(ValueError):
            consumer_publication.verify_signed_approval(
                self.raw, self.signature + self.signature, self.public, self.fingerprint, fixture())

    def test_unbounded_or_malformed_signature_inputs_fail_closed(self):
        for signature, key, fingerprint in (
            (b"", self.public, self.fingerprint),
            (b"x" * 65537, self.public, self.fingerprint),
            (self.signature, b"x" * 65537, self.fingerprint),
            (b"not a signature", self.public, self.fingerprint),
            (self.signature, b"not a public key", self.fingerprint),
            (self.signature, self.public, "main"),
        ):
            with self.subTest(length=len(signature), fingerprint=fingerprint), self.assertRaises(ValueError):
                consumer_publication.verify_signed_approval(
                    self.raw, signature, key, fingerprint, fixture())

    def test_ambient_credentials_and_keyrings_are_not_forwarded(self):
        run = subprocess.run
        with mock.patch.dict(os.environ, {"GH_TOKEN": "SYNTHETIC", "GNUPGHOME": "/synthetic/ambient"}), \
                mock.patch.object(consumer_publication.subprocess, "run", wraps=run) as calls:
            self.assertEqual(consumer_publication.verify_signed_approval(
                self.raw, self.signature, self.public, self.fingerprint, fixture()), fixture())
        self.assertEqual(len(calls.call_args_list), 2)
        for call in calls.call_args_list:
            self.assertNotIn("GH_TOKEN", call.kwargs["env"])
            self.assertNotIn("GNUPGHOME", call.kwargs["env"])
            self.assertEqual(call.kwargs["timeout"], 10)

    def test_missing_or_timed_out_crypto_tool_is_not_signature_success(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired(["gpg"], 10)):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(consumer_publication.subprocess, "run", side_effect=error), \
                    self.assertRaises(ValueError):
                consumer_publication.verify_signed_approval(
                    self.raw, self.signature, self.public, self.fingerprint, fixture())
