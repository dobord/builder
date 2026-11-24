"""Fresh synthetic keys only: delegate one ciphertext, never the log master key."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import consumer_capability, crypto
from secure_release import consumer_ci as consumer


class ConsumerResultCapability(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log_private, self.log_public = crypto.generate("encrypt")
        self.input_private, self.input_public = crypto.generate("encrypt")
        self.signing_private, self.signing_public = crypto.generate("sign")
        self.log_path = self.root / "synthetic-log-private"
        self.sign_path = self.root / "synthetic-operator-private"
        for path, data in ((self.log_path, self.log_private), (self.sign_path, self.signing_private)):
            path.write_text(data)
            path.chmod(0o600)
        self.binding = {
            "schema": 1, "purpose": "consumer-result-capability", "approval_sha256": "a" * 64,
            "request_id": "00000000-0000-4000-8000-000000000001",
            "builder_sha": "b" * 40, "run": 100, "attempt": 1, "request_digest": "c" * 64,
            "lane": "static", "artifact_id": 101, "artifact_sha256": "d" * 64,
            "cipher_sha256": "0" * 64, "recipient": crypto.fingerprint(self.log_public),
        }
        self.context = consumer.context("results", self.binding)
        self.context.update(run=100, attempt=1, request_digest="c" * 64, lane="static")
        self.plain = self.root / "synthetic-original"
        self.plain.write_bytes(b"synthetic exact original result archive")
        self.cipher = self.root / "results.enc"
        crypto.encrypt_file(self.plain, self.cipher, self.log_public, self.context)
        self.binding["cipher_sha256"] = crypto.digest(self.cipher)

    def create(self):
        if os.name != "posix":
            # Windows exercises the receiver with a fresh reference capability;
            # production operator ownership checks deliberately remain POSIX-only.
            with self.assertRaises(ValueError):
                consumer_capability.create(
                    self.cipher, self.log_path, self.sign_path, self.input_public, self.binding)
            with self.cipher.open("rb") as stream:
                header = crypto.read_header(stream)
            _, hybrid, _, _ = crypto._tink()
            key = crypto.key(self.log_private).primitive(hybrid.HybridDecrypt).decrypt(
                crypto.unb64(header["wrapped"]), b"vcpkg-file-key-v1\x00" + crypto.canonical(self.context)).decode()
            payload = {"schema": 1, "binding": self.binding, "streaming_key": key}
            return crypto.seal_message(
                crypto.canonical(crypto.sign(payload, self.signing_private)), self.input_public, self.binding)
        # Model the local operator with newly generated synthetic-only secrets.
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            return consumer_capability.create(
                self.cipher, self.log_path, self.sign_path, self.input_public, self.binding)

    def test_delegation_authenticates_original_ciphertext_without_changing_it(self):
        before = self.cipher.read_bytes()
        capsule = self.create()
        target = self.root / "decrypted"
        consumer_capability.open_result(
            self.cipher, capsule, target, self.input_private, self.signing_public, self.binding)
        self.assertEqual(target.read_bytes(), self.plain.read_bytes())
        self.assertEqual(self.cipher.read_bytes(), before)
        self.assertEqual(self.log_path.read_text(), self.log_private)
        self.assertEqual(self.sign_path.read_text(), self.signing_private)
        self.assertNotIn(self.log_private, capsule)
        self.assertNotIn(self.signing_private, capsule)
        payload = crypto.verify(crypto.parse(crypto.open_message(
            capsule, self.input_private, self.binding)), self.signing_public)
        self.assertEqual(set(payload), {"schema", "binding", "streaming_key"})
        self.assertNotEqual(payload["streaming_key"], self.log_private)
        self.assertNotEqual(payload["streaming_key"], self.signing_private)
        with self.assertRaises(ValueError):
            crypto.decrypt_file(self.cipher, self.root / "not-delegated", self.input_private, self.context)

    def test_even_authenticated_capability_and_matching_cipher_hash_cannot_bypass_aead_tags(self):
        capsule = self.create()
        payload = crypto.verify(crypto.parse(crypto.open_message(
            capsule, self.input_private, self.binding)), self.signing_public)
        original = self.cipher.read_bytes()
        self.cipher.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        binding = dict(self.binding, cipher_sha256=crypto.digest(self.cipher))
        payload["binding"] = binding
        changed_capsule = crypto.seal_message(
            crypto.canonical(crypto.sign(payload, self.signing_private)), self.input_public, binding)
        with self.assertRaises(ValueError):
            consumer_capability.open_result(
                self.cipher, changed_capsule, self.root / "output",
                self.input_private, self.signing_public, binding)
        self.assertFalse((self.root / "output").exists())
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), self.assertRaises(ValueError):
            consumer_capability.create(self.cipher, self.log_path, self.sign_path, self.input_public, binding)

    def test_malformed_signed_payload_existing_target_and_bounds_fail_without_partial_plaintext(self):
        capsule = self.create()
        payload = crypto.verify(crypto.parse(crypto.open_message(
            capsule, self.input_private, self.binding)), self.signing_public)
        target = self.root / "output"
        for change in ({"schema": True}, {"extra": "untrusted"}, {"streaming_key": "invalid"},
                       {"streaming_key": "x" * 8193}, {"binding": dict(self.binding, run=True)}):
            changed = dict(copy.deepcopy(payload), **change)
            sealed = crypto.seal_message(
                crypto.canonical(crypto.sign(changed, self.signing_private)), self.input_public, self.binding)
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                consumer_capability.open_result(
                    self.cipher, sealed, target, self.input_private, self.signing_public, self.binding)
            self.assertFalse(target.exists())
        with mock.patch.object(consumer, "MAX_PREPARED", 1), self.assertRaises(ValueError):
            consumer_capability.open_result(
                self.cipher, capsule, target, self.input_private, self.signing_public, self.binding)
        self.assertFalse(target.exists())
        target.write_bytes(b"preserve")
        with self.assertRaises(ValueError):
            consumer_capability.open_result(
                self.cipher, capsule, target, self.input_private, self.signing_public, self.binding)
        self.assertEqual(target.read_bytes(), b"preserve")
        self.assertFalse(any(p.name.startswith(".consumer-capability-") for p in self.root.iterdir()))

    def test_wrong_signer_recipient_binding_or_cipher_never_publishes_plaintext(self):
        capsule = self.create()
        wrong_private, _ = crypto.generate("encrypt")
        _, wrong_signer = crypto.generate("sign")
        for key, signer, binding in (
            (wrong_private, self.signing_public, self.binding),
            (self.input_private, wrong_signer, self.binding),
            (self.input_private, self.signing_public, dict(self.binding, run=102)),
            (self.input_private, self.signing_public, dict(self.binding, approval_sha256="e" * 64)),
            (self.input_private, self.signing_public, dict(self.binding, artifact_id=102)),
        ):
            target = self.root / "output"
            with self.subTest(run=binding["run"]), self.assertRaises(ValueError):
                consumer_capability.open_result(self.cipher, capsule, target, key, signer, binding)
            self.assertFalse(target.exists())
        self.cipher.write_bytes(self.cipher.read_bytes()[:-1])
        with self.assertRaises(ValueError):
            consumer_capability.open_result(
                self.cipher, capsule, self.root / "output",
                self.input_private, self.signing_public, self.binding)
        self.assertFalse((self.root / "output").exists())

    def test_master_keys_are_never_read_by_creator_in_actions(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), \
                mock.patch.object(consumer_capability, "_secret_file") as read, self.assertRaises(ValueError):
            consumer_capability.create(
                self.cipher, self.log_path, self.sign_path, self.input_public, self.binding)
        read.assert_not_called()

    def test_original_recipient_and_context_must_match_independent_binding(self):
        for change in ({"recipient": "f" * 64}, {"request_digest": "f" * 64},
                       {"attempt": 2}, {"lane": "gcc"}, {"run": True}, {"extra": "untrusted"}):
            with self.subTest(change=change), \
                    mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), self.assertRaises(ValueError):
                consumer_capability.create(
                    self.cipher, self.log_path, self.sign_path, self.input_public, dict(self.binding, **change))
