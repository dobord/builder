"""Synthetic archive handoff; never use or export an operator log private key."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import consumer_handoff, crypto
from tests.test_consumer_publication import fixture


class ConsumerArchiveHandoff(unittest.TestCase):
    def test_authenticated_encryption_does_not_replace_the_approved_plaintext_digest(self):
        private, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = fixture()
            source = root / "synthetic-wrong-bytes"
            source.write_bytes(b"not the approved bytes")
            cipher = root / "archive.enc"
            context = {"schema": 1, "purpose": "consumer-release-archive",
                       "approval_sha256": hashlib.sha256(crypto.canonical(expected)).hexdigest()}
            crypto.encrypt_file(source, cipher, public, context)
            output = root / "output"
            output.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                consumer_handoff.open_archive(
                    cipher, output / expected["archive"]["name"], private, expected)
            self.assertEqual(list(output.iterdir()), [])

    def test_bounds_links_and_failed_atomic_publication_leave_no_partial_output(self):
        _, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = fixture()
            content = b"synthetic archive"
            expected["archive"]["sha256"] = hashlib.sha256(content).hexdigest()
            source = root / expected["archive"]["name"]
            source.write_bytes(content)
            output = root / "output"
            output.mkdir(mode=0o700)
            cipher = output / "archive.enc"
            with mock.patch.object(consumer_handoff, "_MAX", 1), self.assertRaises(ValueError):
                consumer_handoff.seal_archive(source, cipher, public, expected)
            self.assertEqual(list(output.iterdir()), [])
            source.write_bytes(b"")
            with self.assertRaises(ValueError):
                consumer_handoff.seal_archive(source, cipher, public, expected)
            self.assertEqual(list(output.iterdir()), [])
            source.write_bytes(content)
            if os.name == "posix":
                original = root / "original"
                source.rename(original)
                source.symlink_to(original)
                with self.assertRaises(ValueError):
                    consumer_handoff.seal_archive(source, cipher, public, expected)
                self.assertEqual(list(output.iterdir()), [])
                source.unlink()
                original.rename(source)
            def race(*args):
                cipher.write_bytes(b"racing-owner")
                raise FileExistsError()
            with mock.patch.object(consumer_handoff.os, "link", side_effect=race), self.assertRaises(ValueError):
                consumer_handoff.seal_archive(source, cipher, public, expected)
            self.assertEqual(cipher.read_bytes(), b"racing-owner")
            self.assertEqual(list(output.iterdir()), [cipher])

    def test_exact_bytes_roundtrip_without_extracting_or_executing_archive(self):
        private, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = fixture()
            content = b"synthetic opaque archive bytes; never execute or unpack\n"
            expected["archive"]["sha256"] = hashlib.sha256(content).hexdigest()
            source = root / expected["archive"]["name"]
            source.write_bytes(content)
            cipher = root / "archive.enc"
            consumer_handoff.seal_archive(source, cipher, public, expected)
            output = root / "output"
            output.mkdir(mode=0o700)
            target = output / source.name
            consumer_handoff.open_archive(cipher, target, private, expected)
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(source.read_bytes(), content)
            if os.name == "posix":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_wrong_archive_digest_context_and_recipient_fail_without_output(self):
        private, public = crypto.generate("encrypt")
        other_private, _ = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b"synthetic opaque archive\n"
            expected = fixture()
            source = root / expected["archive"]["name"]
            source.write_bytes(content)
            cipher = root / "archive.enc"
            with self.assertRaises(ValueError):
                consumer_handoff.seal_archive(source, cipher, public, expected)
            self.assertFalse(cipher.exists())
            expected["archive"]["sha256"] = hashlib.sha256(content).hexdigest()
            consumer_handoff.seal_archive(source, cipher, public, expected)
            output = root / "output"
            output.mkdir(mode=0o700)
            target = output / source.name
            changed = copy.deepcopy(expected)
            changed["run"] += 1
            for key, approval in ((other_private, expected), (private, changed)):
                with self.subTest(changed=approval["run"]), self.assertRaises(ValueError):
                    consumer_handoff.open_archive(cipher, target, key, approval)
                self.assertFalse(target.exists())
                self.assertEqual(list(output.iterdir()), [])
            cipher.write_bytes(cipher.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                consumer_handoff.open_archive(cipher, target, private, expected)
            self.assertFalse(target.exists())

    def test_existing_outputs_and_unsafe_source_are_not_replaced(self):
        private, public = crypto.generate("encrypt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = fixture()
            content = b"synthetic archive"
            expected["archive"]["sha256"] = hashlib.sha256(content).hexdigest()
            source = root / expected["archive"]["name"]
            source.write_bytes(content)
            cipher = root / "archive.enc"
            cipher.write_bytes(b"preserve")
            with self.assertRaises(ValueError):
                consumer_handoff.seal_archive(source, cipher, public, expected)
            self.assertEqual(cipher.read_bytes(), b"preserve")
            cipher.unlink()
            consumer_handoff.seal_archive(source, cipher, public, expected)
            with self.assertRaises(ValueError):
                consumer_handoff.open_archive(cipher, source, private, expected)
            self.assertEqual(source.read_bytes(), content)
            wrong_name = root / "wrong-name"
            wrong_name.write_bytes(content)
            with self.assertRaises(ValueError):
                consumer_handoff.seal_archive(wrong_name, root / "bad.enc", public, expected)
