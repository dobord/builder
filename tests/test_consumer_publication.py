import copy
import hashlib
import os
from pathlib import Path
import re
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
    def test_acceptance_requires_exact_qualified_identity_and_every_required_check(self):
        identity = {"source_sha": "2" * 40, "builder_sha": "4" * 40,
                    "run": 21, "attempt": 1, "archive_sha256": "6" * 64}
        value = dict(identity, schema=1, purpose="consumer-release-acceptance",
                     kind="dataplane", checks={"handshake": "pass", "rollback": "pass"})
        raw = crypto.canonical(value)
        self.assertEqual(consumer_publication.check_acceptance_receipt(
            raw, "dataplane", identity, ("handshake", "rollback")), hashlib.sha256(raw).hexdigest())
        for override in (
            {"source_sha": "8" * 40}, {"builder_sha": "9" * 40}, {"run": 22},
            {"attempt": 2}, {"archive_sha256": "7" * 64}, {"kind": "client"},
            {"purpose": "candidate-only"}, {"schema": True}, {"extra": "untrusted"},
            {"checks": {"handshake": "pass"}},
            {"checks": {"handshake": "pass", "rollback": "NOT RUN"}},
            {"checks": {"handshake": "pass", "rollback": "skipped"}},
            {"checks": {"handshake": "pass", "rollback": True}},
            {"checks": {"handshake": "pass", "rollback": "pass", "extra": "pass"}},
        ):
            with self.subTest(override=override), self.assertRaises(ValueError):
                consumer_publication.check_acceptance_receipt(
                    crypto.canonical(dict(value, **override)), "dataplane", identity,
                    ("handshake", "rollback"))

    def test_acceptance_inventory_and_input_bounds_fail_closed(self):
        identity = {"source_sha": "2" * 40, "builder_sha": "4" * 40,
                    "run": 21, "attempt": 1, "archive_sha256": "6" * 64}
        value = dict(identity, schema=1, purpose="consumer-release-acceptance",
                     kind="client", checks={"import": "pass"})
        raw = crypto.canonical(value)
        for checks in ((), ("import", "import"), ("../import",), ("x" * 65,), ("import",) * 129,
                       "import", {"import": "pass"}):
            with self.subTest(checks=str(checks)[:32]), self.assertRaises(ValueError):
                consumer_publication.check_acceptance_receipt(raw, "client", identity, checks)
        for body in (b"", b"x" * 32769, b" " + raw, b"{}", raw.decode()):
            with self.subTest(body=str(body)[:20]), self.assertRaises(ValueError):
                consumer_publication.check_acceptance_receipt(body, "client", identity, ("import",))
        for override in ({"run": True}, {"attempt": True}, {"source_sha": "bad"},
                         {"archive_sha256": "bad"}, {"extra": "untrusted"}):
            bad_identity = dict(identity, **override)
            bad_raw = crypto.canonical(dict(value, **override))
            with self.subTest(override=override), self.assertRaises(ValueError):
                consumer_publication.check_acceptance_receipt(
                    bad_raw, "client", bad_identity, ("import",))

    def test_windows_msys_toolchain_receives_its_own_path_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cygpath.exe").touch()
            env = {"PATH": "synthetic"}
            reply = subprocess.CompletedProcess(["cygpath"], 0, stdout=b"/c/synthetic/home\n")
            with mock.patch.object(shutil, "which", return_value=str(root / "gpg.exe")), \
                    mock.patch.object(subprocess, "run", return_value=reply) as run:
                self.assertEqual(consumer_publication._tool_home(root, env, windows=True), "/c/synthetic/home")
            self.assertEqual(run.call_args.args[0], [str(root / "cygpath.exe"), "-u", root.as_posix()])
            self.assertEqual(run.call_args.kwargs["env"], env)
            self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_native_toolchain_does_not_require_msys_translation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(subprocess, "run") as run:
                self.assertEqual(consumer_publication._tool_home(root, {}, windows=False), root.as_posix())
                with mock.patch.object(shutil, "which", return_value=str(root / "gpg.exe")):
                    self.assertEqual(consumer_publication._tool_home(root, {}, windows=True), root.as_posix())
            run.assert_not_called()

    def test_unsafe_translated_home_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cygpath.exe").touch()
            for output in (b"", b"relative-path", b"/home\nother", b"/home\0other", b"/" + b"x" * 4096):
                with self.subTest(output=output[:12]), \
                        mock.patch.object(shutil, "which", return_value=str(root / "gpg.exe")), \
                        mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(
                            ["cygpath"], 0, stdout=output)), self.assertRaises(ValueError):
                    consumer_publication._tool_home(root, {}, windows=True)

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
        cls.tool_home = consumer_publication._tool_home(home, dict(os.environ))
        cls.addClassCleanup(
            subprocess.run, ["gpgconf", "--homedir", cls.tool_home, "--kill", "gpg-agent"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        # A file avoids empty-argument loss in Windows/MSYS tool invocation.
        # This passphrase protects only a disposable synthetic test signer.
        cls.passphrase = home / "synthetic-passphrase"
        cls.passphrase.write_bytes(b"synthetic-test-only\n")
        cls.passphrase.chmod(0o600)
        cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file", cls.tool_home + "/synthetic-passphrase",
                    "--quick-generate-key", "Synthetic Approver <signer@example.invalid>", "ed25519", "sign", "1d")
        listing = cls.run_gpg("--with-colons", "--list-keys").decode()
        cls.fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.public = cls.run_gpg("--armor", "--export", cls.fingerprint)
        cls.raw = crypto.canonical(fixture())
        cls.signature = cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file", cls.tool_home + "/synthetic-passphrase",
                                    "--armor", "--detach-sign", "--output", "-", data=cls.raw)

    @classmethod
    def run_gpg(cls, *args, data=None):
        if any(not arg for arg in args):
            raise RuntimeError("synthetic OpenPGP invocation has an empty argument")
        result = subprocess.run(["gpg", "--no-options", "--batch", "--homedir", cls.tool_home, *args],
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
            detail = result.stderr.decode("utf-8", errors="replace")
            detail = re.sub(r"""(?i)[`'"](?:[a-z]:[/\\]|/)[^`'"\r\n]*[`'"]""", "<path>", detail)
            detail = re.sub(r"""(?i)(?:[a-z]:)?[/\\][^\s`'"]+""", "<path>", detail)
            detail = re.sub(r"\b[0-9a-fA-F]{32,}\b", "<synthetic-fingerprint>", detail)
            detail = " ".join(detail.split())[:400]
            context = ("posix" if cls.tool_home.startswith("/") else "drive") + \
                f"; passphrase_exists={cls.passphrase.is_file()}; agent_on_path={bool(shutil.which('gpg-agent'))}"
            raise RuntimeError(f"synthetic OpenPGP {stage} failed: {reason} "
                               f"(exit {result.returncode}; home={context}); "
                               f"redacted tool diagnostic: {detail}")
        return result.stdout

    def test_only_pinned_signer_can_authenticate_exact_approval(self):
        self.assertEqual(
            consumer_publication.verify_signed_approval(
                self.raw, self.signature, self.public, self.fingerprint, fixture()),
            fixture())
        with self.assertRaises(ValueError):
            consumer_publication.verify_signed_approval(
                self.raw, self.signature, self.public, "0" * 40, fixture())

    def test_release_tag_requires_exact_git_object_and_pinned_signature(self):
        payload = (b"object " + b"2" * 40 + b"\ntype commit\ntag 0.9.1\n"
                   b"tagger Synthetic Approver <signer@example.invalid> 1 +0000\n\nRelease\n")
        signature = self.run_gpg(
            "--pinentry-mode", "loopback", "--passphrase-file",
            self.tool_home + "/synthetic-passphrase", "--armor", "--detach-sign",
            "--output", "-", data=payload)
        raw = payload + signature
        oid = hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if shutil.which("git"):
            git_oid = subprocess.run(
                ["git", "hash-object", "-t", "tag", "--stdin"], input=raw,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True)
            self.assertEqual(git_oid.stdout.decode("ascii").strip(), oid)
        args = (raw, "0.9.1", "2" * 40, oid, self.public, self.fingerprint)
        self.assertEqual(consumer_publication.verify_source_tag(*args), oid)
        for position, changed in (
            (0, raw + b"tamper"), (1, "0.9.2"), (2, "3" * 40),
            (3, "4" * 40), (5, "0" * 40),
        ):
            with self.subTest(position=position), self.assertRaises(ValueError):
                bad = list(args)
                bad[position] = changed
                consumer_publication.verify_source_tag(*bad)
        extra = raw + b"unsigned suffix\n"
        extra_oid = hashlib.sha1(b"tag " + str(len(extra)).encode() + b"\0" + extra).hexdigest()
        with self.assertRaises(ValueError):
            consumer_publication.verify_source_tag(
                extra, "0.9.1", "2" * 40, extra_oid, self.public, self.fingerprint)

    def test_tag_signature_cannot_be_replaced_by_github_verified_metadata(self):
        for raw in (b"", b"x" * 65537, b'{"verified":true}', b"object " + b"2" * 40):
            with self.subTest(raw=raw[:24]), self.assertRaises(ValueError):
                consumer_publication.verify_source_tag(
                    raw, "0.9.1", "2" * 40, "1" * 40, self.public, self.fingerprint)

    def test_correct_signature_does_not_authorize_nested_or_foreign_tags(self):
        good = (b"object " + b"2" * 40 + b"\ntype commit\ntag 0.9.1\n"
                b"tagger Synthetic Approver <signer@example.invalid> 1 +0000\n\nRelease\n")
        for payload in (
            good.replace(b"type commit", b"type tag"),
            good.replace(b"tag 0.9.1", b"tag 0.9.2"),
            good.replace(b"2" * 40, b"3" * 40),
            good.replace(b"\n\nRelease", b"\nextra header\n\nRelease"),
            good.replace(b" 1 +0000", b" invalid"),
            good.rstrip(b"\n"),
        ):
            signature = self.run_gpg(
                "--pinentry-mode", "loopback", "--passphrase-file",
                self.tool_home + "/synthetic-passphrase", "--armor", "--detach-sign",
                "--output", "-", data=payload)
            raw = payload + signature
            oid = hashlib.sha1(b"tag " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            with self.subTest(payload=payload[:80]), self.assertRaises(ValueError):
                consumer_publication.verify_source_tag(
                    raw, "0.9.1", "2" * 40, oid, self.public, self.fingerprint)

    def test_setup_never_relies_on_empty_tool_arguments(self):
        with self.assertRaisesRegex(RuntimeError, "empty argument"):
            self.run_gpg("--passphrase", "")

    def test_synthetic_setup_diagnostic_is_bounded_and_redacts_paths_and_fingerprint(self):
        path = "C:/Users/Fixture User/synthetic-key/packet"
        fingerprint = "A" * 40
        stderr = f"gpg: cannot open '{path}': No such file; {fingerprint}; " + "x" * 600
        failed = subprocess.CompletedProcess(["gpg"], 2, stdout=b"", stderr=stderr.encode())
        with mock.patch.object(subprocess, "run", return_value=failed):
            with self.assertRaises(RuntimeError) as caught:
                self.run_gpg("--quick-generate-key")
        message = str(caught.exception)
        self.assertIn("file-unavailable", message)
        self.assertNotIn("Fixture User", message)
        self.assertNotIn(fingerprint, message)
        self.assertLess(len(message), 700)

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
        self.assertIn(len(calls.call_args_list), (2, 3))
        if len(calls.call_args_list) == 3:
            self.assertEqual(Path(calls.call_args_list[0].args[0][0]).name.lower(), "cygpath.exe")
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
