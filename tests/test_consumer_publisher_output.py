"""Direct publisher encryption uses fresh keys; no delegated result keys."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from secure_release import consumer_ci as consumer, crypto
from tests.test_consumer_ci import request


class ConsumerPublisherOutput(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log_private, self.log_public = crypto.generate("encrypt")
        self.publisher_private, self.publisher_public = crypto.generate("encrypt")
        (self.root / "ci").mkdir()
        (self.root / "ci/builder-logs-public-key.b64").write_text(crypto.b64(self.log_public.encode()))
        self.value = request()
        work = self.root / "consumer-ci"
        (work / "results").mkdir(parents=True)
        (work / "request.json").write_bytes(crypto.canonical(self.value))
        (work / "results/result.json").write_bytes(crypto.canonical({
            "schema": 1, "source_sha": self.value["source_sha"], "builder_sha": self.value["builder_sha"],
            "lane": "static", "status": "success"}))
        self.env = {
            "RUNNER_TEMP": str(self.root), "CONSUMER_LANE": "static", "GITHUB_RUN_ID": "100",
            "GITHUB_RUN_ATTEMPT": "1", "CONSUMER_REQUEST_DIGEST": "c" * 64,
            "CONSUMER_PUBLISH_ENABLED": "true",
            "CONSUMER_PUBLISH_PUBLIC_KEY_B64": crypto.b64(self.publisher_public.encode()),
        }

    def output(self):
        def diagnostics(roots, path, public, context):
            path.write_bytes(b"synthetic diagnostics not consumed")
        with mock.patch.dict(os.environ, self.env), \
                mock.patch.object(consumer, "__file__", str(self.root / "secure_release/consumer_ci.py")), \
                mock.patch.object(consumer.encrypted_logs, "github_context", return_value={}), \
                mock.patch.object(consumer.encrypted_logs, "collect", side_effect=diagnostics):
            consumer.outputs()

    def test_static_result_is_directly_encrypted_to_two_independent_public_recipients(self):
        self.output()
        out = self.root / "consumer-output"
        self.assertEqual({p.name for p in out.iterdir()}, {"results.enc", "diagnostics.enc", "publisher-results.enc"})
        context = consumer.context("results", self.value)
        context.update(run=100, attempt=1, request_digest="c" * 64, lane="static")
        publisher_context = dict(context, purpose="consumer-ci-publisher-results")
        crypto.decrypt_file(out / "results.enc", self.root / "log-plain", self.log_private, context)
        crypto.decrypt_file(out / "publisher-results.enc", self.root / "publisher-plain",
                            self.publisher_private, publisher_context)
        self.assertEqual((self.root / "log-plain").read_bytes(), (self.root / "publisher-plain").read_bytes())
        with self.assertRaises(ValueError):
            crypto.decrypt_file(out / "publisher-results.enc", self.root / "wrong-context",
                                self.publisher_private, context)
        with self.assertRaises(ValueError):
            crypto.decrypt_file(out / "results.enc", self.root / "wrong-recipient",
                                self.publisher_private, context)
        self.assertFalse((self.root / "consumer-ci/results.tar.gz").exists())

    def test_disabled_and_nonstatic_runs_do_not_emit_publisher_ciphertext(self):
        self.env["CONSUMER_PUBLISH_ENABLED"] = "false"
        self.output()
        self.assertFalse((self.root / "consumer-output/publisher-results.enc").exists())

    def test_nonstatic_lane_keeps_legacy_inventory_even_when_opted_in(self):
        self.env["CONSUMER_LANE"] = "gcc"
        self.output()
        self.assertEqual({p.name for p in (self.root / "consumer-output").iterdir()}, {"results.enc", "diagnostics.enc"})

    def test_enabled_missing_key_and_unknown_mode_fail_closed(self):
        self.env["CONSUMER_PUBLISH_PUBLIC_KEY_B64"] = ""
        with self.assertRaises(ValueError):
            self.output()
        self.assertFalse((self.root / "consumer-output/publisher-results.enc").exists())

    def test_unknown_mode_does_not_silently_disable_publisher_result(self):
        self.env["CONSUMER_PUBLISH_ENABLED"] = "maybe"
        with self.assertRaises(ValueError):
            self.output()

    def test_publisher_cannot_silently_reuse_the_local_log_recipient(self):
        self.env["CONSUMER_PUBLISH_PUBLIC_KEY_B64"] = crypto.b64(self.log_public.encode())
        with self.assertRaises(ValueError):
            self.output()
        self.assertFalse((self.root / "consumer-output/publisher-results.enc").exists())

    def test_dual_ciphertext_total_keeps_artifact_transport_bounded_and_cleans_plain_tar(self):
        def encrypt(source, target, public, context):
            target.write_bytes(b"x" * (1024 * 1024))
        with mock.patch.object(consumer, "MAX_PREPARED", 2 * 1024 * 1024), \
                mock.patch.object(crypto, "encrypt_file", side_effect=encrypt), self.assertRaises(ValueError):
            self.output()
        self.assertFalse((self.root / "consumer-ci/results.tar.gz").exists())

    def test_workflow_only_passes_publisher_public_key_to_result_encryption(self):
        import yaml
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/encrypted-consumer-ci.yml"
        value = yaml.load(workflow.read_text(), Loader=yaml.BaseLoader)
        qualify = value["jobs"]["qualify"]
        for step in qualify["steps"]:
            env = step.get("env", {})
            if step.get("name") == "Encrypt results and diagnostics":
                self.assertEqual(env["CONSUMER_PUBLISH_PUBLIC_KEY_B64"],
                                 "${{ secrets.CONSUMER_CI_PUBLISH_PUBLIC_KEY_B64 }}")
            else:
                self.assertNotIn("CONSUMER_PUBLISH_PUBLIC_KEY_B64", env)
            self.assertFalse(any("PUBLISH" in key and "PRIVATE" in key for key in env))
        self.assertNotIn("CONSUMER_PUBLISH_PUBLIC_KEY_B64", qualify.get("env", {}))
