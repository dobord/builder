"""Real disposable Tink/OpenPGP over an in-memory GitHub API and synthetic ZIPs."""
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
import zipfile
from unittest import mock

from secure_release import consumer_automation as automation, consumer_publisher as publisher, crypto
from tests import test_consumer_publication as signatures, test_consumer_publisher as publisher_tests


class AutomationRoundTrip(unittest.TestCase):
    run_gpg = classmethod(signatures.ConsumerPublicationSignatures.run_gpg.__func__)
    sign = classmethod(publisher_tests.ConsumerPublisherCryptography.sign.__func__)

    @classmethod
    def setUpClass(cls):
        signatures.ConsumerPublicationSignatures.setUpClass.__func__(cls)
        cls.private = cls.run_gpg("--pinentry-mode", "loopback", "--passphrase-file",
                                 cls.tool_home + "/synthetic-passphrase",
                                 "--armor", "--export-secret-keys", cls.fingerprint)

    def setUp(self):
        publisher_tests.ConsumerPublisherCryptography.setUp(self)

    def test_qualified_original_reaches_isolated_signer_then_exact_latest_publication(self):
        signer_private, signer_public = crypto.generate("encrypt")
        self.policy["presentation"] = {
            "notes_sha256": hashlib.sha256(b"### Added\n\n- Synthetic automatic release.\n").hexdigest(),
            "make_latest": True}
        receipts = {k: crypto.unb64(v) for k, v in self.bundle["receipts"].items()}
        operator = crypto.unb64(self.env["CONSUMER_VERIFY_PUBLIC_KEY_B64"]).decode()
        self.policy["automation"] = {"builder_sha": "d" * 40, "signer_sha": "e" * 40,
            "signer_recipient": crypto.fingerprint(signer_public),
            "operator_verify_sha256": hashlib.sha256(crypto.canonical(crypto.parse(operator))).hexdigest(),
            "receipt_sha256": publisher.receipt_digests(self.policy, receipts)}
        common = dict(self.env, CONSUMER_RELEASE_POLICY_B64=crypto.b64(crypto.canonical(self.policy)),
                      CONSUMER_SIGNER_INPUT_PUBLIC_KEY_B64=crypto.b64(signer_public.encode()),
                      BUILDER_READ_TOKEN="synthetic-read")
        for name in ("RUNNER_TEMP", "GITHUB_OUTPUT"):
            common.pop(name, None)
        system = {k: v for k, v in os.environ.items()
                  if k.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"}}
        directories = {}
        for name in ("prepare", "release", "signer"):
            path = self.root / name
            path.mkdir()
            directories[name] = path
        now = int(automation.time.time())
        payload = {"qualification_request": self.sealed_qualification,
                   "qualification_request_id": self.qualified["request_id"],
                   "receipts": self.bundle["receipts"],
                   "notes": "### Added\n\n- Synthetic automatic release.\n", "existing": None}
        request_id = "11111111-1111-4111-8111-111111111111"
        sealed = crypto.seal_message(crypto.canonical(
            {"created": now, "expires": now + 3600, "payload": payload}), self.input_public,
            automation.request_context(request_id, self.policy["automation"]["builder_sha"]))
        request_digest = hashlib.sha256(sealed.encode()).hexdigest()
        producer = {"id": 1000, "repository": {"id": 1372874997}, "head_repository": {"id": 1372874997},
                    "head_sha": "d" * 40, "head_branch": "consumer-automation-" + "d" * 40,
                    "path": ".github/workflows/" + automation.WORKFLOW, "event": "workflow_dispatch",
                    "run_attempt": 1, "actor": {"id": 5323024}, "triggering_actor": {"id": 5323024},
                    "display_title": "Consumer automation " + request_digest,
                    "status": "in_progress", "conclusion": None}
        qrun = {"id": self.policy["run"], "repository": {"id": 1372874997},
                "head_repository": {"id": 1372874997}, "head_sha": self.qualified["builder_sha"],
                "path": ".github/workflows/encrypted-consumer-ci.yml", "event": "workflow_dispatch",
                "run_attempt": 1, "actor": {"id": 5323024}, "triggering_actor": {"id": 5323024},
                "display_title": "Encrypted consumer " + hashlib.sha256(self.sealed_qualification.encode()).hexdigest(),
                "status": "completed", "conclusion": "success",
                "html_url": "https://github.com/dobord/builder/actions/runs/" + str(self.policy["run"]),
                "created_at": datetime.fromtimestamp(self.qualified["created"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        qjobs = [{"name": name, "run_id": self.policy["run"], "head_sha": self.qualified["builder_sha"],
                  "status": "completed", "conclusion": "success",
                  "steps": [{"name": "Authenticate consumer and prepare pinned inputs" if name == "prepare"
                            else "Require every consumer lane" if name == "Consumer required"
                            else "Execute native recipe", "status": "completed", "conclusion": "success"}]}
                 for name in ["prepare", "Consumer required"] +
                    ["Consumer " + lane for lane in publisher.consumer.LANES]]
        state = {}
        owner = self
        class API:
            def get(self, path):
                if "/actions/runs/" + str(owner.policy["run"]) + "/attempts/1/jobs" in path:
                    return {"jobs": qjobs}
                if path.endswith("/actions/runs/" + str(owner.policy["run"])):
                    return qrun
                if "/actions/runs/" + str(owner.policy["run"]) + "/artifacts" in path:
                    return {"total_count": 1, "artifacts": [owner.artifact]}
                if path.endswith("/actions/runs/1000"):
                    return producer
                if "/actions/runs/1000/attempts/1/jobs" in path:
                    return {"jobs": [{"name": "prepare-signing", "run_id": 1000, "head_sha": "d" * 40,
                        "status": "completed", "conclusion": "success",
                        "steps": [{"name": automation.PREPARE_STEP, "status": "completed", "conclusion": "success"}]}]}
                if "/actions/runs/1000/artifacts" in path:
                    return {"total_count": 1, "artifacts": [state["input_artifact"]]}
                if "/actions/workflows/" + automation.SIGNER_WORKFLOW + "/runs" in path:
                    return {"workflow_runs": [state["signer_run"]]}
                if "/actions/runs/2000/attempts/1/jobs" in path:
                    return {"jobs": [{"name": "sign", "run_id": 2000, "head_sha": "e" * 40,
                        "status": "completed", "conclusion": "success",
                        "steps": [{"name": automation.SIGN_STEP, "status": "completed", "conclusion": "success"}]}]}
                if "/actions/runs/2000/artifacts" in path:
                    return {"total_count": 1, "artifacts": [state["output_artifact"]]}
                raise AssertionError("unexpected synthetic automation API")

            def request(self, method, path):
                if path.endswith("/900/zip"):
                    raise urllib.error.HTTPError("https://api.github.com", 302, "synthetic redirect",
                        {"Location": "https://productionresultssa1.blob.core.windows.net/synthetic"}, None)
                if path.endswith("/901/zip"):
                    return io.BytesIO(state["output_zip"])
                raise AssertionError("unexpected synthetic artifact request")

            def json(self, method, path, dispatch):
                assert method == "POST" and path.endswith("/dispatches")
                inputs = dispatch["inputs"]
                state["signer_run"] = dict(producer, id=2000, head_sha="e" * 40,
                    repository={"id": owner.policy["repository_id"]},
                    head_repository={"id": owner.policy["repository_id"]},
                    head_branch="consumer-signer-" + "e" * 40,
                    path=".github/workflows/" + automation.SIGNER_WORKFLOW,
                    display_title="Consumer signer " + inputs["request_digest"])
                source_common = {k: v for k, v in common.items()
                                 if k not in {"CONSUMER_INPUT_PRIVATE_KEY_B64", "CONSUMER_PUBLISH_PRIVATE_KEY_B64"}}
                source_env = dict(system, **source_common, RUNNER_TEMP=str(directories["signer"]),
                    GITHUB_RUN_ID="2000", CONSUMER_PRODUCER_RUN="1000",
                    CONSUMER_SIGNER_REQUEST_ID=inputs["request_id"],
                    CONSUMER_SIGNER_REQUEST_DIGEST=inputs["request_digest"],
                    CONSUMER_SIGNER_REQUEST=inputs["request"],
                    CONSUMER_SIGNER_INPUT_PRIVATE_KEY_B64=crypto.b64(signer_private.encode()),
                    CONSUMER_RELEASE_SIGNING_PRIVATE_KEY_B64=crypto.b64(owner.private),
                    CONSUMER_RELEASE_SIGNING_PASSPHRASE="synthetic-test-only",
                    CONSUMER_BUILDER_INPUT_PUBLIC_KEY_B64=crypto.b64(owner.input_public.encode()))
                with mock.patch.dict(os.environ, source_env, clear=True):
                    automation.sign()
                raw = (directories["signer"] / "consumer-automation/result.json").read_bytes()
                packet = crypto.parse(raw)
                result = packet["bundle"]
                expected = crypto.parse(crypto.unb64(result["approval"]))
                owner.api = publisher_tests.TagAPI(expected, crypto.unb64(result["tag"]))
                data = io.BytesIO()
                with zipfile.ZipFile(data, "w") as zipped:
                    zipped.write(directories["signer"] / "consumer-signature-output/result.enc", "result.enc")
                state["output_zip"] = data.getvalue()
                state["output_artifact"] = {"id": 901, "expired": False,
                    "name": "consumer-signature-output-2000-1", "size_in_bytes": len(state["output_zip"]),
                    "digest": "sha256:" + hashlib.sha256(state["output_zip"]).hexdigest()}
                state["signer_run"].update(status="completed", conclusion="success")

        api = API()
        def original_download(client, resource, target, digest):
            assert crypto.digest(self.zip) == digest
            target.write_bytes(self.zip.read_bytes())
        env = dict(system, **common, RUNNER_TEMP=str(directories["prepare"]), GITHUB_RUN_ID="1000",
                   CONSUMER_AUTOMATION_REQUEST_ID=request_id, CONSUMER_AUTOMATION_REQUEST_DIGEST=request_digest,
                   CONSUMER_AUTOMATION_REQUEST=sealed)
        with mock.patch.object(automation, "guard"), \
                mock.patch.object(automation, "Client", return_value=api), \
                mock.patch.object(publisher.approval, "resolve_qualification", return_value=self.qualified), \
                mock.patch.object(publisher.consumer.ci, "pages", return_value=[self.artifact]), \
                mock.patch.object(publisher, "download_original", side_effect=original_download):
            with mock.patch.dict(os.environ, env, clear=True):
                automation.prepare()
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as zipped:
                zipped.write(directories["prepare"] / "consumer-signing-input/input.enc", "input.enc")
            state["input_zip"] = data.getvalue()
            state["input_artifact"] = {"id": 900, "expired": False, "name": "consumer-signing-input-1000-1",
                "size_in_bytes": len(state["input_zip"]),
                "digest": "sha256:" + hashlib.sha256(state["input_zip"]).hexdigest()}
            opener = mock.Mock()
            opener.open.side_effect = lambda *args, **kwargs: io.BytesIO(state["input_zip"])
            release_env = dict(system, **common, RUNNER_TEMP=str(directories["release"]), GITHUB_RUN_ID="1000",
                GITHUB_OUTPUT=str(directories["release"] / "outputs"), CONSUMER_DISPATCH_TOKEN="synthetic-dispatch")
            dispatch_env = {k: v for k, v in release_env.items() if "PRIVATE_KEY" not in k}
            with mock.patch.dict(os.environ, dispatch_env, clear=True), \
                    mock.patch.object(automation.urllib.request, "build_opener", return_value=opener):
                automation.orchestrate()
            outputs = dict(line.split("=", 1) for line in
                           (directories["release"] / "outputs").read_text().splitlines())
            release_env["CONSUMER_SIGNER_RETURN_DIGEST"] = outputs["signer_return_digest"]
            complete_env = {k: v for k, v in release_env.items() if k != "CONSUMER_DISPATCH_TOKEN"}
            with mock.patch.dict(os.environ, complete_env, clear=True):
                automation.complete()
            outputs = dict(line.split("=", 1) for line in
                           (directories["release"] / "outputs").read_text().splitlines())
            release_env["CONSUMER_RELEASE_STAGING_DIGEST"] = outputs["staging_digest"]
            release_env["CONSUMER_RELEASE_PUBLISH_TOKEN"] = "synthetic-publication"
            publish_env = {k: v for k, v in release_env.items()
                           if "PRIVATE_KEY" not in k and k != "CONSUMER_DISPATCH_TOKEN"}
            with mock.patch.dict(os.environ, publish_env, clear=True), \
                    mock.patch.object(publisher, "Client", return_value=self.api), \
                    mock.patch.object(publisher, "recheck_qualification"):
                automation.publish()
        self.assertEqual(self.api.latest, 100)
        self.assertFalse(self.api.release["draft"])
        self.assertEqual(len(self.api.assets), 8)
        self.assertIn("Synthetic automatic release.", self.api.release["body"])


if __name__ == "__main__":
    unittest.main()
