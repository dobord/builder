"""Synthetic immutable producer/signer admission; no real credential fixtures."""
import copy
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
import os
from unittest import mock

from secure_release import consumer_automation as automation, crypto
from tests import test_consumer_publisher as publisher_tests


def run_record():
    return {"id": 21, "repository": {"id": 100}, "head_repository": {"id": 100},
            "head_sha": "a" * 40, "head_branch": "consumer-signer-" + "a" * 40,
            "path": ".github/workflows/sign-consumer-release.yml", "event": "workflow_dispatch",
            "run_attempt": 1, "actor": {"id": 5323024}, "triggering_actor": {"id": 5323024},
            "display_title": "Consumer signer " + "b" * 64, "status": "completed", "conclusion": "success"}


class AutomationContracts(unittest.TestCase):
    def test_workflow_credentials_are_separated_and_qualification_recipe_is_untouched(self):
        import yaml
        root = Path(__file__).resolve().parents[1]
        value = yaml.load((root / ".github/workflows/automate-consumer-release.yml").read_text(),
                          Loader=yaml.BaseLoader)
        self.assertEqual(value["permissions"], {})
        self.assertEqual(value["jobs"]["prepare-signing"]["environment"], "consumer-release-preparation")
        self.assertEqual(value["jobs"]["release"]["environment"], "consumer-publication")
        for job in value["jobs"].values():
            self.assertEqual(job["permissions"], {"contents": "read", "actions": "read"})
            for step in job["steps"]:
                env = step.get("env", {})
                stage = step.get("run", "")
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(step["with"]["ref"], "${{ github.sha }}")
                self.assertFalse(any("SIGNING_PRIVATE" in key or "SIGNING_PASSPHRASE" in key for key in env))
                if "CONSUMER_RELEASE_PUBLISH_TOKEN" in env:
                    self.assertEqual(stage, "python -m secure_release.consumer_automation publish")
                    self.assertFalse(any("PRIVATE_KEY" in key or "DISPATCH_TOKEN" in key for key in env))
                if "CONSUMER_DISPATCH_TOKEN" in env:
                    self.assertEqual(stage, "python -m secure_release.consumer_automation orchestrate")
                    self.assertFalse(any("PRIVATE_KEY" in key for key in env))
        original = (root / ".github/workflows/encrypted-consumer-ci.yml").read_text()
        self.assertNotIn("CONSUMER_RELEASE_SIGNING", original)
        self.assertNotIn("consumer_automation", original)
        self.assertEqual(automation.consumer.LANES,
                         ("gcc", "clang", "asan", "tsan", "ubsan", "static", "offline", "browser"))

    def test_guard_denies_wrong_actor_ref_attempt_pin_and_disabled_mode_before_implementation_lookup(self):
        value = publisher_tests.policy()
        value["automation"] = {"builder_sha": "a" * 40, "signer_sha": "b" * 40,
            "signer_recipient": "c" * 64, "operator_verify_sha256": "d" * 64,
            "receipt_sha256": {kind: "e" * 64 for kind in value["acceptance"]}}
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "dobord/builder",
               "GITHUB_REPOSITORY_ID": str(automation.consumer.ci.BUILDER_ID),
               "GITHUB_SHA": "a" * 40, "GITHUB_REF": "refs/tags/consumer-automation-" + "a" * 40,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_ACTOR_ID": "5323024", "CONSUMER_AUTOMATION_ENABLED": "true",
               "GITHUB_WORKFLOW_REF": "dobord/builder/.github/workflows/" + automation.WORKFLOW
                    + "@refs/tags/consumer-automation-" + "a" * 40}
        with mock.patch.dict(os.environ, env):
            for key, changed in (("GITHUB_ACTOR_ID", "1"), ("GITHUB_RUN_ATTEMPT", "2"),
                                 ("GITHUB_SHA", "0" * 40), ("GITHUB_REF", "refs/heads/main"),
                                 ("CONSUMER_AUTOMATION_ENABLED", "false")):
                with self.subTest(key=key), mock.patch.dict(os.environ, {key: changed}), \
                        mock.patch.object(automation.subprocess, "check_output") as process, \
                        self.assertRaises(ValueError):
                    automation.guard("builder", value)
                process.assert_not_called()

    def test_remote_run_identity_is_exact_and_never_accepts_reruns_or_skips(self):
        expected = dict(repository_id=100, sha="a" * 40,
                        ref="consumer-signer-" + "a" * 40, workflow="sign-consumer-release.yml",
                        title="Consumer signer " + "b" * 64, completed=True)
        automation.validate_run(run_record(), **expected)
        for change in ({"run_attempt": 2}, {"head_sha": "c" * 40}, {"event": "push"},
                       {"conclusion": "skipped"}, {"actor": {"id": 100}},
                       {"head_branch": "main"}, {"path": ".github/workflows/other.yml"},
                       {"display_title": "Consumer signer " + "c" * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                automation.validate_run(dict(run_record(), **change), **expected)

    def test_producer_job_requires_executed_success_and_the_immutable_run(self):
        job = {"name": "prepare-signing", "run_id": 21, "head_sha": "a" * 40,
               "status": "completed", "conclusion": "success",
               "steps": [{"name": "Verify qualification and prepare encrypted signing input",
                          "status": "completed", "conclusion": "success"}]}
        automation.validate_job([job], run_record(), "prepare-signing",
                                "Verify qualification and prepare encrypted signing input")
        for change in ("skip", "wrong-sha", "missing-step", "duplicate"):
            jobs = [copy.deepcopy(job)]
            if change == "skip":
                jobs[0]["steps"][0]["conclusion"] = "skipped"
            elif change == "wrong-sha":
                jobs[0]["head_sha"] = "c" * 40
            elif change == "missing-step":
                jobs[0]["steps"] = []
            else:
                jobs.append(copy.deepcopy(job))
            with self.subTest(change=change), self.assertRaises(ValueError):
                automation.validate_job(jobs, run_record(), "prepare-signing",
                                        "Verify qualification and prepare encrypted signing input")

    def test_cipher_zip_has_one_exact_bounded_regular_member(self):
        for mutation in ("valid", "extra", "duplicate", "link", "oversized"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "input.zip"
                with zipfile.ZipFile(source, "w") as archive:
                    item = zipfile.ZipInfo("input.enc")
                    if mutation == "link":
                        item.external_attr = 0o120777 << 16
                    archive.writestr(item, b"ciphertext")
                    if mutation in {"extra", "duplicate"}:
                        archive.writestr("foreign.enc" if mutation == "extra" else "input.enc", b"x")
                target = root / "output.enc"
                if mutation == "valid":
                    automation.extract_cipher(source, target, "input.enc", 100)
                    self.assertEqual(target.read_bytes(), b"ciphertext")
                else:
                    with self.assertRaises(ValueError):
                        automation.extract_cipher(source, target, "input.enc",
                                                  2 if mutation == "oversized" else 100)

    def test_storage_urls_are_https_allowlisted_and_credential_free(self):
        automation.storage_url("https://productionresultssa1.blob.core.windows.net/synthetic?sig=synthetic-only")
        for value in ("http://objects.githubusercontent.com/a", "https://evil.example.invalid/a",
                      "https://user:password@objects.githubusercontent.com/a",
                      "https://objects.githubusercontent.com:444/a", "https://objects.githubusercontent.com/a#x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                automation.storage_url(value)


if __name__ == "__main__":
    unittest.main()
