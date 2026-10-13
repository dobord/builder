"""Fail-closed retry for a transient Windows CEF checkpoint transport mismatch."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from secure_release import cef_windows_iteration as worker


def selector() -> dict:
    return {
        "run": 101,
        "attempt": 1,
        "producer_sha": "a" * 40,
        "artifact_id": 301,
        "artifact_sha256": "b" * 64,
        "summary_artifact_id": 302,
        "summary_artifact_sha256": "c" * 64,
        "build_key": "d" * 64,
    }


class API:
    def __init__(self, failures: list[BaseException]):
        self.failures = list(failures)
        self.downloads = 0
        self.artifact_calls = 0
        self.run_calls = 0
        self.artifact = {
            "id": 301,
            "name": "cef-windows-engine-checkpoint-101-1",
            "expired": False,
            "digest": "sha256:" + "b" * 64,
            "workflow_run": {"id": 101, "head_sha": "a" * 40},
        }
        self.run = {
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
        }
        self.mutate = lambda api: None

    def download(self, endpoint, target, expected, *, max_size):
        self.downloads += 1
        self.assertions = (
            endpoint, expected, max_size, target.name,
        )
        if self.failures:
            error = self.failures.pop(0)
            if error is not None:
                raise error
        target.write_bytes(b"exact-fixture")

    def artifacts(self, repo, run):
        self.artifact_calls += 1
        self.mutate(self)
        return [deepcopy(self.artifact)]

    def get(self, path):
        self.run_calls += 1
        return deepcopy(self.run)


class CheckpointTransportRetryTests(unittest.TestCase):
    def run_download(self, api: API):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "artifact.zip"
            worker.download_checkpoint_transport(api, selector(), target)
            return target.read_bytes()

    def test_one_exact_digest_mismatch_rechecks_and_retries(self):
        api = API([ValueError("download digest mismatch"), None])
        self.assertEqual(self.run_download(api), b"exact-fixture")
        self.assertEqual(api.downloads, 2)
        self.assertEqual(api.artifact_calls, 1)
        self.assertEqual(api.run_calls, 1)
        endpoint, expected, maximum, name = api.assertions
        self.assertEqual(endpoint, "/repos/dobord/builder/actions/artifacts/301/zip")
        self.assertEqual(expected, "b" * 64)
        self.assertEqual(maximum, worker.cef_cache.MAX_TOTAL)
        self.assertEqual(name, "artifact.zip")

    def test_second_digest_mismatch_is_hard_failure(self):
        api = API([
            ValueError("download digest mismatch"),
            ValueError("download digest mismatch"),
        ])
        with self.assertRaisesRegex(ValueError, "^download digest mismatch$"):
            self.run_download(api)
        self.assertEqual(api.downloads, 2)
        self.assertEqual(api.artifact_calls, 1)
        self.assertEqual(api.run_calls, 1)

    def test_other_download_errors_are_never_retried(self):
        for error in (TimeoutError("timeout"), ValueError("artifact download too large")):
            with self.subTest(error=type(error).__name__):
                api = API([error])
                with self.assertRaises(type(error)):
                    self.run_download(api)
                self.assertEqual(api.downloads, 1)
                self.assertEqual(api.artifact_calls, 0)
                self.assertEqual(api.run_calls, 0)

    def test_artifact_drift_blocks_retry(self):
        api = API([ValueError("download digest mismatch"), None])
        api.mutate = lambda value: value.artifact.update(
            digest="sha256:" + "0" * 64
        )
        with self.assertRaisesRegex(ValueError, "artifact changed during download"):
            self.run_download(api)
        self.assertEqual(api.downloads, 1)

    def test_producer_drift_blocks_retry(self):
        api = API([ValueError("download digest mismatch"), None])
        def mutate(value):
            value.run["run_attempt"] = 2
        api.mutate = mutate
        # Artifact recheck happens first, then producer recheck.
        original_artifacts = api.artifacts
        def artifacts(repo, run):
            result = original_artifacts(repo, run)
            api.run["run_attempt"] = 2
            return result
        api.artifacts = artifacts
        with self.assertRaisesRegex(ValueError, "producer changed during download"):
            self.run_download(api)
        self.assertEqual(api.downloads, 1)

    def test_partial_output_from_failed_download_blocks_retry(self):
        api = API([])
        def bad_download(endpoint, target, expected, *, max_size):
            api.downloads += 1
            target.write_bytes(b"partial")
            raise ValueError("download digest mismatch")
        api.download = bad_download
        with self.assertRaisesRegex(ValueError, "published partial output"):
            self.run_download(api)
        self.assertEqual(api.downloads, 1)
        self.assertEqual(api.artifact_calls, 0)


if __name__ == "__main__":
    unittest.main()
