"""Manual continuation checkpoints keep the exact trusted producer boundary."""
from copy import deepcopy
import inspect
import unittest

from secure_release import cef_windows_iteration as worker
from secure_release.protocol import BUILDER, IDS


class ProducerTests(unittest.TestCase):
    def fixture(self, event):
        selected = {"producer_sha": "a" * 40, "attempt": 1}
        producer = {
            "repository": {"id": IDS[BUILDER]},
            "head_repository": {"id": IDS[BUILDER]},
            "path": ".github/workflows/" + worker.WORKFLOW,
            "head_sha": selected["producer_sha"], "run_attempt": 1,
            "event": event, "head_branch": "feature/cef-static-integration",
            "status": "completed", "conclusion": "success",
        }
        return producer, selected

    def test_exact_successful_push_and_manual_producers(self):
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event):
                worker.validate_checkpoint_producer(*self.fixture(event))

    def test_every_producer_identity_and_success_field_remains_bound(self):
        changes = {
            "event": "pull_request", "head_branch": "main",
            "head_sha": "b" * 40, "run_attempt": 2,
            "repository": {"id": 1}, "head_repository": {"id": 1},
            "path": ".github/workflows/other.yml",
            "status": "in_progress", "conclusion": "failure",
        }
        for event in ("push", "workflow_dispatch"):
            producer, selected = self.fixture(event)
            for field, value in changes.items():
                changed = deepcopy(producer)
                changed[field] = value
                with self.subTest(event=event, field=field), self.assertRaises(ValueError):
                    worker.validate_checkpoint_producer(changed, selected)

    def test_restore_validates_producer_before_transport_or_decryption(self):
        source = inspect.getsource(worker.restore_checkpoint)
        self.assertLess(source.index("validate_checkpoint_producer("),
                        source.index("download_checkpoint_transport("))
        self.assertLess(source.index("validate_checkpoint_producer("),
                        source.index("cef_cache.unseal("))


if __name__ == "__main__":
    unittest.main()
