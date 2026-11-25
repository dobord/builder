"""Synthetic presentation authority and metadata-only update contracts."""
import copy
import hashlib
import unittest

from secure_release import consumer_presentation as presentation, consumer_upload
from tests import test_consumer_upload as upload_fixtures


class LatestAPI(upload_fixtures.FakeAPI):
    latest = None

    def get(self, path):
        if path.endswith("/releases/latest"):
            return {"id": self.latest, "tag_name": self.expected["tag"] if self.latest == 100 else "0.9.0"}
        return super().get(path)

    def json(self, method, path, payload):
        result = super().json(method, path, payload)
        if payload.get("make_latest") == "true":
            self.latest = self.release["id"]
        return result


class PresentationContracts(unittest.TestCase):
    def test_changelog_extraction_is_bounded_exact_and_rejects_duplicates(self):
        text = "# Changelog\n\n## [0.9.1] - 2026-11-25\n\n### Added\n\n- Synthetic feature.\n\n## [0.9.0] - 2026-11-12\n\nOlder.\n"
        notes = presentation.extract_changelog(text, "0.9.1")
        self.assertIn("Synthetic feature.", notes)
        self.assertNotIn("Older.", notes)
        for bad in (text + "\n## [0.9.1] - 2026-11-25\nDuplicate\n", "x" * 262145):
            with self.assertRaises(ValueError):
                presentation.extract_changelog(bad, "0.9.1")

    def test_presentation_intent_binds_exact_notes_policy_and_asset_inventory(self):
        fixture = upload_fixtures.ConsumerUpload()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        notes = "### Added\n\n- Synthetic feature.\n"
        policy = {"notes_sha256": hashlib.sha256(notes.encode()).hexdigest(), "make_latest": True}
        raw = presentation.intent(policy, fixture.expected, fixture.manifest, notes)
        self.assertIn(b"consumer-release-presentation", raw)
        for changed in (dict(policy, make_latest=1), dict(policy, notes_sha256="0" * 64),
                        dict(policy, extra=True)):
            with self.assertRaises(ValueError):
                presentation.intent(changed, fixture.expected, fixture.manifest, notes)
        self.assertNotEqual(raw, presentation.intent(policy, fixture.expected,
                                                    dict(fixture.manifest, **{"SHA256SUMS": "a" * 64}), notes))


class PresentationUpload(unittest.TestCase):
    def setUp(self):
        fixture = upload_fixtures.ConsumerUpload()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.expected, self.manifest = fixture.root, fixture.expected, fixture.manifest
        self.api = LatestAPI(self.expected)

    def publish(self, value=None):
        return consumer_upload.publish_release(self.api, "dobord/synthetic-consumer",
                                               self.root, self.expected, self.manifest,
                                               presentation=value)

    def test_existing_release_changes_only_notes_and_latest_then_is_noop(self):
        self.publish()
        assets, content, uploads = copy.deepcopy(self.api.assets), copy.deepcopy(self.api.content), self.api.uploads
        self.api.writes.clear()
        value = {"notes": "### Added\n\n- Synthetic feature.\n", "make_latest": True}
        self.publish(value)
        self.assertIn("Synthetic feature.", self.api.release["body"])
        self.assertIn("Consumer release approval SHA256:", self.api.release["body"])
        self.assertEqual(self.api.latest, 100)
        self.assertEqual((self.api.assets, self.api.content, self.api.uploads), (assets, content, uploads))
        self.assertEqual(len(self.api.writes), 1)
        self.assertEqual(set(self.api.writes[0][1]), {"body", "make_latest"})
        before = copy.deepcopy(self.api.writes)
        self.publish(value)
        self.assertEqual(self.api.writes, before)

    def test_foreign_body_or_asset_conflict_is_not_a_presentation_update(self):
        self.publish()
        self.api.release["body"] = "unapproved description"
        before = copy.deepcopy(self.api.writes)
        with self.assertRaises(ValueError):
            self.publish({"notes": "Approved synthetic notes", "make_latest": True})
        self.assertEqual(self.api.writes, before)


if __name__ == "__main__":
    unittest.main()
