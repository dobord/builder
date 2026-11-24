import copy
import unittest

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
