"""The internal model must never acquire an endurance qualification label."""
import unittest
from secure_release import docker_endurance as subject


class RdpdrFoundationProfile(unittest.TestCase):
    def payload(self):
        return {"schema": 1, "purpose": "docker-endurance", "builder_code_sha": "a" * 40,
                "source": "dobord/frdpd", "source_id": 1, "source_base_sha": "b" * 40,
                "source_digest": "c" * 64, "recipe": "server/frdp/test/e2e/run-rdpdr-irp-ci.py",
                "mode": "rdpdr-foundation", "duration_seconds": 0, "cycles": 1,
                "created": 100, "expires": 200}

    def test_foundation_admission(self):
        subject.validate(self.payload(), "a" * 40, now=150)

    def test_profile_substitution_rejected(self):
        for field, value in [("mode", "qualification"), ("cycles", 100),
                             ("duration_seconds", 18000), ("recipe", "another.py")]:
            with self.subTest(field=field):
                payload = self.payload()
                payload[field] = value
                with self.assertRaises(ValueError):
                    subject.validate(payload, "a" * 40, now=150)


if __name__ == "__main__":
    unittest.main()
