"""Current V17 profile expectations over the preserved callable regression suite."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from unittest import mock

from secure_release import cef_windows_iteration as worker
from secure_release import cef_windows_source_repair as repair
from tests import cef_windows_callable_repair_base as base


class CallableRepairTests(base.CallableRepairTests):
    def test_exact_profile_and_current_repository_lock(self):
        profile = repair.profile()
        self.assertEqual(
            profile["id"],
            "windows-frame-tree-node-iterator-assignment-v17",
        )
        self.assertEqual(len(profile["corrections"]), 17)
        self.assertEqual(worker.qualification_lock(base.ROOT)["source_repair"], profile)
        self.assertEqual(
            profile["implementation_sha256"],
            hashlib.sha256(Path(repair.__file__).read_bytes()).hexdigest(),
        )
        for stale in (
            base.V8_KEY,
            "45d4c9074ab014a263f4c81a1a8e929951adaba4cc1b8c5232bccc13e72e5920",
        ):
            with self.assertRaises(ValueError):
                repair.restore_contract(
                    dict(repair.LEGACY, build_key=stale), repair.BASE_KEY
                )
        with self.assertRaises(ValueError):
            repair.restore_contract(
                dict(repair.LEGACY, run=37191476160), repair.BASE_KEY
            )
        self.assertEqual(
            repair.restore_contract(repair.LEGACY, repair.BASE_KEY),
            (repair.BASE_KEY, "legacy"),
        )
        for index in range(16):
            for field in ("path", "before_sha256", "after_sha256"):
                altered = copy.deepcopy(profile)
                altered["corrections"][index][field] = "0" * len(
                    altered["corrections"][index][field]
                )
                with mock.patch.object(repair, "profile", return_value=altered):
                    self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)


if __name__ == "__main__":
    import unittest

    unittest.main()
