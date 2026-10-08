"""Current V16 profile expectations over the preserved Torque regression suite."""
from __future__ import annotations

from secure_release import cef_windows_source_repair as repair
from tests import cef_windows_tail_size_repair_base as base


class TorqueTailSizeTests(base.TorqueTailSizeTests):
    def test_exact_profile_keeps_source_set_and_rejects_v6(self):
        self.assertEqual(
            repair.profile()["id"],
            "windows-credit-card-number-string-include-v16",
        )
        self.assertEqual(len(repair.CORRECTIONS), 16)
        self.assertEqual(
            repair.profile()["v8_commit"],
            "4323497a6a73839e6d5260f6acd7ec0212cb3321",
        )
        self.assertNotEqual(repair.build_key(repair.BASE_KEY), base.V6_KEY)
        for selected in (
            dict(repair.LEGACY, build_key=base.V6_KEY),
            dict(repair.LEGACY, run=37144079381),
        ):
            with self.assertRaises(ValueError):
                repair.restore_contract(selected, repair.BASE_KEY)


if __name__ == "__main__":
    import unittest

    unittest.main()
