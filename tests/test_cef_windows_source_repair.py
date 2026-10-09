"""Current V17 source-repair regressions over the preserved historical suite.

The implementation-heavy tests remain in cef_windows_source_repair_base so
profile migrations can update current expectations without rewriting their
independent legacy/runtime checks. This module is the unittest discovery entry.
"""
from __future__ import annotations

import copy
from pathlib import Path
from unittest import mock

from secure_release import cef_windows_source_repair as repair
from tests import cef_windows_source_repair_base as base
from tests.cef_windows_layout_inputs import fixture_bytes, public_input


class RepairTests(base.RepairTests):
    pass


class OrchestrationTests(base.OrchestrationTests):
    pass


class PaintHeaderTests(base.PaintHeaderTests):
    def test_profile_binds_both_headers_and_each_digest(self):
        expected_paths = [
            repair.HEADER,
            repair.PAINT_HEADER,
            repair.AUTOFILL_SOURCE,
            repair.ATOMIC_SOURCE,
            repair.HEAP_HEADER,
            repair.TORQUE_SOURCE,
            repair.TEMPLATE_HEADER,
            repair.BIND_HEADER,
            repair.ACCESSIBILITY_HEADER,
            repair.ACCESSIBILITY_SOURCE,
            repair.WTF_STRING_HEADER,
            repair.INLINE_HEADER,
            repair.DOM_HEADER,
            repair.INLINE_ITEMS_SOURCE,
            repair.API_KEY_HEADER,
            repair.CREDIT_CARD_HEADER,
            repair.FRAME_TREE_HEADER,
        ]
        profile = repair.profile()
        self.assertEqual(profile["schema"], 2)
        self.assertEqual(profile["id"], "windows-frame-tree-node-iterator-assignment-v17")
        self.assertEqual(
            [correction["path"] for correction in profile["corrections"]],
            [path.removeprefix("download/chromium/src/") for path in expected_paths],
        )
        for index in range(len(expected_paths)):
            for field in ("path", "before_sha256", "after_sha256"):
                altered = copy.deepcopy(profile)
                altered["corrections"][index][field] = "0" * len(
                    altered["corrections"][index][field]
                )
                with mock.patch.object(repair, "profile", return_value=altered):
                    self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)
        for corrections in (
            profile["corrections"][:1],
            list(reversed(profile["corrections"])),
        ):
            with mock.patch.object(
                repair, "profile", return_value=dict(profile, corrections=corrections)
            ):
                self.assertNotEqual(repair.build_key(repair.BASE_KEY), self.key)

    def test_resume_verifies_both_headers_not_just_marker(self):
        self.apply()
        sources = (
            (repair.HEADER, base.FIXTURE),
            (repair.PAINT_HEADER, base.PAINT_FIXTURE),
            (repair.AUTOFILL_SOURCE, base.AUTOFILL_FIXTURE),
            (repair.ATOMIC_SOURCE, base.ATOMIC_FIXTURE),
            (repair.HEAP_HEADER, base.HEAP_FIXTURE),
            (repair.TORQUE_SOURCE, Path("implementation-visitor.cc")),
            (repair.TEMPLATE_HEADER, Path("v8-template.h")),
            (repair.BIND_HEADER, Path("bind-internal.h")),
            (repair.ACCESSIBILITY_HEADER, Path("browser_accessibility.h")),
            (repair.ACCESSIBILITY_SOURCE, Path("browser_accessibility.cc")),
            (repair.WTF_STRING_HEADER, Path("wtf_string.h")),
            (repair.INLINE_HEADER, Path("inline_node.h")),
            (repair.DOM_HEADER, Path("dom_builder.h")),
            (repair.INLINE_ITEMS_SOURCE, Path("inline_items_data.cc")),
            (repair.API_KEY_HEADER, Path("api_key_request_util.h")),
            (repair.CREDIT_CARD_HEADER, Path("credit_card_number_validation.h")),
            (repair.FRAME_TREE_HEADER, Path("frame_tree.h")),
        )
        for relative, fixture in sources:
            path = self.work / relative
            fixed = path.read_bytes()
            path.write_bytes(
                public_input("include/v8-template.h")
                if relative == repair.TEMPLATE_HEADER
                else fixture_bytes(fixture.name)
            )
            with self.assertRaises(ValueError):
                self.apply("resume")
            path.write_bytes(fixed)
        self.assertEqual(self.apply("resume"), "already-applied")


def load_tests(loader, standard_tests, pattern):
    return base.load_tests(loader, standard_tests, pattern)


if __name__ == "__main__":
    import unittest

    unittest.main()
