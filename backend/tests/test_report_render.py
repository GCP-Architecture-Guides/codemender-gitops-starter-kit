# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the pinned report's findings table (report_render).

Regression: RESOLVED rows were read from a summary key that reconcile never produces, so after
/approve the report said "N Resolved" but listed none (an empty table plus action prompts), and
DISMISSED findings were labelled PERSISTENT with a red severity.
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report_render import lifecycle_of, normalize_severity, render_findings_table  # noqa: E402

PATH = "vulnerable_app.py"


def finding(fid, severity, lifecycle, **extra):
    base = {"id": fid, "severity": severity, "vuln_type": "CWE-89", "description": f"desc {fid}",
            "filepath": PATH, "lifecycle_status": lifecycle}
    base.update(extra)
    return base


class RenderFindingsTableTest(unittest.TestCase):

    def test_nothing_to_list(self):
        self.assertEqual(render_findings_table([], PATH), ("", 0))
        self.assertEqual(render_findings_table(None, PATH), ("", 0))
        self.assertEqual(render_findings_table(["junk", 3], PATH), ("", 0))

    def test_all_resolved_after_approve_lists_them_and_nothing_is_open(self):
        rows = [finding("a387f7c8", "CRITICAL", "RESOLVED", status="RESOLVED"),
                finding("430d3588", "🔴 CRITICAL", "RESOLVED", status="RESOLVED")]
        table, open_count = render_findings_table(rows, PATH)
        self.assertEqual(open_count, 0)
        self.assertEqual(table.count("| ✅ **RESOLVED** |"), 2)
        self.assertIn("`a387f7c8`", table)
        self.assertIn("~~CRITICAL~~", table)
        self.assertIn("`vulnerable_app.py` (Fixed)", table)
        self.assertTrue(table.startswith("| Status | ID | Severity | Type | Location | Description |\n"))

    def test_mixed_order_and_tags(self):
        rows = [
            finding("dis00001", "CRITICAL", "DISMISSED", status="DISMISSED", dismissal_category="COMPENSATING_CONTROL"),
            finding("new00001", "HIGH", "NEW"),
            finding("res00001", "CRITICAL", "RESOLVED"),
            finding("per00001", "CRITICAL", "PERSISTENT"),
        ]
        table, open_count = render_findings_table(rows, PATH)
        self.assertEqual(open_count, 2)
        body = table.splitlines()[2:]
        self.assertEqual([line.split("`")[1] for line in body], ["res00001", "new00001", "per00001", "dis00001"])
        self.assertIn("| 🆕 **NEW** | `new00001` | 🟠 **HIGH** |", table)
        self.assertIn("| ⚠️ **PERSISTENT** | `per00001` | 🔴 **CRITICAL** |", table)
        dismissed = body[3]
        self.assertTrue(dismissed.startswith("| 🟡 **DISMISSED** | `dis00001` | ⚪ CRITICAL |"))
        self.assertIn("*(risk accepted: COMPENSATING_CONTROL)*", dismissed)
        self.assertNotIn("PERSISTENT", dismissed)
        self.assertNotIn("🔴", dismissed)

    def test_dismissal_recorded_on_status_and_dict(self):
        row = finding("dis00002", "CRITICAL", "PERSISTENT", status="DISMISSED", dismissal={"category": "FALSE_POSITIVE"})
        table, open_count = render_findings_table([row], PATH)
        self.assertEqual(open_count, 0)
        self.assertIn("🟡 **DISMISSED**", table)
        self.assertIn("(risk accepted: FALSE_POSITIVE)", table)

    def test_missing_lifecycle_keeps_the_persistent_label(self):
        row = {"id": "old00001", "severity": "MEDIUM", "vuln_type": "CWE-79", "description": "d"}
        table, open_count = render_findings_table([row], PATH)
        self.assertEqual(open_count, 1)
        self.assertIn("| ⚠️ **PERSISTENT** | `old00001` | 🟡 **MEDIUM** |", table)
        self.assertIn("`vulnerable_app.py`", table)

    def test_line_numbers_and_shift(self):
        row = finding("mov00001", "HIGH", "PERSISTENT", line_number=12, previous_line_number=10)
        table, _ = render_findings_table([row], PATH)
        self.assertIn("`vulnerable_app.py`:12 *(was :10)*", table)


class HelpersTest(unittest.TestCase):

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity("🔴 CRITICAL"), "CRITICAL")
        self.assertEqual(normalize_severity("medium"), "MEDIUM")
        self.assertEqual(normalize_severity(None), "HIGH")
        self.assertEqual(normalize_severity("unknown"), "HIGH")

    def test_lifecycle_of(self):
        self.assertEqual(lifecycle_of({"status": "RESOLVED"}), "RESOLVED")
        self.assertEqual(lifecycle_of({"lifecycle_status": "DISMISSED"}), "DISMISSED")
        self.assertEqual(lifecycle_of({"lifecycle_status": "NEW"}), "NEW")
        self.assertEqual(lifecycle_of({}), "PERSISTENT")


class MainUsesRendererTest(unittest.TestCase):
    """The scan worker renders the table through report_render and only prompts while findings are open."""

    def setUp(self):
        self.source = Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8")

    def test_wiring(self):
        self.assertIn("render_findings_table(reconciled_findings, target_file_str)", self.source)
        self.assertNotIn('summary_delta.get("resolved_findings")', self.source)
        self.assertIn("if open_count:", self.source)
        self.assertIn("No open vulnerabilities remain", self.source)


if __name__ == "__main__":
    unittest.main()
