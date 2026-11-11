# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# you may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gate_policy import (  # noqa: E402
    DEFERRED_SCAN_STATUS,
    DUPLICATE_SCAN_WINDOW_SECONDS,
    MAX_DESCRIPTION_CHARS,
    decide_gate,
    should_skip_duplicate_scan,
    unresolved_criticals,
)


def _finding(severity="CRITICAL", status="DETECTED", lifecycle="NEW"):
    return {"id": "abc123", "severity": severity, "status": status, "lifecycle_status": lifecycle}


class DecideGateTest(unittest.TestCase):

    def test_error_is_never_success(self):
        state, desc = decide_gate([], error="cm find exited 1")
        self.assertEqual(state, "error")
        self.assertIn("cm find exited 1", desc)

    def test_error_wins_over_clean_findings(self):
        state, _ = decide_gate([_finding(severity="LOW")], error="scanner crashed")
        self.assertEqual(state, "error")

    def test_error_description_is_single_line_and_bounded(self):
        _, desc = decide_gate([], error="line one\nline two " + "x" * 500)
        self.assertNotIn("\n", desc)
        self.assertLessEqual(len(desc), MAX_DESCRIPTION_CHARS)

    def test_unresolved_critical_blocks(self):
        for status in ("DETECTED", "VERIFIED", "VERIFICATION_FAILED", "PATCHED", "PATCHING", ""):
            with self.subTest(status=status):
                state, desc = decide_gate([_finding(status=status)])
                self.assertEqual(state, "failure")
                self.assertIn("1 unresolved CRITICAL", desc)

    def test_resolved_or_dismissed_critical_passes(self):
        cases = [
            _finding(status="RESOLVED", lifecycle="RESOLVED"),
            _finding(status="DISMISSED"),
            _finding(status="DETECTED", lifecycle="DISMISSED"),
            _finding(status="dismissed"),
        ]
        for finding in cases:
            with self.subTest(finding=finding):
                self.assertEqual(decide_gate([finding])[0], "success")

    def test_non_critical_findings_pass(self):
        findings = [_finding(severity="HIGH"), _finding(severity="MEDIUM"), _finding(severity="LOW")]
        self.assertEqual(decide_gate(findings)[0], "success")

    def test_emoji_severity_counts_as_critical(self):
        self.assertEqual(decide_gate([_finding(severity="🔴 critical")])[0], "failure")

    def test_counts_only_blocking_findings(self):
        findings = [_finding(), _finding(status="DISMISSED"), _finding(), _finding(severity="HIGH")]
        self.assertEqual(len(unresolved_criticals(findings)), 2)
        self.assertIn("2 unresolved CRITICAL", decide_gate(findings)[1])

    def test_empty_or_missing_findings_pass(self):
        self.assertEqual(decide_gate([])[0], "success")
        self.assertEqual(decide_gate(None)[0], "success")

    def test_ignores_malformed_entries(self):
        self.assertEqual(decide_gate(["not-a-dict", None])[0], "success")


class DuplicateScanTest(unittest.TestCase):
    NOW = 1_700_000_000.0

    def test_recent_in_flight_scan_is_skipped(self):
        for status in ("QUEUED", "CLONING", "RUNNING", "running"):
            with self.subTest(status=status):
                self.assertTrue(should_skip_duplicate_scan(status, self.NOW - 60, self.NOW))

    def test_stale_in_flight_scan_is_not_skipped(self):
        stale = self.NOW - DUPLICATE_SCAN_WINDOW_SECONDS - 1
        self.assertFalse(should_skip_duplicate_scan("RUNNING", stale, self.NOW))

    def test_finished_scans_are_not_skipped(self):
        for status in ("COMPLETED", "FAILED", None, ""):
            with self.subTest(status=status):
                self.assertFalse(should_skip_duplicate_scan(status, self.NOW, self.NOW))

    def test_deferred_scan_is_not_in_flight(self):
        self.assertFalse(should_skip_duplicate_scan(DEFERRED_SCAN_STATUS, self.NOW, self.NOW))

    def test_missing_timestamp_is_not_skipped(self):
        self.assertFalse(should_skip_duplicate_scan("QUEUED", None, self.NOW))
        self.assertFalse(should_skip_duplicate_scan("QUEUED", "not-a-number", self.NOW))


if __name__ == "__main__":
    unittest.main()
