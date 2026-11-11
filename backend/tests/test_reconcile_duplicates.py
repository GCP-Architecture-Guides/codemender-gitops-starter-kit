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

"""Tests for agents.reconcile_pr_findings_delta: duplicate fingerprints and dismissal carry-over.

Regression: findings that shared a fingerprint collapsed into one, hiding a CRITICAL from the
report, the gate and `/fix critical`. Dismissals deliberately carry over on an exact fingerprint
match only, so a new finding of the same class never inherits someone else's risk acceptance.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_severity_policy import agents  # noqa: E402  (imports agents with stubs)

HEAD = "c" * 40


def reconcile(current, previous=None):
    return agents.reconcile_pr_findings_delta(
        repo_name="o/r", pr_number=1, current_findings=current,
        previous_pr_state={"findings": previous} if previous else {}, current_commit_sha=HEAD)


class ReconcileDuplicatesTest(unittest.TestCase):

    def test_findings_sharing_a_fingerprint_both_stay(self):
        combined, summary, events = reconcile([
            {"id": "aaaa1111", "fingerprint": "fp1", "severity": "CRITICAL", "vuln_type": "CWE-89"},
            {"id": "bbbb2222", "fingerprint": "fp1", "severity": "CRITICAL", "vuln_type": "CWE-89"},
        ])
        self.assertEqual(sorted(f["id"] for f in combined), ["aaaa1111", "bbbb2222"])
        self.assertEqual(summary["new_count"], 2)
        self.assertEqual(summary["total_active"], 2)
        self.assertEqual(len(events), 2)

    def test_exact_match_carries_a_dismissal(self):
        combined, summary, _ = reconcile(
            [{"id": "new00001", "fingerprint": "fp1", "severity": "CRITICAL"}],
            [{"id": "old00001", "fingerprint": "fp1", "status": "DISMISSED", "dismissal": {"category": "FALSE_POSITIVE"}}])
        self.assertEqual(combined[0]["status"], "DISMISSED")
        self.assertEqual(combined[0]["dismissal_category"], "FALSE_POSITIVE")
        self.assertEqual(summary["dismissed_count"], 1)

    def test_a_different_fingerprint_does_not_inherit_a_dismissal(self):
        combined, summary, _ = reconcile(
            [{"id": "new00001", "fingerprint": "fp2", "severity": "CRITICAL"}],
            [{"id": "old00001", "fingerprint": "fp1", "status": "DISMISSED"}])
        new = next(f for f in combined if f["id"] == "new00001")
        self.assertEqual(new["lifecycle_status"], "NEW")
        self.assertNotEqual(new.get("status"), "DISMISSED")
        self.assertEqual(summary["resolved_count"], 1)


if __name__ == "__main__":
    unittest.main()
