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

"""Tests for command_parse: comment routing, finding targets and dismissal parsing.

Regressions covered:
- `/verify 1` and `/fix 1` (the DEMO_GUIDE examples) and words such as "add" prefix-matched
  fingerprints, so arbitrary findings were verified or patched.
- Routing was case-sensitive after a case-insensitive authorization and once-only claim, so
  `/Approve` or `/approve LGTM` were dropped silently; `/fixed` ran `/fix all`.
- `/dismiss [CAT] reason` without an ID dismissed every finding; `/override-gate <reason>` took
  the reason's first word as a finding ID; `/dismissed ...` could dismiss everything.
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from command_parse import (  # noqa: E402
    APPROVE_USAGE, ID_HINT, no_match_message, parse_dismiss, route_comment, select_findings, split_command,
)

FINDINGS = [
    {"id": "a387f7c8", "fingerprint": "1f2e3d4c5b6a7980", "display_id": "1f2e3d", "severity": "CRITICAL"},
    {"id": "6b1d4385", "fingerprint": "abcdef0123456789", "display_id": "abcdef", "severity": "HIGH"},
    {"id": "430d3588", "fingerprint": "add0beef00112233", "display_id": "add0be", "severity": "🔴 CRITICAL",
     "status": "DISMISSED"},
    {"id": "99999999", "fingerprint": "1234567890abcdef", "severity": "LOW", "lifecycle_status": "RESOLVED"},
]


def ids(selected):
    return [f["id"] for f in selected]


class SplitCommandTest(unittest.TestCase):

    def test_first_line_and_case(self):
        self.assertEqual(split_command("/Fix critical, high\nthanks for the review"), ("fix", ["critical", "high"]))
        self.assertEqual(split_command("  /VERIFY   a387f7c8.  "), ("verify", ["a387f7c8"]))

    def test_ordinary_comments(self):
        for body in ("", None, "looks good to me", "LGTM /approve"):
            with self.subTest(body=body):
                self.assertEqual(split_command(body), (None, []))


class RouteCommentTest(unittest.TestCase):

    def test_approve(self):
        for body in ("/approve", "/Approve", "/APPROVE all", "approve", "approve all", "/approve\nthanks!"):
            with self.subTest(body=body):
                self.assertEqual(route_comment(body), ("approve", [], None))

    def test_approve_with_arguments_gets_usage_not_silence(self):
        self.assertEqual(route_comment("/approve LGTM"), (None, [], APPROVE_USAGE))
        self.assertEqual(route_comment("approve after CI is green"), (None, [], None))

    def test_verify_and_fix(self):
        cases = {
            "/verify": ("verify", ["all"], None),
            "/verify-all": ("verify", ["all"], None),
            "/Verify Critical": ("verify", ["critical"], None),
            "/verify a387f7c8\nis this real?": ("verify", ["a387f7c8"], None),
            "/fix critical": ("fix", ["critical"], None),
            "/Fix CRITICAL, high": ("fix", ["critical", "high"], None),
            "/remediate-all": ("fix", ["all"], None),
            "fix all": ("fix", ["all"], None),
            "fix a387f7c8": ("fix", ["a387f7c8"], None),
            "verify": ("verify", ["all"], None),
        }
        for body, expected in cases.items():
            with self.subTest(body=body):
                self.assertEqual(route_comment(body), expected)

    def test_near_misses_and_sentences_are_not_commands(self):
        for body in ("/fixed", "/verified", "fix the typo please", "verify this later", "/cancelled",
                     "/pr looks good", "/cc @someone", "thanks!"):
            with self.subTest(body=body):
                self.assertEqual(route_comment(body), (None, [], None))

    def test_dismiss_cancel_draft(self):
        for body in ("/dismiss a387f7c8 [FALSE_POSITIVE] verified unreachable", "/Dismiss x", "/override-gate why",
                     "/dismissed oops"):
            with self.subTest(body=body):
                self.assertEqual(route_comment(body)[0], "dismiss")
        self.assertEqual(route_comment("/cancel")[0], "cancel")
        self.assertEqual(route_comment("/Reset now")[0], "cancel")
        self.assertEqual(route_comment("/draft")[0], "draft")
        self.assertEqual(route_comment("/PR")[0], "draft")
        self.assertIsNone(route_comment("dismiss a387f7c8")[0])


class SelectFindingsTest(unittest.TestCase):

    def test_short_or_word_tokens_never_prefix_match(self):
        for token in ("1", "12", "add", "a", "face", "1f2e3"):
            with self.subTest(token=token):
                self.assertEqual(select_findings(FINDINGS, [token]), ([], [token]))

    def test_exact_ids_case_insensitive(self):
        self.assertEqual(ids(select_findings(FINDINGS, ["a387f7c8"])[0]), ["a387f7c8"])
        self.assertEqual(ids(select_findings(FINDINGS, ["A387F7C8"])[0]), ["a387f7c8"])
        self.assertEqual(ids(select_findings(FINDINGS, ["1f2e3d"])[0]), ["a387f7c8"])            # display_id
        self.assertEqual(ids(select_findings(FINDINGS, ["1F2E3D4C"])[0]), ["a387f7c8"])          # fingerprint prefix
        self.assertEqual(ids(select_findings(FINDINGS, ["1f2e3d4c5b6a7980"])[0]), ["a387f7c8"])  # full fingerprint

    def test_keywords_select_open_findings_and_combine(self):
        self.assertEqual(ids(select_findings(FINDINGS, ["critical"])[0]), ["a387f7c8"])
        self.assertEqual(ids(select_findings(FINDINGS, ["critical", "high"])[0]), ["a387f7c8", "6b1d4385"])
        self.assertEqual(ids(select_findings(FINDINGS, ["all"])[0]), ["a387f7c8", "6b1d4385"])
        self.assertEqual(ids(select_findings(FINDINGS, ["*"])[0]), ["a387f7c8", "6b1d4385"])

    def test_unknown_tokens_are_reported_and_known_ones_still_run(self):
        selected, unmatched = select_findings(FINDINGS, ["a387f7c8", "is", "this", "real?"])
        self.assertEqual(ids(selected), ["a387f7c8"])
        self.assertEqual(unmatched, ["is", "this", "real?"])

    def test_explicit_id_still_names_a_dismissed_finding(self):
        self.assertEqual(ids(select_findings(FINDINGS, ["430d3588"])[0]), ["430d3588"])

    def test_empty(self):
        self.assertEqual(select_findings(FINDINGS, []), ([], []))
        self.assertEqual(select_findings([], ["all"]), ([], []))
        self.assertEqual(select_findings(None, None), ([], []))

    def test_no_match_message(self):
        message = no_match_message("fix", ["1"], ["1"])
        self.assertIn("`1`", message)
        self.assertIn(ID_HINT, message)
        self.assertIn("to fix", message)


class ParseDismissTest(unittest.TestCase):

    def test_item_dismissal(self):
        self.assertEqual(
            parse_dismiss("/dismiss a387f7c8 [COMPENSATING_CONTROL] Mitigated by Cloud Armor WAF"),
            {"gate": False, "target_id": "a387f7c8", "category": "COMPENSATING_CONTROL",
             "reason": "Mitigated by Cloud Armor WAF"})
        self.assertEqual(parse_dismiss("/dismiss f1 [FALSE_POSITIVE] verified unreachable")["target_id"], "f1")
        self.assertEqual(parse_dismiss("/Dismiss a387f7c8 reason without a category"),
                         {"gate": False, "target_id": "a387f7c8", "category": None,
                          "reason": "reason without a category"})

    def test_missing_id_is_flagged_not_turned_into_all(self):
        parsed = parse_dismiss("/dismiss [FALSE_POSITIVE] forgot the finding id")
        self.assertEqual(parsed["target_id"], None)
        self.assertFalse(parsed["gate"])

    def test_gate_override(self):
        self.assertEqual(parse_dismiss("/override-gate Mitigated upstream by the WAF"),
                         {"gate": True, "target_id": "all", "category": None, "reason": "Mitigated upstream by the WAF"})
        self.assertEqual(parse_dismiss("/override-gate [BUSINESS_ACCEPTED_RISK] accepted for this release")["category"],
                         "BUSINESS_ACCEPTED_RISK")
        self.assertTrue(parse_dismiss("/dismiss gate [FALSE_POSITIVE] demo environment only")["gate"])
        self.assertTrue(parse_dismiss("/dismiss-gate accepted for the demo")["gate"])

    def test_invalid_forms(self):
        for body in ("/dismissed everything now please", "/overrides x", "dismiss a387f7c8 reason", ""):
            with self.subTest(body=body):
                self.assertIsNone(parse_dismiss(body))

    def test_reason_is_first_line_only(self):
        parsed = parse_dismiss("/dismiss a387f7c8 [FALSE_POSITIVE] first line reason\nsecond line")
        self.assertEqual(parsed["reason"], "first line reason")


class MainWiringTest(unittest.TestCase):

    def setUp(self):
        self.source = Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8")

    def test_routers_and_dismissal_use_command_parse(self):
        self.assertIn("route_comment(clean_body)", self.source)
        self.assertIn("route_comment(comment_body)", self.source)
        self.assertIn("parse_dismiss(comment_body)", self.source)
        self.assertIn("async def reply_command_usage(", self.source)
        self.assertNotIn('clean_body.startswith("/verify")', self.source)
        self.assertNotIn('comment_body.startswith("/fix")', self.source)
        self.assertNotIn('target_id = "all"\n', self.source.split("async def process_dismiss_command_task")[1].split("\nasync def ")[0])


if __name__ == "__main__":
    unittest.main()
