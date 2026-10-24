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
"""Plan 3.1 (file cap), 3.8 (patch proposals), 3.10 (redacted comments), 3.12 (comment pagination)."""
import asyncio
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
import github_helpers  # noqa: E402
from gate_policy import decide_gate  # noqa: E402
from request_guards import dismissal_gate_decision  # noqa: E402
from tests import test_status_semantics as status_tests  # noqa: E402

FAKE_TOKEN = "ghp_" + "F4k3F4k3F4" * 3 + "abcdef"
DATABASE = main.update_scan_status.__globals__


class PartialScanGateTest(unittest.TestCase):
    def test_unscanned_files_block_an_otherwise_clean_gate(self):
        self.assertEqual(decide_gate([], unscanned_count=0)[0], "success")
        state, description = decide_gate([], unscanned_count=3)
        self.assertEqual(state, "failure")
        self.assertIn("3 changed file(s) not scanned", description)
        self.assertLessEqual(len(description), 140)

    def test_criticals_and_errors_still_take_priority(self):
        critical = [{"severity": "CRITICAL", "status": "DETECTED"}]
        self.assertIn("CRITICAL", decide_gate(critical, unscanned_count=2)[1])
        self.assertEqual(decide_gate([], error="boom", unscanned_count=2)[0], "error")

    def test_a_dismissal_cannot_turn_a_partial_scan_green(self):
        dismissed = [{"severity": "CRITICAL", "status": "DISMISSED"}]
        self.assertEqual(dismissal_gate_decision("COMPLETED", dismissed)[0], "success")
        self.assertEqual(dismissal_gate_decision("COMPLETED", dismissed, unscanned_count=1)[0], "failure")


class ScanFileLimitTest(unittest.TestCase):
    def test_default_parse_and_clamp(self):
        for raw, expected in (("", 20), ("7", 7), ("0", 1), ("500", 100), ("abc", 20)):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"CM_MAX_SCAN_FILES": raw}):
                self.assertEqual(main.scan_file_limit(), expected)


class FileCapScanTest(status_tests.ScanWorkerHarness):
    def test_files_over_the_limit_are_reported_and_block_the_gate(self):
        for name in ("a.py", "b.py", "c.py"):
            Path(self.workspace, name).write_text("x = 1\n")
        self.changed_files = ["a.py", "b.py", "c.py"]
        self.findings = []
        with mock.patch.dict(os.environ, {"CM_MAX_SCAN_FILES": "2"}):
            self._run(draft=True)
        scanned = [c.kwargs["filepath"] for c in main.run_triage_agent.call_args_list]
        self.assertEqual(scanned, ["a.py", "b.py"])
        final = [k for _, k in self.updates.calls if k.get("status") == "COMPLETED"][-1]
        self.assertEqual((final["scan_complete"], final["unscanned_files"]), (False, ["c.py"]))
        self.assertEqual(self._gate()["state"], "failure")
        self.assertIn("Partial scan", self.comments.call_args.args[2])
        self.promote.assert_not_called()


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code, self._payload, self.text = status_code, payload, ""

    def json(self):
        return self._payload


class _FakeClient:
    sent = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeClient.sent.append(("POST", url, json))
        return _FakeResponse(201, {"id": 99})

    async def patch(self, url, json=None, headers=None):
        _FakeClient.sent.append(("PATCH", url, json))
        return _FakeResponse(200, {})


class CommentHelpersTest(unittest.TestCase):
    def setUp(self):
        _FakeClient.sent = []
        for p in (mock.patch.dict(os.environ, {"MOCK_MODE": "false"}),
                  mock.patch.object(github_helpers.httpx, "AsyncClient", _FakeClient)):
            p.start()
            self.addCleanup(p.stop)

    def test_every_comment_body_is_redacted(self):
        asyncio.run(github_helpers.post_pr_comment("o/r", 7, f"error: token {FAKE_TOKEN}", "t"))
        asyncio.run(github_helpers.post_commit_comment("o/r", "c" * 40, f"error: {FAKE_TOKEN}", "t"))
        bodies = [payload["body"] for _, _, payload in _FakeClient.sent]
        self.assertTrue(bodies and all(FAKE_TOKEN not in b for b in bodies), bodies)

    def test_report_found_on_a_later_page_is_edited_in_place(self):
        async def found(*_a, **_k):
            return 1234

        with mock.patch.object(github_helpers, "_find_comment_with_marker", found):
            asyncio.run(github_helpers.update_or_post_pr_comment("o/r", 7, "report body", "t"))
        method, url, payload = _FakeClient.sent[-1]
        self.assertEqual((method, url.endswith("/issues/comments/1234")), ("PATCH", True))
        self.assertEqual(payload["body"].count("<!-- codemender-security-report -->"), 1)

    def test_missing_report_is_posted_once_with_a_single_tag(self):
        async def none(*_a, **_k):
            return None

        tagged = "<!-- codemender-security-report -->\nreport"
        with mock.patch.object(github_helpers, "_find_comment_with_marker", none):
            asyncio.run(github_helpers.update_or_post_pr_comment("o/r", 7, tagged, "t"))
        method, _, payload = _FakeClient.sent[-1]
        self.assertEqual(method, "POST")
        self.assertEqual(payload["body"].count("<!-- codemender-security-report -->"), 1)


class PatchProposalRecordTest(unittest.TestCase):
    def test_original_pr_patch_pr_and_all_files_are_kept(self):
        stored = {}

        class _Doc:
            def set(self, data, merge=False):
                stored.update(data)

        fake_db = types.SimpleNamespace(collection=lambda _n: types.SimpleNamespace(document=lambda _k: _Doc()))
        with mock.patch.dict(DATABASE, {"db": fake_db}):
            DATABASE["save_patch_proposal"]("a" * 40, "feature", "a.py", "diff", "code", pr_number=7,
                                            patch_commit_sha="p" * 40, patch_pr_number=12, changed_files=["a.py", "b.py"])
        self.assertEqual((stored["pr_number"], stored["patch_pr_number"], stored["changed_files"]), (7, 12, ["a.py", "b.py"]))


if __name__ == "__main__":
    unittest.main()
