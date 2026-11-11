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

"""GitHub-safe commit status descriptions.

A scan failed, and its 'error' gate was rejected with 422 "Description doesn't accept
4-byte Unicode": the description quoted cm's log line, emoji included. The gate stayed 'pending'.
"""

import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import github_helpers  # noqa: E402
from gate_policy import decide_gate  # noqa: E402

# A scan error shaped like a real one: cm's log lines with 🔧, ✅ and 📤.
PR67_ERROR = (
    "Triage failed for vulnerable_app.py: cm find failed: CodeMender command failed: "
    "2026-11-05T14:37:57Z [INFO]  🔧 [Step 1] grep_search → pattern=\"import\" path=…/vulnerable_app.py\n"
    "2026-11-05T14:37:57Z [INFO]     ✅ Tool completed: grep_search (took 1ms)\n"
    "2026-11-05T14:37:58Z [INFO]     📤 Result submitted (submit 814ms)"
)


def _has_4_byte_chars(text):
    return any(ord(ch) > 0xFFFF for ch in text)


class StatusDescriptionTest(unittest.TestCase):
    def test_pr67_error_description_becomes_acceptable(self):
        state, desc = decide_gate([], error=PR67_ERROR)
        self.assertEqual(state, "error")
        self.assertTrue(_has_4_byte_chars(desc), "the description GitHub rejected")
        clean = github_helpers.status_description(desc)
        self.assertFalse(_has_4_byte_chars(clean))
        self.assertLessEqual(len(clean), 140)
        self.assertTrue(clean.startswith("CodeMender scan failed: Triage failed for vulnerable_app.py"))

    def test_keeps_3_byte_symbols_and_collapses_whitespace(self):
        self.assertEqual(github_helpers.status_description("✅  Passed →\n 0 … ⚠️ 🔴 CRITICAL"),
                         "✅ Passed → 0 … ⚠️ CRITICAL")

    def test_caps_at_140_characters(self):
        cut = github_helpers.status_description("x" * 200)
        self.assertEqual(len(cut), 140)
        self.assertTrue(cut.endswith("…"))
        self.assertEqual(github_helpers.status_description("Passed: 0 unresolved CRITICAL findings."),
                         "Passed: 0 unresolved CRITICAL findings.")
        self.assertEqual(github_helpers.status_description(None), "")


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code
        self.text = '{"message":"Validation Failed"}'


class _FakeClient:
    status_code = 201
    sent = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeClient.sent.append(json)
        return _FakeResponse(_FakeClient.status_code)


class SetCommitStatusTest(unittest.TestCase):
    def setUp(self):
        _FakeClient.sent = []
        _FakeClient.status_code = 201
        for p in (mock.patch.dict(os.environ, {"MOCK_MODE": "false"}),
                  mock.patch.object(github_helpers.httpx, "AsyncClient", _FakeClient)):
            p.start()
            self.addCleanup(p.stop)

    def _set(self, description):
        return asyncio.run(github_helpers.set_commit_status("o/r", "c" * 40, "error", description, "t"))

    def test_sends_a_github_safe_description_and_reports_acceptance(self):
        self.assertTrue(self._set(decide_gate([], error=PR67_ERROR)[1]))
        sent = _FakeClient.sent[0]["description"]
        self.assertFalse(_has_4_byte_chars(sent))
        self.assertLessEqual(len(sent), 140)

    def test_rejected_status_returns_false(self):
        _FakeClient.status_code = 422
        self.assertFalse(self._set("CodeMender scan failed"))

    def test_request_error_returns_false(self):
        async def boom(*_a, **_k):
            raise RuntimeError("network down")

        with mock.patch.object(_FakeClient, "post", boom):
            self.assertFalse(self._set("CodeMender scan failed"))

    def test_mock_mode_returns_true_without_calling_github(self):
        with mock.patch.dict(os.environ, {"MOCK_MODE": "true"}):
            self.assertTrue(self._set("CodeMender scan failed"))
        self.assertEqual(_FakeClient.sent, [])


if __name__ == "__main__":
    unittest.main()
