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

"""Tests for agents.normalize_finding_severity (GEMINI.md "Canonical CWE Severity Anchoring").

The policy must win over the LLM's raw severity for every class it lists, whether cm reports the
class as a short CWE ('CWE-79', live output) or a long CWE name, and secrets are MEDIUM.
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _import_agents():
    database = sys.modules.get("database") or types.ModuleType("database")
    sys.modules.setdefault("database", database)
    for name in ("update_scan_status", "log_token_usage", "get_scan_repo_name", "append_scan_step",
                 "save_patch_proposal"):
        if not hasattr(database, name):
            setattr(database, name, lambda *args, **kwargs: None)
    saved = sys.modules.get("github_helpers")
    stub = types.ModuleType("github_helpers")

    async def _no_github(*_args, **_kwargs):
        raise AssertionError("GitHub must not be called from unit tests")

    stub.post_pr_comment = stub.get_github_token = stub.update_or_post_pr_comment = _no_github
    sys.modules["github_helpers"] = stub
    try:
        import agents
    finally:
        if saved is None:
            sys.modules.pop("github_helpers", None)
        else:
            sys.modules["github_helpers"] = saved
    return agents


agents = _import_agents()
severity = agents.normalize_finding_severity


class SeverityPolicyTest(unittest.TestCase):

    def test_live_short_cwe_types_follow_the_policy_not_the_llm(self):
        cases = [
            ("CWE-89", "🔴 CRITICAL", "CRITICAL"),
            ("CWE-78", "🟠 HIGH", "CRITICAL"),
            ("CWE-1336", "🟠 HIGH", "CRITICAL"),   # template injection
            ("CWE-79", "🟡 MEDIUM", "HIGH"),       # cm has reported XSS as MEDIUM
            ("CWE-602", "🟡 MEDIUM", "HIGH"),      # client-side price trust
            ("CWE-915", "🟡 MEDIUM", "HIGH"),      # mass assignment
            ("CWE-639", "🔴 CRITICAL", "HIGH"),    # IDOR
            ("CWE-798", "🟠 HIGH", "MEDIUM"),      # secrets (GEMINI.md)
        ]
        for vuln_type, raw, expected in cases:
            with self.subTest(vuln_type=vuln_type, raw=raw):
                self.assertEqual(severity(vuln_type=vuln_type, raw_severity=raw), expected)

    def test_long_cwe_names_and_synonyms(self):
        self.assertEqual(severity(vuln_type="IMPROPER NEUTRALIZATION OF SPECIAL ELEMENTS USED IN AN SQL COMMAND "
                                            "('SQL INJECTION')", raw_severity="🟠 HIGH"), "CRITICAL")
        self.assertEqual(severity(vuln_type="OS COMMAND INJECTION", raw_severity="🟡 MEDIUM"), "CRITICAL")
        self.assertEqual(severity(vuln_type="CROSS-SITE SCRIPTING", raw_severity="🟡 MEDIUM"), "HIGH")
        self.assertEqual(severity(cwe_id="CWE-89", vuln_type="whatever", raw_severity="LOW"), "CRITICAL")

    def test_known_cwe_outside_the_policy_keeps_the_raw_severity(self):
        self.assertEqual(severity(vuln_type="CWE-352", raw_severity="🟡 MEDIUM",
                                  title="CSRF that mentions SQL injection"), "MEDIUM")

    def test_title_is_used_only_when_no_cwe_is_named(self):
        self.assertEqual(severity(vuln_type="Business logic", raw_severity="🟡 MEDIUM",
                                  title="SQL Injection in /login"), "CRITICAL")
        self.assertEqual(severity(vuln_type="", raw_severity="LOW", title="nothing recognizable"), "LOW")

    def test_plain_labels_and_raw_fallback(self):
        self.assertEqual(severity(vuln_type="rce"), "CRITICAL")
        self.assertEqual(severity(vuln_type="hardcoded secret", raw_severity="CRITICAL"), "MEDIUM")
        self.assertEqual(severity(vuln_type="weird", raw_severity="🔵 LOW"), "LOW")
        self.assertEqual(severity(vuln_type="weird", raw_severity=""), "MEDIUM")


if __name__ == "__main__":
    unittest.main()


class ExploitReportPromptTest(unittest.TestCase):
    """A failed exploit attempt never gets a report claiming the issue is active."""

    def _instruction(self, **kwargs):
        import asyncio
        from unittest import mock
        captured = {}

        async def generate_content(model, contents, config):
            captured["instruction"] = config.system_instruction
            usage = types.SimpleNamespace(prompt_token_count=1, candidates_token_count=1,
                                          cached_content_token_count=0, thoughts_token_count=0)
            return types.SimpleNamespace(text="report", usage_metadata=usage)

        client = types.SimpleNamespace(aio=types.SimpleNamespace(models=types.SimpleNamespace(generate_content=generate_content)))
        with mock.patch.object(agents, "client", client), mock.patch.object(agents, "_log_exploit_report_usage", lambda *a, **k: None):
            asyncio.run(agents.generate_ai_exploit_report_async("trace", **kwargs))
        return captured["instruction"]

    def test_failed_attempt_uses_the_failure_prompt(self):
        self.assertEqual(self._instruction(verified=False), agents._EXPLOIT_REPORT_FAILED_INSTRUCTION)
        self.assertIn("Do not claim the vulnerability is active", agents._EXPLOIT_REPORT_FAILED_INSTRUCTION)

    def test_verified_attempt_keeps_the_poc_prompt(self):
        self.assertEqual(self._instruction(), agents._EXPLOIT_REPORT_SYSTEM_INSTRUCTION)
        self.assertEqual(self._instruction(verified=True), agents._EXPLOIT_REPORT_SYSTEM_INSTRUCTION)
