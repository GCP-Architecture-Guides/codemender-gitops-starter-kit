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

"""Stdlib-only tests for hotfix B: `cm find` exit codes, findings-table parsing, cm sandbox default.

No network and no real `cm` binary: a fake CLI script stands in for `cm find`.
"""

import asyncio
import glob
import json
import os
import re
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, BACKEND_DIR)


def _ensure_database_stub():
    """cm_tools imports Firestore/BigQuery helpers from `database`; stub them (no Google Cloud)."""
    module = sys.modules.get("database")
    if module is None:
        module = types.ModuleType("database")
        sys.modules["database"] = module
    for name in ("update_scan_status", "log_token_usage", "get_scan_repo_name", "append_scan_step"):
        if not hasattr(module, name):
            setattr(module, name, lambda *args, **kwargs: None)


_ensure_database_stub()
import cm_tools  # noqa: E402

# Obviously fake credential, built at runtime so no token-shaped literal sits in the source.
FAKE_TOKEN = "ghs_" + "CmF1ndCmF1" * 3

# Shapes of real cm 0.16.0 `cm find` output (2026-10-22), trimmed.
FINDINGS_STDOUT = (
    "🔍 Discovering files in /tmp/session-x/vulnerable_app.py...\n"
    "🎯 Scoping scan to 1 provided file(s) and their immediate dependency closure:\n"
    "     • vulnerable_app.py\n"
    "   Scoped target files: 1 (provided: 1, neighbors: 0)\n"
    "\n"
    "════════════════════════════════════════════════════════════\n"
    "🔍 Deep Scan: Concurrent File-by-File Vulnerability Audit...\n"
    "════════════════════════════════════════════════════════════\n"
    "[1/1 batches] 🚨 vulnerable_app.py (2m23.5s) | 181.3k tok - 3 vulnerabilities\n"
    "────────────────────────────────────────────────────────────\n"
    "📊 Deep Scan Sifter Complete: 1 files in 1 batches (0 pruned at Tier 0, 1 succeeded, 0 failed) in 2m24s\n"
    "   Total tokens consumed: 181.3k (in: 158.5k, cached: 108.7k, out: 4.1k, thinking: 18.6k)\n"
    "\n"
    "🔒 Found 3 vulnerabilities:\n"
    "\n"
    "ID        SEVERITY    TYPE                                                                                        FILE               TITLE                                                    CONFIDENCE\n"
    "────────  ────────    ────                                                                                        ────               ─────                                                    ──────────\n"
    "d60761e6  🔴 CRITICAL  IMPROPER NEUTRALIZATION OF SPECIAL ELEMENTS USED IN AN SQL COMMAND ('SQL INJECTION')        vulnerable_app.py  SQL Injection in User Authentication Endpoint            100%\n"
    "12eea4e5  🟡 MEDIUM    IMPROPER NEUTRALIZATION OF INPUT DURING WEB PAGE GENERATION ('CROSS-SITE SCRIPTING')        vulnerable_app.py  Reflected Cross-Site Scripting (XSS) in Receipt Handler  100%\n"
    "810f393c  🔴 CRITICAL  IMPROPER NEUTRALIZATION OF SPECIAL ELEMENTS USED IN AN OS COMMAND ('OS COMMAND INJECTION')  vulnerable_app.py  OS Command Injection in Network Ping Utility             95%\n"
    "\n"
    "Summary: 2 CRITICAL, 1 MEDIUM\n"
    "\n"
    "Run 'cm report' for detailed analysis, 'cm verify <finding-id>' to validate, or 'cm fix <finding-id>' to generate a patch.\n"
)
# A failed scan: progress text only. "Found 1 source files" fooled the old exit-1 check.
PROGRESS_ONLY_STDOUT = (
    "🔍 Discovering files in /tmp/session-x/vulnerable_app.py...\n"
    "   Found 1 source files\n"
    "🔍 Deep Scan Sifter: 1 total files discovered\n"
    "[1/1 batches] ❌ vulnerable_app.py (0s): start session failed\n"
    "────────────────────────────────────────────────────────────\n"
    "📊 Deep Scan Sifter Complete: 1 files in 1 batches (0 pruned at Tier 0, 0 succeeded, 1 failed) in 1s\n"
)
CLEAN_STDOUT = (
    "🔍 Discovering files in /tmp/session-x/clean_app.py...\n"
    "   Found 1 source files\n"
    "📊 Deep Scan Sifter Complete: 1 files in 1 batches (0 pruned at Tier 0, 1 succeeded, 0 failed) in 40s\n"
    "\n"
    "✅ No vulnerabilities found!\n"
)


class FindingsTableParserTest(unittest.TestCase):
    def test_counts_rows_of_a_real_cm_016_table(self):
        self.assertEqual(cm_tools.count_cli_table_rows(FINDINGS_STDOUT), 3)

    def test_progress_and_clean_output_have_no_rows(self):
        self.assertEqual(cm_tools.count_cli_table_rows(PROGRESS_ONLY_STDOUT), 0)
        self.assertEqual(cm_tools.count_cli_table_rows(CLEAN_STDOUT), 0)
        self.assertEqual(cm_tools.count_cli_table_rows(""), 0)
        self.assertEqual(cm_tools.count_cli_table_rows(None), 0)

    def test_ansi_colored_table_is_counted(self):
        colored = FINDINGS_STDOUT.replace("ID        SEVERITY", "\x1b[1mID\x1b[0m        \x1b[1mSEVERITY\x1b[0m")
        self.assertEqual(cm_tools.count_cli_table_rows(colored), 3)

    def test_clean_scan_line(self):
        self.assertTrue(cm_tools.cli_reports_clean_scan(CLEAN_STDOUT))
        self.assertTrue(cm_tools.cli_reports_clean_scan("\x1b[32m✅ No vulnerabilities found!\x1b[0m\r\n"))
        self.assertFalse(cm_tools.cli_reports_clean_scan(FINDINGS_STDOUT))
        self.assertFalse(cm_tools.cli_reports_clean_scan(PROGRESS_ONLY_STDOUT))
        self.assertFalse(cm_tools.cli_reports_clean_scan("Error: No vulnerabilities found! is not a clean result"))
        self.assertFalse(cm_tools.cli_reports_clean_scan(None))


_FAKE_CM_SCRIPT = '''
import json, sys
state_path = {state!r}
responses = {responses!r}
try:
    with open(state_path) as fh:
        served = json.load(fh)["served"]
except FileNotFoundError:
    served = 0
code, out, err = responses[min(served, len(responses) - 1)]
with open(state_path, "w") as fh:
    json.dump({{"served": served + 1}}, fh)
sys.stdout.buffer.write(out.encode("utf-8"))
sys.stderr.buffer.write(err.encode("utf-8"))
sys.exit(code)
'''


class CmFindExitCodeTest(unittest.TestCase):
    """`cm find` exit 1 counts as a completed scan only when the findings table has rows."""

    def setUp(self):
        self.session_id = f"unittest-cmfind-{os.getpid()}-{time.monotonic_ns()}"
        self.workspace = f"/tmp/session-{self.session_id}"
        os.makedirs(self.workspace)
        self.addCleanup(shutil.rmtree, self.workspace, True)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = os.path.join(self._tmp.name, "state.json")
        # Keep the token parser away from the developer's real ~/.codemender session logs.
        env_patcher = mock.patch.dict(os.environ, {"HOME": self._tmp.name})
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("CM_HOME", None)
        cm_tools._CLI_SEMAPHORE = None  # bind a fresh semaphore to this test's event loop
        delay_patcher = mock.patch.object(cm_tools, "_retry_delay", return_value=0.0)
        delay_patcher.start()
        self.addCleanup(delay_patcher.stop)

    def _run(self, responses):
        script = os.path.join(self._tmp.name, "fake_cm.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(_FAKE_CM_SCRIPT.format(state=self.state_path, responses=[list(r) for r in responses]))
        cmd = [sys.executable, script, "find", "vulnerable_app.py", "-y", "--model", "gemini-3.8-flash"]
        return asyncio.run(cm_tools._run_cm_cmd(cmd, self.session_id))

    def _runs(self):
        with open(self.state_path, encoding="utf-8") as fh:
            return json.load(fh)["served"]

    def test_exit_1_with_findings_table_is_success(self):
        out = self._run([(1, FINDINGS_STDOUT, "")])
        self.assertIn("d60761e6", out)
        self.assertEqual(self._runs(), 1)

    def test_exit_1_with_only_progress_text_fails_with_redacted_stderr(self):
        stderr = f"Error: all 1 deep scan batch(es) failed: INVALID_ARGUMENT: bad request (auth {FAKE_TOKEN})"
        with self.assertRaises(RuntimeError) as err:
            self._run([(1, PROGRESS_ONLY_STDOUT, stderr)])
        message = str(err.exception)
        self.assertIn("INVALID_ARGUMENT", message)
        self.assertNotIn(FAKE_TOKEN, message)
        self.assertIn("***", message)
        self.assertEqual(self._runs(), 1, "a permanent failure is not retried")

    def test_exit_1_without_table_and_without_stderr_fails(self):
        with self.assertRaises(RuntimeError) as err:
            self._run([(1, PROGRESS_ONLY_STDOUT, "")])
        self.assertIn("1 failed", str(err.exception))
        self.assertEqual(self._runs(), 1)

    def test_exit_1_without_table_retries_only_transient_errors(self):
        with self.assertRaises(RuntimeError) as err:
            self._run([(1, PROGRESS_ONLY_STDOUT, "503 Service Unavailable")])
        self.assertIn("503", str(err.exception))
        self.assertEqual(self._runs(), cm_tools._CM_MAX_ATTEMPTS)

    def test_transient_failure_then_table_succeeds(self):
        out = self._run([(1, PROGRESS_ONLY_STDOUT, "429 RESOURCE_EXHAUSTED"), (1, FINDINGS_STDOUT, "")])
        self.assertIn("810f393c", out)
        self.assertEqual(self._runs(), 2)

    def test_exit_0_clean_scan_is_returned(self):
        out = self._run([(0, CLEAN_STDOUT, "")])
        self.assertTrue(cm_tools.cli_reports_clean_scan(out))
        self.assertEqual(self._runs(), 1)


class CmSandboxDefaultTest(unittest.TestCase):
    """H1: the cm OS-level sandbox stays on; CM_DISABLE_SANDBOX is only an operator lever."""

    def _read(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_dockerfile_does_not_disable_the_sandbox(self):
        dockerfile = self._read(os.path.join(REPO_ROOT, "Dockerfile"))
        self.assertIsNone(re.search(r"^\s*(?:ENV|ARG)\b[^\n]*CM_DISABLE_SANDBOX", dockerfile, re.MULTILINE))
        self.assertNotIn("--sandbox", dockerfile)

    def test_backend_never_sets_the_lever_or_passes_sandbox_flags(self):
        sources = glob.glob(os.path.join(BACKEND_DIR, "*.py")) + glob.glob(os.path.join(BACKEND_DIR, "fleet", "*.py"))
        self.assertTrue(sources)
        for path in sources:
            text = self._read(path)
            self.assertNotIn("--sandbox", text, path)
            if os.path.basename(path) != "cm_tools.py":
                self.assertNotIn("CM_DISABLE_SANDBOX", text, path)
        cm_source = self._read(os.path.join(BACKEND_DIR, "cm_tools.py"))
        self.assertIsNone(re.search(r"""CM_DISABLE_SANDBOX["']\s*\]\s*=""", cm_source))
        self.assertIsNone(re.search(r"""setdefault\(\s*["']CM_DISABLE_SANDBOX""", cm_source))

    def test_cm_env_forwards_the_lever_but_never_injects_it(self):
        base = {"PATH": "/usr/bin", "GOOGLE_CLOUD_PROJECT": "your-gcp-project-id"}
        self.assertNotIn("CM_DISABLE_SANDBOX", cm_tools._cm_subprocess_env(dict(base)))
        env = cm_tools._cm_subprocess_env({**base, "CM_DISABLE_SANDBOX": "true"})
        self.assertEqual(env.get("CM_DISABLE_SANDBOX"), "true")


if __name__ == "__main__":
    unittest.main()
