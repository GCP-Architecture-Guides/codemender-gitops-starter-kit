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

"""Real line numbers, enclosing scope and stable fingerprints for triaged findings.

Regression: every finding got line 1 (cm's table has no line column), so the scope was always
"global" and the fingerprint fell back to the LLM-written title. Reports showed `file:1`, and a
re-scan relabelled unchanged findings as NEW + RESOLVED whenever a title was reworded.
"""

import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_severity_policy import agents  # noqa: E402  (imports agents with stubs)
import cm_tools  # noqa: E402
from finding_match import fingerprint_class  # noqa: E402

SAMPLE = (
    "from flask import Flask\n"              # 1
    "import sqlite3\n"                       # 2
    "\n"                                     # 3
    "API_KEY = 'not-a-real-key'\n"           # 4
    "\n"                                     # 5
    "def get_db():\n"                        # 6
    "    return sqlite3.connect(':memory:')\n"  # 7
    "\n"                                     # 8
    "@app.route('/login', methods=['POST'])\n"  # 9
    "def login():\n"                         # 10
    "    q = f'SELECT {x}'\n"                # 11
    "    return q\n"                         # 12
    "\n"                                     # 13
    "@app.route('/ping')\n"                  # 14
    "def ping():\n"                          # 15
    "    return os.popen(cmd).read()\n"      # 16
)

STDOUT = (
    "   Found 1 source files\n"
    "📊 Deep Scan Sifter Complete: 1 files in 1 batches (0 pruned at Tier 0, 1 succeeded, 0 failed) in 1m\n"
    "\n"
    "🔒 Found 2 vulnerabilities:\n"
    "\n"
    "ID        SEVERITY    TYPE     FILE    TITLE                      CONFIDENCE\n"
    "────────  ────────    ────     ────    ─────                      ──────────\n"
    "aaaa1111  🔴 CRITICAL  CWE-89   app.py  SQL injection in login     100%\n"
    "bbbb2222  🔴 CRITICAL  CWE-78   app.py  Command injection in ping  100%\n"
    "\n"
    "Summary: 2 CRITICAL\n"
)


def _state_db(directory: str, rows) -> str:
    path = os.path.join(directory, "state.db")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE findings (finding_id TEXT, session_id TEXT, start_line INTEGER, end_line INTEGER, created_at TEXT)")
    con.executemany("INSERT INTO findings VALUES (?, 's', ?, ?, ?)", rows)
    con.commit()
    con.close()
    return path


class _CmHome(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cm-home-")
        self.addCleanup(shutil.rmtree, self.home, True)
        patcher = mock.patch.dict(os.environ, {"CM_HOME": self.home})
        patcher.start()
        self.addCleanup(patcher.stop)


class FindingLocationsTest(_CmHome):

    def test_lines_come_from_state_db_and_the_newest_row_wins(self):
        _state_db(self.home, [
            ("aaaa1111-0000-5000-8000-000000000000", 1, 1, "2026-10-26T10:00:00Z"),   # older run
            ("aaaa1111-1111-5111-8111-111111111111", 9, 12, "2026-10-27T10:00:00Z"),
            ("bbbb2222-2222-5222-8222-222222222222", 14, 16, "2026-10-27T10:00:00Z"),
            ("cccc3333-3333-5333-8333-333333333333", 0, None, "2026-10-27T10:00:00Z"),
        ])
        self.assertEqual(agents.cm_finding_locations(["AAAA1111", "bbbb2222", "cccc3333", "dddd4444", ""]),
                         {"aaaa1111": (9, 12), "bbbb2222": (14, 16), "cccc3333": (None, None)})

    def test_missing_database_or_columns_returns_nothing(self):
        self.assertEqual(agents.cm_finding_locations(["aaaa1111"]), {})
        con = sqlite3.connect(os.path.join(self.home, "state.db"))
        con.execute("CREATE TABLE findings (finding_id TEXT)")
        con.commit()
        con.close()
        self.assertEqual(agents.cm_finding_locations(["aaaa1111"]), {})


class ScopeAndFamilyTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cm-scope-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "app.py")
        Path(self.path).write_text(SAMPLE)

    def test_reported_range_resolves_to_the_function_not_the_one_above(self):
        self.assertEqual(cm_tools.extract_enclosing_scope(self.path, 9, 12), "login")
        self.assertEqual(cm_tools.extract_enclosing_scope(self.path, 14, 16), "ping")
        self.assertEqual(cm_tools.extract_enclosing_scope(self.path, 4, 4), "global")
        # Without a range the historical backward scan is kept for other callers.
        self.assertEqual(cm_tools.extract_enclosing_scope(self.path, 9), "get_db")

    def test_fingerprint_families(self):
        self.assertEqual(fingerprint_class({"vuln_type": "CWE-602"}), "cwe-472")
        self.assertEqual(fingerprint_class({"vuln_type": "OS COMMAND INJECTION"}), "cwe-78")
        self.assertEqual(fingerprint_class({"vuln_type": "CWE-77"}), "cwe-78")
        self.assertNotEqual(fingerprint_class({"vuln_type": "CWE-79"}), fingerprint_class({"vuln_type": "CWE-1336"}))


class TriageLocationsTest(_CmHome):

    def setUp(self):
        super().setUp()
        self.session_id = f"unittest-loc-{uuid.uuid4().hex[:10]}"
        workspace = f"/tmp/session-{self.session_id}"
        os.makedirs(workspace)
        self.addCleanup(shutil.rmtree, workspace, True)
        Path(workspace, "app.py").write_text(SAMPLE)
        database = sys.modules["database"]
        for name in ("append_scan_step", "update_scan_status", "log_token_usage"):
            patcher = mock.patch.object(database, name, lambda *a, **k: None, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _triage(self, findings):
        usage = types.SimpleNamespace(prompt_token_count=1, candidates_token_count=1,
                                      cached_content_token_count=0, thoughts_token_count=0)
        response = types.SimpleNamespace(text=json.dumps({"findings": findings}), usage_metadata=usage)
        client = types.SimpleNamespace(aio=types.SimpleNamespace(models=types.SimpleNamespace(
            generate_content=mock.AsyncMock(return_value=response))))
        with mock.patch.object(agents, "cm_init", mock.AsyncMock(return_value="")), \
                mock.patch.object(agents, "cm_find", mock.AsyncMock(return_value=STDOUT)), \
                mock.patch.object(agents, "client", client):
            return {r["id"]: r for r in asyncio.run(agents.run_triage_agent(self.session_id, "app.py", repo_name="o/r"))}

    @staticmethod
    def _findings(sqli_title, sqli_type, cmd_title, cmd_type):
        return [
            {"id": "aaaa1111", "severity": "CRITICAL", "filepath": "app.py", "vuln_type": sqli_type, "description": sqli_title},
            {"id": "bbbb2222", "severity": "CRITICAL", "filepath": "app.py", "vuln_type": cmd_type, "description": cmd_title},
        ]

    def test_real_lines_scope_and_title_independent_fingerprints(self):
        _state_db(self.home, [("aaaa1111-1111-5111-8111-111111111111", 9, 12, "2026-10-27T10:00:00Z"),
                              ("bbbb2222-2222-5222-8222-222222222222", 14, 16, "2026-10-27T10:00:00Z")])
        first = self._triage(self._findings("SQL injection in login", "CWE-89", "Command injection in ping", "CWE-78"))
        self.assertEqual((first["aaaa1111"]["line_number"], first["aaaa1111"]["end_line"]), (9, 12))
        self.assertEqual(first["aaaa1111"]["enclosing_scope"], "login")
        self.assertEqual(first["bbbb2222"]["enclosing_scope"], "ping")
        self.assertNotEqual(first["aaaa1111"]["fingerprint"], first["bbbb2222"]["fingerprint"])

        reworded = self._triage(self._findings("Authentication bypass via SQL injection in /login endpoint", "CWE-89",
                                               "OS command injection in /ping", "OS COMMAND INJECTION"))
        for fid in ("aaaa1111", "bbbb2222"):
            self.assertEqual(reworded[fid]["fingerprint"], first[fid]["fingerprint"])

    def test_unknown_location_is_none_not_line_one(self):
        result = self._triage(self._findings("SQL injection in login", "CWE-89", "Command injection in ping", "CWE-78"))
        self.assertIsNone(result["aaaa1111"]["line_number"])
        self.assertEqual(result["aaaa1111"]["enclosing_scope"], "global")


if __name__ == "__main__":
    unittest.main()
