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

"""Stdlib-only tests for finding_match.select_finding (no Google Cloud imports)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from finding_match import finding_line, normalize_path, select_finding, vuln_class  # noqa: E402


def _finding(finding_id, path, vuln_type, line=None, **extra):
    finding = {"id": finding_id, "filepath": path, "vuln_type": vuln_type}
    if line is not None:
        finding["line_number"] = line
    finding.update(extra)
    return finding


class SelectFindingOrderTest(unittest.TestCase):
    def test_exact_id_wins_over_heuristic(self):
        heuristic_best = _finding("L1", "app.py", "SQL Injection", 12)
        id_match = _finding("T1", "app.py", "SQL Injection", 80)
        target = _finding("T1", "app.py", "SQL Injection", 12)
        self.assertIs(select_finding(target, [heuristic_best, id_match]), id_match)

    def test_id_match_ignored_when_files_differ(self):
        wrong_file = _finding("T1", "other.py", "SQL Injection", 12)
        right_file = _finding("L2", "app.py", "SQL Injection", 14)
        target = _finding("T1", "app.py", "SQL Injection", 12)
        self.assertIs(select_finding(target, [wrong_file, right_file]), right_file)

    def test_exact_fingerprint_when_ids_differ(self):
        xss = _finding("L1", "app.py", "XSS", 10, fingerprint="aaa")
        sqli = _finding("L2", "app.py", "SQLi", 50, fingerprint="bbb")
        target = _finding("OLD", "app.py", "XSS", 10, fingerprint="bbb")
        self.assertIs(select_finding(target, [xss, sqli]), sqli)

    def test_duplicate_fingerprints_need_unique_nearest_line(self):
        first = _finding("L1", "app.py", "SQLi", 10, fingerprint="fp")
        second = _finding("L2", "app.py", "SQLi", 40, fingerprint="fp")
        self.assertIs(select_finding({"fingerprint": "fp", "line_number": 38}, [first, second]), second)
        self.assertIsNone(select_finding({"fingerprint": "fp"}, [first, second]))


class SelectFindingHeuristicTest(unittest.TestCase):
    def test_single_candidate_same_file_and_class(self):
        local = _finding("L1", "app.py", "SQL Injection", 42)
        target = _finding("GONE", "app.py", "SQL Injection", 40)
        self.assertIs(select_finding(target, [local]), local)

    def test_cwe_aware_class_and_path_normalization(self):
        local = _finding("L1", "src/db.py", "SQL Injection", 42)
        target = {"id": "GONE", "file_path": "./src/db.py:40", "cwe": "CWE-89"}
        self.assertIs(select_finding(target, [local]), local)

    def test_different_class_returns_none(self):
        local = _finding("L1", "app.py", "Cross-Site Scripting", 10)
        target = _finding("GONE", "app.py", "SQL Injection", 10)
        self.assertIsNone(select_finding(target, [local]))

    def test_nosql_is_not_sql_injection(self):
        local = _finding("L1", "app.py", "NoSQL Injection", 10)
        target = _finding("GONE", "app.py", "SQL Injection", 10)
        self.assertIsNone(select_finding(target, [local]))

    def test_different_file_returns_none(self):
        local = _finding("L1", "other.py", "SQL Injection", 10)
        target = _finding("GONE", "app.py", "SQL Injection", 10)
        self.assertIsNone(select_finding(target, [local]))

    def test_line_window_is_15(self):
        local = _finding("L1", "app.py", "SQL Injection", 30)
        self.assertIs(select_finding(_finding("GONE", "app.py", "SQL Injection", 15), [local]), local)
        self.assertIsNone(select_finding(_finding("GONE", "app.py", "SQL Injection", 14), [local]))

    def test_missing_line_on_one_side_does_not_block_single_candidate(self):
        local = _finding("L1", "app.py", "SQL Injection")
        target = _finding("GONE", "app.py", "SQL Injection", 100)
        self.assertIs(select_finding(target, [local]), local)

    def test_several_candidates_unique_nearest_line(self):
        far = _finding("L1", "app.py", "SQLi", 10)
        near = _finding("L2", "app.py", "SQL Injection", 20)
        target = _finding("GONE", "app.py", "CWE-89", 18)
        self.assertIs(select_finding(target, [far, near]), near)

    def test_several_candidates_tied_returns_none(self):
        above = _finding("L1", "app.py", "SQLi", 10)
        below = _finding("L2", "app.py", "SQLi", 20)
        self.assertIsNone(select_finding(_finding("GONE", "app.py", "SQLi", 15), [above, below]))

    def test_several_candidates_without_target_line_returns_none(self):
        first = _finding("L1", "app.py", "SQLi", 10)
        second = _finding("L2", "app.py", "SQLi", 20)
        self.assertIsNone(select_finding(_finding("GONE", "app.py", "SQLi"), [first, second]))


class NeverGuessTest(unittest.TestCase):
    def test_never_falls_back_to_first_local_finding(self):
        only = _finding("L1", "app.py", "Hardcoded Secret", 5)
        self.assertIsNone(select_finding(_finding("GONE", "app.py", "SQL Injection", 5), [only]))
        self.assertIsNone(select_finding({"id": "GONE"}, [only]))
        self.assertIsNone(select_finding({"id": "GONE", "vuln_type": "Hardcoded Secret"}, [only]))

    def test_empty_and_invalid_inputs(self):
        local = [_finding("L1", "app.py", "SQLi", 5)]
        self.assertIsNone(select_finding(_finding("L1", "app.py", "SQLi", 5), []))
        self.assertIsNone(select_finding(_finding("L1", "app.py", "SQLi", 5), None))
        self.assertIsNone(select_finding(None, local))
        self.assertIsNone(select_finding({}, local))
        self.assertIs(select_finding({"id": "L1"}, ["junk", None, local[0]]), local[0])


class NormalizationTest(unittest.TestCase):
    def test_normalize_path(self):
        self.assertEqual(normalize_path("./src//db.py:42:7"), "src/db.py")
        self.assertEqual(normalize_path("/tmp/session-abc123/src/db.py"), "src/db.py")
        self.assertEqual(normalize_path("SRC\\db.py"), "src/db.py")
        self.assertEqual(normalize_path(None), "")

    def test_vuln_class(self):
        self.assertEqual(vuln_class({"cwe": "CWE-089"}), "cwe-89")
        self.assertEqual(vuln_class({"vuln_type": "SQL Injection"}), "cwe-89")
        self.assertEqual(vuln_class({"type": "sql_injection"}), "cwe-89")
        self.assertEqual(vuln_class({"category": "Cross-Site Scripting (CWE-79)"}), "cwe-79")
        self.assertEqual(vuln_class({"vuln_type": "Hard-coded Credentials"}), "cwe-798")
        self.assertEqual(vuln_class({"vuln_type": "Weird  Thing"}), "weird thing")
        self.assertEqual(vuln_class({}), "")

    def test_finding_line(self):
        self.assertEqual(finding_line({"filepath": "a.py:12"}), 12)
        self.assertEqual(finding_line({"line_number": "7"}), 7)
        self.assertIsNone(finding_line({"line_number": 0}))
        self.assertIsNone(finding_line({"line_number": True}))
        self.assertIsNone(finding_line({}))


if __name__ == "__main__":
    unittest.main()
