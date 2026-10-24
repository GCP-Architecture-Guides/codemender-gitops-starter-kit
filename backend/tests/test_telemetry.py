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
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

"""Telemetry attribution, SKU split and BigQuery schema alignment (plan 4.1-4.3, conflict review B8/C5)."""
import asyncio
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
DB = main.update_scan_status.__globals__  # the real database module's namespace
CM = main.cm_verify.__globals__  # the real cm_tools module's namespace
import task_context  # noqa: E402
from tests import test_status_semantics as status_tests  # noqa: E402

REPO = "your-org/your-repo"
SHA = "b" * 40

# Live schemas (bq show --schema, 2026-10-23). Rows must use exactly these columns.
TOKEN_USAGE_COLUMNS = [
    "log_id", "timestamp", "repo_name", "session_id", "task_type", "model_name", "input_tokens",
    "output_tokens", "cached_tokens", "thoughts_tokens", "total_tokens", "cost_usd", "duration_sec",
    "pr_number", "is_draft", "event_type", "compute_cost_usd", "license_cost_usd",
    "cached_savings_usd", "pricing_tier",
]
APPLIED_PATCHES_COLUMNS = [
    "merge_id", "pr_number", "repo_name", "branch", "commit_sha", "merged_at", "merged_by",
    "time_to_remediate_sec", "total_findings", "critical_count", "high_count", "medium_count",
    "low_count", "verified_count", "verified_finding_ids", "patched_count", "patched_finding_ids",
    "unpatched_count", "unpatched_finding_ids", "remediation_rate_pct", "findings_full_json",
]


class TelemetryContextTest(unittest.TestCase):
    def test_values_are_normalised_updated_and_reset(self):
        with task_context.telemetry_context(pr_number="7", event_type=" issue_comment ", is_draft=0):
            self.assertEqual(task_context.get_telemetry_context(),
                             {"pr_number": 7, "event_type": "issue_comment", "is_draft": False})
            task_context.update_telemetry_context(is_draft=True)
            self.assertTrue(task_context.get_telemetry_context()["is_draft"])
        self.assertEqual(task_context.get_telemetry_context(), {})

    def test_unknown_values_are_left_out(self):
        with task_context.telemetry_context(pr_number=0, event_type="  "):
            self.assertEqual(task_context.get_telemetry_context(), {})

    def test_threads_started_inside_inherit_it(self):
        async def run():
            with task_context.telemetry_context(pr_number=9, event_type="dashboard"):
                return await asyncio.to_thread(task_context.get_telemetry_context)

        self.assertEqual(asyncio.run(run()), {"pr_number": 9, "event_type": "dashboard"})

    def test_cm_tools_names_are_aliases(self):
        self.assertIs(CM["cm_telemetry_context"], task_context.telemetry_context)
        self.assertIs(CM["get_cm_telemetry_context"], task_context.get_telemetry_context)
        self.assertIs(CM["set_cm_telemetry_context"], task_context.set_telemetry_context)


class _CaptureInserts(unittest.TestCase):
    def setUp(self):
        self.rows = []

        def capture(table, rows, ensure_fn=None, success_msg=None):
            self.rows.append((table, rows))
            return True

        patcher = mock.patch.dict(DB, {"bq_client": object(), "_enqueue_bq_insert": capture})
        patcher.start()
        self.addCleanup(patcher.stop)


class LogTokenUsageRowTest(_CaptureInserts):
    def _log(self, **overrides):
        args = dict(session_id=SHA, repo_name=REPO, task_type="cm_verify", model_name="gemini-3.8-flash",
                    input_tokens=1_000_000, output_tokens=100_000, cached_tokens=200_000)
        args.update(overrides)
        DB["log_token_usage"](**args)
        table, rows = self.rows[-1]
        self.assertEqual(table, "token_usage_log")
        return rows[0]

    def test_row_has_exactly_the_live_columns(self):
        self.assertEqual(sorted(self._log()), sorted(TOKEN_USAGE_COLUMNS))

    def test_codemender_rows_split_compute_and_licence(self):
        row = self._log()
        self.assertEqual(row["pricing_tier"], "DUAL_TIER_CODEMENDER")
        self.assertAlmostEqual(row["compute_cost_usd"], row["license_cost_usd"])
        self.assertAlmostEqual(row["cost_usd"], row["compute_cost_usd"] + row["license_cost_usd"])
        self.assertGreater(row["cached_savings_usd"], 0.0)

    def test_helper_rows_are_compute_only(self):
        row = self._log(task_type="qa_agent")
        self.assertEqual(row["pricing_tier"], "SINGLE_TIER_COMPUTE")
        self.assertEqual(row["license_cost_usd"], 0.0)
        self.assertAlmostEqual(row["cost_usd"], row["compute_cost_usd"])

    def test_attribution_comes_from_the_context(self):
        with task_context.telemetry_context(pr_number=7, event_type="issue_comment", is_draft=True):
            row = self._log()
        self.assertEqual((row["pr_number"], row["event_type"], row["is_draft"]), (7, "issue_comment", True))

    def test_explicit_values_win_and_unknown_values_are_null(self):
        with task_context.telemetry_context(pr_number=7, event_type="issue_comment", is_draft=True):
            row = self._log(pr_number=8, event_type="dashboard", is_draft=False)
        self.assertEqual((row["pr_number"], row["event_type"], row["is_draft"]), (8, "dashboard", False))
        row = self._log()
        self.assertEqual((row["pr_number"], row["event_type"], row["is_draft"]), (None, None, None))


class ScanSummaryAttributionTest(_CaptureInserts):
    def test_pr_and_draft_default_to_the_context(self):
        args = dict(commit_sha=SHA, repo_name=REPO, branch_name="feature", event_type="dashboard", status="COMPLETED",
                    target_file=None, findings_count=0, findings=[], action_taken="verify")
        with task_context.telemetry_context(pr_number=7, event_type="dashboard", is_draft=True):
            DB["log_scan_summary"](**args)
            DB["log_scan_summary"](**args, is_draft=False)
        first, second = (rows[0] for _table, rows in self.rows)
        self.assertEqual((first["pr_number"], first["is_draft"]), (7, True))
        self.assertIs(second["is_draft"], False)


class CreatedTableSchemaTest(unittest.TestCase):
    """Fresh installs create the same columns as the live tables."""

    def _created_schema(self, ensure_name):
        if "bigquery" not in DB:
            self.skipTest("google-cloud-bigquery is not installed")
        from google.api_core.exceptions import NotFound
        created = []

        class FakeClient:
            project = "test-project"

            def get_dataset(self, _dataset_id):
                return None

            def get_table(self, _table_id):
                raise NotFound("missing")

            def create_table(self, table, timeout=None):
                created.append(table)

        with mock.patch.dict(DB, {"bq_client": FakeClient()}):
            DB[ensure_name]()
        return [field.name for field in created[0].schema]

    def test_token_usage_log(self):
        self.assertEqual(self._created_schema("ensure_token_usage_table"), TOKEN_USAGE_COLUMNS)

    def test_applied_security_patches(self):
        self.assertEqual(self._created_schema("ensure_bigquery_table"), APPLIED_PATCHES_COLUMNS)


class LiveSchemaFilterTest(unittest.TestCase):
    def setUp(self):
        self.inserted = []
        self.schema = ["a"]
        self.schema_reads = 0
        test = self

        class FakeClient:
            project = "p"

            def get_table(self, _table_id):
                test.schema_reads += 1
                if test.schema is None:
                    raise RuntimeError("no access")
                return types.SimpleNamespace(schema=[types.SimpleNamespace(name=name) for name in test.schema])

            def insert_rows_json(self, _table_id, rows, timeout=None):
                test.inserted.append(rows)
                return []

        patcher = mock.patch.dict(DB, {"bq_client": FakeClient(), "_bq_schema_cache": {}, "_bq_dropped_warned": set()})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _insert(self, rows):
        DB["_process_bq_insert_job"]({"table": "t", "rows": rows})
        return self.inserted[-1]

    def test_unknown_columns_are_dropped_and_logged_once(self):
        with self.assertLogs("database", level="WARNING") as logs:
            self.assertEqual(self._insert([{"a": 1, "b": 2}]), [{"a": 1}])
            self.assertEqual(self._insert([{"a": 3, "b": 4}]), [{"a": 3}])
        self.assertEqual(sum("has no column(s) ['b']" in line for line in logs.output), 1)
        self.assertEqual(self.schema_reads, 1)

    def test_rows_pass_unchanged_when_the_schema_cannot_be_read(self):
        self.schema = None
        with self.assertLogs("database", level="WARNING"):
            self.assertEqual(self._insert([{"a": 1, "b": 2}]), [{"a": 1, "b": 2}])

    def test_new_columns_are_picked_up_after_the_ttl(self):
        self._insert([{"a": 1}])
        self.schema = ["a", "b"]
        columns, _fetched_at = DB["_bq_schema_cache"]["t"]
        DB["_bq_schema_cache"]["t"] = (columns, 0.0)  # expired
        self.assertEqual(self._insert([{"a": 1, "b": 2}]), [{"a": 1, "b": 2}])


class RemediationAnalyticsTest(unittest.TestCase):
    def test_queries_read_only_live_columns_and_one_writer_remains(self):
        queries = []

        class FakeJob:
            def result(self):
                return []

        class FakeClient:
            project = "p"

            def query(self, sql, job_config=None):
                queries.append(sql)
                return FakeJob()

        with mock.patch.dict(DB, {"bq_client": FakeClient()}):
            result = DB["get_remediation_analytics"](range_days=7)
        self.assertEqual(result["status"], "success")
        joined = "\n".join(queries)
        self.assertNotIn("dismissed_count", joined)
        self.assertNotIn("total_discovered_count", joined)
        self.assertIn("JSON_QUERY_ARRAY(findings_full_json", joined)
        self.assertNotIn("log_applied_patch_telemetry", DB)
        self.assertNotIn("ensure_applied_patches_table", DB)


class MergedPrAnalyticsTest(unittest.TestCase):
    PAYLOAD = {"pull_request": {"number": 7, "merged": True, "merged_at": "2026-10-23T18:00:00Z",
                                "merged_by": {"login": "alice"}, "base": {"ref": "main"}, "head": {"sha": SHA}}}

    def _run(self, fake_db):
        insert = mock.Mock()
        with mock.patch.object(sys.modules["database"], "db", fake_db, create=True), \
                mock.patch.object(sys.modules["database"], "insert_analytics_patch_merged", insert, create=True):
            asyncio.run(main.process_merged_pr_analytics(REPO, 7, self.PAYLOAD))
        insert.assert_called_once()
        return insert.call_args.args[0]

    def test_the_merged_head_scan_feeds_one_row_with_the_live_columns(self):
        record = {"repo_name": REPO, "pr_number": 7, "commit_sha": SHA, "steps": [{"timestamp": 1.0}],
                  "findings": [{"id": "f1", "severity": "CRITICAL", "status": "DISMISSED"},
                               {"id": "f2", "severity": "HIGH", "status": "PATCHED"}]}
        snap = types.SimpleNamespace(exists=True, to_dict=lambda: dict(record))

        def no_query(*_args, **_kwargs):
            raise AssertionError("the PR query must not run when the merged head has a scan")

        fake_db = types.SimpleNamespace(collection=lambda _name: types.SimpleNamespace(
            document=lambda key: types.SimpleNamespace(get=lambda: snap if key == SHA else None), where=no_query))
        row = self._run(fake_db)
        self.assertEqual(sorted(row), sorted(APPLIED_PATCHES_COLUMNS))
        self.assertEqual((row["commit_sha"], row["patched_count"], row["critical_count"]), (SHA, 1, 1))

    def test_fallback_is_scoped_to_the_repository_and_takes_the_newest_scan(self):
        missing = types.SimpleNamespace(exists=False, to_dict=lambda: {})
        older = {"repo_name": REPO, "pr_number": 7, "updated_at": 1.0, "commit_sha": "c" * 40, "findings": []}
        newer = {"repo_name": REPO, "pr_number": 7, "updated_at": 9.0, "commit_sha": "d" * 40,
                 "findings": [{"id": "f1", "severity": "LOW"}]}
        filters = []

        class Query:
            def where(self, field, op, value):
                filters.append((field, op, value))
                return self

            def stream(self):
                return [types.SimpleNamespace(to_dict=lambda record=record: dict(record)) for record in (older, newer)]

        collection = types.SimpleNamespace(document=lambda _key: types.SimpleNamespace(get=lambda: missing),
                                           where=lambda *args: Query().where(*args))
        row = self._run(types.SimpleNamespace(collection=lambda _name: collection))
        self.assertIn(("repo_name", "==", REPO), filters)
        self.assertEqual((row["commit_sha"], row["low_count"]), ("d" * 40, 1))


class EntryPointAttributionTest(unittest.TestCase):
    def _capture(self, name):
        seen = []

        async def fake(*_args, **_kwargs):
            seen.append(task_context.get_telemetry_context())

        patcher = mock.patch.object(main, name, fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return seen

    def test_comment_and_dashboard_runs_are_attributed(self):
        for wrapper, impl in (("verify_findings_task", "_verify_findings_task"), ("fix_findings_task", "_fix_findings_task")):
            with self.subTest(wrapper=wrapper):
                seen = self._capture(impl)
                asyncio.run(getattr(main, wrapper)(REPO, SHA, ["f1"], True, 7))
                asyncio.run(getattr(main, wrapper)(REPO, SHA, ["f1"], False, None))
                asyncio.run(getattr(main, wrapper)(REPO, SHA, ["f1"], True, 7, event_type="dashboard"))
                self.assertEqual(seen, [{"pr_number": 7, "event_type": "issue_comment"},
                                        {"event_type": "commit_comment"},
                                        {"pr_number": 7, "event_type": "dashboard"}])
        self.assertEqual(task_context.get_telemetry_context(), {})

    def test_scan_runs_carry_the_pr_and_draft_flag(self):
        seen = self._capture("_process_pr_scan_event")
        asyncio.run(main.process_pr_scan_event({"number": 7, "pull_request": {"number": 7, "draft": True}}))
        self.assertEqual(seen, [{"pr_number": 7, "event_type": "pull_request", "is_draft": True}])


class VerifyScanLogAttributionTest(status_tests.VerifyHarness):
    def test_failed_dashboard_run_logs_its_pr_and_event(self):
        summary = mock.Mock()
        self.patch(sys.modules["database"], "log_scan_summary", summary, create=True)
        self.patch(sys.modules["database"], "db", status_tests._db_with(self._record()), create=True)
        self.patch(main, "ensure_workspace", mock.AsyncMock(side_effect=RuntimeError("clone failed")))
        asyncio.run(main.verify_findings_task(status_tests.REPO, status_tests.HEAD, ["f1"], True, 7, event_type="dashboard"))
        kwargs = summary.call_args.kwargs
        self.assertEqual((kwargs["event_type"], kwargs["pr_number"], kwargs["status"]), ("dashboard", 7, "FAILED"))


if __name__ == "__main__":
    unittest.main()
