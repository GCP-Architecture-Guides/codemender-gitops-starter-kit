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
"""Plan 3.4 (conflict review A3/A4): /cancel asks the worker to stop; live leases are never taken."""
import asyncio
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
import cm_tools  # noqa: E402
import task_context  # noqa: E402
from gate_policy import orphan_record_update  # noqa: E402
from tests import test_status_semantics as status_tests  # noqa: E402

HEAD, REPO, _Recorder = status_tests.HEAD, status_tests.REPO, status_tests._Recorder

DATABASE = main.update_scan_status.__globals__  # the real database module namespace


class OrphanRecordTest(unittest.TestCase):
    def test_interrupted_verify_returns_to_the_scan_result(self):
        record = {"status": "RUNNING", "active_task": "verify", "status_before_task": "COMPLETED",
                  "findings": [{"id": "a", "status": "VERIFYING"}, {"id": "b", "status": "VERIFIED"}]}
        fields, needs_gate = orphan_record_update(record, "CANCELLED", "cancelled by @alice")
        self.assertFalse(needs_gate)
        self.assertEqual(fields["status"], "COMPLETED")
        self.assertEqual([f["status"] for f in fields["findings"]], ["DETECTED", "VERIFIED"])
        self.assertIsNone(fields["active_task"])
        self.assertEqual(record["findings"][0]["status"], "VERIFYING", "input must not be mutated")

    def test_interrupted_scan_ends_terminal_and_needs_a_gate(self):
        for status in ("QUEUED", "CLONING", "RUNNING", "DEFERRED"):
            with self.subTest(status=status):
                fields, needs_gate = orphan_record_update({"status": status, "active_task": "scan"}, "STALE", "no heartbeat")
                self.assertEqual((fields["status"], needs_gate), ("STALE", True))

    def test_finished_records_are_left_alone(self):
        for status in ("COMPLETED", "FAILED", "CANCELLED", None):
            with self.subTest(status=status):
                self.assertEqual(orphan_record_update({"status": status}, "STALE", "x"), (None, False))


class CancelCheckTest(unittest.TestCase):
    def test_reads_are_throttled_older_flags_ignored_and_a_cancel_sticks(self):
        calls = []
        answers = [None, "alice"]

        def fake_since(sha, since):
            calls.append((sha, since))
            return answers.pop(0) if answers else None

        with mock.patch.dict(DATABASE, {"cancel_requested_since": fake_since}), \
                mock.patch.object(sys.modules["database"], "cancel_requested_since", fake_since, create=True):
            check = task_context.make_cancel_check("s1", 123.0, interval=0.05)
            self.assertIsNone(check())
            self.assertIsNone(check())  # throttled: no second read yet
            time.sleep(0.06)
            self.assertEqual(check(), "alice")
            self.assertEqual(check(), "alice")  # sticky, no more reads
        self.assertEqual(calls, [("s1", 123.0), ("s1", 123.0)])

    def test_a_cancel_sent_while_waiting_stops_the_task_at_start(self):
        async def scenario():
            session = task_context.TaskSession("s2", "scan", owner="o", cancel_check=lambda: "bob")
            try:
                await session.start()
            finally:
                session.finish()
            return task_context.cm_state_lock().locked()

        with self.assertRaises(task_context.TaskCancelled) as ctx:
            asyncio.run(scenario())
        self.assertEqual(ctx.exception.cancelled_by, "bob")
        self.assertEqual(task_context.IN_FLIGHT, {})

    def test_task_cancelled_is_not_swallowed_by_broad_handlers(self):
        self.assertFalse(issubclass(task_context.TaskCancelled, Exception))


class RunningCliCancelTest(unittest.TestCase):
    def test_running_cli_is_killed_and_the_task_cancelled(self):
        async def scenario():
            process = await asyncio.create_subprocess_exec(
                "sleep", "30", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=True)
            started = time.monotonic()
            try:
                await cm_tools._collect_process_output(process, b"", 30, grace=0.5, cancel_check=lambda: "carol")
            finally:
                await asyncio.sleep(0.1)
                return_code = process.returncode
                elapsed = time.monotonic() - started
            return return_code, elapsed

        with mock.patch.object(cm_tools, "_CM_CANCEL_POLL_SEC", 0.1):
            with self.assertRaises(task_context.TaskCancelled):
                asyncio.run(scenario())


class ReleaseRulesTest(unittest.TestCase):
    def test_release_without_owner_is_refused(self):
        sentinel = mock.Mock()
        with mock.patch.dict(DATABASE, {"db": sentinel}):
            self.assertFalse(DATABASE["release_lock"]("workspace-x"))
        sentinel.collection.assert_not_called()


class CancelCommitTaskTest(unittest.TestCase):
    def setUp(self):
        self.updates = _Recorder()
        self.requests = []
        self.statuses = mock.AsyncMock()
        self.held = False
        self.record = None
        database = sys.modules["database"]

        async def load(_sha):
            return self.record

        async def token(*_a, **_k):
            return "t"

        for target, attr, value in (
            (main, "update_scan_status", self.updates), (main, "append_scan_step", lambda *a, **k: None),
            (main, "is_lock_held", lambda _l: self.held), (main, "load_scan_record", load),
            (main, "set_commit_status", self.statuses), (main, "get_github_token", token),
            (database, "request_cancel", lambda sha, by: self.requests.append((sha, by)) or True),
            (database, "release_expired_lock", lambda _l: False),
        ):
            p = mock.patch.object(target, attr, value, create=True)
            p.start()
            self.addCleanup(p.stop)

    def test_live_task_is_asked_to_stop_and_nothing_else_changes(self):
        self.held = True
        self.assertEqual(asyncio.run(main.cancel_commit_task(HEAD, "alice")), "running")
        self.assertEqual(self.requests, [(HEAD, "alice")])
        self.assertEqual(self.updates.calls, [])

    def test_orphaned_scan_is_closed_out_with_an_error_gate(self):
        self.record = {"status": "RUNNING", "active_task": "scan", "repo_name": REPO}
        self.assertEqual(asyncio.run(main.cancel_commit_task(HEAD, "alice")), "closed")
        self.assertEqual(self.updates.calls[-1][1]["status"], "CANCELLED")
        self.assertEqual(self.statuses.call_args.kwargs["state"], "error")

    def test_idle_commit_is_left_alone(self):
        self.record = {"status": "COMPLETED", "repo_name": REPO}
        self.assertEqual(asyncio.run(main.cancel_commit_task(HEAD, "alice")), "idle")
        self.assertEqual(self.updates.calls, [])
        self.statuses.assert_not_called()


class CancelledWorkersTest(status_tests.ScanWorkerHarness):
    def test_cancelled_scan_ends_cancelled_with_an_error_gate(self):
        with mock.patch.object(main, "make_cancel_check", lambda sha, started: (lambda: "dave")):
            self._run()
        final = [k for _, k in self.updates.calls if k.get("status")][-1]
        self.assertEqual(final["status"], "CANCELLED")
        self.assertEqual(self.statuses.call_args.kwargs["state"], "error")
        self.comments.assert_not_called()


class CancelledVerifyTest(status_tests.VerifyHarness):
    def test_cancelled_verify_restores_and_says_so(self):
        self.patch(sys.modules["database"], "db", status_tests._db_with(self._record()), create=True)
        self.patch(main, "ensure_workspace", mock.AsyncMock())
        checks = iter([None, None, "erin"])  # start, then the first finding checkpoint
        self.patch(main, "make_cancel_check", lambda sha, started: (lambda: next(checks, "erin")))
        self.patch(sys.modules["gcs_helpers"] if "gcs_helpers" in sys.modules else __import__("gcs_helpers"),
                   "download_codemender_state_bundle", lambda *a, **k: True)
        asyncio.run(main.verify_findings_task(REPO, HEAD, ["f1"], True, 7))
        final = self.updates.calls[-1][1]
        self.assertEqual((final["status"], final["findings"][0]["status"]), ("COMPLETED", "NEW"))
        self.assertIn("cancelled by @erin", self.comments.call_args.args[2])


if __name__ == "__main__":
    unittest.main()
