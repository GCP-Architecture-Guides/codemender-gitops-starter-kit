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

"""Shutdown hook, in-process sweep and workspace safety (plan 3.15/3.16, conflict review C1/C2/C4, N2)."""
import asyncio
import os
import shutil
import signal
import sys
import tempfile
import threading
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
import gate_policy  # noqa: E402
import lock_logic  # noqa: E402
import maintenance  # noqa: E402
import task_context  # noqa: E402

REPO = "your-org/your-repo"
NOW = 1_800_000_000.0


class _ShutdownReset(unittest.TestCase):
    def setUp(self):
        task_context._SHUTDOWN.clear()
        self.addCleanup(task_context._SHUTDOWN.clear)
        saved = dict(task_context.IN_FLIGHT)
        task_context.IN_FLIGHT.clear()
        self.addCleanup(lambda: (task_context.IN_FLIGHT.clear(), task_context.IN_FLIGHT.update(saved)))


class CancelReasonTest(_ShutdownReset):
    def test_people_and_shutdowns_read_differently(self):
        self.assertEqual(str(task_context.TaskCancelled("alice")), "Task cancelled by @alice")
        self.assertEqual(task_context.TaskCancelled().reason, "cancelled")
        stop = task_context.TaskCancelled(task_context.SHUTDOWN_CANCELLER)
        self.assertTrue(stop.shutdown)
        self.assertEqual(stop.reason, task_context.SHUTDOWN_REASON)

    def test_cancel_check_reports_a_shutdown_without_waiting_for_the_interval(self):
        reads = []

        def cancel_requested_since(_sha, _started):
            reads.append(1)
            return None

        with mock.patch.object(sys.modules["database"], "cancel_requested_since", cancel_requested_since, create=True):
            check = task_context.make_cancel_check("a" * 40, NOW, interval=3600)
            self.assertIsNone(check())
            task_context.request_shutdown()
            self.assertEqual(check(), task_context.SHUTDOWN_CANCELLER)
        self.assertEqual(len(reads), 1)

    def test_a_person_cancel_seen_first_is_kept(self):
        with mock.patch.object(sys.modules["database"], "cancel_requested_since", lambda *_a: "alice", create=True):
            check = task_context.make_cancel_check("a" * 40, NOW)
            self.assertEqual(check(), "alice")
            task_context.request_shutdown()
            self.assertEqual(check(), "alice")


class TouchWorkspaceTest(unittest.TestCase):
    def test_workspace_mtime_is_bumped_and_missing_ones_are_ignored(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        sha = "c" * 40
        path = os.path.join(root, f"session-{sha}")
        os.mkdir(path)
        os.utime(path, (1, 1))
        with mock.patch.object(task_context, "WORKSPACE_ROOT", root):
            task_context.touch_workspace(sha)
            task_context.touch_workspace("d" * 40)
        self.assertGreater(os.stat(path).st_mtime, time.time() - 60)


class RestorableStatusTest(unittest.TestCase):
    def test_in_flight_statuses_left_by_dead_tasks_restore_to_completed(self):
        self.assertEqual(gate_policy.restorable_status("RUNNING"), "COMPLETED")
        self.assertEqual(gate_policy.restorable_status(None), "COMPLETED")
        self.assertEqual(gate_policy.restorable_status("FAILED"), "FAILED")
        fields, needs_gate = gate_policy.orphan_record_update(
            {"status": "RUNNING", "active_task": "verify", "status_before_task": "RUNNING", "findings": []},
            gate_policy.STALE_SCAN_STATUS, "test")
        self.assertEqual((fields["status"], needs_gate), ("COMPLETED", False))


class DrainTest(_ShutdownReset):
    def setUp(self):
        super().setUp()
        self.records = {}
        self.updates, self.released = [], []
        self.gate = mock.AsyncMock()

        async def load(sha):
            return dict(self.records.get(sha) or {}) or None

        async def token():
            return "token"

        for name, value in (("load_scan_record", load), ("update_scan_status", lambda sha, **f: self.updates.append((sha, f))),
                            ("release_lock", lambda lock_id, owner: self.released.append((lock_id, owner))),
                            ("get_github_token", token), ("set_commit_status", self.gate)):
            patcher = mock.patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _entry(self, sha, task_type):
        task_context.IN_FLIGHT[sha] = {"task_type": task_type, "lock_id": f"workspace-{sha}", "owner": "o1",
                                       "repo_name": REPO, "pr_number": 7, "started_at": NOW}

    def test_tasks_that_stop_in_time_are_left_to_their_workers(self):
        sha = "a" * 40
        self._entry(sha, "scan")

        async def run():
            asyncio.get_running_loop().call_later(0.3, task_context.IN_FLIGHT.pop, sha, None)
            return await main.drain_in_flight_work(drain_sec=2.0)

        self.assertEqual(asyncio.run(run()), [])
        self.assertEqual((self.updates, self.released), ([], []))

    def test_a_scan_left_running_is_closed_out_with_an_error_gate(self):
        sha = "b" * 40
        self.records[sha] = {"status": "RUNNING", "active_task": "scan", "repo_name": REPO}
        self._entry(sha, "scan")
        self.assertEqual(asyncio.run(main.drain_in_flight_work(drain_sec=0.2)), [sha])
        self.assertEqual(self.updates[0][1]["status"], gate_policy.STALE_SCAN_STATUS)
        self.assertEqual(self.released, [(f"workspace-{sha}", "o1")])
        self.assertEqual(self.gate.call_args.kwargs["state"], "error")
        self.assertIn(task_context.SHUTDOWN_REASON, self.gate.call_args.kwargs["description"])
        self.assertNotIn(sha, task_context.IN_FLIGHT)

    def test_a_verify_left_running_gets_its_record_back_and_no_gate(self):
        sha = "c" * 40
        self.records[sha] = {"status": "RUNNING", "active_task": "verify", "status_before_task": "COMPLETED",
                             "repo_name": REPO, "findings": [{"id": "f1", "status": "VERIFYING"}]}
        self._entry(sha, "verify")
        asyncio.run(main.drain_in_flight_work(drain_sec=0.2))
        fields = self.updates[0][1]
        self.assertEqual((fields["status"], fields["findings"][0]["status"]), ("COMPLETED", "DETECTED"))
        self.gate.assert_not_called()


class SigtermChainTest(_ShutdownReset):
    def test_hook_flags_the_shutdown_and_still_calls_the_server_handler(self):
        original = signal.getsignal(signal.SIGTERM)
        calls = []
        signal.signal(signal.SIGTERM, lambda signum, frame: calls.append(signum))
        self.addCleanup(signal.signal, signal.SIGTERM, original)

        async def run():
            self.assertTrue(main.install_shutdown_handler())
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(0.3)

        asyncio.run(run())
        self.assertEqual(calls, [signal.SIGTERM])
        self.assertTrue(task_context.shutdown_requested())

    def test_not_installed_off_the_main_thread(self):
        result = []
        thread = threading.Thread(target=lambda: result.append(main.install_shutdown_handler()))
        thread.start()
        thread.join()
        self.assertEqual(result, [False])


class MaintenanceIntervalTest(unittest.TestCase):
    def test_on_for_cloud_run_off_elsewhere_and_clamped(self):
        cases = (({}, 0.0), ({"K_SERVICE": "codemender-webhook"}, 300.0),
                 ({"K_SERVICE": "x", "CM_MAINTENANCE_INTERVAL_SEC": "0"}, 0.0),
                 ({"CM_MAINTENANCE_INTERVAL_SEC": "30"}, 60.0), ({"CM_MAINTENANCE_INTERVAL_SEC": "abc"}, 0.0))
        for env, expected in cases:
            with self.subTest(env=env), mock.patch.dict(os.environ, env, clear=False):
                for name in ("K_SERVICE", "CM_MAINTENANCE_INTERVAL_SEC"):
                    if name not in env:
                        os.environ.pop(name, None)
                self.assertEqual(main.maintenance_interval_seconds(), expected)


class MaintenanceCycleTest(unittest.TestCase):
    def _run(self, token_error=None):
        calls = []

        def sweep(**kwargs):
            calls.append(kwargs)
            return {"stale_gates": [{"repo_name": REPO, "commit_sha": "e" * 40, "state": "error", "description": "d"}]}

        async def token():
            if token_error:
                raise token_error
            return "token"

        gate = mock.AsyncMock()
        with mock.patch.object(maintenance, "run_maintenance_sweep", sweep), \
                mock.patch.object(main, "get_github_token", token), mock.patch.object(main, "set_commit_status", gate):
            summary = asyncio.run(main.run_maintenance_cycle())
        return calls[0], summary, gate

    def test_closed_scans_get_their_error_gate(self):
        kwargs, summary, gate = self._run()
        self.assertTrue(kwargs["close_gated_scans"])
        self.assertEqual(summary["gates_set"], 1)
        self.assertEqual(gate.call_args.kwargs["commit_sha"], "e" * 40)

    def test_without_a_token_scans_needing_a_gate_are_left_alone(self):
        kwargs, _summary, _gate = self._run(token_error=RuntimeError("no token"))
        self.assertFalse(kwargs["close_gated_scans"])


# ----------------------------------------------------------------------------- fake Firestore
class _Snap:
    def __init__(self, coll, doc_id):
        self.id, self._coll = doc_id, coll
        self.exists = doc_id in coll.docs
        self._data = dict(coll.docs.get(doc_id) or {})
        self.update_time = coll.versions.get(doc_id)
        self.reference = _Ref(coll, doc_id)

    def to_dict(self):
        return dict(self._data) if self.exists else None


class _Ref:
    def __init__(self, coll, doc_id):
        self.id, self._coll = doc_id, coll

    def get(self):
        return _Snap(self._coll, self.id)

    def update(self, fields, option=None):
        self._coll.check(self.id, option)
        self._coll.docs[self.id].update(fields)
        self._coll.bump(self.id)

    def delete(self, option=None):
        self._coll.check(self.id, option)
        self._coll.docs.pop(self.id, None)


class _Query:
    def __init__(self, coll, filters=(), limit=None):
        self._coll, self._filters, self._limit = coll, tuple(filters), limit

    def where(self, field, op, value):
        return _Query(self._coll, self._filters + ((field, op, value),), self._limit)

    def limit(self, count):
        return _Query(self._coll, self._filters, count)

    def stream(self):
        def match(value, op, target):
            return value == target if op == "==" else (value is not None and value < target)

        hits = [_Snap(self._coll, doc_id) for doc_id, data in list(self._coll.docs.items())
                if all(match(data.get(f), op, v) for f, op, v in self._filters)]
        return hits[: self._limit] if self._limit else hits


class _Coll(_Query):
    def __init__(self):
        self.docs, self.versions = {}, {}
        super().__init__(self)

    def document(self, doc_id):
        return _Ref(self, doc_id)

    def put(self, doc_id, data):
        self.docs[doc_id] = dict(data)
        self.bump(doc_id)

    def bump(self, doc_id):
        self.versions[doc_id] = object()

    def check(self, doc_id, option):
        if option is not None and option.last_update_time is not self.versions.get(doc_id):
            raise RuntimeError("precondition failed")


class _FakeDb:
    def __init__(self):
        self.collections = {}

    def collection(self, name):
        return self.collections.setdefault(name, _Coll())

    def write_option(self, last_update_time=None):
        return types.SimpleNamespace(last_update_time=last_update_time)


class SweepTest(unittest.TestCase):
    def setUp(self):
        self.db = _FakeDb()
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        old = NOW - 3600
        scans = self.db.collection("scans")
        scans.put("stale-scan", {"status": "RUNNING", "active_task": "scan", "repo_name": REPO, "updated_at": old})
        scans.put("fresh-scan", {"status": "RUNNING", "active_task": "scan", "repo_name": REPO, "updated_at": NOW - 60})
        scans.put("stale-verify", {"status": "RUNNING", "active_task": "verify", "status_before_task": "COMPLETED",
                                   "repo_name": REPO, "updated_at": old, "findings": [{"id": "f1", "status": "VERIFYING"}]})
        scans.put("legacy", {"status": "CLONING", "repo_name": REPO, "updated_at": old})
        scans.put("other-repo", {"status": "RUNNING", "active_task": "scan", "repo_name": "someone/else", "updated_at": old})
        scans.put("local-task", {"status": "RUNNING", "active_task": "scan", "repo_name": REPO, "updated_at": old})
        locks = self.db.collection("locks")
        locks.put("workspace-held", lock_logic.build_lock_doc("workspace-held", "o1", NOW - 60))
        locks.put("workspace-dead", lock_logic.build_lock_doc("workspace-dead", "o2", NOW - 7200))
        comments = self.db.collection("processed_comments")
        comments.put("issue_comment-1", {"claimed_at": datetime.fromtimestamp(NOW, tz=timezone.utc) - timedelta(days=400)})
        comments.put("issue_comment-2", {"claimed_at": datetime.fromtimestamp(NOW, tz=timezone.utc) - timedelta(days=5)})
        for name, age in (("session-held", 2 * 86400), ("session-gone", 2 * 86400), ("session-new", 60),
                          ("session-local-task", 2 * 86400), ("sandbox-old", 2 * 86400)):
            path = os.path.join(self.tmp, name)
            os.mkdir(path)
            os.utime(path, (NOW - age, NOW - age))

    def _sweep(self, **overrides):
        args = dict(allowed_repos=frozenset({REPO}), in_flight=frozenset({"local-task"}), now=NOW, db=self.db, tmp_dir=self.tmp)
        args.update(overrides)
        return maintenance.run_maintenance_sweep(**args)

    def test_abandoned_work_is_closed_out_and_live_work_is_left(self):
        summary = self._sweep()
        docs = self.db.collection("scans").docs
        self.assertEqual(docs["stale-scan"]["status"], gate_policy.STALE_SCAN_STATUS)
        self.assertEqual((docs["stale-verify"]["status"], docs["stale-verify"]["findings"][0]["status"]), ("COMPLETED", "DETECTED"))
        self.assertEqual(docs["legacy"]["status"], gate_policy.STALE_SCAN_STATUS)
        for untouched in ("fresh-scan", "other-repo", "local-task"):
            self.assertEqual(docs[untouched]["status"], "RUNNING", untouched)
        self.assertEqual([g["commit_sha"] for g in summary["stale_gates"]], ["stale-scan"])
        self.assertIn("no heartbeat for 10 min", summary["stale_gates"][0]["description"])
        self.assertEqual((summary["stale_scans_cleaned"], summary["other_repo_records_skipped"]), (3, 1))

    def test_without_a_token_scans_needing_a_gate_wait(self):
        summary = self._sweep(close_gated_scans=False)
        docs = self.db.collection("scans").docs
        self.assertEqual(docs["stale-scan"]["status"], "RUNNING")
        self.assertEqual(docs["stale-verify"]["status"], "COMPLETED")
        self.assertEqual((summary["stale_scans_deferred"], summary["stale_gates"]), (1, []))

    def test_locks_workspaces_and_comment_records(self):
        summary = self._sweep()
        self.assertEqual(sorted(self.db.collection("locks").docs), ["workspace-held"])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["session-held", "session-local-task", "session-new"])
        self.assertEqual(sorted(self.db.collection("processed_comments").docs), ["issue_comment-2"])
        self.assertEqual((summary["locks_swept"], summary["temp_dirs_removed"], summary["comments_pruned"]), (1, 2, 1))


if __name__ == "__main__":
    unittest.main()
