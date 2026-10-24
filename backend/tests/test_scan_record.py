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
"""Scan record fields and the task heartbeat (conflict review A1/A2, plan 3.17)."""
import asyncio
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
REAL_UPDATE = main.update_scan_status
DATABASE_GLOBALS = REAL_UPDATE.__globals__


class _Doc:
    def __init__(self, store, key, fail=None):
        self.store, self.key, self.fail = store, key, fail

    def set(self, data, merge=False):
        self.store.setdefault(self.key, {}).update(data)

    def update(self, data):
        if self.fail:
            raise self.fail
        if self.key not in self.store:
            raise KeyError("no document to update")
        self.store[self.key].update(data)

    def get(self):
        data = self.store.get(self.key)
        return types.SimpleNamespace(exists=data is not None, to_dict=lambda: dict(data or {}))


class _FakeDb:
    def __init__(self, fail=None):
        self.store, self.fail = {}, fail

    def collection(self, name):
        db = self
        return types.SimpleNamespace(document=lambda key: _Doc(db.store, (name, key), db.fail))


class UpdateScanStatusTest(unittest.TestCase):
    def test_extra_fields_are_written_and_none_clears(self):
        db = _FakeDb()
        with mock.patch.dict(DATABASE_GLOBALS, {"db": db}):
            REAL_UPDATE("abc", status="RUNNING", active_task="verify", status_before_task="COMPLETED")
            REAL_UPDATE("abc", status="COMPLETED", active_task=None, unknown_field="x")
        doc = db.store[("scans", "abc")]
        self.assertEqual(doc["status"], "COMPLETED")
        self.assertIsNone(doc["active_task"])
        self.assertEqual(doc["status_before_task"], "COMPLETED")
        self.assertNotIn("unknown_field", doc)

    def test_touch_never_creates_a_document(self):
        db = _FakeDb()
        touch = DATABASE_GLOBALS["touch_scan"]
        with mock.patch.dict(DATABASE_GLOBALS, {"db": db}):
            self.assertFalse(touch("missing"))
            REAL_UPDATE("abc", status="RUNNING")
            self.assertTrue(touch("abc"))
        self.assertNotIn(("scans", "missing"), db.store)
        self.assertIn("heartbeat_at", db.store[("scans", "abc")])


class HeartbeatLoopTest(unittest.TestCase):
    def _run(self, statuses, touch_results, pr_number=7, task_type="scan"):
        """Runs post_periodic_progress with one scripted status/touch result per minute."""
        statuses, touch_results = list(statuses), list(touch_results)
        touches, comments = [], []

        class _Snap:
            def __init__(self, status):
                self.exists = status is not None
                self._status = status

            def to_dict(self):
                return {"status": self._status, "message": "Scanning a.py"}

        def get_snapshot():
            return _Snap(statuses.pop(0) if statuses else "COMPLETED")

        def touch(sha):
            touches.append(sha)
            result = touch_results.pop(0) if touch_results else True
            if isinstance(result, Exception):
                raise result
            return result

        fake_db = types.SimpleNamespace(collection=lambda _n: types.SimpleNamespace(
            document=lambda _k: types.SimpleNamespace(get=get_snapshot)))
        fake_database = types.ModuleType("database")
        fake_database.db = fake_db
        fake_database.touch_scan = touch

        async def no_sleep(_seconds):
            return None

        async def upsert(*args, **_kwargs):
            comments.append(args[1])

        with mock.patch.dict(sys.modules, {"database": fake_database}), \
                mock.patch.object(main.asyncio, "sleep", no_sleep), \
                mock.patch.object(main, "upsert_progress_comment", upsert), \
                mock.patch.dict("shared_state.active_tasks", {"sha1": "run1"}):
            asyncio.run(main.post_periodic_progress("o/r", "sha1", pr_number, True, "t", task_type, "run1"))
        return touches, comments

    def test_a_failed_heartbeat_does_not_end_the_loop(self):
        touches, _ = self._run(["RUNNING", "RUNNING", "RUNNING"], [RuntimeError("firestore blip"), True, True])
        self.assertEqual(len(touches), 3)

    def test_terminal_statuses_end_the_loop(self):
        for status in ("COMPLETED", "FAILED", "CANCELLED", "STALE", "SUPERSEDED"):
            with self.subTest(status=status):
                touches, _ = self._run(["RUNNING", status], [True])
                self.assertEqual(len(touches), 1)

    def test_commit_level_tasks_post_no_periodic_comments(self):
        touches, comments = self._run(["RUNNING", "RUNNING"], [True, True], pr_number=None)
        self.assertEqual((len(touches), comments), (2, []))

    def test_pr_tasks_refresh_one_progress_comment(self):
        _, comments = self._run(["RUNNING", "RUNNING"], [True, True], pr_number=7)
        self.assertEqual(comments, [7, 7])


if __name__ == "__main__":
    unittest.main()
