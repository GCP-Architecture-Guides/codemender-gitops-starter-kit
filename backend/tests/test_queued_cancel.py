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

"""TaskSession.start(): a task queued behind another one honors /cancel while it waits.

Regression: the wait loop only refreshed the heartbeat and checked for cancellation after the
lock was acquired, so `/cancel` on a queued task took effect only when the running task (up to
~20 min) finished, although the reply promises seconds.
"""

import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import task_context  # noqa: E402
from task_context import TaskCancelled, TaskSession, cm_state_lock  # noqa: E402

SHA = "d" * 40


class QueuedCancelTest(unittest.TestCase):

    def setUp(self):
        for patcher in (mock.patch.object(task_context, "LOCK_WAIT_HEARTBEAT_SEC", 0.01),
                        mock.patch.object(task_context, "_touch", lambda _sha: None)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_cancel_while_queued_stops_without_taking_the_lock(self):
        checks = []

        def cancel_check():
            checks.append(1)
            return "alice" if len(checks) >= 2 else None

        async def scenario():
            lock = cm_state_lock()
            await lock.acquire()  # another task holds the instance's cm lock
            session = TaskSession(SHA, "verify", lock_id="l", owner="o", cancel_check=cancel_check)
            try:
                with self.assertRaises(TaskCancelled):
                    await asyncio.wait_for(session.start(), timeout=5)
                session.finish()  # nothing taken, nothing released
                self.assertTrue(lock.locked())
                self.assertNotIn(SHA, task_context.IN_FLIGHT)
            finally:
                lock.release()

        asyncio.run(scenario())
        self.assertGreaterEqual(len(checks), 2)

    def test_uncancelled_task_starts_once_the_lock_is_free(self):
        async def scenario():
            lock = cm_state_lock()
            await lock.acquire()
            session = TaskSession(SHA, "scan", lock_id="l", owner="o", cancel_check=lambda: None)
            starter = asyncio.create_task(session.start())
            await asyncio.sleep(0.05)
            self.assertFalse(starter.done())
            lock.release()
            await asyncio.wait_for(starter, timeout=5)
            self.assertIn(SHA, task_context.IN_FLIGHT)
            session.finish()
            self.assertFalse(lock.locked())

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
