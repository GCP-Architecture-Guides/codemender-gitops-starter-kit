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

"""Stdlib-only tests for the lease decision helpers in lock_logic (no Firestore)."""

import asyncio
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lock_logic import (  # noqa: E402
    DEFAULT_LOCK_TTL_SECONDS,
    build_lock_doc,
    can_acquire,
    is_lock_expired,
    is_owner,
    lock_expiry,
    renewal_fields,
    start_renewal_task,
)

NOW = 1_800_000_000.0


class CanAcquireTest(unittest.TestCase):
    def test_missing_doc_is_free(self):
        self.assertTrue(can_acquire(None, NOW))
        self.assertTrue(can_acquire({}, NOW))

    def test_active_lease_blocks(self):
        self.assertFalse(can_acquire(build_lock_doc("workspace-abc", "owner-1", NOW - 10, 1800), NOW))

    def test_expired_lease_can_be_taken_over(self):
        self.assertTrue(can_acquire(build_lock_doc("workspace-abc", "owner-1", NOW - 1801, 1800), NOW))

    def test_renewed_lease_blocks_even_if_locked_long_ago(self):
        doc = build_lock_doc("workspace-abc", "owner-1", NOW - 7200, 1800)
        doc.update(renewal_fields(NOW - 60, 1800))
        self.assertFalse(can_acquire(doc, NOW))

    def test_legacy_doc_expires_1800s_after_locked_at(self):
        self.assertFalse(can_acquire({"lock_id": "x", "locked_at": NOW - 600}, NOW))
        self.assertTrue(can_acquire({"lock_id": "x", "locked_at": NOW - 1801}, NOW))

    def test_legacy_firestore_timestamp(self):
        self.assertTrue(can_acquire({"locked_at": datetime.fromtimestamp(NOW - 1801, tz=timezone.utc)}, NOW))
        self.assertFalse(can_acquire({"locked_at": datetime.fromtimestamp(NOW - 5, tz=timezone.utc)}, NOW))

    def test_unknown_shape_fails_closed(self):
        self.assertFalse(can_acquire({"locked_by": "someone"}, NOW))
        self.assertFalse(can_acquire({"expires_at": "soon"}, NOW))
        self.assertFalse(can_acquire({"expires_at": True}, NOW))


class IsOwnerTest(unittest.TestCase):
    def test_owner_checks(self):
        doc = build_lock_doc("workspace-abc", "owner-1", NOW)
        self.assertTrue(is_owner(doc, "owner-1"))
        self.assertFalse(is_owner(doc, "owner-2"))
        self.assertFalse(is_owner(doc, None))
        self.assertFalse(is_owner(doc, ""))
        self.assertFalse(is_owner(None, "owner-1"))
        self.assertFalse(is_owner({"locked_at": NOW}, "owner-1"))


class SweeperExpiryTest(unittest.TestCase):
    def test_new_shape_uses_expires_at(self):
        self.assertTrue(is_lock_expired({"owner": "o", "locked_at": NOW - 10, "expires_at": NOW - 1}, NOW))
        self.assertFalse(is_lock_expired({"owner": "o", "locked_at": NOW - 9999, "expires_at": NOW + 1}, NOW))

    def test_legacy_locked_at_boundary(self):
        self.assertTrue(is_lock_expired({"locked_at": NOW - 1801}, NOW))
        self.assertFalse(is_lock_expired({"locked_at": NOW - 1799}, NOW))

    def test_unknown_shapes_are_never_swept(self):
        self.assertFalse(is_lock_expired({"created_at": NOW - 99999}, NOW))
        self.assertFalse(is_lock_expired({}, NOW))
        self.assertFalse(is_lock_expired(None, NOW))
        self.assertIsNone(lock_expiry({"expires_at": True}))


class LockDocTest(unittest.TestCase):
    def test_build_lock_doc_fields(self):
        doc = build_lock_doc("workspace-abc", "tok", NOW, 1800)
        self.assertEqual(doc["lock_id"], "workspace-abc")
        self.assertEqual(doc["owner"], "tok")
        self.assertEqual(doc["locked_at"], NOW)
        self.assertEqual(doc["expires_at"], NOW + 1800)

    def test_default_ttl_is_1800(self):
        self.assertEqual(DEFAULT_LOCK_TTL_SECONDS, 1800)
        self.assertEqual(build_lock_doc("x", "t", NOW)["expires_at"], NOW + 1800)

    def test_renewal_extends_expiry(self):
        self.assertEqual(renewal_fields(NOW, 1800), {"expires_at": NOW + 1800, "renewed_at": NOW})


class RenewalTaskTest(unittest.IsolatedAsyncioTestCase):
    async def _run_briefly(self, task, seconds=0.15):
        await asyncio.sleep(seconds)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_renews_until_cancelled(self):
        calls = []

        def renew(lock_id, owner, ttl):
            calls.append((lock_id, owner, ttl))
            return True

        task = start_renewal_task(renew, "workspace-abc", "tok", ttl_seconds=60, interval_seconds=0.01)
        await self._run_briefly(task)
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[0], ("workspace-abc", "tok", 60))
        count_after_cancel = len(calls)
        await asyncio.sleep(0.05)
        self.assertEqual(len(calls), count_after_cancel)

    async def test_failures_are_logged_and_retried(self):
        calls = []

        def renew(lock_id, owner, ttl):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("firestore unavailable")
            return False

        with self.assertLogs("lock_logic", level="ERROR") as logs:
            task = start_renewal_task(renew, "workspace-abc", "tok", ttl_seconds=60, interval_seconds=0.01)
            await self._run_briefly(task)
        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(any("raised" in line for line in logs.output))
        self.assertTrue(any("failed" in line for line in logs.output))

    async def test_interval_not_shorter_than_ttl_is_clamped(self):
        with self.assertLogs("lock_logic", level="WARNING"):
            task = start_renewal_task(lambda *args: True, "workspace-abc", "tok", ttl_seconds=30, interval_seconds=300)
        await self._run_briefly(task, seconds=0)


if __name__ == "__main__":
    unittest.main()
