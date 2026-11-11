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

"""Tests for log_stream: the scan SSE stream always ends (Firestore is stubbed)."""

import asyncio
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_stream import scan_log_events, stream_limit_seconds  # noqa: E402


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def _collect(records, max_seconds=900, poll=2.0, on_error=None):
    """Runs the generator against a scripted sequence of scan records (or exceptions)."""
    clock = _Clock()
    script = list(records)
    reads = []

    async def fetch():
        reads.append(1)
        item = script.pop(0) if len(script) > 1 else script[0]
        if isinstance(item, Exception):
            raise item
        return item

    async def sleep(seconds):
        clock.now += seconds

    async def run():
        frames = []
        async for frame in scan_log_events(fetch, max_seconds=max_seconds, poll_seconds=poll,
                                           on_error=on_error, sleep=sleep, clock=clock):
            frames.append(json.loads(frame[len("data: "):].strip()))
        return frames

    return asyncio.run(run()), len(reads)


def _step(n):
    return {"timestamp": n, "type": "info", "message": f"step {n}"}


class ScanLogEventsTest(unittest.TestCase):

    def test_streams_new_steps_then_ends_on_completion(self):
        frames, reads = _collect([
            {"status": "RUNNING", "steps": [_step(1)]},
            {"status": "RUNNING", "steps": [_step(1), _step(2)]},
            {"status": "COMPLETED", "steps": [_step(1), _step(2), _step(3)]},
        ])
        self.assertEqual([f.get("message") for f in frames[:-1]], ["step 1", "step 2", "step 3"])
        self.assertEqual(frames[-1]["type"], "end")
        self.assertEqual(frames[-1]["status"], "COMPLETED")
        self.assertEqual(reads, 3)

    def test_missing_scan_ends_immediately(self):
        frames, reads = _collect([None])
        self.assertEqual(len(frames), 1)
        self.assertEqual((frames[0]["type"], frames[0]["status"]), ("end", "NOT_FOUND"))
        self.assertEqual(reads, 1)

    def test_deferred_and_failed_scans_end(self):
        for status in ("DEFERRED", "FAILED", "deferred", "SKIPPED"):
            with self.subTest(status=status):
                frames, _ = _collect([{"status": status, "steps": [_step(1)]}])
                self.assertEqual(frames[0]["message"], "step 1")
                self.assertEqual(frames[-1]["status"], status.upper())

    def test_duration_cap_ends_a_stuck_scan(self):
        frames, reads = _collect([{"status": "RUNNING", "steps": []}], max_seconds=10, poll=2.0)
        self.assertEqual(frames[-1]["status"], "TIMEOUT")
        self.assertLessEqual(reads, 7)

    def test_read_error_ends_with_error_id(self):
        frames, _ = _collect([RuntimeError("firestore down")], on_error=lambda err: "abc123")
        self.assertEqual(frames[-1]["status"], "ERROR")
        self.assertIn("abc123", frames[-1]["message"])
        self.assertNotIn("firestore down", frames[-1]["message"])

    def test_stream_limit_parsing(self):
        self.assertEqual(stream_limit_seconds("120"), 120.0)
        for bad in ("", None, "abc", "0", "-5"):
            with self.subTest(bad=bad):
                self.assertEqual(stream_limit_seconds(bad), 900.0)


if __name__ == "__main__":
    unittest.main()
