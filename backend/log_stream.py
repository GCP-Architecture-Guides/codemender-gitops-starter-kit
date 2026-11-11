# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# you may obtain a copy of the License at
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

"""Server-sent events for a scan's live log (GET /api/scans/{sha}/logs/stream).

Every stream ends with one final ``{"type": "end", "status": ...}`` event: when the scan is
terminal (COMPLETED, FAILED, DEFERRED, ...), when it does not exist, when it cannot be read, or
when the duration cap is reached. An open stream never holds a server slot indefinitely.
"""

import asyncio
import json
import time

DEFAULT_MAX_STREAM_SECONDS = 900.0
DEFAULT_POLL_SECONDS = 2.0

# Scan statuses after which no new log steps are expected. DEFERRED is never re-queued by itself.
TERMINAL_SCAN_STATUSES = frozenset({
    "COMPLETED", "FAILED", "ERROR", "DEFERRED", "SKIPPED", "CANCELLED", "SUPERSEDED",
})


def stream_limit_seconds(raw, default: float = DEFAULT_MAX_STREAM_SECONDS) -> float:
    """Parses SSE_MAX_SEC: a positive number of seconds, else ``default``."""
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def sse_event(payload) -> str:
    """One SSE frame on the default event type, so EventSource.onmessage receives it."""
    return f"data: {json.dumps(payload, default=str)}\n\n"


def end_event(status: str, message: str) -> str:
    return sse_event({"type": "end", "status": status, "message": message, "timestamp": time.time()})


async def scan_log_events(fetch_scan, max_seconds=DEFAULT_MAX_STREAM_SECONDS, poll_seconds=DEFAULT_POLL_SECONDS,
                          on_error=None, sleep=asyncio.sleep, clock=time.monotonic):
    """Yields an SSE frame for each new step of a scan, then one final end frame.

    ``fetch_scan`` is an async callable returning the scan record (dict), or None when the scan
    does not exist; it must not block the event loop (read Firestore in a worker thread).
    ``on_error(exc)`` may log the exception and return an error id for the final frame.
    """
    deadline = clock() + stream_limit_seconds(max_seconds)
    sent = 0
    while True:
        try:
            scan = await fetch_scan()
        except Exception as err:
            error_id = on_error(err) if on_error else None
            suffix = f" (error id: {error_id})" if error_id else ""
            yield end_event("ERROR", f"Could not read the scan{suffix}")
            return
        if scan is None:
            yield end_event("NOT_FOUND", "Scan not found")
            return
        steps = scan.get("steps") or []
        if isinstance(steps, list) and len(steps) > sent:
            for step in steps[sent:]:
                yield sse_event(step)
            sent = len(steps)
        status = str(scan.get("status") or "").strip().upper()
        if status in TERMINAL_SCAN_STATUSES:
            yield end_event(status, f"Scan is {status}; no more log steps are expected.")
            return
        if clock() >= deadline:
            yield end_event("TIMEOUT", "Stream time limit reached; reconnect to keep following the scan.")
            return
        await sleep(poll_seconds)
