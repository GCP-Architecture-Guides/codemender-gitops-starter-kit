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

"""Per-task execution context for the CodeMender workers (scan, verify, fix).

TaskSession is opened by each worker right after it takes the Firestore workspace lease:

- cm state lock (plan 3.5, conflict review A5). The CLI keeps one state database, config and
  report folder per home (~/.codemender). Verify/fix hydrate state.db from Cloud Storage, which
  replaces the file under any other task on the instance. One task at a time therefore owns the
  CodeMender home, from hydration through its cm runs to the state upload. (cm commands were
  already serialized by cm_tools' CLI semaphore; this extends the critical section to the whole
  task.) Lock order is always: workspace lease -> cm state lock -> CLI semaphore.
  While a task waits for the lock it keeps its scan record's heartbeat fresh.
- in-flight registry (plan 3.15): the shutdown hook uses it to mark interrupted work.
- cancel check (plan 3.4): cm runs started inside the session poll it and stop the CLI.
- shutdown (plan 3.15): after SIGTERM every cancel check reports SHUTDOWN_CANCELLER at once.
- workspace touch (conflict review C4): start() bumps /tmp/session-{sha} so the /tmp sweep
  never takes a workspace in use for an abandoned one.

It also holds the telemetry attribution (plan 4.2): the PR number, webhook event and draft flag
that every token-usage and scan_log row of a task carries.
"""

import asyncio
import contextlib
import contextvars
import logging
import os
import threading
import time
import weakref

logger = logging.getLogger(__name__)

# How often a task waiting for the cm state lock refreshes its scan heartbeat.
LOCK_WAIT_HEARTBEAT_SEC = 60.0

_state_locks: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()

# commit_sha -> {"task_type", "lock_id", "owner", "repo_name", "pr_number", "started_at"}
IN_FLIGHT: dict = {}

_CANCEL_CHECK = contextvars.ContextVar("codemender_cancel_check", default=None)

# Instance shutdown (plan 3.15). The SIGTERM hook calls request_shutdown(); from then on every
# cancel check reports SHUTDOWN_CANCELLER at once, so running cm processes are stopped and the
# workers close out their records before Cloud Run kills the instance (10 s after SIGTERM).
SHUTDOWN_CANCELLER = "codemender:shutdown"
SHUTDOWN_REASON = "interrupted by a service restart"
_SHUTDOWN = threading.Event()


def request_shutdown() -> None:
    """Marks this instance as shutting down (idempotent)."""
    _SHUTDOWN.set()


def shutdown_requested() -> bool:
    return _SHUTDOWN.is_set()


class TaskCancelled(BaseException):
    """Raised inside a worker when /cancel (or the dashboard) asked it to stop, or when the
    instance is shutting down (cancelled_by == SHUTDOWN_CANCELLER, plan 3.15).

    A BaseException (like asyncio.CancelledError), so the broad `except Exception` handlers in the
    scan/verify/fix code don't record it as a failed finding; each worker catches it explicitly.
    """

    def __init__(self, cancelled_by: str = None):
        self.cancelled_by = cancelled_by
        super().__init__(f"Task {self.reason}")

    @property
    def shutdown(self) -> bool:
        """True when the instance is shutting down rather than a person cancelling."""
        return self.cancelled_by == SHUTDOWN_CANCELLER

    @property
    def reason(self) -> str:
        """'cancelled by @user' (or 'cancelled'), or SHUTDOWN_REASON for a shutdown."""
        if self.shutdown:
            return SHUTDOWN_REASON
        return f"cancelled by @{self.cancelled_by}" if self.cancelled_by else "cancelled"


def cm_state_lock() -> asyncio.Lock:
    """The instance-wide cm state lock for the running event loop (one per loop)."""
    loop = asyncio.get_running_loop()
    lock = _state_locks.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _state_locks[loop] = lock
    return lock


def current_cancel_check():
    """The cancel check of the task session this code runs in, or None."""
    return _CANCEL_CHECK.get()


# Minimum seconds between two Firestore reads of the same task's cancel flag.
CANCEL_CHECK_INTERVAL_SEC = 5.0


def make_cancel_check(commit_sha: str, started_at: float, interval: float = CANCEL_CHECK_INTERVAL_SEC):
    """A blocking callable returning who cancelled this task (or None), reading at most every ``interval`` s.

    Only cancel requests made at or after ``started_at`` count, so a flag left by an earlier task
    on the same commit never stops a new one. Once a cancel is seen it stays seen. After
    request_shutdown() it reports SHUTDOWN_CANCELLER at once, without waiting for the interval.
    """
    state = {"checked_at": None, "cancelled_by": None}

    def check():
        if state["cancelled_by"]:
            return state["cancelled_by"]
        if shutdown_requested():
            state["cancelled_by"] = SHUTDOWN_CANCELLER
            return SHUTDOWN_CANCELLER
        now = time.monotonic()
        if state["checked_at"] is not None and now - state["checked_at"] < interval:
            return None
        state["checked_at"] = now
        try:
            from database import cancel_requested_since
            state["cancelled_by"] = cancel_requested_since(commit_sha, started_at)
        except Exception as err:  # a flag that can't be read never stops the task
            logger.debug(f"Cancel check for {commit_sha[:8]} failed: {err}")
        return state["cancelled_by"]

    return check


def _touch(commit_sha: str) -> None:
    try:
        from database import touch_scan
        touch_scan(commit_sha)
    except Exception as err:  # pragma: no cover - best effort
        logger.debug(f"Heartbeat while waiting for the cm state lock failed: {err}")


WORKSPACE_ROOT = "/tmp"


def workspace_dir(commit_sha: str) -> str:
    """The commit's workspace (/tmp/session-{sha})."""
    return os.path.join(WORKSPACE_ROOT, f"session-{commit_sha}")


def touch_workspace(commit_sha: str) -> None:
    """Bumps the workspace's mtime so the 24 h /tmp sweep never removes a workspace in use
    (conflict review C4). A missing workspace is ignored."""
    path = workspace_dir(commit_sha)
    try:
        if os.path.isdir(path):
            os.utime(path, None)
    except OSError as err:
        logger.debug(f"Could not touch {path}: {err}")


class TaskSession:
    """Holds the cm state lock and the task's registry entry; see the module docstring.

    Usage (inside the worker's try/finally, after the workspace lease is taken):
        session = TaskSession(sha, "verify", lock_id=lock_id, owner=owner, ...)
        try:
            await session.start()
            ...
        finally:
            session.finish()
    """

    def __init__(self, commit_sha: str, task_type: str, lock_id: str = None, owner: str = None,
                 repo_name: str = None, pr_number=None, cancel_check=None):
        self.commit_sha = commit_sha
        self.task_type = task_type
        self.lock_id = lock_id
        self.owner = owner
        self.repo_name = repo_name
        self.pr_number = pr_number
        self.cancel_check = cancel_check
        self._lock = None
        self._cancel_token = None

    async def start(self) -> None:
        lock = cm_state_lock()
        waited = False
        while True:
            try:
                await asyncio.wait_for(lock.acquire(), timeout=LOCK_WAIT_HEARTBEAT_SEC)
                break
            except asyncio.TimeoutError:
                if not waited:
                    logger.info(f"{self.task_type} for {self.commit_sha[:8]} is waiting for another CodeMender task on this instance.")
                    waited = True
                await asyncio.to_thread(_touch, self.commit_sha)
        self._lock = lock
        self._cancel_token = _CANCEL_CHECK.set(self.cancel_check)
        IN_FLIGHT[self.commit_sha] = {
            "task_type": self.task_type,
            "lock_id": self.lock_id,
            "owner": self.owner,
            "repo_name": self.repo_name,
            "pr_number": self.pr_number,
            "started_at": time.time(),
        }
        touch_workspace(self.commit_sha)
        # A cancel sent while this task waited for the lock stops it before any work.
        await self.raise_if_cancelled()

    async def raise_if_cancelled(self) -> None:
        """Checkpoint: raises TaskCancelled when someone asked this task to stop."""
        if self.cancel_check is None:
            return
        cancelled_by = await asyncio.to_thread(self.cancel_check)
        if cancelled_by:
            raise TaskCancelled(cancelled_by)

    def finish(self) -> None:
        """Releases everything start() took; safe to call more than once or after a failed start."""
        entry = IN_FLIGHT.get(self.commit_sha)
        if entry is not None and entry.get("owner") == self.owner and entry.get("task_type") == self.task_type:
            IN_FLIGHT.pop(self.commit_sha, None)
        if self._cancel_token is not None:
            try:
                _CANCEL_CHECK.reset(self._cancel_token)
            except ValueError:
                pass  # finished from a different context; the context var dies with the task
            self._cancel_token = None
        if self._lock is not None:
            self._lock.release()
            self._lock = None


# --------------------------------------------------------------------------- telemetry attribution
# pr_number, event_type ('pull_request', 'issue_comment', 'commit_comment', 'dashboard') and
# is_draft for the token-usage rows a task logs (plan 4.2). The scan/verify/fix entry points set
# it; asyncio tasks and asyncio.to_thread calls started inside inherit it, and
# database.log_token_usage / log_scan_summary fall back to it when a caller passes no attribution.
_TELEMETRY_CONTEXT = contextvars.ContextVar("cm_telemetry_context", default=None)
_EVENT_TYPE_MAX_LEN = 64


def _positive_int_or_none(value):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _telemetry_fields(pr_number=None, event_type: str = None, is_draft: bool = None) -> dict:
    fields = {}
    pr = _positive_int_or_none(pr_number)
    if pr is not None:
        fields["pr_number"] = pr
    if event_type is not None and str(event_type).strip():
        fields["event_type"] = str(event_type).strip()[:_EVENT_TYPE_MAX_LEN]
    if is_draft is not None:
        fields["is_draft"] = bool(is_draft)
    return fields


def set_telemetry_context(pr_number=None, event_type: str = None, is_draft: bool = None) -> contextvars.Token:
    """Attributes token-usage rows logged from the current context to a PR and webhook event.

    Rows logged afterwards in this context -- and in asyncio tasks or asyncio.to_thread calls it
    starts -- carry ``pr_number``, ``event_type`` and ``is_draft``; unknown values are left out.
    Returns a token for reset_telemetry_context. Prefer telemetry_context(), which always resets.
    """
    return _TELEMETRY_CONTEXT.set(_telemetry_fields(pr_number, event_type, is_draft))


def update_telemetry_context(pr_number=None, event_type: str = None, is_draft: bool = None) -> None:
    """Adds known values to the active attribution (e.g. is_draft once the scan record is loaded).

    The enclosing telemetry_context() restores the attribution it replaced when it exits.
    """
    merged = dict(_TELEMETRY_CONTEXT.get() or {})
    merged.update(_telemetry_fields(pr_number, event_type, is_draft))
    _TELEMETRY_CONTEXT.set(merged)


def reset_telemetry_context(token: contextvars.Token) -> None:
    """Restores the attribution that was active before set_telemetry_context()."""
    _TELEMETRY_CONTEXT.reset(token)


@contextlib.contextmanager
def telemetry_context(pr_number=None, event_type: str = None, is_draft: bool = None):
    """Context manager form of set_telemetry_context; always resets, and may span awaits."""
    token = set_telemetry_context(pr_number=pr_number, event_type=event_type, is_draft=is_draft)
    try:
        yield
    finally:
        _TELEMETRY_CONTEXT.reset(token)


def get_telemetry_context() -> dict:
    """The active telemetry attribution ({} when none is set)."""
    return dict(_TELEMETRY_CONTEXT.get() or {})
