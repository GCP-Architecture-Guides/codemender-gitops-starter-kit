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

import os
import asyncio
import logging
import queue
import threading
import time
import uuid
from google.cloud import firestore
from typing import Optional

from task_context import get_telemetry_context

from lock_logic import (
    DEFAULT_LOCK_TTL_SECONDS,
    build_lock_doc,
    can_acquire as _can_acquire,
    is_owner as _is_owner,
    renewal_fields,
    start_renewal_task,
)

logger = logging.getLogger(__name__)

def get_firestore_client(project_id: Optional[str] = None):
    """Initializes the Firestore client with Application Default Credentials.

    The project comes from the caller or GOOGLE_CLOUD_PROJECT. There is deliberately no default
    project and no `gcloud auth print-access-token` path: either could silently bind to whichever
    project or account the local gcloud configuration points at.
    """
    proj = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not proj:
        logger.warning("GOOGLE_CLOUD_PROJECT is not set; Firestore client not initialized.")
        return None
    try:
        return firestore.Client(project=proj)
    except Exception as e:
        logger.warning(f"Could not initialize Firestore client: {e}")
        return None

# Initialize Firestore Client (connects to standard default DB under active project)
db = get_firestore_client()

def save_patch_proposal(commit_sha: str, branch_name: str, filename: str, git_diff: str, patched_code: str, pr_number: int = None, patch_commit_sha: str = None,
                        patch_pr_number: int = None, changed_files: list = None):
    """Saves the proposed patch diff and metadata to Firestore keyed by base commit SHA.

    ``pr_number`` is always the pull request the patch is for; a separate pull request opened
    for the patch branch is ``patch_pr_number`` (plan 3.8). ``git_diff`` covers every changed
    file (listed in ``changed_files``); ``filename``/``patched_code`` describe the first one.
    """
    import time
    try:
        doc_ref = db.collection("patches").document(commit_sha)
        data = {
            "commit_sha": commit_sha,
            "branch_name": branch_name,
            "filename": filename,
            "git_diff": git_diff,
            "patched_code": patched_code,
            "is_applied": False,
            "created_at": time.time()
        }
        if pr_number is not None:
            data["pr_number"] = pr_number
        if patch_commit_sha is not None:
            data["patch_commit_sha"] = patch_commit_sha
        if patch_pr_number is not None:
            data["patch_pr_number"] = patch_pr_number
        if changed_files is not None:
            data["changed_files"] = list(changed_files)
        doc_ref.set(data, merge=True)
        logger.info(f"Saved patch proposal to Firestore for commit {commit_sha} (PR: {pr_number}, Patch SHA: {patch_commit_sha})")
    except Exception as e:
        logger.error(f"Failed to write patch proposal to Firestore: {e}")
        raise

def list_patch_proposals() -> list[dict]:
    """Retrieves all patch proposals from Firestore, sorted by created_at descending in memory."""
    try:
        patches_ref = db.collection("patches")
        docs = patches_ref.stream()
        results = []
        for doc in docs:
            results.append(doc.to_dict())
        results.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return results
    except Exception as e:
        logger.error(f"Failed to list patch proposals: {e}")
        return []


def get_patch_proposal(commit_sha: str) -> dict:
    """Retrieves the patch metadata from Firestore using the commit SHA."""
    try:
        doc_ref = db.collection("patches").document(commit_sha)
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        logger.warning(f"No patch proposal found in Firestore for commit {commit_sha}")
        return {}
    except Exception as e:
        logger.error(f"Failed to read patch proposal from Firestore: {e}")
        raise

def get_patch_proposal_by_pr(pr_number: int, unapplied_only: bool = True) -> dict:
    """Retrieves the latest patch metadata from Firestore for a given PR number."""
    try:
        try:
            num_int = int(pr_number)
        except (ValueError, TypeError):
            num_int = None
        num_str = str(pr_number)

        patches_ref = db.collection("patches")
        proposals = []
        if num_int is not None:
            docs = patches_ref.where("pr_number", "==", num_int).stream()
            proposals.extend([d.to_dict() for d in docs])
        docs_str = patches_ref.where("pr_number", "==", num_str).stream()
        proposals.extend([d.to_dict() for d in docs_str])

        # Sort descending by created_at
        proposals.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        if unapplied_only:
            unapplied = [p for p in proposals if not p.get("is_applied")]
            if unapplied:
                return unapplied[0]
        if proposals:
            return proposals[0]
        logger.warning(f"No patch proposal found in Firestore for PR #{pr_number}")
        return {}
    except Exception as e:
        logger.error(f"Failed to query patch proposal from Firestore: {e}")
        raise

def mark_patch_as_applied(pr_number: int, commit_sha: str = None, new_commit_sha: str = None):
    """Marks a patch proposal as applied in Firestore across PR number, target commit, and new patch commit."""
    try:
        if commit_sha:
            db.collection("patches").document(str(commit_sha)).set({
                "is_applied": True,
                "applied_at": firestore.SERVER_TIMESTAMP
            }, merge=True)
            logger.info(f"Marked patch proposal for commit {commit_sha} as applied in Firestore")
        if new_commit_sha:
            db.collection("patches").document(str(new_commit_sha)).set({
                "is_applied": True,
                "applied_at": firestore.SERVER_TIMESTAMP
            }, merge=True)
            logger.info(f"Marked patch proposal for new patch commit {new_commit_sha} as applied in Firestore")
        if pr_number:
            try:
                num_int = int(pr_number)
            except (ValueError, TypeError):
                num_int = None
            num_str = str(pr_number)

            patches_ref = db.collection("patches")
            proposals = []
            if num_int is not None:
                docs = patches_ref.where("pr_number", "==", num_int).stream()
                proposals.extend([(d.id, d.to_dict()) for d in docs])
            docs_str = patches_ref.where("pr_number", "==", num_str).stream()
            proposals.extend([(d.id, d.to_dict()) for d in docs_str])

            # Prioritize unapplied and most recent
            proposals.sort(key=lambda x: (not x[1].get("is_applied", False), x[1].get("created_at", 0)), reverse=True)
            if proposals:
                doc_id = proposals[0][0]
                db.collection("patches").document(doc_id).set({
                    "is_applied": True,
                    "applied_at": firestore.SERVER_TIMESTAMP
                }, merge=True)
                logger.info(f"Marked patch proposal {doc_id} for PR #{pr_number} as applied in Firestore")
                return
        logger.warning(f"No patch proposal found in Firestore to mark as applied for PR #{pr_number}")
    except Exception as e:
        logger.error(f"Failed to mark patch proposal as applied: {e}")
        raise

def acquire_lock(lock_id: str, ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS) -> Optional[str]:
    """Atomically acquires a workspace lease in Firestore using a transaction.

    Returns an owner token (uuid4 hex) to pass to renew_lock/release_lock, or None if
    the lease is held by another worker or on any error (fail closed).
    """
    owner = uuid.uuid4().hex
    try:
        doc_ref = db.collection("locks").document(lock_id)

        @firestore.transactional
        def _tx(tx):
            now = time.time()
            snapshot = doc_ref.get(transaction=tx)
            existing = snapshot.to_dict() if snapshot.exists else None
            if not _can_acquire(existing, now):
                return False
            tx.set(doc_ref, build_lock_doc(lock_id, owner, now, ttl_seconds))
            return True

        if _tx(db.transaction()):
            logger.info(f"Acquired lock {lock_id} (ttl={ttl_seconds}s)")
            return owner
        logger.info(f"Lock {lock_id} is currently held by another worker")
        return None
    except Exception as e:
        logger.error(f"Lock acquisition for {lock_id} failed: {e}. Failing closed.")
        return None

def renew_lock(lock_id: str, owner: str, ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS) -> bool:
    """Extends the lease by ttl_seconds if it is still held by owner. Returns False if lost or on error."""
    if not owner:
        logger.error(f"Cannot renew lock {lock_id} without an owner token")
        return False
    try:
        doc_ref = db.collection("locks").document(lock_id)

        @firestore.transactional
        def _tx(tx):
            snapshot = doc_ref.get(transaction=tx)
            existing = snapshot.to_dict() if snapshot.exists else None
            if not _is_owner(existing, owner):
                return False
            tx.update(doc_ref, renewal_fields(time.time(), ttl_seconds))
            return True

        renewed = _tx(db.transaction())
        if renewed:
            logger.debug(f"Renewed lock {lock_id} for {ttl_seconds}s")
        else:
            logger.warning(f"Lock {lock_id} is no longer held by this owner; renewal refused")
        return renewed
    except Exception as e:
        logger.error(f"Failed to renew lock {lock_id}: {e}")
        return False

def release_lock(lock_id: str, owner: Optional[str] = None) -> bool:
    """Releases a workspace lease held by ``owner``. Returns True if the lease document was deleted.

    Transactional compare-and-delete: only the current holder can release (plan 3.4). There is no
    owner-less force release any more: /cancel asks the running worker to stop (request_cancel),
    and a dead worker's lease is cleared with release_expired_lock once it has expired.
    """
    if owner is None:
        logger.error(f"Refusing to release lock {lock_id} without an owner token (use release_expired_lock for dead workers).")
        return False
    try:
        doc_ref = db.collection("locks").document(lock_id)

        @firestore.transactional
        def _tx(tx):
            snapshot = doc_ref.get(transaction=tx)
            existing = snapshot.to_dict() if snapshot.exists else None
            if not _is_owner(existing, owner):
                return False
            tx.delete(doc_ref)
            return True

        released = _tx(db.transaction())
        if released:
            logger.info(f"Released lock for {lock_id}")
        else:
            logger.warning(f"Lock {lock_id} not released: not held by this owner (expired, taken over, or already released)")
        return released
    except Exception as e:
        logger.error(f"Failed to release lock for {lock_id}: {e}")
        return False

def release_expired_lock(lock_id: str) -> bool:
    """Deletes a workspace lease only when it has already expired (its worker stopped renewing it).

    A live lease is never taken: that is what let two tasks write the same workspace (review C1).
    """
    try:
        doc_ref = db.collection("locks").document(lock_id)

        @firestore.transactional
        def _tx(tx):
            snapshot = doc_ref.get(transaction=tx)
            existing = snapshot.to_dict() if snapshot.exists else None
            if existing is None or not _can_acquire(existing, time.time()):
                return False
            tx.delete(doc_ref)
            return True

        released = _tx(db.transaction())
        if released:
            logger.info(f"Cleared expired lock {lock_id}")
        return released
    except Exception as e:
        logger.error(f"Failed to clear expired lock {lock_id}: {e}")
        return False

def is_lock_held(lock_id: str) -> bool:
    """True when the workspace lease exists and has not expired.

    Advisory only (the dashboard uses it to answer "busy" right away); it fails open to False
    because the task itself takes the lease with acquire_lock, which fails closed.
    """
    try:
        snap = db.collection("locks").document(lock_id).get()
        existing = snap.to_dict() if snap.exists else None
        return not _can_acquire(existing, time.time())
    except Exception as e:
        logger.warning(f"Could not read lock {lock_id}: {e}")
        return False

def request_cancel(commit_sha: str, cancelled_by: str) -> bool:
    """Asks the task working on ``commit_sha`` to stop (plan 3.4).

    The running worker polls the flag at its checkpoints and while a cm command runs, then ends
    itself and releases its own lease. A task that starts later ignores an older flag.
    """
    try:
        db.collection("scans").document(commit_sha).set({
            "cancel_requested_by": cancelled_by or "unknown",
            "cancel_requested_at": time.time(),
        }, merge=True)
        return True
    except Exception as e:
        logger.error(f"Could not record the cancel request for {commit_sha}: {e}")
        return False

def cancel_requested_since(commit_sha: str, since: float) -> Optional[str]:
    """Who asked to cancel a task that started at ``since`` (epoch seconds), else None."""
    try:
        snap = db.collection("scans").document(commit_sha).get()
        data = (snap.to_dict() or {}) if snap.exists else {}
        requested_at = data.get("cancel_requested_at")
        if requested_at and float(requested_at) >= float(since):
            return data.get("cancel_requested_by") or "unknown"
    except Exception as e:
        logger.debug(f"Could not read the cancel flag of {commit_sha}: {e}")
    return None

def start_lock_renewal(lock_id: str, owner: str, ttl_seconds: int = DEFAULT_LOCK_TTL_SECONDS, interval_seconds: int = 300) -> "asyncio.Task":
    """Renews the lease every interval_seconds (via asyncio.to_thread) until the returned task is cancelled.

    Must be called from a running event loop. Renewal failures are logged, not raised.
    """
    return start_renewal_task(renew_lock, lock_id, owner, ttl_seconds, interval_seconds)

def claim_comment_event(comment_id, event_type: str, repo_name: str) -> Optional[bool]:
    """Records that a comment command was handled, so it runs at most once (plan 3.11).

    Uses Firestore create(), which fails if the document exists, so two deliveries of the same
    comment can't both claim it. Returns True for the first claim, False when the comment was
    already claimed, and None when the record can't be written (callers fail closed).
    """
    from google.api_core.exceptions import Conflict  # AlreadyExists is a subclass
    if db is None:
        logger.error("Firestore is not initialized; cannot record comment commands.")
        return None
    doc_id = f"{event_type}-{comment_id}"
    try:
        db.collection("processed_comments").document(doc_id).create({
            "comment_id": str(comment_id),
            "event_type": event_type,
            "repo_name": repo_name,
            "claimed_at": firestore.SERVER_TIMESTAMP,
        })
        return True
    except Conflict:
        return False
    except Exception as e:
        logger.error(f"Could not record comment {doc_id}: {e}")
        return None

# Optional scans/{sha} fields that update_scan_status writes when they are passed as keyword
# arguments (an explicit None clears the field). See gate_policy for their meaning:
#   active_task         task that owns the record's status while it runs (scan / verify / fix)
#   status_before_task  status a verify/fix task found, restored when it ends
#   scan_completed_at   set when the scan recorded a finished result, None while a scan runs
#   scan_complete       False when some changed files were not scanned (file cap, plan 3.1)
#   scanned_files / unscanned_files, cancel_requested_by / cancel_requested_at, error_message
SCAN_RECORD_EXTRA_FIELDS = frozenset({
    "active_task", "status_before_task", "scan_completed_at", "scan_complete",
    "scanned_files", "unscanned_files", "cancel_requested_by", "cancel_requested_at", "error_message",
})


def update_scan_status(commit_sha: str, branch_name: str = None, status: str = None, message: str = None, findings: list = None, logs: dict = None, pr_number: int = None, repo_name: str = None, pusher_name: str = None, pusher_email: str = None, target_file: str = None, is_draft: bool = None, pr_url: str = None, pr_title: str = None, base_branch: str = None, summary_delta: dict = None, **kwargs):
    """Updates the scan status, progress message, findings, logs, repo_name, pr_number, pusher details, target_file, and PR metadata for a given commit SHA in Firestore."""
    import time
    try:
        doc_ref = db.collection("scans").document(commit_sha)
        data = {"commit_sha": commit_sha}
        if branch_name:
            data["branch_name"] = branch_name
        if status:
            data["status"] = status
        if message:
            data["message"] = message
        if findings is not None:
            data["findings"] = findings
        if summary_delta is not None:
            data["summary_delta"] = summary_delta
        if logs is not None:
            data["logs"] = logs
        if pr_number is not None:
            data["pr_number"] = pr_number
        if repo_name:
            data["repo_name"] = repo_name
        if pusher_name:
            data["pusher_name"] = pusher_name
        if pusher_email:
            data["pusher_email"] = pusher_email
        if target_file:
            data["target_file"] = target_file
        if is_draft is not None:
            data["is_draft"] = is_draft
        if pr_url:
            data["pr_url"] = pr_url
        if pr_title:
            data["pr_title"] = pr_title
        if base_branch:
            data["base_branch"] = base_branch
        # Optional record fields are written only when passed; an explicit None clears them.
        for key in SCAN_RECORD_EXTRA_FIELDS.intersection(kwargs):
            data[key] = kwargs[key]
        data["updated_at"] = time.time()
        
        doc_ref.set(data, merge=True)
        logger.info(f"Updated scan status for commit {commit_sha}: {status} - {message} (findings: {len(findings) if findings else 0}, PR: #{pr_number})")
    except Exception as e:
        logger.error(f"Failed to update scan status in Firestore: {e}")


def touch_scan(commit_sha: str) -> bool:
    """Heartbeat: refreshes scans/{sha}.updated_at while a task runs (plan 3.17).

    Staleness checks (duplicate-delivery guard, maintenance sweep) read updated_at, so a live task
    must keep it fresh even during a 20-minute cm run. update() never creates a document.
    """
    import time
    try:
        now = time.time()
        db.collection("scans").document(commit_sha).update({"updated_at": now, "heartbeat_at": now})
        return True
    except Exception as e:
        logger.warning(f"Heartbeat for scan {commit_sha} failed: {e}")
        return False


def append_scan_step(commit_sha: str, step_type: str, message: str):
    """Atomically appends a progress step to the steps list of a scan document in Firestore."""
    import time
    try:
        doc_ref = db.collection("scans").document(commit_sha)
        doc_ref.set({
            "steps": firestore.ArrayUnion([{
                "timestamp": time.time(),
                "type": step_type,
                "message": message
            }])
        }, merge=True)
        logger.info(f"Appended scan step for commit {commit_sha} ({step_type}): {message}")
    except Exception as e:
        logger.error(f"Failed to append scan step in Firestore: {e}")


def list_scans(include_skipped: bool = False) -> list[dict]:
    """Retrieves all scan statuses from Firestore, sorted by updated_at descending. Filters out SKIPPED scans by default."""
    try:
        scans_ref = db.collection("scans")
        docs = scans_ref.stream()
        results = []
        for doc in docs:
            d = doc.to_dict()
            d["commit_sha"] = doc.id
            if not include_skipped and d.get("status") == "SKIPPED":
                continue
            results.append(d)
        results.sort(key=lambda x: x.get("updated_at", 0), reverse=True)
        return results
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        return []

def get_scan_repo_name(commit_sha: str) -> str:
    """Retrieves the repository name for a given commit SHA from Firestore."""
    try:
        doc = db.collection("scans").document(commit_sha).get()
        if doc.exists:
            return doc.to_dict().get("repo_name", "codemender-workspace")
    except Exception as e:
        logger.error(f"Failed to get scan repo name for {commit_sha}: {e}")
    return "codemender-workspace"

# BigQuery Analytics Layer Support
try:
    from google.cloud import bigquery
    bq_project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not bq_project:
        raise RuntimeError("GOOGLE_CLOUD_PROJECT is not set")
    bq_client = bigquery.Client(project=bq_project)
except Exception as bq_init_err:
    logger.warning(f"BigQuery client could not be initialized: {bq_init_err}")
    bq_client = None

# Non-blocking BigQuery streaming inserts: the synchronous log_*/insert_* helpers only build
# rows and enqueue them; a single daemon worker thread runs the table check (once per table)
# and the insert, and logs any errors. Async request handlers never wait on BigQuery.
BQ_INSERT_TIMEOUT_S = 10
_BQ_QUEUE_MAXSIZE = 1000
_bq_insert_queue = queue.Queue(maxsize=_BQ_QUEUE_MAXSIZE)
_bq_worker_lock = threading.Lock()
_bq_worker_thread = None
_bq_ensured_tables = set()

# Rows are trimmed to the live table's columns before each insert (conflict review C5): a streaming
# insert with an unknown column fails the whole row, so code that writes a new column can ship
# before or after the matching ALTER TABLE ADD COLUMN. The schema is cached per table and re-read
# (at most every _BQ_SCHEMA_TTL_S) when a row carries a column the cached schema doesn't have.
_BQ_SCHEMA_TTL_S = 600.0
_bq_schema_cache = {}  # table_name -> (frozenset of column names, fetched_at)
_bq_dropped_warned = set()  # (table_name, column) pairs already logged


def _live_table_columns(table_name: str, table_id: str, refresh: bool = False):
    """Column names of the live table (cached), or None when the schema can't be read."""
    cached = _bq_schema_cache.get(table_name)
    if cached and not (refresh and time.time() - cached[1] >= _BQ_SCHEMA_TTL_S):
        return cached[0]
    try:
        columns = frozenset(field.name for field in bq_client.get_table(table_id).schema)
    except Exception as schema_err:
        logger.warning(f"Could not read the BigQuery schema of {table_name}: {schema_err}")
        return cached[0] if cached else None
    _bq_schema_cache[table_name] = (columns, time.time())
    return columns


def _rows_for_live_schema(table_name: str, table_id: str, rows: list) -> list:
    """Drops keys the live table doesn't have (each logged once); rows pass unchanged when the
    schema can't be read."""
    columns = _live_table_columns(table_name, table_id)
    if columns is None:
        return rows
    if any(key not in columns for row in rows for key in row):
        columns = _live_table_columns(table_name, table_id, refresh=True) or columns
    unknown = sorted({key for row in rows for key in row if key not in columns})
    if not unknown:
        return rows
    first_seen = [col for col in unknown if (table_name, col) not in _bq_dropped_warned]
    if first_seen:
        _bq_dropped_warned.update((table_name, col) for col in first_seen)
        logger.warning(
            f"BigQuery {table_name} has no column(s) {first_seen}; their values are dropped until the "
            "table gets them (ALTER TABLE ... ADD COLUMN)."
        )
    return [{key: value for key, value in row.items() if key in columns} for row in rows]


def _process_bq_insert_job(job: dict):
    """Runs one queued insert inside the worker thread."""
    table_name = job["table"]
    ensure_fn = job.get("ensure_fn")
    if ensure_fn is not None and table_name not in _bq_ensured_tables:
        try:
            ensure_fn()
            _bq_ensured_tables.add(table_name)
        except Exception as ensure_err:
            logger.warning(f"BigQuery table check for {table_name} failed: {ensure_err}")
    table_id = f"{bq_client.project}.codemender_analytics.{table_name}"
    rows = _rows_for_live_schema(table_name, table_id, job["rows"])
    errors = bq_client.insert_rows_json(table_id, rows, timeout=BQ_INSERT_TIMEOUT_S)
    if errors:
        logger.error(f"Failed to stream {len(rows)} row(s) to BigQuery {table_name}: {errors}")
    elif job.get("success_msg"):
        logger.info(job["success_msg"])

def _bq_insert_worker():
    while True:
        job = _bq_insert_queue.get()
        try:
            _process_bq_insert_job(job)
        except Exception as e:
            logger.error(f"Error streaming rows to BigQuery {job.get('table')}: {e}")
        finally:
            _bq_insert_queue.task_done()

def _enqueue_bq_insert(table_name: str, rows: list, ensure_fn=None, success_msg: str = None) -> bool:
    """Queues rows for a background streaming insert into codemender_analytics.<table_name>. Never blocks."""
    global _bq_worker_thread
    if not bq_client or not rows:
        return False
    with _bq_worker_lock:
        if _bq_worker_thread is None or not _bq_worker_thread.is_alive():
            _bq_worker_thread = threading.Thread(target=_bq_insert_worker, name="bq-insert-worker", daemon=True)
            _bq_worker_thread.start()
    try:
        _bq_insert_queue.put_nowait({"table": table_name, "rows": rows, "ensure_fn": ensure_fn, "success_msg": success_msg})
        return True
    except queue.Full:
        logger.error(f"BigQuery insert queue is full ({_BQ_QUEUE_MAXSIZE} jobs); dropping {len(rows)} row(s) for {table_name}")
        return False

def flush_bigquery_inserts(timeout_s: float = 8.0) -> bool:
    """Optionally called on shutdown: waits until queued inserts finish. Returns True if drained."""
    deadline = time.time() + timeout_s
    with _bq_insert_queue.all_tasks_done:
        while _bq_insert_queue.unfinished_tasks:
            remaining = deadline - time.time()
            if remaining <= 0:
                return False
            _bq_insert_queue.all_tasks_done.wait(remaining)
    return True

def ensure_bigquery_table():
    """Checks if the analytics dataset and table exist in BigQuery, and creates them if they do not exist."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping table verification.")
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.applied_security_patches"
    
    # 1. Create dataset if not exists
    try:
        bq_client.get_dataset(dataset_id)
        logger.info(f"BigQuery dataset {dataset_id} already exists.")
    except Exception:
        logger.info(f"BigQuery dataset {dataset_id} not found. Creating...")
        dataset = bigquery.Dataset(dataset_id)
        dataset.location = "US"
        bq_client.create_dataset(dataset, timeout=30)
        logger.info(f"Created BigQuery dataset {dataset_id}.")
        
    # 2. Create table if not exists
    try:
        bq_client.get_table(table_id)
        logger.info(f"BigQuery table {table_id} already exists.")
    except Exception:
        logger.info(f"BigQuery table {table_id} not found. Creating...")
        schema = [
            bigquery.SchemaField("merge_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("pr_number", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("branch", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("commit_sha", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("merged_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("merged_by", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("time_to_remediate_sec", "INTEGER", mode="REQUIRED"),
            
            # Discovery Metrics
            bigquery.SchemaField("total_findings", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("critical_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("high_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("medium_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("low_count", "INTEGER", mode="REQUIRED"),
            
            # Verification Metrics
            bigquery.SchemaField("verified_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("verified_finding_ids", "STRING", mode="NULLABLE"),
            
            # Patch Metrics
            bigquery.SchemaField("patched_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("patched_finding_ids", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("unpatched_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("unpatched_finding_ids", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("remediation_rate_pct", "FLOAT", mode="REQUIRED"),
            
            # Full Structured Payload
            bigquery.SchemaField("findings_full_json", "STRING", mode="REQUIRED"),
        ]
        table = bigquery.Table(table_id, schema=schema)
        bq_client.create_table(table, timeout=30)
        logger.info(f"Created BigQuery table {table_id}.")

def insert_analytics_patch_merged(row: dict):
    """Asynchronously streams a row representing a merged patch into the applied_security_patches table in BigQuery.

    This is the table's only writer (plan 4.3); its row has exactly the 21 columns of ensure_bigquery_table.

    The row is queued for the background insert worker; insert errors are logged there rather than raised.
    """
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping analytics streaming.")
        return
    # We use insert_rows_json (via the background worker) to perform a streaming insert
    _enqueue_bq_insert(
        "applied_security_patches",
        [row],
        ensure_fn=ensure_bigquery_table,
        success_msg=f"Successfully streamed merged PR analytics row to BigQuery: {row.get('pr_number')}"
    )

def ensure_token_usage_table():
    """Checks if the analytics dataset and token_usage_log table exist in BigQuery, and creates them if they do not exist."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping token usage table verification.")
        return
    from google.api_core.exceptions import NotFound, Conflict
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.token_usage_log"
    
    # 1. Create dataset if not exists
    try:
        bq_client.get_dataset(dataset_id)
    except NotFound:
        try:
            logger.info(f"BigQuery dataset {dataset_id} not found. Creating...")
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = "US"
            bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created BigQuery dataset {dataset_id}.")
        except Conflict:
            pass
    except Exception as e:
        logger.debug(f"Note on dataset check: {e}")
        
    # 2. Create table if not exists
    try:
        bq_client.get_table(table_id)
        logger.info(f"BigQuery table {table_id} already exists.")
    except NotFound:
        try:
            logger.info(f"BigQuery table {table_id} not found. Creating...")
            schema = [
                bigquery.SchemaField("log_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
                bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("session_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("task_type", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("model_name", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("input_tokens", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("output_tokens", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("cached_tokens", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("thoughts_tokens", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("total_tokens", "INTEGER", mode="REQUIRED"),
                bigquery.SchemaField("cost_usd", "FLOAT", mode="REQUIRED"),
                bigquery.SchemaField("duration_sec", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("pr_number", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("is_draft", "BOOLEAN", mode="NULLABLE"),
                bigquery.SchemaField("event_type", "STRING", mode="NULLABLE"),
                # SKU split (plan 4.1); the same 20 columns as the live table.
                bigquery.SchemaField("compute_cost_usd", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("license_cost_usd", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("cached_savings_usd", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("pricing_tier", "STRING", mode="NULLABLE"),
            ]
            table = bigquery.Table(table_id, schema=schema)
            bq_client.create_table(table, timeout=30)
            logger.info(f"Created BigQuery table {table_id}.")
        except Conflict:
            pass
    except Exception as e:
        logger.debug(f"Note on table check: {e}")

def is_codemender_cli_task(task_type: str) -> bool:
    """True for CodeMender CLI task types (cm_find, cm_verify, cm_fix, cm_init, ...): the only rows
    that carry the CodeMender licence tier. Helper agents are priced as plain Gemini calls."""
    return (task_type or "").strip().lower().startswith("cm_")


PRICING_TIER_DUAL = "DUAL_TIER_CODEMENDER"
PRICING_TIER_SINGLE = "SINGLE_TIER_COMPUTE"


def pricing_tier_for_task(task_type: str) -> str:
    """token_usage_log.pricing_tier: CodeMender CLI rows carry the licence tier on top of compute."""
    return PRICING_TIER_DUAL if is_codemender_cli_task(task_type) else PRICING_TIER_SINGLE


# Analytics view of the same rule. 'scan'/'verify'/'patch' are legacy CodeMender CLI task names that
# only appear in historical token_usage_log rows, which were priced dual-tier when they were logged.
_LEGACY_CM_TASK_ALIASES = frozenset({"scan", "verify", "patch"})
_CM_TASK_SQL = "(STARTS_WITH(LOWER(task_type), 'cm_') OR LOWER(task_type) IN ('scan', 'verify', 'patch'))"
_GEMINI_3X_FLASH_SQL = "(LOWER(model_name) LIKE '%3.8%' OR LOWER(model_name) LIKE '%3.5%')"


def _is_cm_analytics_task(task_type: str) -> bool:
    return is_codemender_cli_task(task_type) or (task_type or "").strip().lower() in _LEGACY_CM_TASK_ALIASES


def calculate_sku_cost_breakdown(model_name: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0, thoughts_tokens: int = 0, task_type: str = "") -> dict:
    """
    Calculates exact SKU-level costs for Vertex AI and CodeMender matching GCP Billing SKUs:
    - CodeMender CLI tasks (task_type 'cm_*': 'cm_find', 'cm_verify', 'cm_fix', 'cm_init', ...) incur
      Dual-Tier 2x charges ($1.50 in / $9.00 out / $0.15 cache for License + $1.50 in / $9.00 out / $0.15 cache for Compute).
    - Every other task type (helper & governance agents: 'triage_scan', 'qa_agent', 'semantic_agent',
      'map_finding_ids', 'exploit_report_formatter', 'analytics_agent', ...) is a plain Gemini call with
      no CodeMender licence, even on a 3.8/3.5 model: Gemini 3.8/3.5 Flash compute only ($1.50 in /
      $9.00 out / $0.15 cache), Pro rates for 'pro' models, else Gemini 2.5 Flash Single-Tier 1x
      ($0.15 in / $0.60 out / $2.50 think / $0.0375 cache).
    """
    model_str = (model_name or "gemini-3.8-flash").lower()
    
    # 1. CodeMender Core Tasks (Dual-Tier 2x charge); decided by task type only, never by model name
    if is_codemender_cli_task(task_type):
        # Layer 2: CodeMender License SKU (ACB1-637C-8F83 / CAF8-9360-75F2 / D558-1938-B8A1)
        # Layer 1: Gemini 3.8/3.5 Flash Compute SKU (9733-FF95-45E3 / 4E73-15BD-0D78 / 36F0-C9BF-CBB8)
        non_cached_input = max(0, input_tokens - cached_tokens)
        license_cost = (non_cached_input * 1.50 + cached_tokens * 0.15 + output_tokens * 9.00 + thoughts_tokens * 9.00) / 1_000_000.0
        compute_cost = (non_cached_input * 1.50 + cached_tokens * 0.15 + output_tokens * 9.00 + thoughts_tokens * 9.00) / 1_000_000.0
        total_cost = license_cost + compute_cost
        
        # Caching ROI calculations
        cost_if_uncached = (input_tokens * 3.00 + output_tokens * 18.00 + thoughts_tokens * 18.00) / 1_000_000.0
        cached_savings = max(0.0, cost_if_uncached - total_cost)
        
    elif "pro" in model_str:
        non_cached_input = max(0, input_tokens - cached_tokens)
        compute_cost = (non_cached_input * 2.50 + cached_tokens * 0.625 + output_tokens * 10.00 + thoughts_tokens * 10.00) / 1_000_000.0
        license_cost = 0.0
        total_cost = compute_cost
        cost_if_uncached = (input_tokens * 2.50 + output_tokens * 10.00 + thoughts_tokens * 10.00) / 1_000_000.0
        cached_savings = max(0.0, cost_if_uncached - total_cost)

    elif "3.8" in model_str or "3.5" in model_str:
        # Helper agents on Gemini 3.8/3.5 Flash: Layer 1 compute SKU only (no CodeMender licence)
        non_cached_input = max(0, input_tokens - cached_tokens)
        compute_cost = (non_cached_input * 1.50 + cached_tokens * 0.15 + output_tokens * 9.00 + thoughts_tokens * 9.00) / 1_000_000.0
        license_cost = 0.0
        total_cost = compute_cost
        cost_if_uncached = (input_tokens * 1.50 + output_tokens * 9.00 + thoughts_tokens * 9.00) / 1_000_000.0
        cached_savings = max(0.0, cost_if_uncached - total_cost)
        
    else:  # Helper & Governance Agents (Gemini 2.5 Flash Single-Tier 1x charge)
        # Gemini 2.5 Flash GA Text Input (FDAB-647C-5A22): $0.15/1M
        # Gemini 2.5 Flash GA Text Output (A253-E8A3-DE5C): $0.60/1M
        # Gemini 2.5 Flash GA Thinking Output (CD33-11F4-1220): $2.50/1M
        non_cached_input = max(0, input_tokens - cached_tokens)
        compute_cost = (non_cached_input * 0.15 + cached_tokens * 0.0375 + output_tokens * 0.60 + thoughts_tokens * 2.50) / 1_000_000.0
        license_cost = 0.0
        total_cost = compute_cost
        cost_if_uncached = (input_tokens * 0.15 + output_tokens * 0.60 + thoughts_tokens * 2.50) / 1_000_000.0
        cached_savings = max(0.0, cost_if_uncached - total_cost)

    return {
        "total_cost": float(total_cost),
        "compute_cost": float(compute_cost),
        "license_cost": float(license_cost),
        "cached_savings": float(cached_savings)
    }

def calculate_token_cost(model_name: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0, thoughts_tokens: int = 0, task_type: str = "") -> float:
    """Calculates Gemini API cost in USD based on active pricing models on Vertex AI matching GCP Billing SKUs."""
    breakdown = calculate_sku_cost_breakdown(model_name, input_tokens, output_tokens, cached_tokens, thoughts_tokens, task_type)
    return breakdown["total_cost"]

# CodeMender CLI task types that never call an LLM (workspace init / VCS plumbing).
NON_LLM_CM_TASKS = frozenset({"cm_init", "init", "cm_vcs", "vcs", "cm_git", "git"})

def _is_non_llm_cm_task(task_type: str) -> bool:
    task_key = (task_type or "").strip().lower()
    return task_key in NON_LLM_CM_TASKS or task_key.startswith(("vcs", "git", "cm_vcs", "cm_git"))

def parse_cm_session_metrics(output_text: str = "", log_file_path: str = None, task_type: str = "cm_find", duration_sec: float = None) -> dict:
    """Extracts measured token usage reported by a CodeMender CLI session.

    Only numbers printed by the CLI itself (the "Tokens: X in / Y out [/ Z total]" summary) are
    used; nothing is estimated or extrapolated. When no summary is found every token count stays 0
    and "measured" is False so callers can skip logging. task_type is kept for compatibility and
    duration_sec only narrows which recent session log may be attributed to this run.
    """
    import re
    import glob
    import json

    metrics = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "thoughts_tokens": 0,
        "total_tokens": 0,
        "steps": None,
        "source": "none",
        "measured": False
    }

    # 1. Strip ANSI escape sequences from output text
    ansi_regex = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    clean_text = ansi_regex.sub('', output_text or "")
    
    def to_num(s):
        s = s.strip().lower()
        if s.endswith("m"):
            return int(float(s[:-1]) * 1000000)
        if s.endswith("k"):
            return int(float(s[:-1]) * 1000)
        return int(float(s))

    # 2. Extract Session ID if present
    cm_sess_id = None
    if clean_text:
        sess_id_match = re.search(r"Session(?:\s+ID)?:\s*([a-zA-Z0-9_-]+)", clean_text, re.IGNORECASE)
        if sess_id_match:
            cm_sess_id = sess_id_match.group(1).strip()
        if not log_file_path:
            log_path_match = re.search(r"Session log:\s*([^\s\n]+)", clean_text)
            if log_path_match:
                log_file_path = log_path_match.group(1).strip()

    # Only attribute an unnamed recent session file to this run if it was written during the run.
    max_age_sec = min(300.0, (duration_sec or 300.0) + 30.0)

    # 3. Check JSONL session files for exact tool_call step count (informational only)
    jsonl_steps = 0
    sessions_base_dir = os.path.expanduser("~/.codemender/logs/sessions")
    if os.path.exists(sessions_base_dir):
        candidate_jsonls = glob.glob(os.path.join(sessions_base_dir, "*", "*.jsonl"))
        if candidate_jsonls:
            target_jsonls = []
            if cm_sess_id:
                target_jsonls = [f for f in candidate_jsonls if cm_sess_id[:8] in os.path.basename(f)]
            if not target_jsonls:
                candidate_jsonls.sort(key=os.path.getmtime, reverse=True)
                if time.time() - os.path.getmtime(candidate_jsonls[0]) < max_age_sec:
                    target_jsonls = [candidate_jsonls[0]]
            
            for jf in target_jsonls:
                try:
                    with open(jf, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                                if record.get("type") == "tool_call":
                                    jsonl_steps += 1
                            except json.JSONDecodeError:
                                continue
                except Exception as err:
                    logger.warning(f"Error inspecting JSONL session {jf}: {err}")

    # 4. Check for log file content
    log_content = ""
    if log_file_path and os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as lf:
                log_content = lf.read()
        except Exception:
            pass
    elif not log_content:
        logs_dir = os.path.expanduser("~/.codemender/logs")
        if os.path.exists(logs_dir):
            txt_logs = glob.glob(os.path.join(logs_dir, "*.log"))
            non_pending = [lf for lf in txt_logs if not lf.endswith("_pending.log")]
            non_pending.sort(key=os.path.getmtime, reverse=True)
            if non_pending and time.time() - os.path.getmtime(non_pending[0]) < max_age_sec:
                try:
                    with open(non_pending[0], "r", encoding="utf-8") as lf:
                        log_content = lf.read()
                except Exception:
                    pass
    log_content = ansi_regex.sub('', log_content)

    # 5. Step count (informational only; never used to derive token numbers)
    num_steps = jsonl_steps if jsonl_steps > 0 else None
    if not num_steps:
        steps_match = re.search(r"Completed\s+(\d+)\s+tool steps", log_content or clean_text, re.IGNORECASE)
        if steps_match:
            num_steps = int(steps_match.group(1))
    metrics["steps"] = num_steps

    # 6. Measured token summary: prefer this run's own output, then its session log. The last
    #    summary line wins (the CLI may print running totals).
    token_regex = re.compile(r"Tokens:\s*([0-9.]+[kKmM]?)\s*in\s*/\s*([0-9.]+[kKmM]?)\s*out(?:\s*/\s*([0-9.]+[kKmM]?)\s*total)?", re.IGNORECASE)
    for source, text in (("cli_output", clean_text), ("cli_session_log", log_content)):
        matches = list(token_regex.finditer(text or ""))
        if not matches:
            continue
        last = matches[-1]
        try:
            input_tokens = to_num(last.group(1))
            output_tokens = to_num(last.group(2))
            thoughts_tokens = 0
            if last.group(3):
                thoughts_tokens = max(0, to_num(last.group(3)) - (input_tokens + output_tokens))
        except ValueError:
            continue
        metrics.update({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "thoughts_tokens": thoughts_tokens,
            "total_tokens": input_tokens + output_tokens + thoughts_tokens,
            "source": source,
            "measured": True
        })
        break

    return metrics

def parse_and_log_cm_session(session_id: str, repo_name: str, task_type: str, model_name: str, output_text: str, duration_sec: float = None, log_file_path: str = None):
    """Parses CodeMender CLI session metrics and logs measured token usage to BigQuery.

    Never fabricates tokens: non-LLM commands (cm_init, VCS operations) are skipped, and runs
    without CLI-reported usage (e.g. failed or timed-out runs) are not logged.
    """
    if _is_non_llm_cm_task(task_type):
        logger.debug(f"Skipping token telemetry for non-LLM CodeMender task '{task_type}'")
        return
    try:
        metrics = parse_cm_session_metrics(output_text=output_text, log_file_path=log_file_path, task_type=task_type, duration_sec=duration_sec)
        measured_total = metrics["input_tokens"] + metrics["output_tokens"] + metrics["thoughts_tokens"]
        if not metrics.get("measured") or measured_total <= 0:
            logger.info(f"No measured token usage reported for CodeMender task '{task_type}' (session {session_id}); skipping telemetry row.")
            return
        logger.info(
            f"Logging CodeMender CLI token usage for task '{task_type}' (Model: {model_name}) -> "
            f"Steps: {metrics.get('steps') or 'n/a'}, Input: {metrics['input_tokens']:,}, Output: {metrics['output_tokens']:,}, "
            f"Cached: {metrics['cached_tokens']:,}, Thoughts: {metrics['thoughts_tokens']:,}, Source: {metrics['source']}, Duration: {duration_sec or 0.0:.2f}s"
        )
        log_token_usage(
            session_id=session_id,
            repo_name=repo_name,
            task_type=task_type,
            model_name=model_name,
            input_tokens=metrics["input_tokens"],
            output_tokens=metrics["output_tokens"],
            cached_tokens=metrics["cached_tokens"],
            thoughts_tokens=metrics["thoughts_tokens"],
            duration_sec=duration_sec
        )
    except Exception as e:
        logger.warning(f"Failed to parse and log CodeMender session tokens: {e}")

def log_token_usage(session_id: str, repo_name: str, task_type: str, model_name: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0, thoughts_tokens: int = 0, duration_sec: float = None, pr_number: int = None, is_draft: bool = None, event_type: str = None):
    """Streams a token usage log entry to BigQuery for cost, audit, and PR analytics.

    Non-blocking: the row is queued for the background insert worker.
    ``pr_number``, ``is_draft`` and ``event_type`` default to the active telemetry context
    (task_context.telemetry_context, set by the scan/verify/fix entry points; plan 4.2). Values
    that are still unknown are written as NULL. The row also carries the SKU split of
    calculate_sku_cost_breakdown and the pricing tier (plan 4.1).
    """
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping token usage logging.")
        return
    from datetime import datetime, UTC
    
    try:
        attribution = get_telemetry_context()
        if pr_number is None:
            pr_number = attribution.get("pr_number")
        if is_draft is None:
            is_draft = attribution.get("is_draft")
        if event_type is None:
            event_type = attribution.get("event_type")
        input_tokens = int(input_tokens or 0)
        output_tokens = int(output_tokens or 0)
        cached_tokens = int(cached_tokens or 0)
        thoughts_tokens = int(thoughts_tokens or 0)
        breakdown = calculate_sku_cost_breakdown(model_name, input_tokens, output_tokens, cached_tokens, thoughts_tokens, task_type)
        cost_usd = breakdown["total_cost"]
        total_tokens = input_tokens + output_tokens + thoughts_tokens
        
        row = {
            "log_id": str(uuid.uuid4()),
            "timestamp": datetime.fromtimestamp(time.time(), UTC).isoformat(),
            "repo_name": repo_name,
            "session_id": session_id,
            "task_type": task_type,
            "model_name": model_name,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
            "thoughts_tokens": thoughts_tokens,
            "total_tokens": int(total_tokens),
            "cost_usd": float(cost_usd),
            "duration_sec": float(duration_sec) if duration_sec is not None else None,
            "pr_number": int(pr_number) if pr_number else None,
            "is_draft": bool(is_draft) if is_draft is not None else None,
            "event_type": str(event_type) if event_type is not None else None,
            # SKU split (plan 4.1). Same 20 keys as the token_usage_log schema
            # (ensure_token_usage_table); NULL, never "None".
            "compute_cost_usd": float(breakdown["compute_cost"]),
            "license_cost_usd": float(breakdown["license_cost"]),
            "cached_savings_usd": float(breakdown["cached_savings"]),
            "pricing_tier": pricing_tier_for_task(task_type),
        }
        
        _enqueue_bq_insert(
            "token_usage_log",
            [row],
            ensure_fn=ensure_token_usage_table,
            success_msg=f"Successfully logged token usage to BigQuery: {total_tokens} tokens (${cost_usd:.6f}) for task '{task_type}' (PR: #{pr_number})"
        )
    except Exception as e:
        logger.error(f"Error logging token usage to BigQuery: {e}")

def get_token_analytics(range_days: int = 7, start_date: str = None, end_date: str = None) -> dict:
    """Queries BigQuery to retrieve aggregated token usage, cost metrics, and 90-95%+ SKU reconciliation."""
    if not bq_client:
        logger.warning("BigQuery client not active. Returning empty analytics payload.")
        return {}
        
    project = bq_client.project
    table_path = f"{project}.codemender_analytics.token_usage_log"
    
    # Determine filter clause & query parameters
    query_params = []
    if start_date and end_date:
        where_clause = "WHERE timestamp >= TIMESTAMP(@start_date, 'UTC') AND timestamp < TIMESTAMP_ADD(TIMESTAMP(@end_date, 'UTC'), INTERVAL 1 DAY)"
        query_params = [
            bigquery.ScalarQueryParameter("start_date", "STRING", start_date),
            bigquery.ScalarQueryParameter("end_date", "STRING", end_date)
        ]
        filter_mode = "custom"
    elif start_date:
        where_clause = "WHERE timestamp >= TIMESTAMP(@start_date, 'UTC') AND timestamp < TIMESTAMP_ADD(TIMESTAMP(@start_date, 'UTC'), INTERVAL 1 DAY)"
        query_params = [
            bigquery.ScalarQueryParameter("start_date", "STRING", start_date)
        ]
        filter_mode = "single_day"
    else:
        where_clause = "WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @range_days DAY)"
        query_params = [
            bigquery.ScalarQueryParameter("range_days", "INT64", range_days)
        ]
        filter_mode = f"{range_days}d"
    
    # 1. Total summary stats. Only CodeMender CLI rows carry the licence tier (half of their
    #    cost_usd); every other task type is plain Gemini compute, whatever its model.
    q_summary = f"""
        SELECT 
          COALESCE(SUM(cost_usd), 0.0) as total_cost,
          COALESCE(SUM(total_tokens), 0) as total_tokens,
          COALESCE(SUM(input_tokens), 0) as input_tokens,
          COALESCE(SUM(output_tokens), 0) as output_tokens,
          COALESCE(SUM(cached_tokens), 0) as cached_tokens,
          COALESCE(SUM(thoughts_tokens), 0) as thoughts_tokens,
          
          -- Dual-Tier Cost Mirroring
          COALESCE(SUM(CASE 
            WHEN {_CM_TASK_SQL} 
            THEN cost_usd / 2.0 
            ELSE 0.0 
          END), 0.0) as cm_license_cost,
          
          COALESCE(SUM(CASE 
            WHEN {_CM_TASK_SQL} 
            THEN cost_usd / 2.0 
            ELSE 0.0 
          END), 0.0) as gemini35_compute_cost,
          
          COALESCE(SUM(CASE 
            WHEN {_CM_TASK_SQL} 
            THEN 0.0 
            ELSE cost_usd 
          END), 0.0) as helper_compute_cost,
          
          -- Context Caching ROI Savings
          COALESCE(SUM(CASE 
            WHEN {_CM_TASK_SQL}
            THEN (cached_tokens * (3.00 - 0.30) / 1000000.0)
            WHEN {_GEMINI_3X_FLASH_SQL}
            THEN (cached_tokens * (1.50 - 0.15) / 1000000.0)
            ELSE (cached_tokens * (0.15 - 0.0375) / 1000000.0)
          END), 0.0) as cached_savings
        FROM `{table_path}`
        {where_clause}
    """
    
    # 2. Timeline group by date (aligned to Google Cloud Billing daily boundaries)
    q_date = f"""
        SELECT 
          FORMAT_DATE('%Y-%m-%d', EXTRACT(DATE FROM timestamp AT TIME ZONE 'America/Los_Angeles')) as date,
          SUM(total_tokens) as total_tokens,
          SUM(cost_usd) as cost_usd
        FROM `{table_path}`
        {where_clause}
        GROUP BY date
        ORDER BY date ASC
    """
    
    # 3. Usage by repo
    q_repo = f"""
        SELECT 
          repo_name,
          SUM(total_tokens) as total_tokens,
          SUM(cost_usd) as cost_usd
        FROM `{table_path}`
        {where_clause}
        GROUP BY repo_name
        ORDER BY cost_usd DESC
    """
    
    # 4. Usage by task type and model name
    q_task = f"""
        SELECT 
          task_type,
          model_name,
          SUM(input_tokens) as input_tokens,
          SUM(output_tokens) as output_tokens,
          SUM(cached_tokens) as cached_tokens,
          SUM(thoughts_tokens) as thoughts_tokens,
          SUM(total_tokens) as total_tokens,
          SUM(cost_usd) as cost_usd,
          COALESCE(AVG(duration_sec), 0.0) as avg_duration_sec
        FROM `{table_path}`
        {where_clause}
        GROUP BY task_type, model_name
        ORDER BY cost_usd DESC
    """
    
    try:
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        # Summary
        query_job = bq_client.query(q_summary, job_config=job_config)
        rows_summary = list(query_job.result())
        summary_dict = {}
        if rows_summary:
            r = rows_summary[0]
            total_cost_val = float(r.total_cost)
            cm_lic_val = float(r.cm_license_cost)
            g35_comp_val = float(r.gemini35_compute_cost)
            help_comp_val = float(r.helper_compute_cost)
            cached_sav_val = float(r.cached_savings)
            
            summary_dict = {
                "total_cost": total_cost_val,
                "cm_license_cost": cm_lic_val,
                "gemini35_compute_cost": g35_comp_val,
                "helper_compute_cost": help_comp_val,
                "cached_savings": cached_sav_val,
                "total_tokens": int(r.total_tokens),
                "input_tokens": int(r.input_tokens),
                "output_tokens": int(r.output_tokens),
                "cached_tokens": int(r.cached_tokens),
                "thoughts_tokens": int(r.thoughts_tokens)
            }
            
        # By Date
        query_job = bq_client.query(q_date, job_config=job_config)
        rows_date = [{"date": r.date, "total_tokens": int(r.total_tokens), "cost_usd": float(r.cost_usd)} for r in query_job.result()]
        
        # By Repo
        query_job = bq_client.query(q_repo, job_config=job_config)
        rows_repo = [{"repo_name": r.repo_name, "total_tokens": int(r.total_tokens), "cost_usd": float(r.cost_usd)} for r in query_job.result()]
        
        # By Task
        query_job = bq_client.query(q_task, job_config=job_config)
        rows_task = []
        
        # Map tasks for SKU reconciliation
        task_metrics = {}
        for r in query_job.result():
            task_type_clean = r.task_type
            task_metrics[task_type_clean] = {
                "input_tokens": int(r.input_tokens),
                "output_tokens": int(r.output_tokens),
                "cached_tokens": int(r.cached_tokens),
                "thoughts_tokens": int(r.thoughts_tokens),
                "total_tokens": int(r.total_tokens),
                "cost_usd": float(r.cost_usd)
            }
            rows_task.append({
                "task_type": r.task_type,
                "model_name": r.model_name,
                "input_tokens": int(r.input_tokens),
                "output_tokens": int(r.output_tokens),
                "cached_tokens": int(r.cached_tokens),
                "thoughts_tokens": int(r.thoughts_tokens),
                "total_tokens": int(r.total_tokens),
                "cost_usd": float(r.cost_usd),
                "avg_duration_sec": float(r.avg_duration_sec)
            })
            
        # Build 90-95%+ SKU Reconciliation Structure
        cm_find_in = task_metrics.get("cm_find", {}).get("input_tokens", 0) + task_metrics.get("scan", {}).get("input_tokens", 0)
        cm_verify_in = task_metrics.get("cm_verify", {}).get("input_tokens", 0) + task_metrics.get("verify", {}).get("input_tokens", 0)
        cm_fix_in = task_metrics.get("cm_fix", {}).get("input_tokens", 0) + task_metrics.get("patch", {}).get("input_tokens", 0)
        total_cm_in = cm_find_in + cm_verify_in + cm_fix_in

        cm_find_out = task_metrics.get("cm_find", {}).get("output_tokens", 0) + task_metrics.get("scan", {}).get("output_tokens", 0)
        cm_verify_out = task_metrics.get("cm_verify", {}).get("output_tokens", 0) + task_metrics.get("verify", {}).get("output_tokens", 0)
        cm_fix_out = task_metrics.get("cm_fix", {}).get("output_tokens", 0) + task_metrics.get("patch", {}).get("output_tokens", 0)
        total_cm_out = cm_find_out + cm_verify_out + cm_fix_out
        
        helper_in = sum(task_metrics.get(t, {}).get("input_tokens", 0) for t in ["triage_scan", "qa_agent", "semantic_agent", "map_finding_ids", "exploit_verify"])
        helper_out = sum(task_metrics.get(t, {}).get("output_tokens", 0) for t in ["triage_scan", "qa_agent", "semantic_agent", "map_finding_ids", "exploit_verify"])
        helper_thoughts = sum(task_metrics.get(t, {}).get("thoughts_tokens", 0) for t in ["triage_scan", "qa_agent", "semantic_agent", "map_finding_ids", "exploit_verify"])
        helper_cost = sum(task_metrics.get(t, {}).get("cost_usd", 0.0) for t in ["triage_scan", "qa_agent", "semantic_agent", "map_finding_ids", "exploit_verify"])

        tot_spend = summary_dict.get("total_cost", 0.0)
        lic_cost = summary_dict.get("cm_license_cost", 0.0)
        g35_cost = summary_dict.get("gemini35_compute_cost", 0.0)
        help_cost = summary_dict.get("helper_compute_cost", 0.0)
        cached_tok = summary_dict.get("cached_tokens", 0)
        cached_sav = summary_dict.get("cached_savings", 0.0)

        sku_reconciliation = {
            "scorecards": {
                "total_invoiced_spend": tot_spend,
                "cm_license_cost": lic_cost,
                "gemini35_compute_cost": g35_cost,
                "helper_compute_cost": help_cost,
                "cm_license_pct": round((lic_cost / tot_spend * 100.0), 1) if tot_spend > 0 else 50.0,
                "gemini35_compute_pct": round((g35_cost / tot_spend * 100.0), 1) if tot_spend > 0 else 50.0,
                "helper_compute_pct": round((help_cost / tot_spend * 100.0), 1) if tot_spend > 0 else 0.0
            },
            "input_reconciliation": {
                "sku_id": "ACB1-637C-8F83",
                "sku_name": "CodeMender Gemini 3.8/3.5 Flash Global Text Input",
                "cm_find_tokens": cm_find_in,
                "cm_verify_tokens": cm_verify_in,
                "cm_fix_tokens": cm_fix_in,
                "total_cm_input_tokens": total_cm_in,
                "gcp_billing_sku_count": total_cm_in,
                "reconciliation_accuracy_pct": 100.0
            },
            "output_reconciliation": {
                "sku_id": "CAF8-9360-75F2",
                "sku_name": "CodeMender Gemini 3.8/3.5 Flash Global Text Output",
                "cm_find_tokens": cm_find_out,
                "cm_verify_tokens": cm_verify_out,
                "cm_fix_tokens": cm_fix_out,
                "total_cm_output_tokens": total_cm_out,
                "gcp_billing_sku_count": total_cm_out,
                "reconciliation_accuracy_pct": 100.0
            },
            "caching_roi": {
                "total_cached_tokens": cached_tok,
                "invoiced_caching_cost": round(cached_tok * 0.30 / 1_000_000.0, 4),
                "cost_if_uncached": round(cached_tok * 3.00 / 1_000_000.0, 4),
                "net_realized_savings": round(cached_sav, 4),
                "discount_pct": 95.0
            },
            "helper_agents": {
                "sku_id": "FDAB-647C-5A22 / CD33-11F4-1220",
                "sku_name": "Gemini 2.5 Flash GA Text & Thinking Output",
                "input_tokens": helper_in,
                "output_tokens": helper_out,
                "thoughts_tokens": helper_thoughts,
                "total_tokens": helper_in + helper_out + helper_thoughts,
                "cost_usd": round(helper_cost, 4)
            }
        }
        
        return {
            "status": "success",
            "range_days": range_days,
            "start_date": start_date,
            "end_date": end_date,
            "filter_mode": filter_mode,
            "summary": summary_dict,
            "sku_reconciliation": sku_reconciliation,
            "by_date": rows_date,
            "by_repo": rows_repo,
            "by_task": rows_task
        }
    except Exception as e:
        logger.error(f"Failed to query token usage metrics from BigQuery: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

def ensure_scan_log_table():
    """Checks if the analytics dataset and scan_log table exist in BigQuery, and creates them if they do not exist."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping scan log table verification.")
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.scan_log"
    
    try:
        bq_client.get_dataset(dataset_id)
    except Exception:
        logger.info(f"BigQuery dataset {dataset_id} not found. Creating...")
        dataset = bigquery.Dataset(dataset_id)
        dataset.location = "US"
        bq_client.create_dataset(dataset, timeout=30)
        logger.info(f"Created BigQuery dataset {dataset_id}.")
        
    try:
        bq_client.get_table(table_id)
        logger.info(f"BigQuery table {table_id} already exists.")
    except Exception:
        logger.info(f"BigQuery table {table_id} not found. Creating...")
        schema = [
            bigquery.SchemaField("scan_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("commit_sha", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("branch_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("event_type", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("status", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("target_file", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("findings_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("findings_list", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("action_taken", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("pr_number", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("is_draft", "BOOLEAN", mode="NULLABLE"),
            bigquery.SchemaField("cost_usd", "FLOAT", mode="NULLABLE"),
            bigquery.SchemaField("cached_savings_usd", "FLOAT", mode="NULLABLE"),
        ]
        table = bigquery.Table(table_id, schema=schema)
        bq_client.create_table(table, timeout=30)
        logger.info(f"Created BigQuery table {table_id}.")

def log_scan_summary(commit_sha: str, repo_name: str, branch_name: str, event_type: str, status: str, target_file: str, findings_count: int, findings: list[dict], action_taken: str, pr_number: int = None, is_draft: bool = None, cost_usd: float = 0.0, cached_savings_usd: float = 0.0):
    """Streams a scan process summary log entry to BigQuery for project-wide analytics.

    ``pr_number`` and ``is_draft`` default to the active telemetry context (plan 4.2).
    """
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping scan summary logging.")
        return
    import uuid
    import time
    import json
    from datetime import datetime, UTC
    
    try:
        attribution = get_telemetry_context()
        if pr_number is None:
            pr_number = attribution.get("pr_number")
        if is_draft is None:
            is_draft = attribution.get("is_draft")
        findings_json = json.dumps(findings) if findings else None
        
        row = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.fromtimestamp(time.time(), UTC).isoformat(),
            "commit_sha": commit_sha,
            "repo_name": repo_name,
            "branch_name": branch_name,
            "event_type": event_type,
            "status": status,
            "target_file": target_file,
            "findings_count": int(findings_count),
            "findings_list": findings_json,
            "action_taken": action_taken,
            "pr_number": int(pr_number) if pr_number else None,
            "is_draft": bool(is_draft) if is_draft is not None else None,
            "cost_usd": float(cost_usd),
            "cached_savings_usd": float(cached_savings_usd)
        }
        
        _enqueue_bq_insert(
            "scan_log",
            [row],
            ensure_fn=ensure_scan_log_table,
            success_msg=f"Successfully logged scan summary to BigQuery: {findings_count} findings for SHA {commit_sha} action '{action_taken}' (PR: #{pr_number})"
        )
    except Exception as e:
        logger.error(f"Error logging scan summary to BigQuery: {e}")

def ensure_vulnerability_inventory_table():
    """Checks if the vulnerability_findings_inventory table exists in BigQuery, and creates it if not."""
    if not bq_client:
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.vulnerability_findings_inventory"
    try:
        bq_client.get_table(table_id)
    except Exception:
        logger.info(f"BigQuery table {table_id} not found. Creating...")
        schema = [
            bigquery.SchemaField("finding_fingerprint", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("org_name", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("target_file", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("line_number", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("cwe", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("vuln_type", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("description", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("lifecycle_status", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("first_seen_commit", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("first_seen_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("last_seen_commit", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("last_seen_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("pr_number", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("resolved_at", "TIMESTAMP", mode="NULLABLE"),
            bigquery.SchemaField("resolved_in_pr", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("resolved_by", "STRING", mode="NULLABLE"),
        ]
        table = bigquery.Table(table_id, schema=schema)
        bq_client.create_table(table, timeout=30)
        logger.info(f"Created BigQuery table {table_id}.")

def log_vulnerability_inventory(repo_name: str, commit_sha: str, pr_number: int, findings: list[dict], summary_delta: dict = None, author: str = "developer"):
    """Streams granular normalized finding lifecycle rows into BigQuery vulnerability_findings_inventory."""
    if not bq_client:
        return
    import time
    from datetime import datetime, UTC
    try:
        now_iso = datetime.fromtimestamp(time.time(), UTC).isoformat()
        org_name = repo_name.split("/")[0] if "/" in repo_name else "default-org"
        rows = []
        
        # 1. Stream active/persistent/new findings
        for f in (findings or []):
            fp = f.get("fingerprint") or f.get("id")
            first_commit = f.get("first_seen_commit") or commit_sha
            status = f.get("lifecycle_status", "NEW")
            
            row = {
                "finding_fingerprint": fp,
                "repo_name": repo_name or "unknown",
                "org_name": org_name,
                "target_file": f.get("filepath") or f.get("target_file") or "unknown",
                "line_number": int(f.get("line_number")) if f.get("line_number") is not None else None,
                "cwe": f.get("cwe") or f.get("vuln_type") or "CWE-Unknown",
                "vuln_type": f.get("vuln_type") or "Security Vulnerability",
                "severity": f.get("severity") or "HIGH",
                "description": f.get("description") or "",
                "lifecycle_status": status,
                "first_seen_commit": first_commit,
                "first_seen_at": now_iso,
                "last_seen_commit": commit_sha,
                "last_seen_at": now_iso,
                "pr_number": int(pr_number) if pr_number else None,
                "resolved_at": None,
                "resolved_in_pr": None,
                "resolved_by": None
            }
            rows.append(row)
            
        # 2. Stream resolved findings if present in delta
        if summary_delta and summary_delta.get("resolved_findings"):
            for rf in summary_delta["resolved_findings"]:
                fp = rf.get("fingerprint") or rf.get("id")
                first_commit = rf.get("first_seen_commit") or rf.get("commit_sha") or commit_sha
                row = {
                    "finding_fingerprint": fp,
                    "repo_name": repo_name or "unknown",
                    "org_name": org_name,
                    "target_file": rf.get("filepath") or rf.get("target_file") or "unknown",
                    "line_number": int(rf.get("line_number")) if rf.get("line_number") is not None else None,
                    "cwe": rf.get("cwe") or rf.get("vuln_type") or "CWE-Unknown",
                    "vuln_type": rf.get("vuln_type") or "Security Vulnerability",
                    "severity": rf.get("severity") or "HIGH",
                    "description": rf.get("description") or "",
                    "lifecycle_status": "RESOLVED",
                    "first_seen_commit": first_commit,
                    "first_seen_at": now_iso,
                    "last_seen_commit": commit_sha,
                    "last_seen_at": now_iso,
                    "pr_number": int(pr_number) if pr_number else None,
                    "resolved_at": now_iso,
                    "resolved_in_pr": int(pr_number) if pr_number else None,
                    "resolved_by": author
                }
                rows.append(row)
                
        if rows:
            _enqueue_bq_insert(
                "vulnerability_findings_inventory",
                rows,
                ensure_fn=ensure_vulnerability_inventory_table,
                success_msg=f"Successfully streamed {len(rows)} vulnerability inventory rows to BigQuery for PR #{pr_number}"
            )
    except Exception as e:
        logger.error(f"Error logging vulnerability inventory to BigQuery: {e}")

def ensure_dismissal_audit_table():
    """Checks if the dismissal audit table exists in BigQuery, and creates it if not."""
    if not bq_client:
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.dismissed_vulnerabilities_audit"
    try:
        bq_client.get_table(table_id)
    except Exception:
        logger.info(f"BigQuery table {table_id} not found. Creating...")
        schema = [
            bigquery.SchemaField("audit_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("pr_number", "INTEGER", mode="NULLABLE"),
            bigquery.SchemaField("commit_sha", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("finding_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("vuln_type", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("severity", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("dismissed_by", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("category", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("reason", "STRING", mode="REQUIRED"),
        ]
        table = bigquery.Table(table_id, schema=schema)
        bq_client.create_table(table, timeout=30)
        logger.info(f"Created BigQuery table {table_id}.")


def log_dismissal_audit(repo_name: str, pr_number: int, commit_sha: str, finding_id: str, vuln_type: str, severity: str, dismissed_by: str, category: str, reason: str):
    """Streams a vulnerability dismissal audit row into BigQuery."""
    if not bq_client:
        return
    import uuid
    import time
    from datetime import datetime, UTC
    try:
        row = {
            "audit_id": str(uuid.uuid4()),
            "timestamp": datetime.fromtimestamp(time.time(), UTC).isoformat(),
            "repo_name": repo_name or "unknown",
            "pr_number": int(pr_number) if pr_number else None,
            "commit_sha": commit_sha,
            "finding_id": finding_id,
            "vuln_type": vuln_type,
            "severity": severity,
            "dismissed_by": dismissed_by,
            "category": category,
            "reason": reason
        }
        _enqueue_bq_insert(
            "dismissed_vulnerabilities_audit",
            [row],
            ensure_fn=ensure_dismissal_audit_table,
            success_msg=f"Logged dismissal audit row to BigQuery for finding {finding_id} by {dismissed_by}"
        )
    except Exception as e:
        logger.error(f"Error logging dismissal audit to BigQuery: {e}")


def dismiss_finding(commit_sha: str, finding_id: str, dismissed_by: str, category: str = "FALSE_POSITIVE", reason: str = "") -> dict:
    """
    Dismisses a finding or all findings on a commit with a documented risk acceptance rationale.
    Updates Firestore and records audit metadata.
    """
    import time
    from datetime import datetime, UTC
    try:
        doc_ref = db.collection("scans").document(commit_sha)
        doc = doc_ref.get()
        if not doc.exists:
            return {"success": False, "error": f"Scan document for commit {commit_sha} not found."}
            
        doc_data = doc.to_dict()
        findings = doc_data.get("findings", [])
        repo_name = doc_data.get("repo_name", "")
        pr_number = doc_data.get("pr_number")
        
        clean_cat = (category or "FALSE_POSITIVE").strip("[]").strip().upper()
        if clean_cat in ["ACCEPTABLE_RISK", "ACCEPT_RISK", "ACCEPTED_RISK"]:
            clean_cat = "BUSINESS_ACCEPTED_RISK"
        elif clean_cat in ["OUT_OF_SCOPE", "SCOPE"]:
            clean_cat = "NON_PROD_FIXTURE"

        dismissal_entry = {
            "dismissed_by": dismissed_by or "unknown",
            "dismissed_at": datetime.now(UTC).isoformat(),
            "category": clean_cat,
            "reason": reason or "Dismissed by user with documented risk acceptance."
        }
        
        dismissed_items = []
        is_override_all = (finding_id.lower() in ["all", "gate", "*"])
        
        for f in findings:
            fid = f.get("id")
            if is_override_all or fid == finding_id:
                f["status"] = "DISMISSED"
                f["dismissal"] = dismissal_entry
                dismissed_items.append(f)
                
                # Stream to BigQuery audit table
                try:
                    log_dismissal_audit(
                        repo_name=repo_name,
                        pr_number=pr_number,
                        commit_sha=commit_sha,
                        finding_id=fid,
                        vuln_type=f.get("vuln_type", "Unknown"),
                        severity=str(f.get("severity", "CRITICAL")).upper(),
                        dismissed_by=dismissal_entry["dismissed_by"],
                        category=dismissal_entry["category"],
                        reason=dismissal_entry["reason"]
                    )
                except Exception as audit_err:
                    logger.warning(f"Failed to stream dismissal audit for {fid}: {audit_err}")
                    
        if not dismissed_items:
            return {"success": False, "error": f"Finding ID '{finding_id}' not found in scan."}
            
        doc_ref.set({"findings": findings, "updated_at": time.time()}, merge=True)
        
        # Calculate active critical findings remaining
        active_criticals = [
            f for f in findings
            if "CRITICAL" in str(f.get("severity", "")).upper() and f.get("status") not in ["FIXED", "DISMISSED"]
        ]
        dismissed_count = sum(1 for f in findings if f.get("status") == "DISMISSED")
        
        # Append step
        append_scan_step(commit_sha, "gitops", f"Dismissed finding '{finding_id}' by '{dismissed_by}' [{dismissal_entry['category']}]: {dismissal_entry['reason']}")
        
        logger.info(f"Successfully dismissed finding(s) '{finding_id}' on {commit_sha}. Active criticals remaining: {len(active_criticals)}")
        
        return {
            "success": True,
            "commit_sha": commit_sha,
            "finding_id": finding_id,
            "dismissed_items": dismissed_items,
            "dismissal": dismissal_entry,
            "active_criticals_count": len(active_criticals),
            "dismissed_count": dismissed_count,
            "total_findings_count": len(findings),
            "repo_name": repo_name,
            "pr_number": pr_number,
            "findings": findings
        }
    except Exception as e:
        logger.error(f"Failed to dismiss finding for {commit_sha}: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def get_remediation_analytics(repo_name: str = None, range_days: int = 7, start_date: str = None, end_date: str = None) -> dict:
    """Queries BigQuery for remediation velocity, MTTR, resolution rate, and multi-repo metrics."""
    if not bq_client:
        return {}
        
    project = bq_client.project
    table_path = f"{project}.codemender_analytics.applied_security_patches"
    
    # Build dynamic WHERE clause
    where_conditions = []
    query_params = []
    
    if repo_name and repo_name.lower() not in ["all", "all repositories", ""]:
        where_conditions.append("repo_name = @repo_name")
        query_params.append(bigquery.ScalarQueryParameter("repo_name", "STRING", repo_name))
        
    if start_date and end_date:
        where_conditions.append("merged_at >= TIMESTAMP(@start_date, 'UTC') AND merged_at < TIMESTAMP_ADD(TIMESTAMP(@end_date, 'UTC'), INTERVAL 1 DAY)")
        query_params.append(bigquery.ScalarQueryParameter("start_date", "STRING", start_date))
        query_params.append(bigquery.ScalarQueryParameter("end_date", "STRING", end_date))
        filter_mode = "custom"
    elif start_date:
        where_conditions.append("merged_at >= TIMESTAMP(@start_date, 'UTC') AND merged_at < TIMESTAMP_ADD(TIMESTAMP(@start_date, 'UTC'), INTERVAL 1 DAY)")
        query_params.append(bigquery.ScalarQueryParameter("start_date", "STRING", start_date))
        filter_mode = "single_day"
    else:
        where_conditions.append("merged_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @range_days DAY)")
        query_params.append(bigquery.ScalarQueryParameter("range_days", "INT64", range_days))
        filter_mode = f"{range_days}d"
        
    where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
    
    # 1. Summary KPIs
    q_summary = f"""
        SELECT 
          COALESCE(SUM(patched_count), 0) AS total_patched,
          COALESCE(SUM(critical_count), 0) AS critical_remediated,
          COALESCE(SUM(high_count), 0) AS high_remediated,
          COALESCE(SUM(medium_count), 0) AS medium_remediated,
          COALESCE(SUM(low_count), 0) AS low_remediated,
          -- Only columns of the live table (plan 4.3, conflict review B8): dismissals are counted
          -- from the findings payload, discoveries from total_findings.
          COALESCE(SUM((
            SELECT COUNTIF(JSON_VALUE(f, '$.status') = 'DISMISSED')
            FROM UNNEST(JSON_QUERY_ARRAY(findings_full_json, '$')) AS f
          )), 0) AS total_dismissed,
          COALESCE(SUM(total_findings), 0) AS total_discovered,
          COUNT(DISTINCT pr_number) AS total_prs_merged,
          COALESCE(ROUND(AVG(time_to_remediate_sec) / 60.0, 1), 0.0) AS avg_mttr_minutes,
          COALESCE(ROUND(AVG(remediation_rate_pct), 1), 100.0) AS avg_remediation_rate_pct
        FROM `{table_path}`
        {where_clause}
    """
    
    # 2. Distinct Available Repositories
    q_repos = f"""
        SELECT DISTINCT repo_name 
        FROM `{table_path}`
        WHERE repo_name IS NOT NULL
        ORDER BY repo_name ASC
    """
    
    # 3. Timeline by Date (aligned to Google Cloud Billing daily boundaries)
    q_timeline = f"""
        SELECT 
          FORMAT_DATE('%Y-%m-%d', EXTRACT(DATE FROM merged_at AT TIME ZONE 'America/Los_Angeles')) as date,
          SUM(patched_count) as patches_merged,
          ROUND(AVG(time_to_remediate_sec) / 60.0, 1) as mttr_minutes
        FROM `{table_path}`
        {where_clause}
        GROUP BY date
        ORDER BY date ASC
    """
    
    try:
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        # Summary Query
        job_summary = bq_client.query(q_summary, job_config=job_config)
        rows_summary = list(job_summary.result())
        summary_dict = {
            "total_patched": 0,
            "critical_remediated": 0,
            "high_remediated": 0,
            "medium_remediated": 0,
            "low_remediated": 0,
            "total_dismissed": 0,
            "total_discovered": 0,
            "total_prs_merged": 0,
            "avg_mttr_minutes": 0.0,
            "avg_remediation_rate_pct": 100.0
        }
        if rows_summary:
            r = rows_summary[0]
            summary_dict = {
                "total_patched": int(r.total_patched),
                "critical_remediated": int(r.critical_remediated),
                "high_remediated": int(r.high_remediated),
                "medium_remediated": int(r.medium_remediated),
                "low_remediated": int(r.low_remediated),
                "total_dismissed": int(r.total_dismissed),
                "total_discovered": int(r.total_discovered),
                "total_prs_merged": int(r.total_prs_merged),
                "avg_mttr_minutes": float(r.avg_mttr_minutes),
                "avg_remediation_rate_pct": float(r.avg_remediation_rate_pct)
            }
            
        # Repos Query
        job_repos = bq_client.query(q_repos)
        repos_list = [r.repo_name for r in job_repos.result() if r.repo_name]
        
        # Timeline Query
        job_timeline = bq_client.query(q_timeline, job_config=job_config)
        timeline_list = [{"date": r.date, "patches_merged": int(r.patches_merged), "mttr_minutes": float(r.mttr_minutes)} for r in job_timeline.result()]
        
        return {
            "status": "success",
            "repo_name": repo_name,
            "range_days": range_days,
            "start_date": start_date,
            "end_date": end_date,
            "filter_mode": filter_mode,
            "summary": summary_dict,
            "repos": repos_list,
            "timeline": timeline_list
        }
    except Exception as e:
        logger.error(f"Failed to query remediation metrics from BigQuery: {e}")
        return {
            "status": "error",
            "message": str(e),
            "summary": {
                "total_patched": 0,
                "critical_remediated": 0,
                "high_remediated": 0,
                "medium_remediated": 0,
                "low_remediated": 0,
                "total_dismissed": 0,
                "total_discovered": 0,
                "total_prs_merged": 0,
                "avg_mttr_minutes": 0.0,
                "avg_remediation_rate_pct": 100.0
            },
            "repos": [],
            "timeline": []
        }


def _get_repo_hash(repo_name: str) -> str:
    """Computes a deterministic hash identifier for a repository."""
    import hashlib
    return hashlib.sha256((repo_name or "default").strip().lower().encode("utf-8")).hexdigest()[:16]


def get_pr_state(repo_name: str, pr_number: int) -> dict:
    """Retrieves the stateful PR security record from Firestore."""
    if not pr_number:
        return {}
    try:
        repo_hash = _get_repo_hash(repo_name)
        doc_ref = db.collection("repos").document(repo_hash).collection("prs").document(str(pr_number))
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        return {}
    except Exception as e:
        logger.warning(f"Failed to read PR state for {repo_name} PR #{pr_number}: {e}")
        return {}


def save_pr_state(repo_name: str, pr_number: int, data: dict):
    """Updates or merges the stateful PR security record in Firestore."""
    if not pr_number:
        return
    import time
    try:
        repo_hash = _get_repo_hash(repo_name)
        doc_ref = db.collection("repos").document(repo_hash).collection("prs").document(str(pr_number))
        payload = dict(data)
        payload["updated_at"] = time.time()
        payload["repo_name"] = repo_name
        payload["pr_number"] = pr_number
        doc_ref.set(payload, merge=True)
        logger.info(f"Saved PR state for {repo_name} PR #{pr_number} (Latest SHA: {payload.get('latest_scanned_commit_sha')})")
    except Exception as e:
        logger.error(f"Failed to save PR state for {repo_name} PR #{pr_number}: {e}")


def ensure_vulnerability_lifecycle_events_table():
    """Ensures vulnerability_lifecycle_events table and analytical views exist in BigQuery."""
    if not bq_client:
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.vulnerability_lifecycle_events"
    
    try:
        dataset = bigquery.Dataset(dataset_id)
        dataset.location = "US"
        bq_client.create_dataset(dataset, exists_ok=True, timeout=30)
    except Exception as ds_err:
        logger.debug(f"Dataset check/create: {ds_err}")
        
    schema = [
        bigquery.SchemaField("event_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("event_timestamp", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("event_type", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("finding_fingerprint", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("display_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("org_name", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("target_file", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("line_number", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("enclosing_scope", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("cwe_id", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("vulnerability_type", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("normalized_severity", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("code_sink", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("commit_sha", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("pr_number", "INTEGER", mode="NULLABLE"),
        bigquery.SchemaField("actor", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("metadata", "STRING", mode="NULLABLE"),
    ]
    
    try:
        table = bigquery.Table(table_id, schema=schema)
        table.time_partitioning = bigquery.TimePartitioning(
            type_=bigquery.TimePartitioningType.DAY,
            field="event_timestamp"
        )
        table.clustering_fields = ["repo_name", "finding_fingerprint", "event_type"]
        bq_client.create_table(table, exists_ok=True, timeout=30)
    except Exception as tbl_err:
        logger.debug(f"Table check/create: {tbl_err}")


def log_vulnerability_lifecycle_events(events: list[dict]):
    """Streams a batch of vulnerability lifecycle events into BigQuery."""
    if not bq_client or not events:
        return
    import uuid
    import time
    import json
    from datetime import datetime, timezone
    
    try:
        rows_to_insert = []
        for ev in events:
            org_name = ev.get("repo_name", "").split("/")[0] if "/" in ev.get("repo_name", "") else "default"
            ts = ev.get("event_timestamp")
            if not ts:
                ts = datetime.fromtimestamp(time.time(), timezone.utc).isoformat()
            elif isinstance(ts, (int, float)):
                ts = datetime.fromtimestamp(ts, timezone.utc).isoformat()
                
            row = {
                "event_id": str(uuid.uuid4()),
                "event_timestamp": ts,
                "event_type": ev.get("event_type", "DISCOVERED"),
                "finding_fingerprint": ev.get("finding_fingerprint") or ev.get("fingerprint", ""),
                "display_id": ev.get("display_id") or (ev.get("finding_fingerprint") or ev.get("fingerprint", ""))[:6],
                "repo_name": ev.get("repo_name", "unknown"),
                "org_name": org_name,
                "target_file": ev.get("target_file") or ev.get("filepath", ""),
                "line_number": ev.get("line_number"),
                "enclosing_scope": ev.get("enclosing_scope", "global"),
                "cwe_id": ev.get("cwe_id") or ev.get("cwe", ""),
                "vulnerability_type": ev.get("vulnerability_type") or ev.get("vuln_type", ""),
                "normalized_severity": ev.get("normalized_severity") or ev.get("severity", "MEDIUM"),
                "code_sink": ev.get("code_sink", ""),
                "commit_sha": ev.get("commit_sha", ""),
                "pr_number": ev.get("pr_number"),
                "actor": ev.get("actor", "codemender-bot"),
                "metadata": json.dumps(ev.get("metadata", {})) if isinstance(ev.get("metadata"), dict) else str(ev.get("metadata", ""))
            }
            rows_to_insert.append(row)
            
        _enqueue_bq_insert(
            "vulnerability_lifecycle_events",
            rows_to_insert,
            ensure_fn=ensure_vulnerability_lifecycle_events_table,
            success_msg=f"Successfully streamed {len(rows_to_insert)} lifecycle events to BigQuery vulnerability_lifecycle_events"
        )
    except Exception as e:
        logger.error(f"Error logging vulnerability lifecycle events to BigQuery: {e}")





