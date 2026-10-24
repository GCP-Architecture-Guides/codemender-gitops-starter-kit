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

"""Maintenance sweep for CodeMender (plans 3.3 and 3.16; conflict review C1 and C4).

Runs in-process every 5 minutes (main.maintenance_loop) and on demand (/api/maintenance/gc).
Every step is idempotent and judged on leases and heartbeats, so tag revisions and several
services can run it side by side:

1. Expired workspace leases are deleted (precondition: unchanged since they were read).
2. Scan records still in flight (QUEUED / CLONING / PRE_CHECKS / RUNNING) whose heartbeat
   (``updated_at``, refreshed every 60 s by a live task) is older than CM_STALE_TASK_SEC
   (default 10 min) are closed out with gate_policy.orphan_record_update: an interrupted
   verify/fix gets its record back, an interrupted scan becomes STALE and its 'error' gate is
   returned for the caller to set. Only records of allowed repositories are touched.
3. /tmp/session-* workspaces older than 24 h are removed, except those of commits with a task on
   this instance or a live lease; sandbox-* directories older than 24 h are removed.
4. processed_comments (comment-command dedupe records) older than CM_COMMENT_RETENTION_DAYS
   (default 365, never under 31: GitHub allows re-running a workflow up to 30 days after it first ran) are
   deleted, at most 200 per run.
"""

import os
import shutil
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

from command_auth import is_repo_allowed
from gate_policy import IN_FLIGHT_SCAN_STATUSES, STALE_SCAN_STATUS, orphan_record_update, stale_gate
from lock_logic import can_acquire, is_lock_expired

logger = logging.getLogger(__name__)

STALE_TASK_DEFAULT_SEC = 600.0
STALE_TASK_MIN_SEC = 600.0
STALE_TASK_MAX_SEC = 21600.0
TMP_MAX_AGE_SEC = 86400
COMMENT_RETENTION_DEFAULT_DAYS = 365.0
COMMENT_PRUNE_BATCH = 200


def _env_number(name: str, default: float, low: float, high: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning(f"Ignoring invalid {name}={raw!r}; using {default:g}.")
        return default
    if value != value:  # NaN
        return default
    return min(max(value, low), high)


def stale_task_seconds() -> float:
    """Heartbeat age after which an in-flight record counts as abandoned (CM_STALE_TASK_SEC)."""
    return _env_number("CM_STALE_TASK_SEC", STALE_TASK_DEFAULT_SEC, STALE_TASK_MIN_SEC, STALE_TASK_MAX_SEC)


def comment_retention_days() -> float:
    """Days a processed_comments record is kept (CM_COMMENT_RETENTION_DAYS, at least 31)."""
    return _env_number("CM_COMMENT_RETENTION_DAYS", COMMENT_RETENTION_DEFAULT_DAYS, 31.0, 3650.0)


def _epoch_seconds(value):
    """updated_at as epoch seconds (float, or a Firestore timestamp), else None."""
    if hasattr(value, "timestamp"):
        try:
            return float(value.timestamp())
        except Exception:
            return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def run_maintenance_sweep(project_id: str = None, allowed_repos=None, in_flight=frozenset(),
                          close_gated_scans: bool = True, now: float = None, db=None,
                          tmp_dir: str = "/tmp") -> dict:
    """Runs one idempotent sweep (see the module docstring) and returns a summary.

    ``stale_gates`` lists the 'error' gates (repo_name, commit_sha, state, description) the caller
    must set for the scans this sweep closed out. With ``close_gated_scans`` False (no GitHub token
    available), scans that would need a gate are left for a sweep that can set it.
    """
    if db is None:
        proj = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not proj:
            raise RuntimeError("GOOGLE_CLOUD_PROJECT is not set; refusing to run maintenance without an explicit project.")
        from google.cloud import firestore
        db = firestore.Client(project=proj)
    now = time.time() if now is None else now
    in_flight = frozenset(in_flight or ())

    summary = {
        "timestamp": now,
        "locks_swept": 0,
        "stale_scans_cleaned": 0,
        "stale_scans_deferred": 0,
        "other_repo_records_skipped": 0,
        "temp_dirs_removed": 0,
        "comments_pruned": 0,
        "stale_gates": [],
        "status": "success",
    }
    _sweep_expired_locks(db, now, summary)
    _close_out_stale_records(db, now, summary, allowed_repos, in_flight, close_gated_scans)
    _remove_old_workspaces(db, now, summary, in_flight, tmp_dir)
    _prune_processed_comments(db, now, summary)

    brief = {key: value for key, value in summary.items() if key != "stale_gates"}
    logger.info(f"Maintenance sweep completed: {brief}")
    return summary


def _sweep_expired_locks(db, now: float, summary: dict) -> None:
    """New lease docs carry expires_at; legacy docs with only locked_at expire 1800 s after it.
    Docs of unknown shape are left alone."""
    try:
        for doc in db.collection("locks").stream():
            if not is_lock_expired(doc.to_dict() or {}, now):
                continue
            try:
                # Precondition: skip if the lease was renewed or re-acquired after we read it.
                doc.reference.delete(option=db.write_option(last_update_time=doc.update_time))
            except Exception as del_err:
                logger.info(f"Skipped sweeping lock {doc.id} (changed since read or delete failed): {del_err}")
                continue
            summary["locks_swept"] += 1
            logger.info(f"Swept expired lock: {doc.id}")
    except Exception as lock_err:
        logger.warning(f"Error sweeping expired locks: {lock_err}")


def _close_out_stale_records(db, now: float, summary: dict, allowed_repos, in_flight, close_gated_scans: bool) -> None:
    stale_after = stale_task_seconds()
    reason = f"no heartbeat for {int(stale_after // 60)} min; the worker is gone"
    for status in sorted(IN_FLIGHT_SCAN_STATUSES):
        try:
            docs = list(db.collection("scans").where("status", "==", status).stream())
        except Exception as list_err:
            logger.warning(f"Could not list {status} scans: {list_err}")
            continue
        for doc in docs:
            sha = doc.id
            record = doc.to_dict() or {}
            if sha in in_flight:
                continue
            heartbeat = _epoch_seconds(record.get("updated_at"))
            if heartbeat is None or now - heartbeat < stale_after:
                continue
            if not is_repo_allowed(record.get("repo_name"), allowed_repos):
                summary["other_repo_records_skipped"] += 1
                continue
            fields, needs_gate = orphan_record_update(record, STALE_SCAN_STATUS, reason)
            if not fields:
                continue
            gate_wanted = needs_gate and str(record.get("active_task") or "").strip().lower() == "scan"
            if gate_wanted and not close_gated_scans:
                summary["stale_scans_deferred"] += 1
                continue
            update = dict(fields)
            update["updated_at"] = now
            try:
                # Precondition: a live task that wrote after our read keeps its record.
                doc.reference.update(update, option=db.write_option(last_update_time=doc.update_time))
            except Exception as update_err:
                logger.info(f"Skipped closing out scan {sha[:8]} (changed since read or update failed): {update_err}")
                continue
            summary["stale_scans_cleaned"] += 1
            logger.info(f"Closed out stale {status} record {sha[:8]} ({record.get('active_task') or 'legacy'}): {reason}.")
            if gate_wanted:
                state, description = stale_gate(reason)
                summary["stale_gates"].append({
                    "repo_name": record.get("repo_name"),
                    "commit_sha": sha,
                    "state": state,
                    "description": description,
                })


def _workspace_in_use(db, sha: str, now: float, in_flight) -> bool:
    if sha in in_flight:
        return True
    try:
        snap = db.collection("locks").document(f"workspace-{sha}").get()
        lease = snap.to_dict() if snap.exists else None
    except Exception as read_err:
        logger.info(f"Could not read the lease of {sha[:8]}; keeping its workspace: {read_err}")
        return True
    return not can_acquire(lease, now)


def _remove_old_workspaces(db, now: float, summary: dict, in_flight, tmp_dir: str) -> None:
    cutoff = now - TMP_MAX_AGE_SEC
    root = Path(tmp_dir)
    for prefix in ("session-", "sandbox-"):
        try:
            entries = list(root.glob(f"{prefix}*"))
        except Exception as glob_err:
            logger.warning(f"Error listing {prefix}* workspaces: {glob_err}")
            continue
        for entry in entries:
            try:
                if not entry.is_dir() or entry.stat().st_mtime >= cutoff:
                    continue
                if prefix == "session-" and _workspace_in_use(db, entry.name[len(prefix):], now, in_flight):
                    continue
                shutil.rmtree(entry, ignore_errors=True)
                summary["temp_dirs_removed"] += 1
                logger.info(f"Removed stale workspace: {entry}")
            except Exception as rm_err:
                logger.debug(f"Could not inspect or remove {entry}: {rm_err}")


def _prune_processed_comments(db, now: float, summary: dict) -> None:
    cutoff = datetime.fromtimestamp(now - comment_retention_days() * 86400, tz=timezone.utc)
    try:
        docs = list(db.collection("processed_comments").where("claimed_at", "<", cutoff).limit(COMMENT_PRUNE_BATCH).stream())
    except Exception as list_err:
        logger.warning(f"Could not list old processed_comments: {list_err}")
        return
    for doc in docs:
        try:
            doc.reference.delete()
            summary["comments_pruned"] += 1
        except Exception as del_err:
            logger.info(f"Could not delete processed_comments/{doc.id}: {del_err}")
