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

"""Automated Maintenance & Garbage Collection Module for CodeMender.

Provides serverless weekly maintenance to sweep expired Firestore locks,
recover orphaned or abandoned 'RUNNING' scans, and clean up ephemeral /tmp
workspaces.
"""

import os
import shutil
import time
import logging
from pathlib import Path
from google.cloud import firestore

logger = logging.getLogger(__name__)

def run_maintenance_sweep(project_id: str = None) -> dict:
    """Runs a complete, idempotent maintenance and garbage collection sweep.

    Returns:
        dict: Summary of swept locks, cleaned scans, and removed temp workspaces.
    """
    proj = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
    db = firestore.Client(project=proj)
    now = time.time()

    summary = {
        "timestamp": now,
        "locks_swept": 0,
        "stale_scans_cleaned": 0,
        "temp_dirs_removed": 0,
        "status": "success"
    }

    # 1. Sweep Expired / Dangling Firestore Locks
    try:
        locks_ref = db.collection("locks")
        for doc in locks_ref.stream():
            data = doc.to_dict() or {}
            expires_at = data.get("expires_at", 0)
            # If expired or older than 1 hour
            if expires_at and (expires_at < now or (now - data.get("acquired_at", 0) > 3600)):
                doc.reference.delete()
                summary["locks_swept"] += 1
                logger.info(f"Swept expired lock: {doc.id}")
    except Exception as lock_err:
        logger.warning(f"Error sweeping expired locks: {lock_err}")

    # 2. Reconcile Orphaned 'RUNNING' Scans (Older than 2 hours)
    try:
        scans_ref = db.collection("scans")
        two_hours_ago = now - 7200
        running_scans = scans_ref.where("status", "==", "RUNNING").stream()
        for doc in running_scans:
            data = doc.to_dict() or {}
            updated_at = data.get("updated_at", 0)
            if updated_at and updated_at < two_hours_ago:
                doc.reference.update({
                    "status": "FAILED",
                    "message": "Session timed out during automated weekly maintenance sweep.",
                    "updated_at": now
                })
                summary["stale_scans_cleaned"] += 1
                logger.info(f"Cleaned stale RUNNING scan: {doc.id}")
    except Exception as scan_err:
        logger.warning(f"Error cleaning stale scans: {scan_err}")

    # 3. Clean up Ephemeral /tmp Workspaces (Older than 24 hours)
    try:
        tmp_dir = Path("/tmp")
        one_day_ago = now - 86400
        for entry in tmp_dir.glob("session-*"):
            if entry.is_dir():
                try:
                    mtime = entry.stat().st_mtime
                    if mtime < one_day_ago:
                        shutil.rmtree(entry, ignore_errors=True)
                        summary["temp_dirs_removed"] += 1
                        logger.info(f"Removed stale session workspace: {entry}")
                except Exception:
                    pass

        for entry in tmp_dir.glob("sandbox-*"):
            if entry.is_dir():
                try:
                    mtime = entry.stat().st_mtime
                    if mtime < one_day_ago:
                        shutil.rmtree(entry, ignore_errors=True)
                        summary["temp_dirs_removed"] += 1
                except Exception:
                    pass
    except Exception as tmp_err:
        logger.warning(f"Error cleaning temp workspace directories: {tmp_err}")

    logger.info(f"Automated maintenance sweep completed: {summary}")
    return summary
