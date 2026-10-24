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

"""Pure policy for the `security/codemender-gate` commit status.

This module performs no I/O. The scan worker for a commit is the only code path that writes the
gate for that commit; it asks this module what the state should be, which keeps the rule small
enough to unit test without GitHub, Firestore or the CodeMender CLI.
"""

GATE_CONTEXT = "security/codemender-gate"

# Finding statuses (or lifecycle statuses) that no longer block a merge. Everything else -- DETECTED,
# VERIFIED, VERIFICATION_FAILED, PATCHED (a patch staged on a side branch is not merged code), ... --
# still blocks when the finding is CRITICAL.
NON_BLOCKING_STATUSES = frozenset({"RESOLVED", "DISMISSED"})

# Scan statuses written while a worker owns a commit (webhook: QUEUED, worker: CLONING/RUNNING).
IN_FLIGHT_SCAN_STATUSES = frozenset({"QUEUED", "CLONING", "PRE_CHECKS", "RUNNING"})
DUPLICATE_SCAN_WINDOW_SECONDS = 30 * 60

# Written when the scan worker could not take the workspace lock. Deliberately NOT in flight:
# a re-delivery or re-push must be able to start a fresh scan instead of being de-duplicated.
DEFERRED_SCAN_STATUS = "DEFERRED"

# Terminal statuses for a scan that stopped without a result. None of them is a pass: the head's
# commit status is set to 'error' alongside them, so no gate is left at 'pending'.
SUPERSEDED_SCAN_STATUS = "SUPERSEDED"  # the PR head moved on; the newer head is scanned instead
CANCELLED_SCAN_STATUS = "CANCELLED"    # stopped by /cancel, the dashboard, or a lost workspace lease
STALE_SCAN_STATUS = "STALE"            # abandoned by a dead worker and not re-queued (reaper.py)
FAILED_SCAN_STATUS = "FAILED"

# Statuses under which scans/{sha}.findings is a finished result.
COMPLETED_SCAN_STATUSES = frozenset({"COMPLETED", "SUCCESS", "PASSED"})
ABANDONED_SCAN_STATUSES = frozenset({SUPERSEDED_SCAN_STATUS, CANCELLED_SCAN_STATUS, STALE_SCAN_STATUS})
TERMINAL_SCAN_STATUSES = COMPLETED_SCAN_STATUSES | ABANDONED_SCAN_STATUSES | {FAILED_SCAN_STATUS}

# scans/{sha}.active_task names the task that owns the record's status while it runs. Verify and
# fix share the record with the scan, so their RUNNING/FAILED statuses say nothing about the scan.
SCAN_TASK = "scan"
FOLLOW_UP_TASKS = frozenset({"verify", "fix"})

# GitHub rejects commit status descriptions longer than 140 characters.
MAX_DESCRIPTION_CHARS = 140

# Finding statuses a verify/fix task sets while it works on a finding, and the status triage gives
# a finding. A finding left in a transient status by a dead task goes back to DETECTED.
TRANSIENT_FINDING_STATUSES = frozenset({"VERIFYING", "PATCHING"})
DEFAULT_FINDING_STATUS = "DETECTED"


def _truncate(text: str, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def is_critical(finding: dict) -> bool:
    """Severity strings may carry emoji ('🔴 CRITICAL'), so match on the word, not equality."""
    return "CRITICAL" in str(finding.get("severity") or "").upper()


def is_unresolved(finding: dict) -> bool:
    status = str(finding.get("status") or "").upper()
    lifecycle = str(finding.get("lifecycle_status") or "").upper()
    return status not in NON_BLOCKING_STATUSES and lifecycle not in NON_BLOCKING_STATUSES


def unresolved_criticals(findings) -> list:
    return [f for f in (findings or []) if isinstance(f, dict) and is_critical(f) and is_unresolved(f)]


def decide_gate(findings, error=None, unscanned_count: int = 0) -> tuple:
    """Returns (state, description) for the merge gate.

    - ('error', ...)   when the scan did not complete. A failed scan is never a pass.
    - ('failure', ...) when any CRITICAL finding is not RESOLVED or DISMISSED.
    - ('failure', ...) when changed files were left unscanned (file cap, plan 3.1): a partial
      scan is never a pass, whatever the scanned files contained.
    - ('success', ...) otherwise.
    """
    if error:
        reason = " ".join(str(error).split()) or "unknown error"
        return "error", _truncate(f"CodeMender scan failed: {reason}")

    blocking = unresolved_criticals(findings)
    if blocking:
        return "failure", _truncate(
            f"Merge blocked: {len(blocking)} unresolved CRITICAL finding(s). Fix or dismiss required."
        )
    try:
        unscanned = int(unscanned_count or 0)
    except (TypeError, ValueError):
        unscanned = 1
    if unscanned > 0:
        return "failure", _truncate(
            f"Merge blocked: {unscanned} changed file(s) not scanned (file limit). Split the PR or raise CM_MAX_SCAN_FILES."
        )
    return "success", "Passed: 0 unresolved CRITICAL findings."


def should_skip_duplicate_scan(status, updated_at, now, window_seconds=DUPLICATE_SCAN_WINDOW_SECONDS) -> bool:
    """True when another scan of the same head SHA is queued/running and was updated recently.

    GitHub webhooks and the Actions relay can both deliver the same pull_request event. A stale
    in-flight status (worker crashed) stops blocking new scans once it is older than the window.
    """
    if str(status or "").upper() not in IN_FLIGHT_SCAN_STATUSES:
        return False
    try:
        age = float(now) - float(updated_at)
    except (TypeError, ValueError):
        return False
    return abs(age) < window_seconds


def _upper(value) -> str:
    return str(value or "").strip().upper()


def _same_pr_number(left, right) -> bool:
    try:
        return int(str(left).strip()) == int(str(right).strip())
    except (TypeError, ValueError):
        return False


def scan_result_available(record) -> bool:
    """True when the record holds the finished scan result for its commit.

    The scan worker stamps ``scan_completed_at`` when it records a result and resets it to None when
    a new scan of the same commit starts. Verify/fix tasks never touch it, so a RUNNING or FAILED
    status they write does not hide the scan result. Records written before the field existed fall
    back to the status (a completed status with a findings list).
    """
    if not isinstance(record, dict) or not isinstance(record.get("findings"), list):
        return False
    if "scan_completed_at" in record:
        return bool(record.get("scan_completed_at"))
    return _upper(record.get("status")) in COMPLETED_SCAN_STATUSES


def scan_in_progress(record) -> bool:
    """True while the scan itself (not a verify/fix task) is queued, deferred or running."""
    if not isinstance(record, dict):
        return False
    status = _upper(record.get("status"))
    if status not in IN_FLIGHT_SCAN_STATUSES and status != DEFERRED_SCAN_STATUS:
        return False
    return str(record.get("active_task") or "").strip().lower() not in FOLLOW_UP_TASKS


def has_terminal_scan_result(record, repo_name=None, pr_number=None) -> bool:
    """True when this PR head already has a finished scan result, so it must not be scanned again.

    Used for ready_for_review: a Draft -> Ready promotion (CodeMender's own after a green gate, or a
    person's) does not change the head commit, so its recorded result and gate stand.
    """
    if not scan_result_available(record) or scan_in_progress(record):
        return False
    if repo_name and str(record.get("repo_name") or "").strip().lower() != str(repo_name).strip().lower():
        return False
    if pr_number is not None and not _same_pr_number(record.get("pr_number"), pr_number):
        return False
    return True


def superseded_gate(live_head_sha) -> tuple:
    """Terminal gate for a scan whose head is no longer the PR head (never left at 'pending')."""
    return "error", _truncate(f"Superseded by {str(live_head_sha or 'a newer commit')[:7]}")


def cancelled_gate(cancelled_by=None) -> tuple:
    """Terminal gate for a scan stopped before it finished (cancel or lost workspace lease)."""
    who = f" by @{cancelled_by}" if cancelled_by else ""
    return "error", _truncate(f"CodeMender scan cancelled{who}; push a commit or reopen the PR to re-run")


def stale_gate(reason) -> tuple:
    """Terminal gate for a scan abandoned by a dead worker that is not re-queued."""
    return "error", _truncate(f"CodeMender scan did not finish ({reason}); push a commit or reopen the PR")


def gate_state_after_dismissal(scan_record) -> tuple:
    """Returns (state, description) for the merge gate after a dismissal changed scan_record['findings'].

    Same rule as the scan (decide_gate on the current findings), bounded by the scan's own status:
    - (None, reason) while the scan of this commit is queued, deferred or running: write nothing.
      The scan worker sets the gate when it finishes; a write now could race it.
    - ('error', ...) when the commit has no completed scan (failed, cancelled, superseded, stale or
      unknown). A dismissal never turns a scan that did not finish into a pass.
    - decide_gate(findings) otherwise, so RESOLVED and DISMISSED findings stop blocking exactly as
      in the scan, and every other status of a CRITICAL finding (FIXED, PATCHED, ...) still blocks.
    """
    if not isinstance(scan_record, dict):
        return decide_gate([], error="no scan record for this commit")
    if scan_in_progress(scan_record):
        return None, "Scan in progress: the gate is set when it finishes."
    if not scan_result_available(scan_record):
        status = _upper(scan_record.get("status")) or "UNKNOWN"
        return "error", _truncate(f"CodeMender scan did not complete ({status}); dismissal recorded, re-scan required.")
    return decide_gate(scan_record.get("findings"), unscanned_count=len(scan_record.get("unscanned_files") or []))


def restorable_status(status) -> str:
    """The status a verify/fix run gives back when it ends.

    That is the status the run found, unless it was itself an in-flight status left by a task that
    died (e.g. RUNNING from a crashed /verify): then COMPLETED, since verify/fix only start on a
    finished scan. Restoring RUNNING would leave the record stuck (implementation finding N2).
    """
    if not status or _upper(status) in IN_FLIGHT_SCAN_STATUSES:
        return "COMPLETED"
    return status


def orphan_record_update(record, terminal_status: str, reason: str):
    """How to close out a scans/{sha} record whose worker is gone (cancelled, or the instance died).

    Returns (fields, needs_gate):
    - (None, False) when the record is not in flight (nothing to close out).
    - Interrupted verify/fix (active_task verify/fix): the scan result is intact, so the record
      returns to the status the task found (status_before_task, else COMPLETED) and findings left
      VERIFYING/PATCHING go back to DETECTED. needs_gate is False: the scan's gate stands.
    - Interrupted scan (or a record without active_task): status becomes ``terminal_status``
      (CANCELLED or STALE) and needs_gate is True, so the caller sets the commit status to error
      instead of leaving it at 'pending'.
    ``fields`` are keyword arguments for update_scan_status.
    """
    if not isinstance(record, dict):
        return None, False
    status = _upper(record.get("status"))
    if status not in IN_FLIGHT_SCAN_STATUSES and status != DEFERRED_SCAN_STATUS:
        return None, False
    task = str(record.get("active_task") or "").strip().lower()
    if task in FOLLOW_UP_TASKS:
        findings = []
        for finding in record.get("findings") or []:
            finding = dict(finding)
            if _upper(finding.get("status")) in TRANSIENT_FINDING_STATUSES:
                finding["status"] = DEFAULT_FINDING_STATUS
            findings.append(finding)
        return {
            "status": restorable_status(record.get("status_before_task")),
            "message": f"The {task} run did not finish ({reason}); the scan result is unchanged.",
            "findings": findings,
            "active_task": None,
            "status_before_task": None,
            "error_message": reason,
        }, False
    return {
        "status": terminal_status,
        "message": f"The scan did not finish ({reason}).",
        "active_task": None,
        "error_message": reason,
    }, True
