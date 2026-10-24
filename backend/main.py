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

# Guard against missing required environment variables to prevent configuration drift or project routing errors.
required_vars = ["GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI"]
missing_vars = [var for var in required_vars if not os.environ.get(var)]
if missing_vars:
    raise RuntimeError(
        f"CRITICAL CONFIGURATION ERROR: The following required environment variables are missing: "
        f"{', '.join(missing_vars)}. Aborting container startup."
    )

import logging
from log_redaction import install_log_redaction, redact

logging.basicConfig(level=logging.INFO)
# Installed before the remaining imports so import-time log lines are redacted too.
install_log_redaction()
logger = logging.getLogger(__name__)

import json
import hashlib
from typing import Optional, Dict, Any, List, Union
from pathlib import Path
import time
import asyncio
import contextlib
import signal
import threading
import httpx
from fastapi import FastAPI, Request, BackgroundTasks, Response, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from agents import TriageError, CommitIdentityError, run_triage_agent, reconcile_finding_lifecycle, _is_ignored_artifact_path
from cm_tools import cm_verify

from git_manager import GitWorkspace, CODEMENDER_STATE_PATHS, _STATE_EXCLUDE_PATHSPECS, HEAD_MISMATCH_REASON, HeadMismatchError
from github_helpers import (
    verify_signature,
    get_github_token,
    post_pr_comment,
    update_or_post_pr_comment,
    post_commit_comment,
    get_pr_head_sha,
    convert_draft_pr_to_ready,
    set_commit_status,
    get_collaborator_role,
    get_collaborator_permission,
    github_get_json,
    upsert_progress_comment,
    get_progress_comment_id,
    delete_comment,
    get_pull_request,
    get_commit_author
)
from database import get_patch_proposal, mark_patch_as_applied, acquire_lock, release_lock, is_lock_held, start_lock_renewal, list_patch_proposals, update_scan_status, list_scans, append_scan_step, get_token_analytics, dismiss_finding, get_remediation_analytics, log_scan_summary, claim_comment_event
from finding_match import select_finding
from gate_policy import (
    CANCELLED_SCAN_STATUS,
    DEFERRED_SCAN_STATUS,
    STALE_SCAN_STATUS,
    SUPERSEDED_SCAN_STATUS,
    TERMINAL_SCAN_STATUSES,
    cancelled_gate,
    decide_gate,
    has_terminal_scan_result,
    orphan_record_update,
    restorable_status,
    scan_in_progress,
    scan_result_available,
    should_skip_duplicate_scan,
    stale_gate,
    superseded_gate,
)
from command_auth import (
    command_name,
    env_flag,
    has_maintainer_role,
    has_write_permission,
    is_independent_approver,
    is_repo_allowed as _repo_in_allowlist,
    is_trusted_association,
    parse_allowed_repos
)
from request_guards import (
    WEBHOOK_ONLY_PATHS,
    ScanTarget,
    WebhookOnlyMiddleware,
    error_payload,
    is_error_result,
    new_error_id,
    resolve_scan_target,
    scrub_error_result
)


# Advisory threshold only. Verification is always sequential -- shards derived their workspace
# from the commit SHA and therefore collided. Above this count we log that a fan-out would have
# helped, which is the signal to build per-shard workspaces.
PARALLEL_SHARDING_THRESHOLD = int(os.getenv("PARALLEL_SHARDING_THRESHOLD", "4"))

@contextlib.asynccontextmanager
async def app_lifespan(_app):
    """Instance lifecycle: the SIGTERM hook (plan 3.15) and the in-process maintenance loop (3.16)."""
    install_shutdown_handler()
    interval = maintenance_interval_seconds()
    sweeper = asyncio.create_task(maintenance_loop(interval)) if interval else None
    try:
        yield
    finally:
        if sweeper is not None:
            sweeper.cancel()


app = FastAPI(lifespan=app_lifespan)

# Phase 2 API surface: verified IAP identity, cross-site guard, dashboard dismissal gate.
from iap_auth import get_iap_user_email, verify_google_oidc
from event_validation import apply_authoritative, needs_validation, validate_relayed_event
from task_context import (IN_FLIGHT, SHUTDOWN_REASON, TaskCancelled, TaskSession, get_telemetry_context,
                          make_cancel_check, request_shutdown, shutdown_requested, telemetry_context,
                          update_telemetry_context)
from log_stream import scan_log_events, stream_limit_seconds
from request_guards import (
    INTERVENTION_RESOLUTIONS,
    CrossSiteGuardMiddleware,
    api_error_payload,
    check_dismissal_target,
    check_intervention_record,
    dismissal_gate_decision,
    parse_origins,
    validate_dismissal_request,
    validate_intervention_resolution
)

# CORS. The dashboard UI is served from this same origin and needs no CORS. Extra origins (for
# example http://localhost:3000 during local UI development) are allowed only through
# DASHBOARD_ORIGINS (comma list), without credentials. Default: no CORS middleware at all.
DASHBOARD_ORIGINS = parse_origins(os.getenv("DASHBOARD_ORIGINS", ""))
if DASHBOARD_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(DASHBOARD_ORIGINS),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Refuses state-changing requests and WebSocket handshakes that a browser sends from another site
# (CSRF riding the IAP cookie). Requests without an Origin header (GitHub webhooks, the Actions
# relay, Cloud Scheduler) and same-origin dashboard calls pass.
app.add_middleware(CrossSiteGuardMiddleware, allowed_origins=DASHBOARD_ORIGINS)

if not os.getenv("IAP_AUDIENCE", "").strip():
    logger.warning(
        "IAP_AUDIENCE is not set: no verified dashboard identity is available, so identity-bearing "
        "actions (dismiss / Accept Risk, intervention resolve) return 401."
    )

# Webhook-only mode, set on the codemender-webhook service: only /github-webhook, /webhook and
# /health are served. Every other path (dashboard APIs, static UI) gets 404 from this
# ASGI middleware before any route or the static mount runs. Off by default.
WEBHOOK_ONLY = env_flag(os.getenv("WEBHOOK_ONLY"), default=False)
if WEBHOOK_ONLY:
    app.add_middleware(WebhookOnlyMiddleware)
    logger.info(f"WEBHOOK_ONLY=true: serving only {', '.join(sorted(WEBHOOK_ONLY_PATHS))}; every other path returns 404.")

@app.get("/health")
async def health_check():
    """Liveness probe and service health endpoint."""
    return {
        "status": "healthy",
        "service": "codemender",
        "project": os.getenv("GOOGLE_CLOUD_PROJECT", "your-gcp-project-id"),
        "timestamp": time.time()
    }


# Load webhook secret from environment (configured in Secret Manager in prod)
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")

# Signature-bypass gate. The X-CodeMender-Auth: WIF header is NOT a credential -- it only
# signals that authentication already happened at the Cloud Run IAM layer. Enabling this on a
# service deployed with --allow-unauthenticated makes the webhook publicly writable, so it is
# opt-in and must be paired with --no-allow-unauthenticated plus a run.invoker binding
# restricted to the federated service account.
WIF_AUTH_ENABLED = env_flag(os.getenv("WIF_AUTH_ENABLED"), default=False)

# Repository enrollment allowlist. Target repos are read from the webhook payload (required so
# scoped PATs resolve correctly), which means an unvalidated payload can point the agent at any
# repository its token can reach. Empty set = allow all, intended for local development only.
ALLOWED_REPOS = parse_allowed_repos(os.getenv("ALLOWED_REPOS", ""))

# When true, /approve must come from someone other than the PR author (four-eyes approval).
REQUIRE_INDEPENDENT_APPROVER = env_flag(os.getenv("REQUIRE_INDEPENDENT_APPROVER"), default=False)

# Base URL for dashboard links on commit statuses (per-environment override).
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "https://codemender-dashboard-your-project-number.us-central1.run.app").rstrip("/")

BOT_EMAIL = "agent@codemender.ai"


def is_repo_allowed(repo_name: str) -> bool:
    """Returns True when the repository is enrolled, or when no allowlist is configured."""
    return _repo_in_allowlist(repo_name, ALLOWED_REPOS)


def log_internal_error(context: str, err) -> str:
    """Logs ``err`` (redacted) under a new short error id and returns that id."""
    error_id = new_error_id()
    is_exc = isinstance(err, BaseException)
    detail = f"{type(err).__name__}: {err}" if is_exc else str(err)
    logger.error(f"{context} [error_id={error_id}]: {redact(detail)}", exc_info=err if is_exc else None)
    return error_id


def internal_error_response(context: str, err, status_code: int = 500) -> JSONResponse:
    """Generic JSON error carrying a short error id; the exception is only logged, under that id.

    Exception text never goes into a response body: it can carry tokens, internal paths or
    upstream API payloads.
    """
    return JSONResponse(status_code=status_code, content=error_payload(log_internal_error(context, err)))


def without_error_text(result, context: str):
    """Returns a helper result with the exception text of an {'status': 'error'} dict replaced by an error id."""
    if not is_error_result(result):
        return result
    return scrub_error_result(result, log_internal_error(context, result.get("message")))


async def load_scan_record(commit_sha: str) -> dict | None:
    """Returns scans/{commit_sha} from Firestore, or None when it does not exist (read off the event loop)."""
    from database import db
    if db is None:
        raise RuntimeError("Firestore client is not initialized")
    snap = await asyncio.to_thread(db.collection("scans").document(commit_sha).get)
    return (snap.to_dict() or {}) if snap.exists else None


async def resolve_dashboard_target(commit_sha: str, body_repo_name=None, body_pr_number=None) -> ScanTarget:
    """Repository/PR for a dashboard action, from the stored scan record only (see resolve_scan_target)."""
    try:
        scan_record = await load_scan_record(commit_sha)
    except Exception as err:
        error_id = log_internal_error(f"Could not load scan record {commit_sha}", err)
        return ScanTarget(500, f"Could not load the scan (error id: {error_id})")
    return resolve_scan_target(scan_record, ALLOWED_REPOS, body_repo_name=body_repo_name, body_pr_number=body_pr_number)


async def dashboard_identity_or_401(request):
    """(email, None) for a verified IAP user, else (None, 401 JSONResponse).

    Every state-changing dashboard action (verify, fix, draft PR, cancel, sandbox, analytics chat)
    needs a verified identity: they spend model budget, push branches or change scan state, and the
    identity is recorded for audit. Identity only comes from a verified IAP JWT (see iap_auth).
    """
    email = await get_iap_user_email(request)
    if not email:
        return None, JSONResponse(
            status_code=401,
            content=api_error_payload("A verified dashboard identity (IAP) is required"),
        )
    return email, None


def scan_target_error(target: ScanTarget) -> JSONResponse:
    """JSON error for a dashboard action refused by resolve_scan_target."""
    return JSONResponse(status_code=target.status_code, content={"status": "error", "message": target.message})


def is_trusted_commenter(payload: dict) -> bool:
    """Checks the GitHub author_association on a comment payload.

    The webhook replaces relayed comments with GitHub's copy first (plan 1.6), so this value is
    GitHub's. Anything outside OWNER/MEMBER/COLLABORATOR (NONE, FIRST_TIME_CONTRIBUTOR,
    CONTRIBUTOR) is rejected. It is only a pre-filter: see require_write_access.
    """
    return is_trusted_association((payload.get("comment", {}) or {}).get("author_association"))


async def require_write_access(repo_name: str, payload: dict, commenter: str, command: str) -> Response | None:
    """Returns a 403 response unless the commenter can push to the repository (fails closed).

    Slash commands spend model budget, push branches and approve patches. author_association
    MEMBER only means membership of the owning org, so the decision is the commenter's base
    permission from the collaborator API (admin or write).
    """
    if not is_trusted_commenter(payload):
        assoc = (payload.get("comment", {}) or {}).get("author_association", "NONE")
        logger.warning(f"Rejecting command '/{command}' from '{commenter}' (author_association={assoc}).")
        return Response(content="Insufficient repository permissions", status_code=403)
    try:
        token = await get_github_token()
        permission = await get_collaborator_permission(repo_name, commenter, token)
    except Exception as err:
        logger.error(f"Could not verify repository permission for '{commenter}': {type(err).__name__}")
        permission = "none"
    if has_write_permission(permission):
        return None
    logger.warning(f"Rejecting command '/{command}' from '{commenter}': repository permission '{permission}' lacks write.")
    return Response(content="Write access to the repository is required", status_code=403)


async def reject_duplicate_command(event_type: str, payload: dict, repo_name: str) -> Response | None:
    """Runs each comment command at most once (plan 3.11).

    GitHub redeliveries, relay workflow re-runs and replays of an old, genuine comment all carry
    the same comment id, so they are ignored with 200. Fails closed (503) when the record can't
    be written.
    """
    comment_id = (payload.get("comment", {}) or {}).get("id")
    if not comment_id:
        return Response(content="Comment has no id", status_code=400)
    claimed = await asyncio.to_thread(claim_comment_event, comment_id, event_type, repo_name)
    if claimed is True:
        return None
    if claimed is False:
        logger.info(f"Ignoring {event_type} {comment_id}: this comment was already processed.")
        return Response(content="Comment already processed", status_code=200)
    return Response(content="Could not record the command; please retry", status_code=503)


SCAN_FILE_LIMIT_DEFAULT = 20


def scan_file_limit() -> int:
    """CM_MAX_SCAN_FILES (default 20, clamped to 1-100): changed files scanned per PR head (plan 3.1)."""
    raw = (os.getenv("CM_MAX_SCAN_FILES") or "").strip()
    try:
        value = int(raw) if raw else SCAN_FILE_LIMIT_DEFAULT
    except ValueError:
        value = SCAN_FILE_LIMIT_DEFAULT
    return max(1, min(100, value))


def owns_scan_record(head_sha: str, run_id: str | None) -> bool:
    """True unless a newer webhook delivery for the same commit took over its scan record."""
    if not run_id:
        return True
    from shared_state import active_tasks
    current = active_tasks.get(head_sha)
    return current is None or current == run_id


async def mark_scan_superseded(repo_name: str, head_sha: str, pr_number, run_id: str | None, token: str | None = None):
    """Terminal state for a scan whose PR moved on to a newer head (plan 3.14).

    The record and gate are only written when no newer run for the same commit owns them.
    """
    if not owns_scan_record(head_sha, run_id):
        return
    update_scan_status(head_sha, status=SUPERSEDED_SCAN_STATUS, message="Superseded: the pull request moved on to a newer commit.",
                       pr_number=pr_number, active_task=None)
    if token and repo_name:
        state, description = superseded_gate(None)
        try:
            await set_commit_status(repo=repo_name, commit_sha=head_sha, state=state, description=description,
                                    token=token, target_url=f"{DASHBOARD_URL}/scans/{head_sha}")
        except Exception as err:
            logger.warning(f"Could not set the superseded gate on {head_sha[:8]}: {err}")


def restore_after_failed_task(commit_sha: str, findings: list, prior_finding_status: dict, prior_status,
                              transient_statuses: tuple, error=None) -> None:
    """Puts the scan record back the way a failed or cancelled verify/fix found it (plan 3.3).

    Findings still in a transient status (VERIFYING/PATCHING) get their previous status back;
    findings the task already finished keep their new status. The record's status returns to
    the one the task found (never a blanket COMPLETED, so a failed scan stays failed).
    """
    for finding in findings or []:
        fid = finding.get("id")
        if finding.get("status") in transient_statuses and fid in prior_finding_status:
            finding["status"] = prior_finding_status[fid]
    detail = " ".join(redact(str(error)).split())[:500] if error else None
    update_scan_status(
        commit_sha,
        status=prior_status or "COMPLETED",
        message="The last verify/fix run did not finish; see error_message." if error else "Verify/fix run ended.",
        findings=findings,
        active_task=None,
        status_before_task=None,
        error_message=detail,
    )


def parse_yaml_value(content: str, key: str) -> str:
    import re
    match = re.search(fr"^{key}\s*:\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip().strip('"').strip("'")
    return ""


_PROGRESS_LABELS = {"scan": "Triage Scan", "verify": "Exploit Verification", "patch": "Patch Generation"}


def progress_key(task_type: str, commit_sha: str) -> str:
    """Key of the single in-place progress comment for one task on one commit."""
    return f"{task_type}-{(commit_sha or '')[:12]}"


async def post_periodic_progress(repo_name: str, commit_sha: str, pr_number: int | None, is_pr: bool, token: str, task_type: str, run_id: str):
    """Every 60 s while the task runs: refreshes the scan heartbeat and, on PRs, the progress comment.

    The heartbeat (scans/{sha}.updated_at, plan 3.17) is what the duplicate-delivery guard and the
    maintenance sweep use to tell a live task from a dead one, so a failed refresh is logged and
    retried next minute instead of ending the loop. The loop ends when the task is superseded or
    its record leaves the running state. Commits get no periodic comment: commit comments can't be
    edited in place, so each refresh would post a new one.
    """
    minutes = 0
    while True:
        await asyncio.sleep(60)
        minutes += 1
        try:
            from shared_state import active_tasks
            if active_tasks.get(commit_sha) != run_id:
                logger.info(f"Terminating stale progress loop for commit {commit_sha} (superseded by run {active_tasks.get(commit_sha)})")
                break
            from database import db, touch_scan
            snap = await asyncio.to_thread(db.collection("scans").document(commit_sha).get)
            if not snap.exists:
                break
            data = snap.to_dict() or {}
            status = str(data.get("status") or "").upper()
            if status in TERMINAL_SCAN_STATUSES:
                break
            if task_type in ("verify", "patch") and status != "RUNNING":
                break
            await asyncio.to_thread(touch_scan, commit_sha)
        except Exception as err:
            logger.warning(f"Progress heartbeat for {commit_sha[:8]} failed; retrying next minute: {err}")
            continue

        if not pr_number:
            continue
        step_desc = data.get("message", "")
        step_suffix = f" — [{step_desc}]" if step_desc else ""
        if task_type == "scan":
            msg = f"⏳ **CodeMender Triage Scan is in progress...** ({minutes}m elapsed){step_suffix}"
        elif task_type == "verify":
            msg = f"⏳ **CodeMender Exploit Verification is in progress...** ({minutes}m elapsed){step_suffix}"
        else:
            msg = f"⏳ **CodeMender Patch Generation is in progress...** ({minutes}m elapsed){step_suffix}"
        try:
            await upsert_progress_comment(repo_name, pr_number, progress_key(task_type, commit_sha), msg, token)
        except Exception as err:
            logger.warning(f"Could not refresh the progress comment on PR #{pr_number}: {err}")


async def stop_background_task(task: asyncio.Task | None):
    """Cancels a helper task (heartbeat) and waits for it, so it cannot race a final comment edit."""
    if task is not None and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def finish_progress_comment(repo_name: str, pr_number: int | None, task_type: str, commit_sha: str, token: str | None, started_at: float, error=None):
    """Closes out the heartbeat comment: deleted on success, replaced by a one-line reason on failure."""
    if not (repo_name and pr_number and token):
        return
    key = progress_key(task_type, commit_sha)
    comment_id = get_progress_comment_id(repo_name, pr_number, key)
    if not comment_id:
        return  # The task ended before anything was posted.
    label = _PROGRESS_LABELS.get(task_type, "Task")
    try:
        if error is None:
            if await delete_comment(repo_name, comment_id, token):
                return
            minutes = max(1, round((time.monotonic() - started_at) / 60))
            body = f"✅ CodeMender {label} finished in {minutes}m."
        else:
            reason = " ".join(redact(str(error)).split())[:300]
            body = f"❌ CodeMender {label} failed: {reason}"
        await upsert_progress_comment(repo_name, pr_number, key, body, token)
    except Exception as err:
        logger.warning(f"Failed to finalize progress comment '{key}' on PR #{pr_number}: {err}")


async def post_lock_busy_comment(repo_name: str, pr_number: int | None, commit_sha: str | None, action: str, token: str | None = None):
    """Tells the user a request did not start because another task holds the lock (no silent drops)."""
    if not (repo_name and pr_number):
        return
    try:
        token = token or await get_github_token()
        target = f" on commit `{commit_sha[:7]}`" if commit_sha else " on this pull request"
        msg = (
            f"⏳ CodeMender is busy with another task{target}, so {action} was not started. "
            "Please try again shortly, or comment `/cancel` if it appears stuck."
        )
        await post_pr_comment(repo_name, pr_number, msg, token)
    except Exception as err:
        logger.warning(f"Failed to post busy-lock comment on PR #{pr_number}: {err}")


def _is_bot_identity(name: str, email: str) -> bool:
    return BOT_EMAIL in (email or "").lower() or (name or "").strip().lower() in ("codemender agent", "codemender bot")


async def resolve_commit_identity(repo_name: str, commit_sha: str, token: str, git_ws: GitWorkspace | None = None) -> tuple[str, str]:
    """Identity for CodeMender commits: the head commit's author, else the Firestore pusher fields.

    Never the bot identity, so Google CLA checks pass (GEMINI.md). Raises if nothing usable exists.
    """
    try:
        author = await get_commit_author(repo_name, commit_sha, token)
        if author and not _is_bot_identity(*author):
            return author
    except Exception as err:
        logger.warning(f"GitHub commit author lookup failed for {commit_sha[:8]}: {err}")

    if git_ws is not None:
        try:
            out, _ = await git_ws._run_command(["git", "log", "-1", "--format=%an|%ae", commit_sha])
            name, _, email = out.strip().partition("|")
            if name and email and not _is_bot_identity(name, email):
                return name.strip(), email.strip()
        except Exception as err:
            logger.warning(f"Local git author lookup failed for {commit_sha[:8]}: {err}")

    try:
        from database import db
        snap = db.collection("scans").document(commit_sha).get() if db else None
        if snap is not None and snap.exists:
            data = snap.to_dict() or {}
            name = data.get("pusher_name") or data.get("pusher") or ""
            email = data.get("pusher_email") or (f"{name}@users.noreply.github.com" if name else "")
            if name and email and not _is_bot_identity(name, email):
                return name, email
    except Exception as err:
        logger.warning(f"Firestore pusher lookup failed for {commit_sha[:8]}: {err}")

    if os.getenv("MOCK_MODE") == "true":
        return "developer", "developer@users.noreply.github.com"
    raise CommitIdentityError(f"No commit author identity found for {commit_sha[:8]}; refusing to commit as the CodeMender bot.")


async def stage_and_commit(git_ws: GitWorkspace, message: str) -> str | None:
    """Commits every change (new, modified, deleted files) via GitWorkspace.commit_all.

    commit_all stages with `git add -A` minus CodeMender state (.codemender/.cm_project/.exploit)
    and strips [skip ci], so patch commits are always re-scanned. Returns the new HEAD SHA, or
    None when there is nothing to commit (an empty commit would fail).
    """
    status, _ = await git_ws._run_command(["git", "status", "--porcelain", "--", ".", *_STATE_EXCLUDE_PATHSPECS])
    if not status.strip():
        return None
    return await git_ws.commit_all(message)


async def report_unmapped_finding(repo_name: str, pr_number: int | None, commit_sha: str, finding_id: str, token: str):
    """Posts the 'could not re-locate' notice for a finding that select_finding could not map."""
    msg = f"Could not re-locate finding `{finding_id}` in the current scan; skipped."
    logger.warning(f"{msg} (commit {commit_sha})")
    try:
        if pr_number:
            await post_pr_comment(repo_name, pr_number, msg, token)
        elif commit_sha and commit_sha != "main":
            await post_commit_comment(repo_name, commit_sha, msg, token)
    except Exception as err:
        logger.warning(f"Failed to post unmapped-finding notice for {finding_id}: {err}")


def is_scan_in_flight(head_sha: str) -> bool:
    """True when scans/{head_sha} is QUEUED/RUNNING and was updated within the last 30 minutes."""
    try:
        from database import db
        if not db:
            return False
        snap = db.collection("scans").document(head_sha).get()
        if not snap.exists:
            return False
        data = snap.to_dict() or {}
        return should_skip_duplicate_scan(data.get("status"), data.get("updated_at"), time.time())
    except Exception as err:
        logger.warning(f"Duplicate-scan check failed for {head_sha}: {err}")
        return False


async def reject_command(repo_name: str, message: str, reason: str, pr_number: int | None = None, commit_sha: str | None = None) -> Response:
    """Posts a short refusal on the PR (or commit) and returns HTTP 403."""
    logger.warning(f"Rejecting command: {message}")
    try:
        token = await get_github_token()
        if pr_number:
            await post_pr_comment(repo_name, pr_number, message, token)
        elif commit_sha:
            await post_commit_comment(repo_name, commit_sha, message, token)
    except Exception as err:
        logger.warning(f"Failed to post command refusal: {err}")
    return Response(content=reason, status_code=403)


async def require_maintainer(repo_name: str, commenter: str, command: str, pr_number: int | None = None, commit_sha: str | None = None) -> Response | None:
    """Returns a 403 response unless the commenter has the maintain or admin role (fails closed)."""
    try:
        token = await get_github_token()
        role = await get_collaborator_role(repo_name, commenter, token)
    except Exception as err:
        logger.error(f"Could not verify repository role for '{commenter}': {err}")
        role = "none"
    if has_maintainer_role(role):
        return None
    logger.warning(f"'/{command}' from '{commenter}' denied: repository role '{role}' lacks maintain/admin.")
    return await reject_command(
        repo_name,
        f"⛔ @{commenter}: /{command} requires maintain or admin access.",
        "Maintain or admin access required",
        pr_number=pr_number,
        commit_sha=commit_sha
    )

async def upload_verification_artifacts(commit_sha: str, workspace_path: str, finding_id: str) -> list[dict]:
    """Finds all files in the local .exploit/ directory of the workspace and uploads them to GCS under a finding-specific subfolder."""
    from google.cloud import storage
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-gcp-project-id")
    bucket_name = f"{project_id}-artifacts"
    exploit_dir = Path(workspace_path) / ".exploit"
    
    if not exploit_dir.exists() or not exploit_dir.is_dir():
        logger.warning(f"No .exploit directory found in workspace {workspace_path}")
        return []
        
    uploaded = []
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        for file_path in exploit_dir.rglob("*"):
            if file_path.is_file():
                relative_path = file_path.relative_to(exploit_dir)
                gcs_blob_path = f"sessions/{commit_sha}/.exploit/{finding_id}/{relative_path}"
                blob = bucket.blob(gcs_blob_path)
                blob.upload_from_filename(str(file_path))
                
                url = f"https://console.cloud.google.com/storage/browser/_details/{bucket_name}/{gcs_blob_path}?project={project_id}"
                uploaded.append({
                    "name": str(relative_path),
                    "url": url,
                    "local_path": str(file_path)
                })
        logger.info(f"Uploaded {len(uploaded)} verification artifacts to GCS for finding {finding_id}.")
    except Exception as e:
        logger.error(f"Failed to upload verification artifacts to GCS for finding {finding_id}: {e}")
        
    return uploaded

def sanitize_comment_length(comment: str) -> str:
    """Truncates PR comments exceeding GitHub's 65,536 character limit to prevent API submission failures."""
    MAX_CHAR = 60000
    if len(comment) <= MAX_CHAR:
        return comment
        
    warning_suffix = (
        "\n\n---\n"
        "⚠️ **[Console Output Truncated]** The raw output trace exceeded GitHub's 65KB limit. "
        "The full execution logs are preserved and can be viewed in the Cloud Storage artifacts linked above."
    )
    
    allowed_len = MAX_CHAR - len(warning_suffix)
    return comment[:allowed_len] + warning_suffix

def filter_findings_by_targets(findings: list[dict], target_ids: list[str]) -> list[dict]:
    """
    Filters findings by scope keyword ('all', '*', 'critical', 'high', 'medium', 'low')
    or specific finding IDs.
    """
    if not target_ids or not findings:
        return []

    def _is_active(f: dict) -> bool:
        if str(f.get("lifecycle_status", "")).upper() == "RESOLVED":
            return False
        if str(f.get("status", "")).upper() in ("RESOLVED", "DISMISSED"):
            return False
        return True

    first_arg = target_ids[0].lower().strip(",.;")
    if first_arg in ["all", "*"]:
        return [f for f in findings if _is_active(f)]
    elif first_arg in ["critical", "high", "medium", "low"]:
        target_sev = first_arg.upper()
        return [f for f in findings if _is_active(f) and str(f.get("severity", "")).upper() == target_sev]
    else:
        target_set = {t.strip(",.;").lower() for t in target_ids}
        return [
            f for f in findings 
            if str(f.get("id", "")).lower() in target_set 
            or str(f.get("display_id", "")).lower() in target_set
            or str(f.get("fingerprint", "")).lower() in target_set
            or any(str(f.get("fingerprint", "")).lower().startswith(t) for t in target_set)
        ]

def ensure_codemender_config():
    """Ensures that CodeMender global config exists and supports all extensions including .tf."""
    import os
    cfg_dir = os.path.expanduser("~/.codemender")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, "config.yaml")
    
    # Pre-defined config contents with .tf support and headless non-interactive settings
    default_model = os.getenv("GEMINI_MODEL_NAME", "gemini-3.8-flash")
    config_content = f"""# CodeMender CLI configuration.
model: "{default_model}"

scan:
  extensions:
    include: [".py", ".java", ".go", ".js", ".ts", ".c", ".cc", ".cpp", ".h", ".rb", ".php", ".sh", ".tf"]
    exclude: [".min.js", ".generated.go", ".pb.go"]
  max_file_size_kb: 500
  incremental: true

output:
  format: table

tools:
  confirm_commands: false
  confirm_writes: false
"""
    with open(cfg_path, "w") as f:
        f.write(config_content)
    logger.info(f"Verified CodeMender global configuration with .tf support at {cfg_path}")


async def export_and_upload_reports(commit_sha: str, workspace_path: str) -> dict[str, str]:
    """Generates HTML and MD reports using cm report and uploads them to GCS, returning their URLs."""
    from google.cloud import storage
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-gcp-project-id")
    bucket_name = f"{project_id}-artifacts"
    html_report_path = f"/tmp/REPORT-{commit_sha}.html"
    md_report_path = f"/tmp/REPORT-{commit_sha}.md"
    
    urls = {}
    try:
        # Generate HTML report
        proc_html = await asyncio.create_subprocess_exec(
            "cm", "report", "-f", "html",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        stdout_html, stderr_html = await proc_html.communicate()
        if proc_html.returncode == 0:
            default_report_path = os.path.expanduser("~/.codemender/reports/report.html")
            if os.path.exists(default_report_path):
                with open(default_report_path, "rb") as src, open(html_report_path, "wb") as dst:
                    dst.write(src.read())
            else:
                logger.error(f"HTML report file not found at {default_report_path}")
        else:
            logger.error(f"Failed to run cm report html: {stderr_html.decode()}")
            
        # Generate Markdown report
        proc_md = await asyncio.create_subprocess_exec(
            "cm", "report", "-f", "md",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        stdout_md, stderr_md = await proc_md.communicate()
        if proc_md.returncode == 0:
            with open(md_report_path, "wb") as f:
                f.write(stdout_md)
        else:
            logger.error(f"Failed to run cm report md: {stderr_md.decode()}")
        
        # Upload both to GCS
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        if os.path.exists(html_report_path):
            gcs_html_path = f"sessions/{commit_sha}/REPORT.html"
            blob_html = bucket.blob(gcs_html_path)
            blob_html.upload_from_filename(html_report_path)
            urls["html"] = f"https://console.cloud.google.com/storage/browser/_details/{bucket_name}/{gcs_html_path}?project={project_id}"
            
        if os.path.exists(md_report_path):
            gcs_md_path = f"sessions/{commit_sha}/REPORT.md"
            blob_md = bucket.blob(gcs_md_path)
            blob_md.upload_from_filename(md_report_path)
            urls["md"] = f"https://console.cloud.google.com/storage/browser/_details/{bucket_name}/{gcs_md_path}?project={project_id}"
            
        logger.info(f"Successfully uploaded HTML and MD reports to GCS for commit {commit_sha}")
    except Exception as e:
        logger.error(f"Failed to generate and upload reports to GCS: {e}")
        
    return urls


async def process_pr_scan_event(payload: dict, run_id: str = None):
    """Scans the head of a pull request (webhook `pull_request` event).

    Every token-usage and scan_log row of the scan carries the PR number, the draft flag and
    event_type='pull_request' (plan 4.2).
    """
    pull_request = payload.get("pull_request") or {}
    with telemetry_context(pr_number=payload.get("number") or pull_request.get("number"),
                           event_type="pull_request", is_draft=pull_request.get("draft")):
        return await _process_pr_scan_event(payload, run_id=run_id)


async def _process_pr_scan_event(payload: dict, run_id: str = None):
    """
    Asynchronous background worker to process pull_request events (opened, synchronize, reopened, ready_for_review).
    Performs cumulative merge-base diffing, tooling bypass checks ($0 spend), CodeMender triage,
    in-place single pinned comment updates, and PR merge gate enforcement.

    This worker is the only code path that sets security/codemender-gate for head_sha.
    """
    pr_data = payload.get("pull_request") or {}
    pr_number = payload.get("number") or pr_data.get("number")
    head_sha = pr_data.get("head", {}).get("sha")
    branch = pr_data.get("head", {}).get("ref")
    base_branch = pr_data.get("base", {}).get("ref", "main")
    is_draft = pr_data.get("draft", False)
    pr_title = pr_data.get("title", "")
    pr_url = pr_data.get("html_url", "")
    repo_obj = payload.get("repository") or {}
    repo_name = repo_obj.get("full_name")
    user_obj = pr_data.get("user") or {}
    pusher = user_obj.get("login", "developer")
    pusher_email = user_obj.get("email", "")

    if not head_sha or not pr_number:
        logger.warning(f"Invalid PR scan event: Missing head_sha ({head_sha}) or pr_number ({pr_number})")
        return
    task_started_at = time.time()  # cancel requests from before this delivery don't apply

    # Check for active task cancellation / superseding
    if run_id:
        from shared_state import active_tasks
        current_active = active_tasks.get(f"pr-{pr_number}")
        if current_active and current_active != run_id:
            logger.info(f"PR #{pr_number} task {run_id} superseded by newer run {current_active}. Cleanly exiting.")
            await mark_scan_superseded(repo_name, head_sha, pr_number, run_id)
            return

    lock_id = f"workspace-{head_sha}"
    owner = acquire_lock(lock_id)
    if not owner:
        logger.warning(f"Aborting PR event processing: Lock already active for {lock_id}")
        # Leave QUEUED behind and the duplicate guard would swallow re-deliveries for 30 minutes.
        # Only a scan still at QUEUED is deferred; a status advanced by another worker is kept.
        try:
            from database import db
            snap = db.collection("scans").document(head_sha).get() if db else None
            current_status = (snap.to_dict() or {}).get("status") if snap is not None and snap.exists else None
            if current_status in (None, "QUEUED"):
                update_scan_status(
                    head_sha,
                    status=DEFERRED_SCAN_STATUS,
                    message="Scan deferred: another CodeMender task holds this commit's workspace.",
                    pr_number=pr_number
                )
        except Exception as defer_err:
            logger.warning(f"Failed to mark scan {head_sha[:8]} as deferred: {defer_err}")
        await post_lock_busy_comment(repo_name, pr_number, head_sha, "the security scan")
        return
    renewer = start_lock_renewal(lock_id, owner)
    session = TaskSession(head_sha, "scan", lock_id=lock_id, owner=owner, repo_name=repo_name, pr_number=pr_number,
                          cancel_check=make_cancel_check(head_sha, task_started_at))

    token = None
    heartbeat = None
    scan_error = None
    started_at = time.monotonic()
    dashboard_url = f"{DASHBOARD_URL}/scans/{head_sha}"

    try:
        await session.start()
        # 1. Broker token. Remediation and bot PRs are scanned like any other PR: branch names,
        #    titles and [skip ci] markers are chosen by the PR author and must never pass the gate.
        token = await get_github_token()

        # Set initial commit status gate to pending (Gate 1: Mandatory PR Scan)
        try:
            gate_badge = f"Draft PR #{pr_number}" if is_draft else f"Pull Request #{pr_number}"
            await set_commit_status(
                repo=repo_name,
                commit_sha=head_sha,
                state="pending",
                description=f"CodeMender Gate: Analyzing {gate_badge} security...",
                token=token,
                target_url=dashboard_url
            )
        except Exception as status_err:
            logger.warning(f"Failed to set initial PR commit status: {status_err}")

        # Start periodic progress reporting task
        if run_id:
            heartbeat = asyncio.create_task(post_periodic_progress(repo_name, head_sha, pr_number=pr_number, is_pr=True, token=token, task_type="scan", run_id=run_id))

        logger.info(f"Starting async PR scan processing for PR #{pr_number} ('{branch}' ➔ '{base_branch}') in repo '{repo_name}' (commit {head_sha})...")
        append_scan_step(head_sha, "info", f"Started processing PR #{pr_number} ({'Draft PR' if is_draft else 'Ready for Review'}) by '{pusher}'")
        
        update_scan_status(
            head_sha,
            branch_name=branch,
            repo_name=repo_name,
            pr_number=pr_number,
            is_draft=is_draft,
            pr_url=pr_url,
            pr_title=pr_title,
            base_branch=base_branch,
            status="CLONING",
            message=f"Cloning PR branch '{branch}' from GitHub",
            pusher_name=pusher,
            pusher_email=pusher_email,
            # This scan owns the record until it finishes; no result is available meanwhile.
            active_task="scan",
            scan_completed_at=None,
            scan_complete=None,
            error_message=None,
        )
        append_scan_step(head_sha, "workspace", "Setting up local sandbox workspace for cumulative PR diff...")

        # 3. Setup git workspace & clone branch
        git_ws = GitWorkspace(head_sha, repo=repo_name)
        await git_ws.clone_repo(token, branch)
        # The clone is the branch tip, which may already be past head_sha (or, for a fork PR, a
        # same-named base branch). The gate below is written for head_sha, so the scanned tree must
        # be exactly that commit; HeadMismatchError ends in an 'error' gate (except block below).
        await git_ws.ensure_exact_head(head_sha, pr_number=pr_number)
        logger.info(f"Successfully cloned PR branch '{branch}' to workspace.")
        append_scan_step(head_sha, "workspace", f"Repository PR branch cloned successfully to {git_ws.workspace_path} (pinned to {head_sha[:7]})")

        # Pre-initialize global config so that headless runs have non-interactive configurations
        ensure_codemender_config()

        # 4. Cumulative Merge-Base Diff Resolution across all commits in PR
        changed_files = await git_ws.get_cumulative_diff_files(base_branch=base_branch)
        logger.info(f"Cumulative PR diff files for PR #{pr_number}: {changed_files}")

        supported_exts = {".ts", ".js", ".py", ".go", ".java", ".cpp", ".c", ".rb", ".php", ".sh", ".tf"}
        target_files = []
        for f in changed_files:
            # Skip CodeMender framework, tooling, configuration, and CI files
            if any(f.startswith(prefix) for prefix in ["backend/", "frontend/", "scripts/", "scratch/", "configs/", ".github/", ".gemini/"]):
                continue
            if os.path.splitext(f)[1] in supported_exts:
                target_files.append(f)

        # 5. Tooling & Framework PR Bypass ($0 Spend)
        if not target_files:
            logger.info(f"No application source files modified in PR #{pr_number} (tooling/framework only). Bypassing scan with $0.00 spend.")
            await set_commit_status(
                repo=repo_name,
                commit_sha=head_sha,
                state="success",
                description="Passed: Tooling/framework changes only (0 vulnerabilities)",
                token=token,
                target_url=dashboard_url
            )
            update_scan_status(
                head_sha,
                status="COMPLETED",
                message="Passed: Tooling/framework changes only (0 vulnerabilities)",
                findings=[],
                pr_number=pr_number,
                is_draft=is_draft,
                pr_url=pr_url,
                active_task=None,
                scan_completed_at=time.time(),
                scan_complete=True,
            )
            append_scan_step(head_sha, "workspace", "Scan bypassed ($0 spend): PR contains only framework/tooling changes.")
            
            try:
                log_scan_summary(
                    commit_sha=head_sha,
                    repo_name=repo_name,
                    branch_name=branch,
                    event_type="pull_request",
                    status="COMPLETED",
                    target_file="none",
                    findings_count=0,
                    findings=[],
                    action_taken="bypass",
                    pr_number=pr_number,
                    is_draft=is_draft,
                    cost_usd=0.0,
                    cached_savings_usd=0.0
                )
            except Exception as bq_err:
                logger.error(f"Failed to log bypass summary to BigQuery: {bq_err}")

            # Update in-place single pinned PR comment
            badge = f"📝 **Draft PR #{pr_number}**" if is_draft else f"🚀 **Pull Request #{pr_number}**"
            bypass_comment = (
                "<!-- codemender-security-report -->\n"
                f"### 🔍 CodeMender PR Security Analysis\n\n"
                f"- **PR:** {badge} (`{branch}` ➔ `{base_branch}`)\n"
                f"- **Head Commit:** `{head_sha[:7]}`\n"
                f"- **Status:** 🟢 **Passed** ($0.00 spend)\n\n"
                f"✅ **No application source files modified** (tooling/framework changes only). 0 security vulnerabilities detected.\n"
            )
            try:
                await update_or_post_pr_comment(repo_name, pr_number, bypass_comment, token)
            except Exception as comment_err:
                logger.warning(f"Failed to post bypass comment to PR #{pr_number}: {comment_err}")
            return

        # Check again if active task was superseded before launching heavy LLM scans
        if run_id:
            from shared_state import active_tasks
            current_active = active_tasks.get(f"pr-{pr_number}")
            if current_active and current_active != run_id:
                logger.info(f"PR #{pr_number} task {run_id} superseded before LLM scan by {current_active}. Aborting.")
                await mark_scan_superseded(repo_name, head_sha, pr_number, run_id, token)
                return

        # File cap (plan 3.1): at most CM_MAX_SCAN_FILES changed files are scanned (one cm run each).
        # Files over the cap are listed in the report and keep the gate from passing.
        max_files_to_scan = scan_file_limit()
        files_to_scan = target_files[:max_files_to_scan]
        unscanned_files = target_files[max_files_to_scan:]

        logger.info(f"Target files chosen for CodeMender analysis: {files_to_scan} (not scanned: {unscanned_files})")
        append_scan_step(
            head_sha, "workspace",
            f"Selected {len(files_to_scan)} of {len(target_files)} changed files for analysis"
            + (f"; {len(unscanned_files)} over the limit of {max_files_to_scan} are not scanned." if unscanned_files else ".")
        )

        # (Draft -> Ready reuse of a finished result happens in the webhook: has_terminal_scan_result.)
        all_findings = []
            
        try:
            for filepath in files_to_scan:
                file_path = git_ws.workspace_path / filepath
                if not file_path.exists():
                    logger.warning(f"Target file {filepath} not found in workspace. Skipping.")
                    continue

                # Check again if active task was superseded
                if run_id:
                    from shared_state import active_tasks
                    current_active = active_tasks.get(f"pr-{pr_number}")
                    if current_active and current_active != run_id:
                        logger.info(f"PR #{pr_number} task {run_id} superseded during triage by {current_active}. Aborting.")
                        await mark_scan_superseded(repo_name, head_sha, pr_number, run_id, token)
                        return
                await session.raise_if_cancelled()

                # 6. Run CodeMender Triage scan. A scanner failure raises TriageError, which sets
                #    the gate to 'error' below instead of being mistaken for a clean scan.
                logger.info(f"Starting CodeMender Triage scan for {filepath}...")
                update_scan_status(head_sha, status="RUNNING", message=f"Scanning {filepath} for vulnerabilities", pr_number=pr_number, is_draft=is_draft)

                file_findings = await run_triage_agent(
                    session_id=head_sha,
                    filepath=filepath,
                    repo_name=repo_name
                )
                all_findings.extend(file_findings)
        finally:
            # Back up CodeMender state even when triage failed, so verify/fix can hydrate from it.
            try:
                from gcs_helpers import upload_codemender_state_bundle
                if await asyncio.to_thread(upload_codemender_state_bundle, head_sha, str(git_ws.workspace_path)):
                    append_scan_step(head_sha, "gitops", "Backed up CodeMender state bundle to Cloud Storage.")
            except Exception as state_err:
                logger.error(f"Failed to back up CodeMender state bundle for {head_sha}: {state_err}")
                
        findings = all_findings
        target_file_str = ", ".join(files_to_scan)
            
        # Reconcile lifecycle status against previous PR commits if available
        previous_findings = []
        try:
            from database import db
            if db and pr_number:
                docs = db.collection("scans").where("pr_number", "==", pr_number).stream()
                all_docs = [
                    d for d in docs
                    if d.id != head_sha
                    and (not repo_name or not d.to_dict().get("repo_name") or d.to_dict().get("repo_name") == repo_name)
                ]
                all_docs.sort(key=lambda d: d.to_dict().get("updated_at", d.to_dict().get("timestamp", 0)), reverse=True)
                for doc in all_docs:
                    data = doc.to_dict()
                    if data.get("findings"):
                        previous_findings = [
                            pf for pf in data.get("findings")
                            if str(pf.get("lifecycle_status", "")).upper() != "RESOLVED"
                            and str(pf.get("status", "")).upper() != "RESOLVED"
                        ]
                        break
        except Exception as prev_err:
            logger.warning(f"Could not retrieve previous scan findings for PR #{pr_number}: {prev_err}")

        reconciled_findings, summary_delta = reconcile_finding_lifecycle(
            previous_findings=previous_findings,
            current_findings=findings,
            repo_name=repo_name,
            commit_sha=head_sha
        )
        logger.info(f"CodeMender Triage scan finished for PR #{pr_number}. Active: {len(reconciled_findings)}, Resolved: {summary_delta.get('resolved_count')}, Persistent: {summary_delta.get('persistent_count')}, New: {summary_delta.get('new_count')}")

        update_scan_status(
            head_sha,
            status="COMPLETED",
            message="Vulnerability scan completed; findings list updated.",
            findings=reconciled_findings,
            summary_delta=summary_delta,
            target_file=target_file_str,
            pr_number=pr_number,
            is_draft=is_draft,
            pr_url=pr_url,
            active_task=None,
            scan_completed_at=time.time(),
            scan_complete=not unscanned_files,
            scanned_files=files_to_scan,
            unscanned_files=unscanned_files,
        )
        append_scan_step(head_sha, "info", "Scan process completed successfully.")

        try:
            log_scan_summary(
                commit_sha=head_sha,
                repo_name=repo_name,
                branch_name=branch,
                event_type="pull_request",
                status="COMPLETED",
                target_file=target_file_str,
                findings_count=len(reconciled_findings),
                findings=reconciled_findings,
                action_taken="scan",
                pr_number=pr_number,
                is_draft=is_draft
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log scan summary to BigQuery: {bq_log_err}")

        try:
            from database import log_vulnerability_inventory
            log_vulnerability_inventory(
                repo_name=repo_name,
                commit_sha=head_sha,
                pr_number=pr_number,
                findings=reconciled_findings,
                summary_delta=summary_delta,
                author=pusher
            )
        except Exception as inv_log_err:
            logger.error(f"Failed to log vulnerability inventory to BigQuery: {inv_log_err}")

        # Safeguard 3: the PR may have been merged/closed, or its head may have moved on while this
        # scan ran (plan 3.14). A newer head gets its own scan, so this one must not overwrite the
        # PR-level report or take the PR out of Draft; the gate below is still written for head_sha.
        superseded = False
        try:
            token = await get_github_token()
            pr_info = await get_pull_request(repo_name, pr_number, token)
            if pr_info.get("merged") or pr_info.get("state") == "closed":
                logger.info(f"PR #{pr_number} is already merged/closed. Cleanly aborting comment update.")
                return
            live_head = str((pr_info.get("head") or {}).get("sha") or "")
            superseded = os.getenv("MOCK_MODE") != "true" and bool(live_head) and live_head != head_sha
            if superseded:
                append_scan_step(head_sha, "gitops", f"PR head moved to {live_head[:7]} during this scan; the PR report and Draft state are left to that scan.")
        except Exception as pr_state_err:
            logger.warning(f"Error verifying PR #{pr_number} state before comment update: {pr_state_err}")

        # 8. Post / Update In-Place Single Pinned PR Comment on GitHub (current head only)
        if not superseded:
            try:
                badge = f"📝 **Draft PR #{pr_number}**" if is_draft else f"🚀 **Pull Request #{pr_number}**"
                findings_comment = "<!-- codemender-security-report -->\n"
                findings_comment += f"### 🔍 CodeMender PR Security Analysis\n\n"
                findings_comment += f"We analyzed the cumulative security changes for {badge} (`{branch}` ➔ `{base_branch}`).\n\n"
                findings_comment += f"- **Head Commit:** `{head_sha[:7]}` | **Target File:** `{target_file_str}`\n"
            
                tot_active = summary_delta.get("total_active", len(reconciled_findings))
                res_cnt = summary_delta.get("resolved_count", 0)
                pers_cnt = summary_delta.get("persistent_count", 0)
                new_cnt = summary_delta.get("new_count", 0)
            
                findings_comment += f"- **Vulnerability Tally:** {tot_active} Active"
                if res_cnt > 0 or pers_cnt > 0 or new_cnt > 0:
                    findings_comment += f" (✅ {res_cnt} Resolved, ⚠️ {pers_cnt} Persistent, 🆕 {new_cnt} New)"
                findings_comment += "\n\n"
                if unscanned_files:
                    shown = ", ".join(f"`{f}`" for f in unscanned_files[:20])
                    more = f" and {len(unscanned_files) - 20} more" if len(unscanned_files) > 20 else ""
                    findings_comment += (
                        f"⚠️ **Partial scan:** {len(unscanned_files)} changed file(s) were not scanned "
                        f"(limit {max_files_to_scan} per PR head): {shown}{more}. "
                        "The merge gate stays blocked until the PR is split or the limit is raised.\n\n"
                    )

                if reconciled_findings or (summary_delta and summary_delta.get("resolved_findings")):
                    findings_comment += "| Status | ID | Severity | Type | Location | Description |\n"
                    findings_comment += "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
                
                    # 1. Render Resolved findings
                    if summary_delta and summary_delta.get("resolved_findings"):
                        for rf in summary_delta["resolved_findings"]:
                            raw_sev = str(rf.get("severity", "HIGH")).upper()
                            clean_sev = raw_sev.replace("🔴", "").replace("🟠", "").replace("🟡", "").replace("🔵", "").replace("⚪", "").strip()
                            findings_comment += f"| ✅ **RESOLVED** | `{rf.get('id')}` | ~~{clean_sev}~~ | {rf.get('vuln_type')} | `{rf.get('filepath', target_file_str)}` (Fixed) | {rf.get('description')} |\n"
                        
                    # 2. Render Persistent & New findings
                    for f in reconciled_findings:
                        if str(f.get("lifecycle_status", "")).upper() == "RESOLVED" or str(f.get("status", "")).upper() == "RESOLVED":
                            continue
                        raw_sev = str(f.get("severity", "HIGH")).upper()
                        clean_sev = raw_sev.replace("🔴", "").replace("🟠", "").replace("🟡", "").replace("🔵", "").replace("⚪", "").strip()
                        sev = "CRITICAL" if "CRITICAL" in clean_sev else "HIGH" if "HIGH" in clean_sev else "MEDIUM" if "MEDIUM" in clean_sev else "LOW" if "LOW" in clean_sev else "HIGH"
                        emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵"
                    
                        status_tag = "🆕 **NEW**" if f.get("lifecycle_status") == "NEW" else "⚠️ **PERSISTENT**"
                        loc_str = f"`{f.get('filepath', target_file_str)}`"
                        if f.get("line_number"):
                            loc_str += f":{f.get('line_number')}"
                            if f.get("previous_line_number") and f.get("previous_line_number") != f.get("line_number"):
                                loc_str += f" *(was :{f.get('previous_line_number')})*"
                        findings_comment += f"| {status_tag} | `{f.get('id')}` | {emoji} **{sev}** | {f.get('vuln_type')} | {loc_str} | {f.get('description')} |\n"

                    # Fetch and append raw console scan output
                    try:
                        from database import db
                        doc = db.collection("scans").document(head_sha).get()
                        if doc.exists:
                            find_output = doc.to_dict().get("logs", {}).get("find_output", "")
                            if find_output:
                                findings_comment += "\n<details>\n"
                                findings_comment += "<summary>📋 View Raw CodeMender CLI Output Summary</summary>\n\n"
                                findings_comment += f"```text\n{find_output}\n```\n"
                                findings_comment += "</details>\n"
                    except Exception as db_err:
                        logger.warning(f"Failed to fetch find_output from Firestore for comment: {db_err}")

                    findings_comment += "\n#### ⚡ Actions you can take:\n"
                    findings_comment += "* Reply with `/verify <finding_id>` to run sandbox exploit verification (e.g., `/verify all` or `/verify a1b2c3d4`).\n"
                    findings_comment += "* Reply with `/fix <finding_id>` to generate a secure patch (e.g., `/fix all` or `/fix a1b2c3d4`).\n"
                else:
                    findings_comment += ("✅ No security vulnerabilities were detected in the scanned files."
                                         if unscanned_files else "✅ No security vulnerabilities were detected in the PR code changes.")

                append_scan_step(head_sha, "gitops", f"Updating pinned CodeMender security report on PR #{pr_number}...")
                await update_or_post_pr_comment(repo_name, pr_number, findings_comment, token)
                append_scan_step(head_sha, "gitops", f"Pinned security report successfully updated on PR #{pr_number}.")
            except Exception as comment_err:
                logger.error(f"Failed to update pinned PR comment: {comment_err}")
                append_scan_step(head_sha, "warning", f"Failed to post findings comment to GitHub: {comment_err}")

        # 9. Enforce Critical Finding Merge Gate (the only gate write for head_sha besides 'pending')
        gate_state, gate_desc = decide_gate(reconciled_findings, unscanned_count=len(unscanned_files))
        try:
            await set_commit_status(
                repo=repo_name,
                commit_sha=head_sha,
                state=gate_state,
                description=gate_desc,
                token=token,
                target_url=dashboard_url
            )
            append_scan_step(head_sha, "gitops", f"GitHub Security Gate Status set to '{gate_state.upper()}': {gate_desc}")
        except Exception as gate_err:
            logger.warning(f"Failed to update GitHub commit status gate: {gate_err}")

        # Draft PRs leave Draft automatically once no unresolved CRITICAL finding remains.
        if gate_state == "success" and is_draft and not superseded:
            try:
                await convert_draft_pr_to_ready(repo_name, pr_number, token)
                append_scan_step(head_sha, "gitops", f"PR #{pr_number} promoted from Draft to Ready for Review (no unresolved CRITICAL findings).")
            except Exception as promo_err:
                logger.warning(f"Failed to promote Draft PR #{pr_number} to Ready for Review: {promo_err}")

        # 10. GCS session artifacts upload (the state bundle was backed up right after triage)
        try:
            from database import db
            doc = db.collection("scans").document(head_sha).get()
            if doc.exists:
                logs = doc.to_dict().get("logs", {})
                find_output = logs.get("find_output", "")
                import re
                session_id_match = re.search(r"Session:\s*([a-zA-Z0-9_-]+)", find_output, re.IGNORECASE)
                if session_id_match:
                    cm_session_id = session_id_match.group(1)
                    from gcs_helpers import upload_session_artifacts
                    await asyncio.to_thread(upload_session_artifacts, head_sha, cm_session_id)
        except Exception as upload_err:
            logger.error(f"Failed to upload GCS artifacts after scan: {upload_err}")

    except TaskCancelled as cancel:
        # /cancel, the dashboard (plan 3.4) or an instance shutdown (plan 3.15): the gate ends at
        # 'error', never left 'pending'.
        scan_error = cancel.reason
        logger.info(f"PR scan of {head_sha[:8]} {scan_error}.")
        update_scan_status(head_sha, status=STALE_SCAN_STATUS if cancel.shutdown else CANCELLED_SCAN_STATUS,
                           message=f"Scan {scan_error}.", pr_number=pr_number, active_task=None, error_message=scan_error)
        append_scan_step(head_sha, "info", f"🛑 Scan {scan_error}.")
        if repo_name:
            gate_state, gate_desc = stale_gate(scan_error) if cancel.shutdown else cancelled_gate(cancel.cancelled_by)
            try:
                token = token or await get_github_token()
                await set_commit_status(repo=repo_name, commit_sha=head_sha, state=gate_state, description=gate_desc,
                                        token=token, target_url=dashboard_url)
            except Exception as err_status:
                logger.warning(f"Failed to set the cancelled gate on {head_sha[:8]}: {err_status}")
    except Exception as e:
        # TriageError (scanner failed) or any other error: the gate fails closed, never 'success'.
        if isinstance(e, TriageError):
            scan_error = redact(str(e))
        elif isinstance(e, HeadMismatchError):
            # The checkout could not be pinned to head_sha, so nothing was scanned for it.
            scan_error = HEAD_MISMATCH_REASON
        else:
            scan_error = redact(f"{type(e).__name__}: {e}")
        logger.error(f"Failed to process PR scan event: {scan_error}", exc_info=True)
        update_scan_status(head_sha, status="FAILED", message=f"Vulnerability scan failed: {scan_error}", pr_number=pr_number, is_draft=is_draft,
                           active_task=None, error_message=scan_error)
        append_scan_step(head_sha, "error", f"PR Scan process encountered fatal error: {scan_error}")
        if repo_name:
            gate_state, gate_desc = decide_gate([], error=scan_error)
            try:
                token = token or await get_github_token()
                await set_commit_status(
                    repo=repo_name,
                    commit_sha=head_sha,
                    state=gate_state,
                    description=gate_desc,
                    token=token,
                    target_url=dashboard_url
                )
                await update_or_post_pr_comment(repo_name, pr_number, (
                    "### 🔍 CodeMender PR Security Analysis\n\n"
                    f"- **Head Commit:** `{head_sha[:7]}`\n"
                    f"- **Status:** ⚠️ **Scan error** ({scan_error[:300]})\n\n"
                    "The merge gate is set to `error` because the scan did not complete. "
                    "Push a new commit, or close and reopen the PR, to re-run it."
                ), token)
            except Exception as err_status:
                logger.warning(f"Failed to report scan error on GitHub: {err_status}")
    finally:
        await stop_background_task(heartbeat)
        await finish_progress_comment(repo_name, pr_number, "scan", head_sha, token, started_at, error=scan_error)
        session.finish()
        renewer.cancel()
        release_lock(lock_id, owner)

async def process_push_event(payload: dict):
    """Deprecated: Push events are decommissioned in favor of PR-driven scanning."""
    logger.info("process_push_event called but push scanning is decommissioned. Ignoring.")
    return



async def process_approve_comment(payload: dict):
    """Applies an approved patch proposal to the PR's live head branch as a new commit.

    The gate is never set to success here. The pushed commit triggers a pull_request synchronize
    event, and the scan worker for the new head SHA decides the gate (and Draft -> Ready).
    """
    pr_number = payload.get("issue", {}).get("number")
    if not pr_number:
        return
    repo_name = payload.get("repository", {}).get("full_name")
    commenter = payload.get("comment", {}).get("user", {}).get("login", "")
    lock_id = f"approve-{pr_number}"
    owner = acquire_lock(lock_id)
    if not owner:
        logger.warning(f"Aborting approval comment processing: Lock already active for {lock_id}")
        await post_lock_busy_comment(repo_name, pr_number, None, "`/approve`")
        return
    renewer = start_lock_renewal(lock_id, owner)

    token = None
    git_ws = None
    try:
        logger.info(f"Processing PR #{pr_number} approval from commenter '{commenter}' in repo '{repo_name}'...")
        token = await get_github_token()

        # 1. Live PR head from the GitHub API (never a stored branch name)
        pr_info = await get_pull_request(repo_name, pr_number, token)
        head = pr_info.get("head") or {}
        head_ref = head.get("ref")
        live_head_sha = head.get("sha")

        # 2. Fetch proposed patch from Firestore: the proposal for the live head first
        from database import get_patch_proposal_by_pr, db
        patch = get_patch_proposal(live_head_sha) if live_head_sha else {}
        if not patch:
            patch = get_patch_proposal_by_pr(pr_number)

        if not patch:
            # Fallback: Query scan doc for this PR number
            scans_query = db.collection("scans").where("pr_number", "==", pr_number).limit(1).stream()
            for sdoc in scans_query:
                sdata = sdoc.to_dict()
                sha = sdata.get("commit_sha") or sdoc.id
                patch = get_patch_proposal(sha)
                if patch:
                    logger.info(f"Found patch proposal via scan document commit_sha {sha} for PR #{pr_number}")
                    break

        if not patch:
            friendly_msg = (
                "ℹ️ **No proposed patch to apply yet.**\n\n"
                "The `/approve` command applies a proposed patch to this pull request's branch.\n\n"
                "👉 **Next Step:** Reply with `/fix critical` (or `/fix all`) to generate and preview the code fix first. "
                "Once you review the diff preview, reply `/approve` to apply it."
            )
            await post_pr_comment(repo_name, pr_number, friendly_msg, token)
            return

        if patch.get("is_applied"):
            logger.info(f"Patch for PR #{pr_number} was already applied. Skipping.")
            await post_pr_comment(repo_name, pr_number, "ℹ️ The proposed patch for this pull request was already applied.", token)
            return

        base_sha = patch.get("commit_sha")
        git_diff = patch.get("git_diff")

        if base_sha:
            append_scan_step(base_sha, "gitops", f"Received GitOps PR approval comment (/approve) from '{commenter}' on PR #{pr_number}")

        # 3. Refuse stale proposals: the patch is only applied to the exact commit it was generated for.
        stale_msg = (
            f"⚠️ @{commenter}: patch not applied. It was generated for commit `{(base_sha or 'unknown')[:7]}`, "
            f"but the pull request head is now `{(live_head_sha or 'unknown')[:7]}`. "
            "Reply `/fix` to generate a patch for the current head, then `/approve` it."
        )
        if not live_head_sha or live_head_sha != base_sha:
            await post_pr_comment(repo_name, pr_number, stale_msg, token)
            return
        head_repo = (head.get("repo") or {}).get("full_name") or ""
        if head_repo.lower() != (repo_name or "").lower():
            await post_pr_comment(repo_name, pr_number, f"⚠️ @{commenter}: patch not applied. CodeMender cannot push to a fork (`{head_repo or 'unknown'}`).", token)
            return
        if not head_ref or not git_diff:
            await post_pr_comment(repo_name, pr_number, f"⚠️ @{commenter}: patch not applied. The stored proposal has no diff or the head branch is unknown; reply `/fix` to regenerate it.", token)
            return

        # 4. Clone the live head branch into a unique workspace and confirm it is still at base_sha
        workspace_id = f"pr-{pr_number}-{int(time.time())}"
        git_ws = GitWorkspace(workspace_id, repo=repo_name)
        await git_ws.clone_repo(token, head_ref)
        local_head, _ = await git_ws._run_command(["git", "rev-parse", "HEAD"])
        if local_head.strip() != base_sha:
            await post_pr_comment(repo_name, pr_number, stale_msg, token)
            return
        append_scan_step(base_sha, "gitops", f"Cloned live head branch '{head_ref}' at {base_sha[:8]}")

        # 5. Apply the patch and commit it as the head commit's author (CLA), without [skip ci]
        logger.info(f"Applying git patch to branch '{head_ref}'...")
        await git_ws.apply_patch(git_diff)
        commit_name, commit_email = await resolve_commit_identity(repo_name, base_sha, token, git_ws=git_ws)
        await git_ws._run_command(["git", "config", "user.name", commit_name])
        await git_ws._run_command(["git", "config", "user.email", commit_email])
        new_sha = await stage_and_commit(git_ws, "CodeMender security patch: Applied user approval")
        if not new_sha:
            await post_pr_comment(repo_name, pr_number, "ℹ️ The approved patch made no changes to the current head; nothing was committed.", token)
            return

        # 6. Push (fast-forward only; a concurrent push makes this fail instead of being overwritten)
        logger.info("Pushing patch changes to remote...")
        push_cmd = ["git", "push", "origin", f"HEAD:refs/heads/{head_ref}"]
        if os.getenv("MOCK_MODE") == "true":
            push_cmd.insert(2, "-f")
        await git_ws._run_command(push_cmd)
        append_scan_step(base_sha, "gitops", f"Pushed patch commit {new_sha[:8]} to '{head_ref}'.")
        try:
            mark_patch_as_applied(pr_number, commit_sha=base_sha)
        except Exception as mark_err:
            logger.warning(f"Patch pushed but could not be marked applied in Firestore: {mark_err}")

        # 7. The synchronize event re-scans the new head; hold its gate at pending until then.
        await set_commit_status(
            repo=repo_name,
            commit_sha=new_sha,
            state="pending",
            description="Re-scan in progress after patch",
            token=token,
            target_url=f"{DASHBOARD_URL}/scans/{new_sha}"
        )

        success_msg = (
            f"✅ Patch applied as commit `{new_sha[:7]}` on `{head_ref}`. CodeMender is re-scanning the new commit; "
            "the merge gate updates when it finishes, and the PR leaves Draft automatically if no critical findings remain."
        )
        await post_pr_comment(repo_name, pr_number, success_msg, token)
        logger.info(f"Applied approved patch for PR #{pr_number} as {new_sha[:8]}; awaiting re-scan.")

    except Exception as e:
        logger.error(f"Failed to process approval comment: {e}", exc_info=True)
        if token and repo_name:
            try:
                reason = " ".join(redact(str(e)).split())[:300]
                await post_pr_comment(repo_name, pr_number, f"❌ `/approve` failed: {reason}", token)
            except Exception as comment_err:
                logger.warning(f"Failed to post /approve failure comment: {comment_err}")
    finally:
        if git_ws is not None and git_ws.workspace_path.exists():
            import shutil
            shutil.rmtree(git_ws.workspace_path, ignore_errors=True)
        renewer.cancel()
        release_lock(lock_id, owner)


async def process_merged_pr_analytics(repo_name: str, pr_number: int, payload: dict):
    """Processes GitHub PR merge event, extracts scan/vulnerability telemetry, and streams to BigQuery."""
    try:
        import uuid
        from datetime import datetime
        from database import db, insert_analytics_patch_merged
        
        pr_data = payload.get("pull_request", {})
        merged_at_str = pr_data.get("merged_at")
        merged_by = pr_data.get("merged_by", {}).get("login", "unknown")
        branch = pr_data.get("base", {}).get("ref", "main")
        
        # 1. The scan of the merged head commit (scans are keyed by SHA). Fallback: the newest scan
        #    of this PR in this repository (PR numbers repeat across repositories).
        scan_data = None
        merged_head_sha = (pr_data.get("head") or {}).get("sha") or ""
        if merged_head_sha:
            snap = await asyncio.to_thread(db.collection("scans").document(merged_head_sha).get)
            if snap.exists:
                candidate = snap.to_dict() or {}
                if candidate.get("repo_name") in (None, "", repo_name):
                    scan_data = candidate
        if scan_data is None:
            query = db.collection("scans").where("pr_number", "==", pr_number).where("repo_name", "==", repo_name)
            candidates = [doc.to_dict() or {} for doc in await asyncio.to_thread(lambda: list(query.stream()))]
            if candidates:
                scan_data = max(candidates, key=lambda record: record.get("updated_at") or 0)

        if not scan_data:
            logger.warning(f"No scan document found for PR #{pr_number} in {repo_name}. Cannot compile analytics telemetry.")
            return

        findings = scan_data.get("findings", [])
        steps = scan_data.get("steps", [])
        commit_sha = scan_data.get("commit_sha", pr_data.get("head", {}).get("sha", ""))
        
        # 2. Compile discovery counts
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
        high_count     = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
        medium_count   = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
        low_count      = sum(1 for f in findings if str(f.get("severity")).upper() == "LOW")
        
        # 3. Categorize status metrics
        patched_ids = [f["id"] for f in findings if f.get("status") == "PATCHED" or f.get("is_patched") is True]
        verified_ids = [f["id"] for f in findings if f.get("status") == "VERIFIED" or f.get("verified") is True]
        unpatched_ids = [f["id"] for f in findings if f.get("id") not in patched_ids]
        
        patched_count = len(patched_ids)
        verified_count = len(verified_ids)
        unpatched_count = len(unpatched_ids)
        
        remediation_rate = (patched_count / total_findings * 100.0) if total_findings > 0 else 0.0
        
        # 4. Calculate time to remediate
        scan_start_timestamp = None
        if steps:
            scan_start_timestamp = steps[0].get("timestamp")
        else:
            scan_start_timestamp = scan_data.get("updated_at")
            
        if not scan_start_timestamp:
            scan_start_timestamp = time.time()
            
        # Parse merged_at timestamp
        merged_at_ts = time.time()
        if merged_at_str:
            try:
                clean_date = merged_at_str.replace("Z", "+00:00")
                merged_at_ts = datetime.fromisoformat(clean_date).timestamp()
            except Exception as parse_err:
                logger.warning(f"Failed to parse merged_at timestamp '{merged_at_str}': {parse_err}")
                
        time_to_remediate_sec = int(max(0, merged_at_ts - scan_start_timestamp))
        
        # 5. Stream row to BigQuery
        import json
        row = {
            "merge_id": f"{repo_name.split('/')[-1]}-{pr_number}",
            "pr_number": pr_number,
            "repo_name": repo_name,
            "branch": branch,
            "commit_sha": commit_sha,
            "merged_at": merged_at_str if merged_at_str else datetime.utcnow().isoformat() + "Z",
            "merged_by": merged_by,
            "time_to_remediate_sec": time_to_remediate_sec,
            
            # Discovery Metrics
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            
            # Verification Metrics
            "verified_count": verified_count,
            "verified_finding_ids": ",".join(verified_ids),
            
            # Patch Metrics
            "patched_count": patched_count,
            "patched_finding_ids": ",".join(patched_ids),
            "unpatched_count": unpatched_count,
            "unpatched_finding_ids": ",".join(unpatched_ids),
            "remediation_rate_pct": round(remediation_rate, 2),
            
            # Full Structured Payload
            "findings_full_json": json.dumps(findings)
        }
        
        logger.info(f"Prepared BigQuery row for PR #{pr_number}: {row}")
        insert_analytics_patch_merged(row)

        # insert_analytics_patch_merged is the table's only writer (plan 4.3).
        
    except Exception as ex:
        logger.error(f"Error in process_merged_pr_analytics: {ex}", exc_info=True)


def _command_event_type(is_pr: bool) -> str:
    """Webhook event behind a slash command: PR comments are issue_comment, commit comments commit_comment."""
    return "issue_comment" if is_pr else "commit_comment"


def _task_event_type(is_pr: bool) -> str:
    """event_type for the scan_log rows of the running verify/fix: the attribution set at its entry."""
    return get_telemetry_context().get("event_type") or _command_event_type(is_pr)


async def verify_findings_task(repo_name: str, commit_sha: str, finding_ids: list[str], is_pr: bool, pr_number: int = None,
                               event_type: str = None):
    """Runs sandbox exploit verification for findings of a finished scan (`/verify` or the dashboard).

    The run's token-usage and scan_log rows carry the PR number and ``event_type``: 'dashboard'
    for dashboard buttons, issue_comment/commit_comment (the default) for comment commands (plan 4.2).
    """
    with telemetry_context(pr_number=pr_number, event_type=event_type or _command_event_type(is_pr)):
        return await _verify_findings_task(repo_name, commit_sha, finding_ids, is_pr, pr_number)


async def _verify_findings_task(repo_name: str, commit_sha: str, finding_ids: list[str], is_pr: bool, pr_number: int = None):
    task_started_at = time.time()  # cancel requests from before this command don't apply
    lock_id = f"workspace-{commit_sha}"
    owner = acquire_lock(lock_id)
    if not owner:
        logger.warning(f"Aborting verification task: Lock active for {lock_id}")
        await post_lock_busy_comment(repo_name, pr_number, commit_sha, "`/verify`")
        return
    renewer = start_lock_renewal(lock_id, owner)
    session = TaskSession(commit_sha, "verify", lock_id=lock_id, owner=owner, repo_name=repo_name, pr_number=pr_number,
                          cancel_check=make_cancel_check(commit_sha, task_started_at))
    # Restore state for a run that fails or is cancelled (plan 3.3).
    findings = []
    prior_status = None
    prior_finding_status = {}
    marked = False
    restored = False

    token = None
    heartbeat = None
    task_error = None
    started_at = time.monotonic()
    try:
        await session.start()
        from database import db, update_scan_status, append_scan_step
        token = await get_github_token()
        scan_data = {}
        if commit_sha and db:
            snap = await asyncio.to_thread(db.collection("scans").document(commit_sha).get)
            scan_data = (snap.to_dict() or {}) if snap.exists else {}
        findings = scan_data.get("findings") or []
        branch = scan_data.get("branch_name") or "main"
        update_telemetry_context(pr_number=pr_number or scan_data.get("pr_number"), is_draft=scan_data.get("is_draft"))
        prior_status = restorable_status(scan_data.get("status"))

        # Only a finished scan of this exact commit can be verified or fixed (plan 3.13). There is no
        # fallback to repo-level findings: they belong to no commit, and writing them back let a
        # failed scan be relabelled COMPLETED.
        if not scan_result_available(scan_data) or scan_in_progress(scan_data):
            reason = "a scan of it is still running" if scan_in_progress(scan_data) else "it has no finished scan"
            msg = (f"⚠️ Nothing to act on for commit `{(commit_sha or 'unknown')[:7]}`: {reason}. "
                   "Push a commit, or close and reopen the pull request, to re-run the scan.")
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        if not findings:
            msg = "ℹ️ The CodeMender scan of this commit has no findings to act on."
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        # Parse target IDs / severity filters
        to_verify = filter_findings_by_targets(findings, finding_ids)

        if not to_verify:
            msg = f"⚠️ No matching findings found to verify for targets: {', '.join(finding_ids)}"
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        # Post progress message (on PRs this becomes the in-place heartbeat comment)
        progress_msg = f"⏳ **CodeMender Exploit Verification Started** for finding(s): {', '.join([f.get('id', f.get('display_id', 'finding')) for f in to_verify])}..."
        if pr_number:
            await upsert_progress_comment(repo_name, pr_number, progress_key("verify", commit_sha), progress_msg, token)
        else:
            await post_commit_comment(repo_name, commit_sha, progress_msg, token)

        # Mark as VERIFYING; the statuses found here come back if the run fails (plan 3.3).
        target_ids = {tv.get("id") for tv in to_verify}
        prior_finding_status = {f.get("id"): f.get("status") for f in findings if f.get("id") in target_ids}
        for f in findings:
            if f.get("id") in target_ids:
                f["status"] = "VERIFYING"
        update_scan_status(commit_sha, status="RUNNING", message="Verifying exploitability of findings...", findings=findings,
                           active_task="verify", status_before_task=prior_status, error_message=None)
        marked = True

        # Start periodic progress reporting task
        import uuid
        from shared_state import active_tasks
        run_id = str(uuid.uuid4())
        active_tasks[commit_sha] = run_id
        heartbeat = asyncio.create_task(post_periodic_progress(repo_name, commit_sha, pr_number, is_pr, token, task_type="verify", run_id=run_id))

        await ensure_workspace(commit_sha, branch, repo_name=repo_name, pr_number=pr_number)

        # Hydrate CodeMender state bundle from GCS if available (Fast-path optimization)
        from gcs_helpers import download_codemender_state_bundle
        workspace_path = f"/tmp/session-{commit_sha}"
        state_hydrated = await asyncio.to_thread(download_codemender_state_bundle, commit_sha, workspace_path)
        if state_hydrated:
            append_scan_step(commit_sha, "workspace", "⚡ Fast-path: Successfully hydrated CodeMender state bundle from Cloud Storage.")

        results_report = "### 🧪 CodeMender Sandbox Verification Results\n\n"
        results_report += "| Finding ID | Status | Outcome | Confidence |\n"
        results_report += "| --- | --- | --- | --- |\n"

        detail_blocks = []
        cached_local_findings = {}

        async def _verify_single_finding(tv):
            fid = tv.get("id") or tv.get("display_id")
            filepath = tv.get("file_path") or tv.get("filepath")
            vuln_type = tv.get("cwe") or tv.get("vuln_type") or tv.get("category")
            try:
                local_finding_id = fid
                if not state_hydrated and filepath:
                    if filepath not in cached_local_findings:
                        from agents import run_triage_agent
                        from gcs_helpers import upload_codemender_state_bundle
                        append_scan_step(commit_sha, "find", f"Indexing code AST once for {filepath} to map finding {fid}...")
                        cached_local_findings[filepath] = await run_triage_agent(commit_sha, filepath, repo_name=repo_name)
                        await asyncio.to_thread(upload_codemender_state_bundle, commit_sha, workspace_path)
                    
                    matched_local = select_finding(tv, cached_local_findings.get(filepath, []))
                    if matched_local is None:
                        await report_unmapped_finding(repo_name, pr_number, commit_sha, fid, token)
                        for f in findings:
                            if f.get("id") == fid:
                                f["status"] = "VERIFICATION_FAILED"
                        return f"| `{fid}` | ⏭️ **SKIPPED** | Could not re-locate finding in the current scan. | - |\n", ""
                    local_finding_id = matched_local.get("id")
                    logger.info(f"Mapped external finding {fid} ({vuln_type}) to local finding {local_finding_id}")
                else:
                    logger.info(f"⚡ Fast-path active: Verifying finding {fid} directly using hydrated state.")
                
                import shutil
                shutil.rmtree(Path(workspace_path) / ".exploit", ignore_errors=True)
                verify_out = await cm_verify(commit_sha, local_finding_id)
                
                # Extract exploit confidence and verdict from .exploit/info.yaml
                confidence = "100%"
                info_status = ""
                info_path = Path(workspace_path) / ".exploit" / "info.yaml"
                if info_path.exists():
                    try:
                        info_content = info_path.read_text(encoding="utf-8", errors="replace")
                        extracted = parse_yaml_value(info_content, "confidence")
                        confidence = clean_confidence(extracted)
                        info_status = parse_yaml_value(info_content, "status").strip().lower()
                    except Exception as parse_err:
                        logger.warning(f"Failed to parse info.yaml: {parse_err}")

                # Check actual success status (info.yaml status: valid OR CLI stdout markers)
                is_verified = (
                    info_status in ("valid", "verified", "exploitable")
                    or bool(verify_out and ("EXPLOIT SUCCESSFUL" in verify_out or "finding verified" in verify_out.lower()))
                ) and info_status not in ("invalid", "false_positive", "unexploitable")
                
                # Upload verification artifacts to GCS
                uploaded_arts = await upload_verification_artifacts(commit_sha, workspace_path, fid)
                
                # Successful verification
                from agents import generate_ai_exploit_report_async
                exploit_report = await generate_ai_exploit_report_async(verify_out, session_id=commit_sha, repo_name=repo_name)
                
                if is_verified:
                    for f in findings:
                        if f.get("id") == fid:
                            f["status"] = "VERIFIED"
                            f["exploit_report"] = exploit_report
                    table_row = f"| `{fid}` | ✅ **VERIFIED** | Exploit simulation succeeded. Vulnerability is active. | **{confidence}** |\n"
                else:
                    for f in findings:
                        if f.get("id") == fid:
                            f["status"] = "VERIFICATION_FAILED"
                            f["exploit_report"] = exploit_report
                    table_row = f"| `{fid}` | ❌ **FAILED** | Exploit execution failed (vulnerability not active or unreachable). | - |\n"
                
                # Build detail block for this finding
                exploit_dir = Path(workspace_path) / ".exploit"
                exploit_script = ""
                exploit_plan = ""
                if exploit_dir.exists():
                    for sp in [exploit_dir / "exploit.sh", exploit_dir / "run.sh", exploit_dir / "exploit.py"]:
                        if sp.exists():
                            try:
                                exploit_script = sp.read_text(encoding="utf-8", errors="ignore")
                                break
                            except Exception:
                                pass
                    if not exploit_script:
                        for sh_f in exploit_dir.glob("*.sh"):
                            try:
                                exploit_script = sh_f.read_text(encoding="utf-8", errors="ignore")
                                break
                            except Exception:
                                pass

                    for pp in [exploit_dir / "plan.yaml", exploit_dir / "plan.md", exploit_dir / "plan.txt"]:
                        if pp.exists():
                            try:
                                exploit_plan = pp.read_text(encoding="utf-8", errors="ignore")
                                break
                            except Exception:
                                pass

                detail = f"\n### 🔬 Exploit Verification Report for `{fid}`\n"
                if exploit_report:
                    detail += "<details>\n"
                    detail += "<summary><b>View Exploit Steps & Response Trace (PoC)</b></summary>\n\n"
                    detail += f"{exploit_report}\n"
                    detail += "</details>\n"

                # List GCS artifact links
                if uploaded_arts:
                    detail += "\n#### 📁 Verification Research Artifacts (Cloud Storage):\n"
                    for art in uploaded_arts:
                        detail += f"- 📄 [{art['name']}]({art['url']})\n"

                # Append raw CLI verification output
                if verify_out:
                    detail += "\n<details open>\n"
                    detail += "<summary>📋 <b>Raw CodeMender Verification Console Output (cm verify)</b></summary>\n\n"
                    detail += f"```text\n{verify_out}\n```\n"
                    detail += "</details>\n"

                # If unverifiable / exploit failed, suggest risk acceptance dismissal
                if not is_verified:
                    detail += "\n> [!TIP]\n"
                    detail += f"> **Sandbox Exploit Inconclusive / Failed:** If you determine this finding is an unreachable false positive, test fixture, or mitigated by external controls, you can dismiss it to unblock the merge gate using:\n"
                    detail += f"> ```text\n> /dismiss {fid} [UNVERIFIABLE] <reason>\n> ```\n"
                
                return table_row, detail
            except Exception as ex:
                logger.error(f"Verification failed for {fid}: {ex}")
                for f in findings:
                    if f.get("id") == fid:
                        f["status"] = "VERIFICATION_FAILED"
                table_row = f"| `{fid}` | ❌ **FAILED** | Verification run encountered error. | - |\n"
                err_detail = f"\n### ❌ Verification Error for `{fid}`\n```text\n{redact(str(ex))}\n```\n"
                return table_row, err_detail

        # ========================================================
        # SEQUENTIAL VERIFICATION
        # ========================================================
        # Verification is deliberately serialized. Every shard resolves its workspace from the
        # commit SHA -- cm_verify runs with cwd=/tmp/session-{commit_sha} -- so running findings
        # concurrently meant N exploits sharing one directory. Three failure modes came out of
        # that, and the first is a security regression rather than a cosmetic bug:
        #
        #   1. Mock servers raced for the same port. Losers returned connection refused, so
        #      "EXPLOIT SUCCESSFUL" never appeared and a live vulnerability was recorded as
        #      VERIFICATION_FAILED -- a false negative on the exact PRs (>4 findings) that
        #      warrant the most scrutiny.
        #   2. Confidence was read from a single .exploit/info.yaml that every shard overwrote,
        #      so findings could be annotated with another finding's confidence.
        #   3. The git reset below never ran in the parallel path, letting exploit residue from
        #      one finding leak into the next.
        #
        # Restoring parallelism requires per-shard workspaces (/tmp/session-{sha}-{finding_id}),
        # an explicit workspace_path argument on cm_verify instead of deriving it from the
        # session ID, and a dedicated port range per shard. Tracked as future work.
        if len(to_verify) > PARALLEL_SHARDING_THRESHOLD:
            logger.info(
                f"Finding count ({len(to_verify)}) exceeds threshold ({PARALLEL_SHARDING_THRESHOLD}), "
                "but verification is serialized: shards share one workspace. "
                "Per-shard workspaces are required before this can fan out."
            )

        git_ws = GitWorkspace(commit_sha, repo=repo_name)
        for tv in to_verify:
            await session.raise_if_cancelled()
            table_row, detail = await _verify_single_finding(tv)
            results_report += table_row
            if detail:
                detail_blocks.append(detail)
            # Reset workspace to clean git state between tests
            try:
                await git_ws._run_command(["git", "checkout", "HEAD", "--", "."])
            except Exception:
                pass

        # Append all detail blocks after the table
        if detail_blocks:
            results_report += "\n---\n" + "\n".join(detail_blocks)

        update_scan_status(commit_sha, status=prior_status or "COMPLETED", message="Exploit verification run finished", findings=findings,
                           active_task=None, status_before_task=None)
        restored = True
        
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch,
                event_type=_task_event_type(is_pr),
                pr_number=pr_number,
                status="COMPLETED",
                target_file=None,
                findings_count=len(findings),
                findings=findings,
                action_taken="verify"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log verify summary to BigQuery: {bq_log_err}")
        
        # Post results
        sanitized_report = sanitize_comment_length(results_report)
        if pr_number:
            await post_pr_comment(repo_name, pr_number, sanitized_report, token)
        elif commit_sha and commit_sha != "main":
            await post_commit_comment(repo_name, commit_sha, sanitized_report, token)

    except TaskCancelled as cancel:
        task_error = cancel.reason
        logger.info(f"/verify on {commit_sha[:8]} {task_error}.")
        try:
            msg = f"🛑 `/verify` on `{commit_sha[:7]}` was {task_error}; unfinished findings keep their previous status."
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, msg, token)
        except Exception as cancel_comment_err:
            logger.warning(f"Could not post the cancellation notice: {cancel_comment_err}")
    except Exception as e:
        task_error = e
        logger.error(f"Error in verify_findings_task: {e}", exc_info=True)
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch if 'branch' in locals() else "unknown",
                event_type=_task_event_type(is_pr),
                pr_number=pr_number,
                status="FAILED",
                target_file=None,
                findings_count=0,
                findings=[],
                action_taken="verify"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log failed verify summary to BigQuery: {bq_log_err}")
    finally:
        await stop_background_task(heartbeat)
        await finish_progress_comment(repo_name, pr_number, "verify", commit_sha, token, started_at, error=task_error)
        if marked and not restored:
            try:
                restore_after_failed_task(commit_sha, findings, prior_finding_status, prior_status, ("VERIFYING",), task_error)
            except Exception as restore_err:
                logger.error(f"Could not restore scan record {commit_sha[:8]} after a failed run: {restore_err}")
        try:
            from shared_state import active_tasks
            active_tasks.pop(commit_sha, None)
        except Exception:
            pass
        session.finish()
        renewer.cancel()
        release_lock(lock_id, owner)


async def fix_findings_task(repo_name: str, commit_sha: str, finding_ids: list[str], is_pr: bool, pr_number: int = None,
                            event_type: str = None):
    """Generates patches for findings of a finished scan (`/fix` or the dashboard).

    Telemetry attribution as in verify_findings_task (plan 4.2).
    """
    with telemetry_context(pr_number=pr_number, event_type=event_type or _command_event_type(is_pr)):
        return await _fix_findings_task(repo_name, commit_sha, finding_ids, is_pr, pr_number)


async def _fix_findings_task(repo_name: str, commit_sha: str, finding_ids: list[str], is_pr: bool, pr_number: int = None):
    task_started_at = time.time()  # cancel requests from before this command don't apply
    lock_id = f"workspace-{commit_sha}"
    owner = acquire_lock(lock_id)
    if not owner:
        logger.warning(f"Aborting fix task: Lock active for {lock_id}")
        await post_lock_busy_comment(repo_name, pr_number, commit_sha, "`/fix`")
        return
    renewer = start_lock_renewal(lock_id, owner)
    session = TaskSession(commit_sha, "fix", lock_id=lock_id, owner=owner, repo_name=repo_name, pr_number=pr_number,
                          cancel_check=make_cancel_check(commit_sha, task_started_at))
    # Restore state for a run that fails or is cancelled (plan 3.3).
    findings = []
    prior_status = None
    prior_finding_status = {}
    marked = False
    restored = False

    token = None
    heartbeat = None
    task_error = None
    started_at = time.monotonic()
    try:
        await session.start()
        from database import db, update_scan_status, append_scan_step
        token = await get_github_token()
        scan_data = {}
        if commit_sha and db:
            snap = await asyncio.to_thread(db.collection("scans").document(commit_sha).get)
            scan_data = (snap.to_dict() or {}) if snap.exists else {}
        findings = scan_data.get("findings") or []
        branch = scan_data.get("branch_name") or "main"
        update_telemetry_context(pr_number=pr_number or scan_data.get("pr_number"), is_draft=scan_data.get("is_draft"))
        prior_status = restorable_status(scan_data.get("status"))

        # Only a finished scan of this exact commit can be verified or fixed (plan 3.13). There is no
        # fallback to repo-level findings: they belong to no commit, and writing them back let a
        # failed scan be relabelled COMPLETED.
        if not scan_result_available(scan_data) or scan_in_progress(scan_data):
            reason = "a scan of it is still running" if scan_in_progress(scan_data) else "it has no finished scan"
            msg = (f"⚠️ Nothing to act on for commit `{(commit_sha or 'unknown')[:7]}`: {reason}. "
                   "Push a commit, or close and reopen the pull request, to re-run the scan.")
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        if not findings:
            msg = "ℹ️ The CodeMender scan of this commit has no findings to act on."
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        # Filter target findings by target IDs / severity filters
        to_fix = filter_findings_by_targets(findings, finding_ids)

        if not to_fix:
            msg = f"⚠️ No matching findings found to fix for targets: {', '.join(finding_ids)}"
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        # Post progress message (on PRs this becomes the in-place heartbeat comment)
        progress_msg = f"⏳ **CodeMender Patch Generation Started** for finding(s): {', '.join([f.get('id', f.get('display_id', 'finding')) for f in to_fix])}..."
        if pr_number:
            await upsert_progress_comment(repo_name, pr_number, progress_key("patch", commit_sha), progress_msg, token)
        else:
            await post_commit_comment(repo_name, commit_sha, progress_msg, token)

        # Mark as PATCHING; the statuses found here come back if the run fails (plan 3.3).
        target_ids = {tf.get("id") for tf in to_fix}
        prior_finding_status = {f.get("id"): f.get("status") for f in findings if f.get("id") in target_ids}
        for f in findings:
            if f.get("id") in target_ids:
                f["status"] = "PATCHING"
        update_scan_status(commit_sha, status="RUNNING", message="Generating fixes for findings...", findings=findings,
                           active_task="fix", status_before_task=prior_status, error_message=None)
        marked = True

        # Start periodic progress reporting task
        import uuid
        from shared_state import active_tasks
        run_id = str(uuid.uuid4())
        active_tasks[commit_sha] = run_id
        heartbeat = asyncio.create_task(post_periodic_progress(repo_name, commit_sha, pr_number, is_pr, token, task_type="patch", run_id=run_id))

        # Ensure local checkout is ready (pinned to the scanned commit)
        await ensure_workspace(commit_sha, branch, repo_name=repo_name, pr_number=pr_number)
        
        workspace_path = f"/tmp/session-{commit_sha}"
        
        # Hydrate CodeMender state bundle from GCS if available (Fast-path optimization)
        from gcs_helpers import download_codemender_state_bundle
        state_hydrated = await asyncio.to_thread(download_codemender_state_bundle, commit_sha, workspace_path)
        if state_hydrated:
            append_scan_step(commit_sha, "workspace", "⚡ Fast-path: Successfully hydrated CodeMender state bundle from Cloud Storage.")
        
        # Check out patch branch
        patch_branch = f"codemender/patch-{commit_sha[:8]}"
        git_ws = GitWorkspace(commit_sha, repo=repo_name)
        
        # Check if the patch branch already exists
        has_branch = False
        try:
            # Check if remote branch exists
            proc_check = await asyncio.create_subprocess_exec(
                "git", "show-ref", f"refs/remotes/origin/{patch_branch}",
                stdout=asyncio.subprocess.PIPE,
                cwd=workspace_path
            )
            await proc_check.wait()
            if proc_check.returncode == 0:
                has_branch = True
        except Exception:
            pass

        if has_branch:
            # Checkout the existing branch and pull latest
            await git_ws._run_command(["git", "checkout", patch_branch])
            await git_ws._run_command(["git", "pull", "origin", patch_branch])
        else:
            # Create new branch from base
            await git_ws._run_command(["git", "checkout", "-b", patch_branch])
        
        # Commit as the head commit's author so CLA checks pass; never as the bot identity (GEMINI.md)
        pusher_name, pusher_email = await resolve_commit_identity(repo_name, commit_sha, token, git_ws=git_ws)
        await git_ws._run_command(["git", "config", "user.name", pusher_name])
        await git_ws._run_command(["git", "config", "user.email", pusher_email])

        results = []
        cached_local_findings = {}

        # Apply fixes sequentially
        for tf in to_fix:
            await session.raise_if_cancelled()
            fid = tf.get("id") or tf.get("display_id")
            target_filepath = tf.get("file_path") or tf.get("filepath")
            target_vuln_type = tf.get("cwe") or tf.get("vuln_type") or tf.get("category")
            
            try:
                local_finding_id = fid
                # If state was not hydrated, fallback to re-indexing with AST cache
                if not state_hydrated and target_filepath:
                    if target_filepath not in cached_local_findings:
                        from agents import run_triage_agent
                        from gcs_helpers import upload_codemender_state_bundle
                        append_scan_step(commit_sha, "find", f"Indexing code AST once for {target_filepath} to map finding {fid}...")
                        cached_local_findings[target_filepath] = await run_triage_agent(commit_sha, target_filepath, repo_name=repo_name)
                        await asyncio.to_thread(upload_codemender_state_bundle, commit_sha, workspace_path)
                    
                    matched_local = select_finding(tf, cached_local_findings.get(target_filepath, []))
                    if matched_local is None:
                        await report_unmapped_finding(repo_name, pr_number, commit_sha, fid, token)
                        results.append((fid, False, "Could not re-locate finding in the current scan; skipped."))
                        continue
                    local_finding_id = matched_local.get("id")
                    logger.info(f"Mapped external finding ID {fid} ({target_vuln_type}) to local finding ID {local_finding_id}")
                else:
                    logger.info(f"⚡ Fast-path active: Fixing finding {fid} directly using hydrated state.")
                
                from cm_tools import _run_cm_cmd, resolve_model
                fix_model = resolve_model("fix", None, commit_sha)
                append_scan_step(commit_sha, "fix", f"Executing CodeMender fix engine (cm fix {local_finding_id} -y --model {fix_model})...")
                await _run_cm_cmd(["cm", "fix", local_finding_id, "-y", "--bypass-warning", "--model", fix_model], commit_sha)
                
                # Stage new, modified and deleted files (not just tracked edits) and commit without
                # [skip ci]; returns None when the fix engine changed nothing.
                if await stage_and_commit(git_ws, f"CodeMender: Fix vulnerability {fid}"):
                    results.append((fid, True, "Successfully applied fix"))
                else:
                    results.append((fid, False, "No changes made by fix engine"))
            except Exception as fix_ex:
                logger.error(f"Fix failed for {fid}: {fix_ex}")
                results.append((fid, False, " ".join(redact(str(fix_ex)).split())[:300]))

        successful_fixes = [r for r in results if r[1]]
        
        if not successful_fixes:
            await git_ws._run_command(["git", "checkout", branch])
            await git_ws._run_command(["git", "branch", "-D", patch_branch])
            
            fail_report = "### ❌ CodeMender Patch Generation Failed\n\n"
            for fid, success, msg in results:
                fail_report += f"- `{fid}`: {msg}\n"
                
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, fail_report, token)
            else:
                await post_commit_comment(repo_name, commit_sha, fail_report, token)
            task_error = "no fix could be applied (details in the report above)"
            return

        # Push branch
        await git_ws._run_command(["git", "push", "-f", "origin", patch_branch])

        # Get total diff (excluding bytecode/build artifacts)
        diff_proc = await asyncio.create_subprocess_exec(
            "git", "diff", f"{commit_sha}..{patch_branch}", "--", ".", *_STATE_EXCLUDE_PATHSPECS,
            stdout=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        diff_out, _ = await diff_proc.communicate()
        total_diff = diff_out.decode(errors="replace").strip()

        # Check if PR exists on GitHub
        from git_manager import get_existing_pr
        pr_num, pr_url = await get_existing_pr(repo_name, patch_branch, token)
        if pr_num:
            append_scan_step(commit_sha, "gitops", f"Found existing open GitHub PR #{pr_num} for this patch branch")
        else:
            append_scan_step(commit_sha, "gitops", "No existing PR found. Draft PR creation deferred.")

        # Generate and upload reports to GCS
        report_urls = await export_and_upload_reports(commit_sha, workspace_path)
        logger.info(f"Generated report GCS links: {report_urls}")

        # Save patch proposal
        from database import save_patch_proposal
        changed_files_proc = await asyncio.create_subprocess_exec(
            "git", "diff", "--name-only", f"{commit_sha}..{patch_branch}", "--", ".", *_STATE_EXCLUDE_PATHSPECS,
            stdout=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        files_out, _ = await changed_files_proc.communicate()
        changed_files = [
            f for f in files_out.decode(errors="replace").strip().splitlines()
            if not _is_ignored_artifact_path(f)
        ]
        filename = changed_files[0] if changed_files else "unknown"
        
        patched_code = ""
        patched_file_path = Path(workspace_path) / filename
        if patched_file_path.exists():
            patched_code = patched_file_path.read_text(encoding="utf-8", errors="replace")

        # Get the actual patch commit SHA we just pushed
        patch_commit_sha_proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        sha_out, _ = await patch_commit_sha_proc.communicate()
        patch_commit_sha = sha_out.decode(errors="replace").strip()
        logger.info(f"Retrieved actual patch commit SHA: {patch_commit_sha}")

        save_patch_proposal(
            commit_sha=commit_sha,
            branch_name=branch,
            filename=filename,
            git_diff=total_diff,
            patched_code=patched_code,
            pr_number=pr_number,
            patch_commit_sha=patch_commit_sha,
            patch_pr_number=pr_num,
            changed_files=changed_files,
        )

        for r in results:
            fid, success, msg = r
            for f in findings:
                if f.get("id") == fid:
                    f["status"] = "PATCHED" if success else "PATCH_FAILED"
        
        update_scan_status(commit_sha, status=prior_status or "COMPLETED",
                           message="Patches generated and PR updated" if pr_num else "Patches generated and staged on branch",
                           findings=findings, active_task=None, status_before_task=None)
        restored = True

        # The merge gate is intentionally not touched here: the patch only exists on a side branch.
        # The gate changes when the patched commit lands on the PR branch and is re-scanned.
            
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch,
                event_type=_task_event_type(is_pr),
                pr_number=pr_number,
                status="COMPLETED",
                target_file=filename if 'filename' in locals() else None,
                findings_count=len(findings),
                findings=findings,
                action_taken="fix"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log fix summary to BigQuery: {bq_log_err}")

        # Post PR comment if PR is already open
        reports_md = ""
        if report_urls:
            reports_md += "\n#### 📊 CodeMender Security Reports:\n"
            if "html" in report_urls:
                reports_md += f"- 🌐 [Interactive HTML Report]({report_urls['html']})\n"
            if "md" in report_urls:
                reports_md += f"- 📝 [Markdown Report]({report_urls['md']})\n"

        if pr_num:
            pr_comment = f"""### 🛡️ CodeMender Proposed Security Patch
 
We generated fixes for the following vulnerability finding(s):
{chr(10).join([f"- `{fid}`" for fid, success, _ in successful_fixes])}
{reports_md}
#### Proposed Fix Diff:
```diff
{total_diff}
```
 
Merge this pull request once its CodeMender security gate passes to apply the fix.
"""
            await post_pr_comment(repo_name, pr_num, sanitize_comment_length(pr_comment), token)

        # Report back to commit or PR thread
        diff_preview = f"\n<details>\n<summary><b>🔍 Preview Proposed Code Diff</b></summary>\n\n```diff\n{total_diff}\n```\n</details>\n"
        fixed_ids = ", ".join([f"`{fid}`" for fid, success, _ in successful_fixes])
        if is_pr and pr_number:
            outcome_report = "### 🛡️ CodeMender Proposed Security Patch\n\n"
            outcome_report += f"Generated fix(es) for finding(s) {fixed_ids}, staged on branch `{patch_branch}`. Nothing has been committed to this pull request yet.\n\n"
            if reports_md:
                outcome_report += reports_md
            outcome_report += diff_preview
            outcome_report += "#### ⚡ Next Steps:\n"
            outcome_report += f"* Reply `/approve` to apply this patch to `{branch}` as a new commit. CodeMender then re-scans that commit and updates the merge gate.\n"
            outcome_report += "* Reply `/fix <finding_id>` to patch additional findings first.\n"
            if pr_num:
                outcome_report += f"* Or review and merge the patch pull request **[#{pr_num}]({pr_url})**.\n"
        elif pr_num:
            outcome_report = f"### 🛡️ CodeMender Patches Generated!\n\n"
            outcome_report += f"Successfully created proposed fix(es) and updated the Pull Request!\n\n"
            outcome_report += f"👉 **[Draft Pull Request #{pr_num}]({pr_url})**\n\n"
            if reports_md:
                outcome_report += reports_md
            outcome_report += diff_preview
            outcome_report += "\nPlease review the diff on that pull request and merge it once its CodeMender security gate passes."
        else:
            outcome_report = f"### 🛡️ CodeMender Patch Staged on Branch `{patch_branch}`!\n\n"
            outcome_report += f"Successfully generated proposed fix(es) for finding(s): {fixed_ids}.\n\n"
            if reports_md:
                outcome_report += reports_md
            outcome_report += diff_preview
            outcome_report += "#### ⚡ Next Steps:\n"
            outcome_report += f"* To patch additional findings on this branch, reply here with `/fix <finding_id>`.\n"
            outcome_report += f"* When you are ready to review the changes on GitHub, reply here with `/draft` (or `/pr`) to open the Draft Pull Request.\n"

        sanitized_outcome = sanitize_comment_length(outcome_report)
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, sanitized_outcome, token)
        else:
            await post_commit_comment(repo_name, commit_sha, sanitized_outcome, token)

    except TaskCancelled as cancel:
        task_error = cancel.reason
        logger.info(f"/fix on {commit_sha[:8]} {task_error}.")
        try:
            msg = f"🛑 `/fix` on `{commit_sha[:7]}` was {task_error}; unfinished findings keep their previous status."
            if pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, msg, token)
        except Exception as cancel_comment_err:
            logger.warning(f"Could not post the cancellation notice: {cancel_comment_err}")
    except Exception as ex:
        task_error = ex
        logger.error(f"Error in fix_findings_task: {ex}", exc_info=True)
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch if 'branch' in locals() else "unknown",
                event_type=_task_event_type(is_pr),
                pr_number=pr_number,
                status="FAILED",
                target_file=None,
                findings_count=0,
                findings=[],
                action_taken="fix"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log failed fix summary to BigQuery: {bq_log_err}")
    finally:
        await stop_background_task(heartbeat)
        await finish_progress_comment(repo_name, pr_number, "patch", commit_sha, token, started_at, error=task_error)
        if marked and not restored:
            try:
                restore_after_failed_task(commit_sha, findings, prior_finding_status, prior_status, ("PATCHING",), task_error)
            except Exception as restore_err:
                logger.error(f"Could not restore scan record {commit_sha[:8]} after a failed run: {restore_err}")
        try:
            from shared_state import active_tasks
            active_tasks.pop(commit_sha, None)
        except Exception:
            pass
        session.finish()
        renewer.cancel()
        release_lock(lock_id, owner)


async def process_comment_command_task(repo_name: str, command: str, target_ids: list[str], is_pr: bool, pr_number: int = None, commit_sha: str = None):
    try:
        token = await get_github_token()
        if is_pr and pr_number:
            try:
                commit_sha = await get_pr_head_sha(repo_name, pr_number, token)
            except Exception:
                from database import get_patch_proposal_by_pr
                proposal = get_patch_proposal_by_pr(pr_number)
                if proposal:
                    commit_sha = proposal.get("commit_sha")
                    
            if not commit_sha:
                msg = "⚠️ CodeMender could not determine the head commit SHA for this Pull Request branch."
                await post_pr_comment(repo_name, pr_number, msg, token)
                return
        elif not commit_sha:
            # Issue-level commands (no PR, no commit) were routed to the removed fleet/Titan engine.
            logger.info(f"Ignoring /{command} on issue #{pr_number} in {repo_name}: only pull requests and commits are supported.")
            return

        # Extract model override flag if present, e.g. --model=pro or --model=flash
        model_override = None
        clean_target_ids = []
        for tid in target_ids:
            if tid.startswith("--model="):
                model_override = tid.split("=", 1)[1].strip()
            else:
                clean_target_ids.append(tid)

        if command == "verify":
            await verify_findings_task(repo_name, commit_sha, clean_target_ids, is_pr, pr_number)
        elif command == "fix":
            await fix_findings_task(repo_name, commit_sha, clean_target_ids, is_pr, pr_number)
            
    except Exception as err:
        logger.error(f"Error in process_comment_command_task: {err}", exc_info=True)


async def cancel_commit_task(commit_sha: str, cancelled_by: str, token: str | None = None) -> str:
    """Asks whatever works on ``commit_sha`` to stop (plan 3.4); never takes a live lease.

    Returns 'running' when a live task holds the workspace (it polls the flag and stops itself
    within seconds, then releases its own lease), 'closed' when nothing was running but the
    record was left in flight (it is closed out, with an error gate for an interrupted scan), and
    'idle' otherwise. An expired lease left by a dead worker is cleared.
    """
    from database import request_cancel, release_expired_lock
    lock_id = f"workspace-{commit_sha}"
    await asyncio.to_thread(request_cancel, commit_sha, cancelled_by)
    if await asyncio.to_thread(is_lock_held, lock_id):
        append_scan_step(commit_sha, "info", f"🛑 Cancel requested by @{cancelled_by}; the running task stops at its next checkpoint.")
        return "running"
    await asyncio.to_thread(release_expired_lock, lock_id)
    record = await load_scan_record(commit_sha)
    fields, needs_gate = orphan_record_update(record, CANCELLED_SCAN_STATUS, f"cancelled by @{cancelled_by}")
    if fields is None:
        return "idle"
    update_scan_status(commit_sha, **fields)
    append_scan_step(commit_sha, "info", f"🛑 Unfinished record closed out by @{cancelled_by} (no task was running).")
    if needs_gate and (record or {}).get("repo_name"):
        state, description = cancelled_gate(cancelled_by)
        try:
            token = token or await get_github_token()
            await set_commit_status(repo=record["repo_name"], commit_sha=commit_sha, state=state, description=description,
                                    token=token, target_url=f"{DASHBOARD_URL}/scans/{commit_sha}")
        except Exception as err:
            logger.warning(f"Could not set the cancelled gate on {commit_sha[:8]}: {err}")
    return "closed"


async def process_cancel_command_task(repo_name: str, commenter: str, is_pr: bool, pr_number: int = None, commit_sha: str = None):
    """/cancel and /reset: asks the task on the PR head (or the commented commit) to stop (plan 3.4)."""
    try:
        token = await get_github_token()
        target_sha = commit_sha
        if is_pr and pr_number and not target_sha:
            try:
                target_sha = await get_pr_head_sha(repo_name, pr_number, token)
            except Exception as head_err:
                logger.warning(f"Could not read the head of PR #{pr_number}: {head_err}")
        if not target_sha:
            msg = "⚠️ CodeMender could not determine which commit to cancel."
        else:
            outcome = await cancel_commit_task(target_sha, commenter, token)
            msg = {
                "running": f"🛑 **Cancel requested by @{commenter}.** The CodeMender task on `{target_sha[:7]}` stops within a few seconds and releases its workspace.",
                "closed": f"🛑 **Cancelled by @{commenter}.** No task was running on `{target_sha[:7]}`; its unfinished record was closed out.",
                "idle": f"ℹ️ @{commenter}: no CodeMender task is running on `{target_sha[:7]}`.",
            }[outcome]
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, msg, token)
        elif commit_sha:
            await post_commit_comment(repo_name, commit_sha, msg, token)
        logger.info(f"Processed cancel command for {target_sha or pr_number} from @{commenter}")
    except Exception as cancel_err:
        logger.error(f"Error in process_cancel_command_task: {cancel_err}", exc_info=True)


async def process_dismiss_command_task(repo_name: str, commenter: str, comment_body: str, is_pr: bool, pr_number: int = None, commit_sha: str = None):
    """
    Parses /dismiss or /override or /override-gate commands, updates Firestore finding status,
    streams audit records to BigQuery, re-evaluates security/codemender-gate commit status,
    and posts an audit confirmation comment.
    """
    import re
    try:
        token = await get_github_token()
        if is_pr and pr_number:
            try:
                commit_sha = await get_pr_head_sha(repo_name, pr_number, token)
            except Exception:
                from database import get_patch_proposal_by_pr
                proposal = get_patch_proposal_by_pr(pr_number)
                if proposal:
                    commit_sha = proposal.get("commit_sha")
                    
            if not commit_sha:
                msg = "⚠️ CodeMender could not determine the head commit SHA for this Pull Request branch."
                await post_pr_comment(repo_name, pr_number, msg, token)
                return

        pattern = r"^/(dismiss|override|override-gate)(?:-gate)?(?:\s+([a-zA-Z0-9_-]+))?(?:\s+\[([A-Za-z0-9_]+)\])?\s*(.*)"
        match = re.match(pattern, comment_body.strip(), re.IGNORECASE)
        
        if not match:
            err_msg = (
                "⚠️ **Invalid Dismissal Syntax**\n\n"
                "Usage:\n"
                "- `/dismiss <finding_id> [CATEGORY] <reason>`\n"
                "- `/dismiss <finding_id> <reason>`\n"
                "- `/override-gate [CATEGORY] <reason>`\n\n"
                "**Supported Categories:** `[FALSE_POSITIVE]`, `[COMPENSATING_CONTROL]`, `[NON_PROD_FIXTURE]`, `[UNVERIFIABLE]`, `[BUSINESS_ACCEPTED_RISK]`\n"
                "*(Reason must be at least 10 characters for audit compliance)*"
            )
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, err_msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, err_msg, token)
            return

        cmd, target_id, category, reason = match.groups()
        cmd = cmd.lower()
        
        if cmd == "override-gate" or target_id == "gate":
            target_id = "all"
            category = category or "BUSINESS_ACCEPTED_RISK"
        else:
            category = category or "FALSE_POSITIVE"

        if not target_id:
            target_id = "all"

        reason = (reason or "").strip()
        if len(reason) < 10:
            err_msg = (
                "⚠️ **Dismissal Rejected: Insufficient Justification**\n\n"
                "To comply with security audit and compliance policies, a documented justification of at least **10 characters** is required.\n\n"
                f"**Example:**\n"
                f"```text\n/dismiss {target_id} [{category}] Verified input is sanitized upstream by Cloud Armor WAF\n```"
            )
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, err_msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, err_msg, token)
            return

        # Same rules as the dashboard (plan 3.6): never while a scan/verify/fix of the commit is
        # running (its worker would write the findings back), and the gate only moves for a
        # COMPLETED scan, so a dismissal never turns a failed or unfinished scan green.
        record = await load_scan_record(commit_sha)
        dismissal_target = check_dismissal_target(record, ALLOWED_REPOS, time.time())
        if not dismissal_target.allowed:
            err_msg = f"⚠️ **Dismissal not applied:** {dismissal_target.detail}"
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, err_msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, err_msg, token)
            return

        res = await asyncio.to_thread(
            dismiss_finding,
            commit_sha=commit_sha,
            finding_id=target_id,
            dismissed_by=commenter,
            category=category,
            reason=reason
        )

        if not res.get("success"):
            err_msg = f"⚠️ **Dismissal Failed:** {res.get('error', 'Could not locate finding in scan records.')}"
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, err_msg, token)
            elif commit_sha:
                await post_commit_comment(repo_name, commit_sha, err_msg, token)
            return

        dashboard_url = f"{DASHBOARD_URL}/scans/{commit_sha}"
        gate_state, gate_desc = dismissal_gate_decision(dismissal_target.scan_status, res.get("findings"),
                                                        unscanned_count=len((record or {}).get("unscanned_files") or []))
        if gate_state:
            await set_commit_status(
                repo=repo_name,
                commit_sha=commit_sha,
                state=gate_state,
                description=gate_desc,
                token=token,
                target_url=dashboard_url
            )
            gate_emoji = "🟢" if gate_state == "success" else "🔴"
            if gate_state == "success" and is_pr and pr_number:
                try:
                    await convert_draft_pr_to_ready(repo_name, pr_number, token)
                    logger.info(f"Auto-promoted PR #{pr_number} to Ready for Review after the dismissal cleared the gate.")
                except Exception as promo_err:
                    logger.warning(f"Note on PR Draft-to-Ready conversion during dismissal: {promo_err}")
        else:
            gate_emoji = "⚪"

        dismissed_items = res.get("dismissed_items", [])
        confirm_msg = "### 🛡️ CodeMender Risk Acceptance & Dismissal Applied\n\n"
        confirm_msg += f"- **Dismissed By:** `@{commenter}`\n"
        confirm_msg += f"- **Governance Category:** `[{res.get('dismissal', {}).get('category')}]`\n"
        confirm_msg += f"- **Justification:** \"{reason}\"\n"
        confirm_msg += f"- **Security Gate Status:** {gate_emoji} **{(gate_state or 'unchanged').upper()}** (`{gate_desc}`)\n\n"
        confirm_msg += "| Dismissed Finding ID | Vulnerability Type | Severity | Status |\n"
        confirm_msg += "| :--- | :--- | :--- | :--- |\n"
        for item in dismissed_items:
            confirm_msg += f"| `{item.get('id')}` | {item.get('vuln_type', 'Unknown')} | {item.get('severity', 'CRITICAL')} | ⚠️ **DISMISSED** |\n"

        confirm_msg += f"\n📊 *Audit record streamed to BigQuery dataset `codemender_analytics.dismissed_vulnerabilities_audit`.*"

        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, confirm_msg, token)
        elif commit_sha:
            await post_commit_comment(repo_name, commit_sha, confirm_msg, token)

        logger.info(f"Completed risk acceptance dismissal for {target_id} on {commit_sha} by {commenter}. Gate: {gate_state}")

    except Exception as err:
        logger.error(f"Error in process_dismiss_command_task: {err}", exc_info=True)



def format_findings_comment_report(findings: list, filepath: str) -> str:
    report = "### 🔍 CodeMender Security Scan Results\n\n"
    report += "We scanned this commit for security vulnerabilities.\n\n"
    report += f"- **Status:** Completed\n"
    report += f"- **Target File:** `{filepath}`\n"
    report += f"- **Vulnerabilities Found:** {len(findings)}\n\n"
    
    if findings:
        report += "| ID | Severity | Type | Description |\n"
        report += "| --- | --- | --- | --- |\n"
        for f in findings:
            raw_sev = str(f.get("severity", "HIGH")).upper()
            clean_sev = raw_sev.replace("🔴", "").replace("🟠", "").replace("🟡", "").replace("🔵", "").replace("⚪", "").strip()
            sev = "CRITICAL" if "CRITICAL" in clean_sev else "HIGH" if "HIGH" in clean_sev else "MEDIUM" if "MEDIUM" in clean_sev else "LOW" if "LOW" in clean_sev else "HIGH"
            emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵"
            report += f"| `{f.get('id')}` | {emoji} **{sev}** | {f.get('vuln_type')} | {f.get('description')} |\n"
    else:
        report += "✨ No vulnerabilities found!"
    return report


def clean_confidence(extracted: str) -> str:
    if not extracted:
        return "100%"
    clean = extracted.strip().strip("'").strip('"').replace("%", "").lower()
    if clean.isdigit():
        return f"{clean}%"
    
    mapping = {
        "certain": "100%",
        "high": "80%",
        "likely": "80%",
        "medium": "50%",
        "possible": "50%",
        "low": "20%",
        "unlikely": "10%"
    }
    return mapping.get(clean, extracted)


@app.post("/github-webhook")
@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Main Webhook ingestion endpoint. Validates payload signatures and routes requests asynchronously."""
    raw_body = await request.body()
    headers = request.headers
    
    # 1. Signature Verification
    #
    # Order matters. The WIF branch is only reachable when WIF_AUTH_ENABLED is explicitly set,
    # because X-CodeMender-Auth is an ordinary request header that any client can send. It
    # asserts nothing on its own -- the actual control is the run.invoker IAM binding on a
    # service deployed with --no-allow-unauthenticated.
    if WIF_AUTH_ENABLED and headers.get("X-CodeMender-Auth") == "WIF":
        logger.info("Signature check delegated to Cloud Run IAM (WIF path).")
    elif WEBHOOK_SECRET:
        signature = headers.get("X-Hub-Signature-256", "")
        if not verify_signature(raw_body, signature, WEBHOOK_SECRET):
            logger.warning("Rejecting webhook: Invalid payload signature.")
            return Response(content="Invalid signature", status_code=401)
    elif WIF_AUTH_ENABLED:
        # WIF is the only configured authenticator and this request did not use it.
        logger.warning("Rejecting webhook: not on the WIF path and no GITHUB_WEBHOOK_SECRET is configured.")
        return Response(content="Unauthenticated", status_code=401)
    else:
        # Fail closed. Previously this fell through and processed the request unverified
        # whenever GITHUB_WEBHOOK_SECRET was unset.
        logger.error(
            "Rejecting webhook: no authentication configured. "
            "Set GITHUB_WEBHOOK_SECRET, or set WIF_AUTH_ENABLED=true on a service that is "
            "deployed with --no-allow-unauthenticated."
        )
        return Response(content="Server misconfigured: no webhook authentication", status_code=503)

    # 2. Extract Event Type
    event_type = headers.get("X-GitHub-Event", "")
    
    try:
        import json
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to parse JSON payload: {e}")
        return Response(content="Invalid JSON", status_code=400)

    # 2b. Repository enrollment check.
    # Every downstream handler takes the target repo from this payload, so validate it once
    # here rather than at each of the call sites that read repository.full_name.
    payload_repo = (payload.get("repository", {}) or {}).get("full_name")
    if payload_repo and not is_repo_allowed(payload_repo):
        logger.warning(f"Rejecting webhook for unenrolled repository: {payload_repo}")
        return Response(content="Repository not enrolled", status_code=403)

    # 2c. Re-validate against the GitHub API (plan 1.6, review D4).
    # Relayed (WIF) bodies are not signed by GitHub, so every event that starts work or writes
    # records is re-read from the API: the comment/issue or PR must match, and GitHub's copies
    # replace the relayed ones before routing. Signed webhooks go through the same path, which
    # also drops stale PR events whose head has moved on.
    relayed_command = None
    if event_type in ("issue_comment", "commit_comment"):
        relayed_command = command_name((payload.get("comment", {}) or {}).get("body"))
    if needs_validation(event_type, payload, relayed_command):
        if os.getenv("MOCK_MODE") == "true":
            logger.info("MOCK_MODE: skipping GitHub re-validation of the event.")
        else:
            check = await validate_relayed_event(event_type, payload, github_get_json)
            if not check.ok:
                log = logger.info if check.status_code == 200 else logger.warning
                log(f"Webhook '{event_type}' event not processed: {check.reason} (HTTP {check.status_code}).")
                return Response(content=check.reason, status_code=check.status_code)
            payload = apply_authoritative(payload, check.replacements)

    # 3. Route Pushes (Decommissioned in favor of PR-driven scanning)
    if event_type == "push":
        ref = payload.get("ref", "")
        logger.info(f"Push event received for ref '{ref}'. Push-triggered scanning is decommissioned; returning 200.")
        return JSONResponse(status_code=200, content={"message": "Push event ignored; PR-triggered scans active"})

    # 4. Route PR Events (opened, synchronize, reopened, ready_for_review) as Primary Ingress
    elif event_type == "pull_request":
        action = payload.get("action")
        pr_number = payload.get("number")
        
        # Layer 4 Guard: Whitelisted PR actions only
        if action in ["opened", "synchronize", "reopened", "ready_for_review"]:
            pr_data = payload.get("pull_request", {})
            head_sha = pr_data.get("head", {}).get("sha")
            branch = pr_data.get("head", {}).get("ref")
            base_branch = pr_data.get("base", {}).get("ref", "main")
            is_draft = pr_data.get("draft", False)
            pr_title = pr_data.get("title", "")
            pr_url = pr_data.get("html_url", "")
            repo_name = payload.get("repository", {}).get("full_name")
            pusher = pr_data.get("user", {}).get("login", "developer")

            # No branch/title/[skip ci]/bot-sender bypasses: those are chosen by whoever pushes, and the
            # synchronize event for a CodeMender patch commit must be re-scanned like any other push.

            # Duplicate-delivery guard: the GitHub webhook and the Actions relay can deliver the same
            # event. If a scan for this head SHA is already queued/running (updated < 30 min ago), skip.
            if head_sha and is_scan_in_flight(head_sha):
                logger.info(f"Skipping duplicate PR #{pr_number} '{action}' event: a scan of {head_sha[:8]} is already in progress.")
                return Response(content="Scan already in progress for this commit", status_code=200)

            # A Draft -> Ready promotion doesn't change the head commit. When that commit already has
            # a finished scan result, the result and its gate stand (no second scan, plan 3.9).
            # (There is no "applied patch" bypass: CodeMender's own patch commits are re-scanned
            # like any other push, so their gate is always set.)
            if action == "ready_for_review" and head_sha:
                try:
                    existing_record = await load_scan_record(head_sha)
                except Exception as record_err:
                    existing_record = None
                    logger.warning(f"Could not read the scan record of {head_sha[:8]}: {record_err}")
                if has_terminal_scan_result(existing_record, repo_name=repo_name, pr_number=pr_number):
                    logger.info(f"PR #{pr_number} ready_for_review: {head_sha[:8]} already has a finished scan; its gate stands.")
                    return Response(content="Head commit already scanned; its result stands", status_code=200)

            import uuid
            from shared_state import active_tasks
            run_id = str(uuid.uuid4())
            active_tasks[f"pr-{pr_number}"] = run_id
            active_tasks[head_sha] = run_id

            logger.info(f"Processing PR event '{action}' for PR #{pr_number} (Head SHA: {head_sha}, Draft: {is_draft}, Run ID: {run_id})")

            update_scan_status(
                head_sha,
                branch_name=branch,
                repo_name=repo_name,
                pr_number=pr_number,
                is_draft=is_draft,
                pr_url=pr_url,
                pr_title=pr_title,
                base_branch=base_branch,
                pusher_name=pusher,
                status="QUEUED",
                message=f"PR #{pr_number} ({action}) received; queuing PR scanner worker"
            )
            background_tasks.add_task(process_pr_scan_event, payload, run_id)
            logger.info(f"Enqueued PR scan worker for PR #{pr_number} (commit {head_sha[:8]}, action: {action}, draft: {is_draft}).")
            return Response(content="Accepted pull_request event", status_code=202)

        elif action == "closed":
            if payload.get("pull_request", {}).get("merged", False):
                background_tasks.add_task(
                    process_merged_pr_analytics,
                    repo_name=payload.get("repository", {}).get("full_name"),
                    pr_number=pr_number,
                    payload=payload
                )
                logger.info(f"Enqueued PR merged analytics worker for PR #{pr_number}.")
                return Response(content="Accepted PR merged event", status_code=202)
            return Response(content="PR closed without merge", status_code=200)

        else:
            logger.info(f"Ignoring PR action '{action}' for PR #{pr_number}")
            return Response(content=f"PR action '{action}' ignored", status_code=200)

    # 5. Route PR Comments (/approve, /verify, /fix triggers)
    elif event_type == "issue_comment":
        action = payload.get("action")
        comment_body = payload.get("comment", {}).get("body", "").strip()
        
        if action == "created":
            is_pr = "pull_request" in payload.get("issue", {})
            issue_number = payload.get("issue", {}).get("number")
            repo_name = payload.get("repository", {}).get("full_name")
            clean_body = comment_body.strip()
            command = command_name(clean_body)
            commenter = payload.get("comment", {}).get("user", {}).get("login", "developer")

            # Authorization gate. Slash commands (and the bare-word forms routed below) spend money,
            # mutate branches, and approve patches, so they need push access to the repository.
            if command:
                denied = await require_write_access(repo_name, payload, commenter, command)
                if denied is None:
                    denied = await reject_duplicate_command(event_type, payload, repo_name)
                if denied is not None:
                    return denied

            if clean_body in ("/approve", "approve", "/approve all", "approve all"):
                if is_pr:
                    pr_author = payload.get("issue", {}).get("user", {}).get("login", "")
                    if REQUIRE_INDEPENDENT_APPROVER and not is_independent_approver(commenter, pr_author):
                        return await reject_command(
                            repo_name,
                            f"⛔ @{commenter}: /approve requires an approver other than the PR author.",
                            "Approver must differ from the PR author",
                            pr_number=issue_number
                        )
                    background_tasks.add_task(process_approve_comment, payload)
                    logger.info("Enqueued approval comment worker task for PR.")
                    return Response(content="Accepted approval comment for PR", status_code=202)
                else:
                    # Issue-level /approve batch-merged fleet/Titan PRs; that engine was removed.
                    logger.info(f"Ignoring /approve on issue #{issue_number}: only pull requests are supported.")
                    return Response(content="Issue-level /approve is not supported", status_code=200)
            
            # 1. Verification Commands: /verify, verify, /verify all, /verify-all, /verify critical, /verify <id>
            if clean_body.startswith("/verify") or clean_body.startswith("verify ") or clean_body == "verify":
                parts = clean_body.lstrip("/").split()
                if clean_body in ("/verify-all", "/verify all", "/verify", "verify-all", "verify all", "verify"):
                    target_ids = ["all"]
                elif len(parts) > 1:
                    target_ids = [p.strip(",.;") for p in parts[1:]]
                else:
                    target_ids = ["all"]

                background_tasks.add_task(
                    process_comment_command_task,
                    repo_name=repo_name,
                    command="verify",
                    target_ids=target_ids,
                    is_pr=is_pr,
                    pr_number=issue_number
                )
                logger.info(f"Enqueued verify command worker task for {'PR' if is_pr else 'Issue'} #{issue_number} (targets: {target_ids}).")
                return Response(content="Accepted verify command", status_code=202)
                    
            # 2. Remediation Commands: /fix, fix, /remediate, remediate, /fix all, /fix critical, /fix <id>
            elif (clean_body.startswith("/fix") or clean_body.startswith("fix ") or clean_body == "fix" or
                  clean_body.startswith("/remediate") or clean_body.startswith("remediate ") or clean_body == "remediate"):
                parts = clean_body.lstrip("/").split()
                if clean_body in ("/remediate-all", "/remediate all", "/fix-all", "/fix all", "/fix",
                                  "remediate-all", "remediate all", "fix-all", "fix all", "fix"):
                    target_ids = ["all"]
                elif len(parts) > 1:
                    target_ids = [p.strip(",.;") for p in parts[1:]]
                else:
                    target_ids = ["all"]

                background_tasks.add_task(
                    process_comment_command_task,
                    repo_name=repo_name,
                    command="fix",
                    target_ids=target_ids,
                    is_pr=is_pr,
                    pr_number=issue_number
                )
                logger.info(f"Enqueued fix command worker task for {'PR' if is_pr else 'Issue'} #{issue_number} (targets: {target_ids}).")
                return Response(content="Accepted fix/remediate command", status_code=202)

            elif comment_body.startswith("/dismiss") or comment_body.startswith("/override"):
                # Suppressing findings / overriding the gate needs maintain or admin, not just collaborator.
                denied = await require_maintainer(repo_name, commenter, command, pr_number=issue_number)
                if denied is not None:
                    return denied
                background_tasks.add_task(
                    process_dismiss_command_task,
                    repo_name=repo_name,
                    commenter=commenter,
                    comment_body=comment_body,
                    is_pr=is_pr,
                    pr_number=issue_number
                )
                logger.info(f"Enqueued dismiss command worker task for {'PR' if is_pr else 'Issue'} #{issue_number}.")
                return Response(content="Accepted dismiss command", status_code=202)

            elif comment_body.startswith("/cancel") or comment_body.startswith("/reset"):
                pr_number = payload.get("issue", {}).get("number")
                repo_name = payload.get("repository", {}).get("full_name")
                commenter = payload.get("comment", {}).get("user", {}).get("login", "developer")
                background_tasks.add_task(
                    process_cancel_command_task,
                    repo_name=repo_name,
                    commenter=commenter,
                    is_pr=True,
                    pr_number=pr_number
                )
                logger.info(f"Enqueued cancel/reset command worker task for PR #{pr_number}.")
                return Response(content="Accepted cancel command", status_code=202)

            elif comment_body == "/draft" or comment_body == "/pr":
                pr_number = payload.get("issue", {}).get("number")
                repo_name = payload.get("repository", {}).get("full_name")
                
                from database import db
                target_commit = None
                scans_query = db.collection("scans").where("pr_number", "==", pr_number).limit(1).stream()
                for sdoc in scans_query:
                    target_commit = sdoc.to_dict().get("commit_sha") or sdoc.id
                    break
                
                if not target_commit:
                    token = await get_github_token()
                    target_commit = await get_pr_head_sha(repo_name, pr_number, token)
                    
                if target_commit:
                    background_tasks.add_task(
                        create_draft_pr_task,
                        repo_name=repo_name,
                        commit_sha=target_commit
                    )
                    logger.info(f"Enqueued manual Draft PR creation worker task for commit {target_commit} from PR #{pr_number}.")
                    return Response(content="Accepted PR draft command", status_code=202)
                
        return Response(content="Comment event ignored", status_code=200)

    # 5. Route Commit Comments (/verify, /fix, /draft, /dismiss, /cancel triggers)
    elif event_type == "commit_comment":
        action = payload.get("action")
        comment_body = payload.get("comment", {}).get("body", "").strip()
        commit_sha = payload.get("comment", {}).get("commit_id")
        repo_name = payload.get("repository", {}).get("full_name")
        
        if action == "created" and commit_sha:
            command = command_name(comment_body)
            commenter = payload.get("comment", {}).get("user", {}).get("login", "developer")

            # Same authorization gate as the PR comment path. /dismiss in particular can
            # suppress a finding permanently, so it must not be reachable by any commenter.
            if command:
                denied = await require_write_access(repo_name, payload, commenter, command)
                if denied is None:
                    denied = await reject_duplicate_command(event_type, payload, repo_name)
                if denied is not None:
                    return denied

            if comment_body.startswith("/verify"):
                parts = comment_body.split()
                if len(parts) > 1:
                    target_ids = [p.strip(",.;") for p in parts[1:]]
                    background_tasks.add_task(
                        process_comment_command_task,
                        repo_name=repo_name,
                        command="verify",
                        target_ids=target_ids,
                        is_pr=False,
                        commit_sha=commit_sha
                    )
                    logger.info(f"Enqueued verify command worker task for commit {commit_sha}.")
                    return Response(content="Accepted commit verify command", status_code=202)
                    
            elif comment_body.startswith("/fix"):
                parts = comment_body.split()
                if len(parts) > 1:
                    target_ids = [p.strip(",.;") for p in parts[1:]]
                    background_tasks.add_task(
                        process_comment_command_task,
                        repo_name=repo_name,
                        command="fix",
                        target_ids=target_ids,
                        is_pr=False,
                        commit_sha=commit_sha
                    )
                    logger.info(f"Enqueued fix command worker task for commit {commit_sha}.")
                    return Response(content="Accepted commit fix command", status_code=202)

            elif comment_body.startswith("/dismiss") or comment_body.startswith("/override"):
                denied = await require_maintainer(repo_name, commenter, command, commit_sha=commit_sha)
                if denied is not None:
                    return denied
                background_tasks.add_task(
                    process_dismiss_command_task,
                    repo_name=repo_name,
                    commenter=commenter,
                    comment_body=comment_body,
                    is_pr=False,
                    commit_sha=commit_sha
                )
                logger.info(f"Enqueued dismiss command worker task for commit {commit_sha}.")
                return Response(content="Accepted commit dismiss command", status_code=202)

            elif comment_body.startswith("/cancel") or comment_body.startswith("/reset"):
                background_tasks.add_task(
                    process_cancel_command_task,
                    repo_name=repo_name,
                    commenter=commenter,
                    is_pr=False,
                    commit_sha=commit_sha
                )
                logger.info(f"Enqueued cancel command worker task for commit {commit_sha}.")
                return Response(content="Accepted commit cancel command", status_code=202)

            elif comment_body == "/draft" or comment_body == "/pr":
                background_tasks.add_task(
                    create_draft_pr_task,
                    repo_name=repo_name,
                    commit_sha=commit_sha
                )
                logger.info(f"Enqueued manual Draft PR creation worker task for commit {commit_sha}.")
                return Response(content="Accepted commit draft command", status_code=202)
                
        return Response(content="Commit comment event ignored", status_code=200)

    # Ignore other events
    return Response(content="Event ignored", status_code=200)


@app.get("/api/patches")
async def api_patches():
    """API endpoint to list all patch proposals stored in Firestore."""
    patches = list_patch_proposals()
    return {"status": "success", "patches": patches}

@app.get("/api/scans")
async def api_scans():
    """API endpoint to list all active and historical scans stored in Firestore."""
    scans = list_scans()
    return {"status": "success", "scans": scans}

@app.post("/api/scans/{commit_sha}/cancel")
async def api_cancel_scan(commit_sha: str, request: Request):
    """API endpoint to cancel a running scan or verification session (verified IAP user, enrolled repo)."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    target = await resolve_dashboard_target(commit_sha)
    if not target.allowed:
        return scan_target_error(target)
    outcome = await cancel_commit_task(commit_sha, identity)
    append_scan_step(commit_sha, "info", f"Cancel requested from the dashboard by {identity} ({outcome}).")
    messages = {
        "running": "Cancel requested; the running task stops within a few seconds and releases the workspace.",
        "closed": "No task was running; the unfinished scan record was closed out.",
        "idle": "No task is running for this scan.",
    }
    return {"status": "success", "message": messages[outcome], "outcome": outcome}


# --------------------------------------------------------------------------- instance lifecycle
# Cloud Run sends SIGTERM and kills the instance 10 s later (a new revision was promoted, or the
# instance is recycled). uvicorn runs the lifespan shutdown only after every background task has
# finished, which a running scan never does in time, so the hook chains onto the signal itself
# (plan 3.15, implementation finding N1).
SHUTDOWN_DRAIN_SEC = 5.0
SHUTDOWN_CLOSE_OUT_SEC = 3.5
_lifecycle_tasks: set = set()


def install_shutdown_handler() -> bool:
    """Chains a SIGTERM hook in front of the current handler (uvicorn's). Main thread only.

    The hook flags the shutdown and starts drain_in_flight_work, then calls the previous handler
    so the server still shuts down as before. Returns False when it can't be installed.
    """
    if threading.current_thread() is not threading.main_thread():
        return False
    loop = asyncio.get_running_loop()
    previous = signal.getsignal(signal.SIGTERM)

    def on_sigterm(signum, frame):
        if not shutdown_requested():
            request_shutdown()
            logger.warning(f"SIGTERM: closing out {len(IN_FLIGHT)} in-flight task(s) before the instance stops.")
            loop.call_soon_threadsafe(_start_drain, previous == signal.SIG_DFL)
        if callable(previous):
            previous(signum, frame)

    signal.signal(signal.SIGTERM, on_sigterm)
    return True


def _start_drain(terminate_after: bool = False) -> None:
    task = asyncio.ensure_future(drain_in_flight_work())
    _lifecycle_tasks.add(task)
    task.add_done_callback(_lifecycle_tasks.discard)
    if terminate_after:  # nothing to chain to: end the process the default way once drained
        task.add_done_callback(_terminate_with_default_sigterm)


def _terminate_with_default_sigterm(_task) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    os.kill(os.getpid(), signal.SIGTERM)


async def drain_in_flight_work(drain_sec: float = None, close_out_sec: float = None) -> list:
    """After SIGTERM: lets running tasks stop through their cancel path, then closes out the rest.

    request_shutdown() makes every cancel check report the shutdown at once, so cm runs are killed
    at their next poll (2 s) and each worker records the interruption itself (scan STALE with an
    'error' gate, verify/fix record restored) and releases its lease. Tasks still registered after
    ``drain_sec`` are closed out here within ``close_out_sec``. Returns their commit SHAs.
    """
    drain_sec = SHUTDOWN_DRAIN_SEC if drain_sec is None else drain_sec
    close_out_sec = SHUTDOWN_CLOSE_OUT_SEC if close_out_sec is None else close_out_sec
    deadline = time.monotonic() + drain_sec
    while IN_FLIGHT and time.monotonic() < deadline:
        await asyncio.sleep(0.2)
    leftovers = [(sha, dict(entry)) for sha, entry in list(IN_FLIGHT.items())]
    if not leftovers:
        logger.info("Shutdown drain: no task left in flight.")
        return []
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(close_out_interrupted_task(sha, entry) for sha, entry in leftovers), return_exceptions=True),
            timeout=close_out_sec,
        )
    except asyncio.TimeoutError:
        logger.error(f"Shutdown close-out of {len(leftovers)} task(s) did not finish within {close_out_sec}s.")
        return [sha for sha, _entry in leftovers]
    for (sha, _entry), result in zip(leftovers, results):
        if isinstance(result, BaseException):
            logger.error(f"Shutdown close-out of {sha[:8]} failed: {redact(str(result))}")
    return [sha for sha, _entry in leftovers]


async def close_out_interrupted_task(commit_sha: str, entry: dict) -> None:
    """Closes out a task the shutdown drain could not wait for; its worker dies with the instance.

    The scan record gets gate_policy.orphan_record_update (scan -> STALE, verify/fix restored), the
    owned lease is released, and an interrupted scan's gate is set to 'error' (best effort).
    """
    record = await load_scan_record(commit_sha)
    fields, needs_gate = orphan_record_update(record, STALE_SCAN_STATUS, SHUTDOWN_REASON)
    if fields:
        await asyncio.to_thread(update_scan_status, commit_sha, **fields)
    if entry.get("lock_id") and entry.get("owner"):
        await asyncio.to_thread(release_lock, entry["lock_id"], entry["owner"])
    IN_FLIGHT.pop(commit_sha, None)
    repo_name = entry.get("repo_name") or (record or {}).get("repo_name")
    is_scan = entry.get("task_type") == "scan" or (record or {}).get("active_task") == "scan"
    if needs_gate and is_scan and repo_name:
        state, description = stale_gate(SHUTDOWN_REASON)
        try:
            token = await get_github_token()
            await set_commit_status(repo=repo_name, commit_sha=commit_sha, state=state, description=description,
                                    token=token, target_url=f"{DASHBOARD_URL}/scans/{commit_sha}")
        except Exception as err:
            logger.warning(f"Could not set the interrupted gate on {commit_sha[:8]}: {redact(str(err))}")
    logger.info(f"Closed out {entry.get('task_type') or 'task'} on {commit_sha[:8]}: {SHUTDOWN_REASON}.")


MAINTENANCE_INTERVAL_DEFAULT_SEC = 300.0


def maintenance_interval_seconds() -> float:
    """Seconds between in-process maintenance cycles (plan 3.16); 0 means off.

    CM_MAINTENANCE_INTERVAL_SEC wins (0 disables, otherwise clamped to 60-86400 s). Without it the
    loop runs every 5 min on Cloud Run (K_SERVICE is set) and is off elsewhere (local runs, tests).
    """
    raw = (os.environ.get("CM_MAINTENANCE_INTERVAL_SEC") or "").strip()
    if not raw:
        return MAINTENANCE_INTERVAL_DEFAULT_SEC if os.environ.get("K_SERVICE") else 0.0
    try:
        value = float(raw)
    except ValueError:
        logger.warning(f"Ignoring invalid CM_MAINTENANCE_INTERVAL_SEC={raw!r}; the maintenance loop is off.")
        return 0.0
    if not value > 0:
        return 0.0
    return min(max(value, 60.0), 86400.0)


async def run_maintenance_cycle() -> dict:
    """One maintenance sweep plus the GitHub gates of the scans it closed out (plan 3.16).

    Scans that need an 'error' gate are closed out only when a GitHub token is available, so no
    record is closed while its gate stays 'pending' (implementation finding N8).
    """
    from maintenance import run_maintenance_sweep
    token = None
    try:
        token = await get_github_token()
    except Exception as err:
        logger.warning(f"Maintenance runs without a GitHub token; scans that need a gate are left for later: {redact(str(err))}")
    summary = await asyncio.to_thread(
        run_maintenance_sweep, allowed_repos=ALLOWED_REPOS, in_flight=frozenset(IN_FLIGHT), close_gated_scans=bool(token)
    )
    summary["gates_set"] = 0
    for gate in summary.get("stale_gates") or []:
        try:
            await set_commit_status(repo=gate["repo_name"], commit_sha=gate["commit_sha"], state=gate["state"],
                                    description=gate["description"], token=token,
                                    target_url=f"{DASHBOARD_URL}/scans/{gate['commit_sha']}")
            summary["gates_set"] += 1
        except Exception as err:
            logger.warning(f"Could not set the stale gate on {gate['commit_sha'][:8]}: {redact(str(err))}")
    return summary


async def maintenance_loop(interval: float) -> None:
    """Runs run_maintenance_cycle every ``interval`` seconds, the first time shortly after start."""
    await asyncio.sleep(min(interval, 120.0))
    while not shutdown_requested():
        try:
            summary = await run_maintenance_cycle()
            brief = {key: value for key, value in summary.items() if key != "stale_gates"}
            logger.info(f"In-process maintenance cycle finished: {brief}")
        except Exception as err:
            logger.warning(f"In-process maintenance cycle failed: {redact(str(err))}")
        await asyncio.sleep(interval)


@app.post("/api/maintenance/gc")
async def api_maintenance_gc(request: Request):
    """On-demand maintenance: the same cycle the in-process loop runs every 5 min (plan 3.16).

    The caller must be a verified dashboard (IAP) user, or present a Google-signed OIDC token whose
    audience is MAINTENANCE_OIDC_AUDIENCE and whose e-mail is in MAINTENANCE_INVOKERS. Fails closed
    otherwise: the sweep deletes locks and scan state.
    """
    caller = await get_iap_user_email(request) or await verify_google_oidc(
        request, os.getenv("MAINTENANCE_OIDC_AUDIENCE", ""), os.getenv("MAINTENANCE_INVOKERS", "")
    )
    if not caller:
        return api_error_response(401, "Maintenance requires a verified caller")
    logger.info(f"Maintenance sweep requested by {caller}.")
    return await run_maintenance_cycle()


@app.get("/api/analytics/tokens")
async def api_analytics_tokens(range_days: int = 7, start_date: str = None, end_date: str = None):
    """API endpoint to query aggregated token usage and cost metrics from BigQuery with custom date ranges and specific day filters."""
    analytics = get_token_analytics(range_days=range_days, start_date=start_date, end_date=end_date)
    return without_error_text(analytics, "Token analytics query failed")


@app.get("/api/analytics/sku-reconciliation")
async def api_analytics_sku_reconciliation(range_days: int = 7, start_date: str = None, end_date: str = None):
    """API endpoint to query exact 90-95%+ SKU reconciliation metrics and line-item token breakdowns."""
    analytics = get_token_analytics(range_days=range_days, start_date=start_date, end_date=end_date)
    return {
        "status": analytics.get("status", "success"),
        "filter_mode": analytics.get("filter_mode"),
        "range_days": analytics.get("range_days"),
        "start_date": analytics.get("start_date"),
        "end_date": analytics.get("end_date"),
        "sku_reconciliation": analytics.get("sku_reconciliation", {}),
        "summary": analytics.get("summary", {})
    }


@app.get("/api/analytics/remediation")
async def api_analytics_remediation(repo_name: str = None, range_days: int = 7, start_date: str = None, end_date: str = None):
    """API endpoint to query remediation velocity, MTTR, resolution rate, and multi-repo metrics from BigQuery."""
    analytics = get_remediation_analytics(repo_name=repo_name, range_days=range_days, start_date=start_date, end_date=end_date)
    return without_error_text(analytics, "Remediation analytics query failed")


@app.post("/api/analytics/chat")
async def api_analytics_chat(payload: dict, request: Request):
    """API endpoint to chat with the BigQuery Analytics agent (verified IAP user; spends model budget)."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    from analytics_agent.agent import chat_with_analytics_agent
    message = payload.get("message", "")
    if not message:
        return {"error": "Message parameter is required"}
    with telemetry_context(event_type="dashboard"):
        response = await chat_with_analytics_agent(message)
    return {"response": response}


async def ensure_workspace(commit_sha: str, branch: str, repo_name: str = None, pr_number=None):
    """Checks out exactly ``commit_sha`` in /tmp/session-{commit_sha} for verify/fix (plan 3.2).

    Verify and fix must run on the commit that was scanned, not on the branch tip: the workspace is
    cloned (or reset) and then pinned with GitWorkspace.ensure_exact_head, which fetches the commit
    when the branch has moved on and raises HeadMismatchError when it can't. `cm init` gets the
    same 360 s deadline as the other cm subcommands instead of none.
    """
    from git_manager import GitWorkspace
    import os
    import subprocess

    # If repo_name is missing, try to resolve from Firestore
    if not repo_name:
        try:
            from database import db
            if db:
                doc = db.collection("scans").document(commit_sha).get()
                if doc.exists:
                    repo_name = doc.to_dict().get("repo_name")
        except Exception as get_repo_err:
            logger.warning(f"Could not resolve repo_name from Firestore for {commit_sha}: {get_repo_err}")

    # 1. Restore the repository workspace, then pin it to the scanned commit.
    workspace_path = f"/tmp/session-{commit_sha}"
    git_ws = GitWorkspace(commit_sha, repo=repo_name)
    if not os.path.exists(workspace_path):
        logger.info(f"Workspace path {workspace_path} not found. Cloning repo '{repo_name}' branch '{branch}'...")
        token = await get_github_token()
        await git_ws.clone_repo(token, branch or "main")
    else:
        logger.info(f"Workspace path {workspace_path} already exists. Resetting to clean state...")
        await git_ws._run_command(["git", "reset", "--hard", "HEAD"])
        # Keep CodeMender local state across resets.
        await git_ws._run_command(["git", "clean", "-fd", "-e", ".codemender", "-e", ".cm_project", "-e", ".exploit"])
        if branch:
            try:
                # Leave a patch branch from an earlier /fix; the pin below resets the PR branch.
                await git_ws._run_command(["git", "checkout", branch])
            except Exception as checkout_err:
                logger.warning(f"Could not check out {branch} in {workspace_path}: {checkout_err}")
    await git_ws.ensure_exact_head(commit_sha, pr_number=pr_number)
    try:
        os.utime(workspace_path, None)  # the /tmp sweep skips workspaces used recently
    except OSError:
        pass

    # 2. Initialize CodeMender globally and in the workspace (`cm --version` in Dockerfile creates
    # ~/.codemender without config.yaml or state.db, so check for those files explicitly).
    codemender_path = os.path.expanduser("~/.codemender")
    cfg_file = os.path.join(codemender_path, "config.yaml")
    state_db_file = os.path.join(codemender_path, "state.db")
    if not os.path.exists(cfg_file) or not os.path.exists(state_db_file):
        logger.info("CodeMender config.yaml or state.db not found. Initializing 'cm init'...")
        from cm_tools import _cm_subprocess_env, cm_command_timeout
        init_timeout = cm_command_timeout("cm_init")
        try:
            await asyncio.to_thread(
                subprocess.run, ["cm", "init"], input=b"n\n", cwd=workspace_path, check=False,
                env=_cm_subprocess_env(), timeout=init_timeout
            )
        except subprocess.TimeoutExpired as init_err:
            raise RuntimeError(f"cm init timed out after {init_timeout:.0f}s") from init_err
    ensure_codemender_config()

    # 3. Restore state database from GCS (if exists) after cm init so it is not overwritten.
    try:
        from gcs_helpers import download_state_database
        download_state_database(commit_sha)
    except Exception as db_err:
        logger.error(f"Failed to restore state database from GCS: {db_err}")


@app.post("/api/scans/{commit_sha}/verify/{finding_id}")
async def api_verify_finding(commit_sha: str, finding_id: str, background_tasks: BackgroundTasks, request: Request):
    """API endpoint to manually trigger sandbox exploit verification for a finding (verified IAP user)."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    logger.info(f"Dashboard verify of {finding_id} on {commit_sha[:8]} requested by {identity}.")
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return {"status": "error", "message": "Scan session not found"}
    scan_data = doc.to_dict() or {}
    findings = scan_data.get("findings", [])
    branch = scan_data.get("branch_name")
    
    # Check if there is an active PR or repo configuration (from the stored record; must be enrolled)
    target = resolve_scan_target(scan_data, ALLOWED_REPOS)
    if not target.allowed:
        return scan_target_error(target)
    repo_name = target.repo_name
    pr_number = target.pr_number
    is_pr = True if pr_number else False
    
    if not any(f.get("id") == finding_id for f in findings):
        return {"status": "error", "message": "Finding ID not found in session"}

    # Same pipeline as the bulk endpoint and the PR comment commands (one code path for status,
    # locking and error handling). The busy check is advisory; the task re-checks the lease.
    if is_lock_held(f"workspace-{commit_sha}"):
        return {"status": "error", "message": "Another verify or fix operation is currently running for this scan session. Please try again in a few seconds."}
    background_tasks.add_task(
        verify_findings_task,
        repo_name=repo_name,
        commit_sha=commit_sha,
        finding_ids=[finding_id],
        is_pr=is_pr,
        pr_number=pr_number,
        event_type="dashboard",
    )
    return {"status": "success", "message": "Verification worker enqueued"}

@app.post("/api/scans/{commit_sha}/fix/{finding_id}")
async def api_fix_finding(commit_sha: str, finding_id: str, background_tasks: BackgroundTasks, request: Request):
    """API endpoint to trigger secure patch generation for one finding (verified IAP user).

    The patch is staged on codemender/patch-<sha>; the Draft PR is opened from the dashboard
    (or /draft), as for the bulk endpoint.
    """
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    logger.info(f"Dashboard fix of {finding_id} on {commit_sha[:8]} requested by {identity}.")
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return {"status": "error", "message": "Scan session not found"}
    scan_data = doc.to_dict() or {}
    findings = scan_data.get("findings", [])
    branch = scan_data.get("branch_name")
    
    # Repository and PR come from the stored scan record only, and the repository must be enrolled.
    target = resolve_scan_target(scan_data, ALLOWED_REPOS)
    if not target.allowed:
        return scan_target_error(target)
    repo_name = target.repo_name
    pr_number = target.pr_number
    is_pr = True if pr_number else False
    
    if not any(f.get("id") == finding_id for f in findings):
        return {"status": "error", "message": "Finding ID not found in session"}

    # Same pipeline as the bulk endpoint and the PR comment commands (one code path for status,
    # locking and error handling). The busy check is advisory; the task re-checks the lease.
    if is_lock_held(f"workspace-{commit_sha}"):
        return {"status": "error", "message": "Another verify or fix operation is currently running for this scan session. Please try again in a few seconds."}
    background_tasks.add_task(
        fix_findings_task,
        repo_name=repo_name,
        commit_sha=commit_sha,
        finding_ids=[finding_id],
        is_pr=is_pr,
        pr_number=pr_number,
        event_type="dashboard",
    )
    return {"status": "success", "message": "Patch generation worker enqueued"}

async def create_draft_pr_task(repo_name: str, commit_sha: str):
    """Worker task to manually create a Draft PR for a scan's patch branch."""
    token = None
    try:
        token = await get_github_token()
        from database import db
        
        doc_ref = db.collection("scans").document(commit_sha)
        doc = doc_ref.get()
        if not doc.exists:
            logger.warning(f"No scan document found for commit {commit_sha}")
            return
            
        scan_data = doc.to_dict()
        branch = scan_data.get("branch_name")
        patch_branch = f"codemender/patch-{commit_sha[:8]}"
        
        # Check if PR already exists
        from git_manager import get_existing_pr, create_draft_pr
        pr_num, pr_url = await get_existing_pr(repo_name, patch_branch, token)
        if pr_num:
            msg = f"ℹ️ A Draft Pull Request already exists for this patch branch: **[PR #{pr_num}]({pr_url})**"
            await post_commit_comment(repo_name, commit_sha, msg, token)
            return
            
        # Create Draft PR
        append_scan_step(commit_sha, "gitops", f"Creating Draft Pull Request from '{patch_branch}'...")
        pr_url, pr_num = await create_draft_pr(repo_name, patch_branch, branch, token)
        logger.info(f"Created Draft PR #{pr_num} for commit {commit_sha}")
        
        # Update database scan status and patch proposals
        update_scan_status(commit_sha, pr_number=pr_num)
        
        # Update patch proposal document with pr_number
        patches_ref = db.collection("patches").document(commit_sha)
        patches_ref.set({"pr_number": pr_num}, merge=True)
        
        # Post success message to commit
        msg = f"🎉 **Draft Pull Request Created Successfully!**\n\n👉 **[Draft Pull Request #{pr_num}]({pr_url})**\n\nComment `/approve` on the PR to commit the fix."
        await post_commit_comment(repo_name, commit_sha, msg, token)
        
    except Exception as e:
        logger.error(f"Failed to create draft PR for commit {commit_sha}: {e}", exc_info=True)
        try:
            if token:
                await post_commit_comment(repo_name, commit_sha, f"❌ Failed to create Draft PR: {e}", token)
        except Exception:
            pass

@app.post("/api/scans/{commit_sha}/draft_pr")
async def api_create_draft_pr(commit_sha: str, background_tasks: BackgroundTasks, request: Request):
    """API endpoint to manually trigger Draft PR creation for a patch branch (verified IAP user)."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    logger.info(f"Dashboard draft PR for {commit_sha[:8]} requested by {identity}.")
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return {"status": "error", "message": "Scan session not found"}
        
    scan_data = doc.to_dict() or {}
    target = resolve_scan_target(scan_data, ALLOWED_REPOS)
    if not target.allowed:
        return scan_target_error(target)
    repo_name = target.repo_name
    
    background_tasks.add_task(create_draft_pr_task, repo_name=repo_name, commit_sha=commit_sha)
    return {"status": "success", "message": "Draft PR creation task enqueued"}



@app.get("/api/scans/{commit_sha}")
async def api_scan_details(commit_sha: str):
    """API endpoint to get details of a specific scan."""
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return Response(content=json.dumps({"status": "error", "message": "Scan not found"}), status_code=404, media_type="application/json")
    return {"status": "success", "scan": doc.to_dict()}


class VerifyRequest(BaseModel):
    finding_ids: list[str]
    # Optional cross-checks only: the repository and PR always come from the stored scan record
    # (a different value is rejected with 400). is_pr is derived from the record as well.
    repo_name: Optional[str] = None
    is_pr: bool = False
    pr_number: Optional[int] = None

@app.post("/api/scans/{commit_sha}/verify")
async def api_verify_findings(commit_sha: str, req: VerifyRequest, background_tasks: BackgroundTasks, request: Request):
    """API endpoint to trigger Sandbox Exploit Verification for finding IDs (verified IAP user)."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    logger.info(f"Dashboard verify of {len(req.finding_ids or [])} finding(s) on {commit_sha[:8]} requested by {identity}.")
    target = await resolve_dashboard_target(commit_sha, body_repo_name=req.repo_name, body_pr_number=req.pr_number)
    if not target.allowed:
        return scan_target_error(target)
    background_tasks.add_task(
        verify_findings_task,
        repo_name=target.repo_name,
        commit_sha=commit_sha,
        finding_ids=req.finding_ids,
        is_pr=bool(target.pr_number),
        pr_number=target.pr_number,
        event_type="dashboard",
    )
    return {"status": "accepted", "message": "Verification worker enqueued."}


class FixRequest(BaseModel):
    finding_ids: list[str]
    # Optional cross-checks only: the repository and PR always come from the stored scan record
    # (a different value is rejected with 400). is_pr is derived from the record as well.
    repo_name: Optional[str] = None
    is_pr: bool = False
    pr_number: Optional[int] = None

@app.post("/api/scans/{commit_sha}/fix")
async def api_fix_findings(commit_sha: str, req: FixRequest, background_tasks: BackgroundTasks, request: Request):
    """API endpoint to trigger secure patch generation for finding IDs (verified IAP user)."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    logger.info(f"Dashboard fix of {len(req.finding_ids or [])} finding(s) on {commit_sha[:8]} requested by {identity}.")
    target = await resolve_dashboard_target(commit_sha, body_repo_name=req.repo_name, body_pr_number=req.pr_number)
    if not target.allowed:
        return scan_target_error(target)
    background_tasks.add_task(
        fix_findings_task,
        repo_name=target.repo_name,
        commit_sha=commit_sha,
        finding_ids=req.finding_ids,
        is_pr=bool(target.pr_number),
        pr_number=target.pr_number,
        event_type="dashboard",
    )
    return {"status": "accepted", "message": "Patch generation worker enqueued."}


class DismissRequest(BaseModel):
    finding_id: str
    category: str = "FALSE_POSITIVE"
    reason: str
    # Ignored. Still accepted so the shipped UI's {"user": "dashboard-user"} keeps validating; the
    # audit identity (dismissed_by) is the verified IAP user.
    user: Optional[str] = None

# dismiss_finding's own not-found messages are safe to show; any other error text is an exception.
_SAFE_DISMISS_ERROR_PREFIXES = ("Finding ID '", "Scan document for commit ")

@app.post("/api/scans/{commit_sha}/dismiss")
@app.post("/api/scans/{commit_sha}/dismiss-finding")
async def api_dismiss_finding(commit_sha: str, req: DismissRequest, request: Request):
    """API endpoint to dismiss a vulnerability finding with documented risk acceptance and update the merge gate.

    - dismissed_by is the verified IAP user (401 without one); the body's `user` is ignored.
    - One finding per call: the bulk ids 'all', 'gate' and '*' are refused (400).
    - 409 while a scan, verification or fix of the commit is running: its worker rewrites the
      findings when it finishes and would silently undo the dismissal.
    - The gate is recomputed with the scan worker's rule (decide_gate), and only for a COMPLETED
      scan, so a failed or unfinished scan never turns green here.
    """
    check = validate_dismissal_request(await get_iap_user_email(request), req.finding_id, req.reason)
    if not check.allowed:
        raise HTTPException(status_code=check.status_code, detail=check.detail)
    dismissed_by = check.identity
    finding_id = (req.finding_id or "").strip()
    category = req.category
    reason = (req.reason or "").strip()

    # The repository comes from the stored scan record and must be enrolled before anything changes.
    try:
        scan_record = await load_scan_record(commit_sha)
    except Exception as err:
        error_id = log_internal_error(f"Could not load scan record {commit_sha}", err)
        raise HTTPException(status_code=500, detail=f"Could not load the scan (error id: {error_id})")
    target = check_dismissal_target(scan_record, ALLOWED_REPOS, time.time())
    if not target.allowed:
        raise HTTPException(status_code=target.status_code, detail=target.detail)

    res = await asyncio.to_thread(
        dismiss_finding,
        commit_sha=commit_sha,
        finding_id=finding_id,
        dismissed_by=dismissed_by,
        category=category,
        reason=reason
    )

    if not res.get("success"):
        error_text = str(res.get("error") or "")
        if error_text.startswith(_SAFE_DISMISS_ERROR_PREFIXES):
            raise HTTPException(status_code=404, detail=error_text)
        error_id = log_internal_error(f"Dismissing {finding_id} on {commit_sha} failed", error_text or "unknown error")
        raise HTTPException(status_code=500, detail=f"Failed to dismiss finding (error id: {error_id})")

    gate_state, gate_desc = dismissal_gate_decision(target.scan_status, res.get("findings"),
                                                    unscanned_count=len((scan_record or {}).get("unscanned_files") or []))
    gate = {"state": gate_state or "unchanged", "description": gate_desc}
    if gate_state:
        try:
            token = await get_github_token()
            await set_commit_status(
                repo=target.repo_name,
                commit_sha=commit_sha,
                state=gate_state,
                description=gate_desc,
                token=token,
                target_url=f"{DASHBOARD_URL}/scans/{commit_sha}"
            )
        except Exception as gate_err:
            log_internal_error(f"Failed to update GitHub commit status on dismiss of {commit_sha}", gate_err)
            gate["state"] = "not_updated"
    logger.info(f"Dashboard dismissal of {finding_id} on {commit_sha[:8]} by {dismissed_by}; gate: {gate['state']}")

    return {**res, "gate": gate}

# Upper bound (seconds) for one SSE log stream; the client reconnects to keep following.
SSE_MAX_SEC = stream_limit_seconds(os.getenv("SSE_MAX_SEC", "900"))

@app.get("/api/scans/{commit_sha}/logs/stream")
async def api_stream_logs(commit_sha: str):
    """SSE endpoint streaming live execution log steps of a scan from Firestore.

    Ends with a final {"type": "end", "status": ...} event when the scan is terminal (COMPLETED,
    FAILED, DEFERRED, ...), missing or unreadable, or after SSE_MAX_SEC. Reads run off the event loop.
    """
    async def fetch_scan():
        return await load_scan_record(commit_sha)

    events = scan_log_events(
        fetch_scan,
        max_seconds=SSE_MAX_SEC,
        on_error=lambda err: log_internal_error(f"Log stream for {commit_sha} failed", err),
    )
    return StreamingResponse(events, media_type="text/event-stream", headers={"Cache-Control": "no-cache"})
# Place at the very end so it doesn't shadow explicit REST endpoints like /github-webhook or /api/patches


def api_error_response(status_code: int, message: str) -> JSONResponse:
    """JSON error for a refused request ({status, message, detail}); never carries exception text."""
    return JSONResponse(status_code=status_code, content=api_error_payload(message))



# ==========================================================
# Tri-Plane Plane 3 & Inspection APIs: Traces, Patches, HITL
# ==========================================================

class PatchReviewPayload(BaseModel):
    approved: bool
    rejection_reason: Optional[str] = None
    reviewer: str = "security-lead"

class InterventionResolvePayload(BaseModel):
    action: str  # 'APPROVE' or 'REJECT'
    # Ignored: the reviewer is the verified IAP user. Kept optional so older clients still validate.
    reviewer: Optional[str] = None
    notes: Optional[str] = None

@app.get("/api/v1/agent/traces/{execution_id}")
async def api_get_agent_traces(execution_id: str):
    """Fetches full reasoning & tool execution traces for a given execution run."""
    from agent_db_models import get_agent_traces
    try:
        traces = get_agent_traces(execution_id)
        return {
            "status": "success",
            "execution_id": execution_id,
            "traces": traces
        }
    except Exception as ex:
        return internal_error_response(f"Failed to fetch traces for {execution_id}", ex)

@app.get("/api/v1/agent/patches")
async def api_list_patches():
    """Lists generated patch proposals from Firestore."""
    from database import list_patch_proposals
    try:
        patches = list_patch_proposals()
        return {
            "status": "success",
            "patches": patches
        }
    except Exception as ex:
        return internal_error_response("Failed to list patches", ex)

@app.get("/api/v1/agent/interventions")
async def api_list_interventions(status: Optional[str] = "PENDING"):
    """Lists human intervention requests in the queue."""
    from agent_db_models import list_human_interventions
    try:
        items = list_human_interventions(status=status)
        return {
            "status": "success",
            "interventions": items
        }
    except Exception as ex:
        return internal_error_response("Failed to list interventions", ex)


def _load_human_intervention(intervention_id: str):
    """human_interventions/{id} as a dict, or None when it does not exist (blocking Firestore read)."""
    from agent_db_models import get_firestore_client
    client = get_firestore_client()
    if client is None:
        raise RuntimeError("Firestore client is not initialized")
    snap = client.collection("human_interventions").document(intervention_id).get()
    return (snap.to_dict() or {}) if snap.exists else None


@app.post("/api/v1/agent/interventions/{intervention_id}/resolve")
async def api_resolve_intervention(intervention_id: str, payload: InterventionResolvePayload, request: Request):
    """Resolves a human-in-the-loop intervention.

    The reviewer is the verified IAP user (401 without one); the body's `reviewer` is ignored.
    Errors are JSON: 400 bad action, 404 unknown intervention, 409 already resolved, 500 with an
    error id when the write fails.
    """
    from agent_db_models import resolve_human_intervention
    decision = validate_intervention_resolution(await get_iap_user_email(request), payload.action)
    if not decision.allowed:
        return api_error_response(decision.status_code, decision.detail)
    reviewer, action = decision.identity, decision.value
    try:
        record = await asyncio.to_thread(_load_human_intervention, intervention_id)
        state = check_intervention_record(record)
        if not state.allowed:
            return api_error_response(state.status_code, state.detail)
        success = await asyncio.to_thread(
            resolve_human_intervention,
            intervention_id=intervention_id,
            action=action,
            reviewer=reviewer,
            notes=payload.notes
        )
    except Exception as ex:
        return internal_error_response(f"Failed to resolve intervention {intervention_id}", ex)
    if not success:
        return internal_error_response(f"Failed to resolve intervention {intervention_id}", "resolve_human_intervention returned False")
    return {
        "status": "success",
        "intervention_id": intervention_id,
        "resolution": INTERVENTION_RESOLUTIONS[action],
        "reviewer": reviewer
    }



# ==========================================================
# Interactive Sandbox Endpoints (/ws/{session_id} & /submit)
# ==========================================================

class SandboxSubmitPayload(BaseModel):
    session_id: str
    code: str
    intent: str = ""


async def _ws_send_safe(ws: WebSocket, message: dict) -> bool:
    try:
        await ws.send_json(message)
        return True
    except Exception as ws_err:
        logger.debug(f"Sandbox WebSocket send failed: {ws_err}")
        return False


async def _run_interactive_sandbox_pipeline(session_id: str, code: str, intent: str):
    """Runs the QA + Semantic pre-check agents and streams results to the Interactive Sandbox WS."""
    from shared_state import active_connections, session_futures
    from agents import run_qa_agent, run_semantic_agent
    ws = active_connections.get(session_id)
    if not ws:
        return
    try:
        await _ws_send_safe(ws, {"type": "status", "message": "Running QA & Semantic Security pre-check agents..."})
        qa_task = asyncio.create_task(run_qa_agent(intent or "Verify secure implementation", code, session_id=session_id))
        sem_task = asyncio.create_task(run_semantic_agent(code, session_id=session_id))
        qa_report, sem_report = await asyncio.gather(qa_task, sem_task)

        qa_dict = qa_report.model_dump() if hasattr(qa_report, "model_dump") else qa_report.dict()
        sem_dict = sem_report.model_dump() if hasattr(sem_report, "model_dump") else sem_report.dict()

        await _ws_send_safe(ws, {
            "type": "pre_check_results",
            "qa_report": qa_dict,
            "semantic_report": sem_dict,
        })

        has_issues = bool(sem_dict.get("has_secrets") or sem_dict.get("hygiene_issues") or not qa_dict.get("matches_intent", True))
        if has_issues:
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            session_futures[session_id] = fut
            await _ws_send_safe(ws, {
                "type": "APPROVAL_REQUIRED",
                "filename": "sandbox_submission.py",
                "original_code": code,
                "patched_code": code,
            })
            try:
                decision = await asyncio.wait_for(fut, timeout=300.0)
                await _ws_send_safe(ws, {
                    "type": "status",
                    "message": f"HITL decision recorded: {decision}.",
                })
            except asyncio.TimeoutError:
                await _ws_send_safe(ws, {"type": "error", "message": "HITL approval timed out after 5 minutes."})
            finally:
                session_futures.pop(session_id, None)
        else:
            await _ws_send_safe(ws, {"type": "status", "message": "All pre-checks passed cleanly."})
    except Exception as ex:
        logger.error(f"Interactive sandbox pipeline error for {session_id}: {ex}")
        await _ws_send_safe(ws, {"type": "error", "message": f"Sandbox analysis failed: {redact(str(ex))}"})


@app.websocket("/ws/{session_id}")
async def websocket_sandbox_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket channel for the Dashboard Interactive Sandbox tab."""
    from shared_state import active_connections, session_futures
    if not session_id or len(session_id) > 128:
        await websocket.close(code=1008)
        return
    if not await get_iap_user_email(websocket):
        # Same rule as every other dashboard action: no verified IAP identity, no session.
        await websocket.close(code=1008)
        return
    await websocket.accept()
    active_connections[session_id] = websocket
    await _ws_send_safe(websocket, {"type": "status", "message": f"Sandbox session {session_id[:8]} ready."})
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {"raw": raw}
            action = str(data.get("action") or "").upper() if isinstance(data, dict) else ""
            fut = session_futures.get(session_id)
            if action in ("APPROVE", "REJECT") and fut is not None and not fut.done():
                fut.set_result(action)
            else:
                await _ws_send_safe(websocket, {"type": "echo", "message": f"Received: {action or 'message'}"})
    except WebSocketDisconnect:
        pass
    except Exception as ws_ex:
        logger.debug(f"Sandbox WebSocket closed for {session_id}: {ws_ex}")
    finally:
        if active_connections.get(session_id) is websocket:
            active_connections.pop(session_id, None)
        fut = session_futures.pop(session_id, None)
        if fut is not None and not fut.done():
            fut.cancel()


@app.post("/submit")
async def api_sandbox_submit(payload: SandboxSubmitPayload, background_tasks: BackgroundTasks, request: Request):
    """Accepts an Interactive Sandbox submission (verified IAP user) and streams analysis over /ws/{session_id}."""
    identity, denied = await dashboard_identity_or_401(request)
    if denied is not None:
        return denied
    from shared_state import active_connections
    session_id = (payload.session_id or "").strip()
    if not session_id or len(session_id) > 128:
        return api_error_response(400, "Invalid session_id")
    if not (payload.code or "").strip():
        return api_error_response(400, "Code submission cannot be empty")
    if len(payload.code) > 200_000:
        return api_error_response(400, "Code submission exceeds maximum size (200 KB)")
    if session_id not in active_connections:
        return api_error_response(404, "No active WebSocket connection for this session_id")
    background_tasks.add_task(_run_interactive_sandbox_pipeline, session_id, payload.code, payload.intent)
    return {"status": "accepted", "session_id": session_id}


# Place at the very end so it doesn't shadow explicit REST endpoints like /github-webhook or /api/patches

disable_ui = str(os.getenv("DISABLE_UI", "false")).strip().lower() in ("true", "1", "yes")
if not disable_ui and os.path.exists("frontend/out"):
    app.mount("/", StaticFiles(directory="frontend/out", html=True), name="static")
else:
    logger.info("Static dashboard serving disabled (DISABLE_UI=true).")



