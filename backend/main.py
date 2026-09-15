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
import json
from pathlib import Path
import time
import asyncio
from fastapi import FastAPI, Request, BackgroundTasks, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from agents import run_qa_agent, run_semantic_agent, run_triage_agent, apply_codemender_fix, map_finding_ids
from cm_tools import cm_verify

from git_manager import GitWorkspace
from github_helpers import (
    verify_signature,
    get_github_token,
    post_pr_comment,
    post_commit_comment,
    get_pr_head_sha,
    convert_draft_pr_to_ready,
    set_commit_status,
    update_or_post_pr_comment
)
from database import get_patch_proposal, mark_patch_as_applied, acquire_lock, release_lock, list_patch_proposals, update_scan_status, list_scans, append_scan_step, get_token_analytics


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Execution threshold: <= 4 findings runs sequential in-process, > 4 runs parallel worker sharding
PARALLEL_SHARDING_THRESHOLD = int(os.getenv("PARALLEL_SHARDING_THRESHOLD", "4"))

app = FastAPI()

# Enable CORS (for any local tooling dashboard testing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load webhook secret from environment (configured in Secret Manager in prod)
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
BOT_EMAIL = "agent@codemender.ai"

def parse_yaml_value(content: str, key: str) -> str:
    import re
    match = re.search(fr"^{key}\s*:\s*(.+)$", content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1).strip().strip('"').strip("'")
    return ""

async def post_periodic_progress(repo_name: str, commit_sha: str, pr_number: int | None, is_pr: bool, token: str, task_type: str, run_id: str, findings_count: int = 1):
    """Periodically posts progress updates to GitHub comments every 60 seconds while task is active."""
    import asyncio
    # 7 minutes hard progress cap per vulnerability (scales with batch size for /verify all)
    max_cap = max(7, findings_count * 7)
    minutes = 0
    while True:
        await asyncio.sleep(60)
        minutes += 1
        
        if minutes > max_cap:
            logger.warning(f"Progress loop for {commit_sha} reached {max_cap}-minute cap ({findings_count} finding(s)). Stopping progress loop.")
            break
        
        try:
            from shared_state import active_tasks
            if active_tasks.get(commit_sha) != run_id and active_tasks.get(f"pr-{pr_number}") != run_id:
                logger.info(f"Terminating stale progress loop for commit {commit_sha} (superseded by run {active_tasks.get(commit_sha)})")
                break
                
            from database import db
            doc = db.collection("scans").document(commit_sha).get()
            if not doc.exists:
                break
            data = doc.to_dict()
            status = data.get("status")
            step_msg = data.get("message", "")
            
            # Stop if the process is no longer active
            if status in ("COMPLETED", "FAILED"):
                break
            if task_type in ("verify", "patch", "scan") and status != "RUNNING":
                break
                
            step_info = f" — *{step_msg}*" if step_msg else ""
            if task_type == "scan":
                msg = f"⏳ **CodeMender Triage Scan is in progress...** ({minutes}m elapsed){step_info}"
            elif task_type == "verify":
                msg = f"⏳ **CodeMender Exploit Verification is in progress...** ({minutes}m elapsed){step_info}"
            else:
                msg = f"⏳ **CodeMender Patch Generation is in progress...** ({minutes}m elapsed){step_info}"
                
            if is_pr and pr_number:
                sticky_msg = f"<!-- codemender-security-report -->\n{msg}"
                await update_or_post_pr_comment(repo_name, pr_number, sticky_msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
        except Exception as err:
            logger.warning(f"Error posting periodic progress: {err}")
            break

async def upload_verification_artifacts(commit_sha: str, workspace_path: str, finding_id: str) -> list[dict]:
    """Finds all files in the local .exploit/ directory of the workspace and uploads them to GCS under a finding-specific subfolder."""
    from google.cloud import storage
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
    bucket_name = os.environ.get("ARTIFACT_BUCKET", f"{project_id}-artifacts")
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

def ensure_codemender_config():
    """Ensures that CodeMender global config exists and supports all extensions including .tf."""
    import os
    cfg_dir = os.path.expanduser("~/.codemender")
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_path = os.path.join(cfg_dir, "config.yaml")
    
    # Pre-defined config contents with .tf support and headless non-interactive settings
    config_content = """# CodeMender CLI configuration.
model: "gemini-3-flash-preview"

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
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
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

async def process_pr_scan_event(payload: dict):
    """
    Asynchronous background worker to process Pull Request security scans (including Draft PRs).
    Evaluates the cumulative PR changeset (origin/{base_branch}...HEAD) rather than isolated commits.
    """
    pr_data = payload.get("pull_request") or {}
    pr_number = payload.get("number")
    head_sha = pr_data.get("head", {}).get("sha") or payload.get("after")
    branch = pr_data.get("head", {}).get("ref") or payload.get("ref", "").replace("refs/heads/", "")
    base_branch = pr_data.get("base", {}).get("ref", "main")
    is_draft = pr_data.get("draft", False)
    pr_title = pr_data.get("title", "")
    pr_url = pr_data.get("html_url", "")
    repo_obj = payload.get("repository") or {}
    repo_name = repo_obj.get("full_name")
    pusher_obj = pr_data.get("user") or payload.get("pusher") or {}
    pusher = pusher_obj.get("login") or pusher_obj.get("name", "developer")
    pusher_email = pusher_obj.get("email", "")

    if not head_sha or head_sha == "0000000000000000000000000000000000000000":
        logger.info(f"Ignoring PR event with empty head SHA for PR #{pr_number}")
        return

    # Active Task Tracking & Cancellation of superseded runs on the same PR
    import uuid
    from shared_state import active_tasks
    run_id = str(uuid.uuid4())
    if pr_number:
        active_tasks[f"pr-{pr_number}"] = run_id
    active_tasks[head_sha] = run_id

    lock_id = f"workspace-{head_sha}"
    if not acquire_lock(lock_id):
        logger.warning(f"Aborting PR scan processing: Lock already active for {lock_id}")
        return

    try:
        # Loop Prevention check: ignore PRs created by bot
        if pusher == "codemender-bot[bot]" or "[skip ci]" in pr_title:
            logger.info(f"Skipping scan for PR #{pr_number} in repo {repo_name} (created by bot or skip-ci title)")
            return

        token = await get_github_token()
        dashboard_base = os.getenv("DASHBOARD_URL", "")
        dashboard_url = f"{dashboard_base}/scans/{head_sha}" if dashboard_base else None

        # 1. Update Firestore & GitHub commit status gate to PENDING
        update_scan_status(
            head_sha,
            branch_name=branch,
            repo_name=repo_name,
            status="QUEUED",
            message=f"Analyzing {'Draft ' if is_draft else ''}PR #{pr_number}...",
            pusher_name=pusher,
            pusher_email=pusher_email,
            pr_number=pr_number,
            is_draft=is_draft,
            pr_title=pr_title,
            pr_url=pr_url,
            base_branch=base_branch
        )
        append_scan_step(head_sha, "info", f"Started processing {'Draft ' if is_draft else ''}PR #{pr_number} ('{branch}') by '{pusher}'")

        try:
            await set_commit_status(
                repo=repo_name,
                commit_sha=head_sha,
                state="pending",
                description=f"CodeMender Gate: Analyzing {'Draft ' if is_draft else ''}PR #{pr_number} security...",
                token=token,
                target_url=dashboard_url
            )
            if pr_number:
                start_msg = f"⏳ **CodeMender Security Gate Started** for {'Draft ' if is_draft else ''}PR #{pr_number} on branch `{branch}` (`{head_sha[:7]}`). Running cumulative changeset analysis..."
                await update_or_post_pr_comment(repo_name, pr_number, start_msg, token)
        except Exception as comment_err:
            logger.warning(f"Failed to post initial scan start comment: {comment_err}")

        # Start periodic progress reporting task
        if pr_number:
            asyncio.create_task(post_periodic_progress(repo_name, head_sha, pr_number=pr_number, is_pr=True, token=token, task_type="scan", run_id=run_id))

        update_scan_status(head_sha, status="CLONING", message="Cloning PR branch and fetching merge-base from GitHub")
        append_scan_step(head_sha, "workspace", "Setting up local sandbox workspace for PR diff...")

        # 2. Setup git workspace, clone branch, and fetch base branch
        git_ws = GitWorkspace(head_sha, repo=repo_name)
        await git_ws.clone_repo(token, branch)
        logger.info(f"Successfully cloned PR branch '{branch}' to workspace.")
        append_scan_step(head_sha, "workspace", f"PR branch cloned successfully to {git_ws.workspace_path}")

        # Fetch base branch to enable cumulative diff calculation
        import subprocess
        subprocess.run(["git", "fetch", "origin", base_branch], cwd=str(git_ws.workspace_path), check=False, capture_output=True)

        # Pre-initialize global config
        ensure_codemender_config()

        # 3. Calculate Cumulative Changeset (git diff origin/{base_branch}...HEAD)
        changed_files = []
        try:
            diff_res = subprocess.run(
                ["git", "diff", "--name-only", f"origin/{base_branch}...HEAD"],
                cwd=str(git_ws.workspace_path),
                capture_output=True,
                text=True,
                check=True
            )
            changed_files = [line.strip() for line in diff_res.stdout.split("\n") if line.strip()]
            logger.info(f"Cumulative files modified in PR #{pr_number} against origin/{base_branch}: {changed_files}")
        except Exception as diff_err:
            logger.warning(f"Failed to calculate cumulative PR diff, falling back to git show: {diff_err}")
            show_res = subprocess.run(
                ["git", "show", "--name-only", "--pretty=format:", head_sha],
                cwd=str(git_ws.workspace_path),
                capture_output=True,
                text=True
            )
            changed_files = [line.strip() for line in show_res.stdout.split("\n") if line.strip()]

        supported_exts = {".ts", ".js", ".py", ".go", ".java", ".cpp", ".c", ".rb", ".php", ".sh", ".tf"}
        target_files = []
        for f in changed_files:
            # Skip CodeMender framework, tooling, configuration, and CI files
            if any(f.startswith(prefix) for prefix in ["backend/", "frontend/", "scripts/", "scratch/", ".github/", ".gemini/"]):
                continue
            if os.path.splitext(f)[1] in supported_exts:
                target_files.append(f)

        # 4. Handle Framework / Tooling Only PRs
        if not target_files:
            logger.info(f"No application source files modified in PR #{pr_number}. Auto-passing security gate.")
            update_scan_status(head_sha, status="COMPLETED", message="No application source files were modified in this PR.", findings=[])
            append_scan_step(head_sha, "workspace", "Scan completed: PR contains only framework/tooling changes.")
            
            # Pass GitHub Gate Check instantly
            await set_commit_status(
                repo=repo_name,
                commit_sha=head_sha,
                state="success",
                description="Passed: Tooling/framework changes only (0 vulnerabilities).",
                token=token,
                target_url=dashboard_url
            )
            if pr_number:
                skip_msg = f"### 🔍 CodeMender Security Gate: Passed ✅\n\nNo application source files were modified in {'Draft ' if is_draft else ''}PR #{pr_number}. Framework/tooling changes only (0 vulnerabilities)."
                await update_or_post_pr_comment(repo_name, pr_number, skip_msg, token)

            try:
                from database import log_scan_summary
                log_scan_summary(
                    commit_sha=head_sha,
                    repo_name=repo_name,
                    branch_name=branch,
                    event_type="pull_request",
                    status="COMPLETED",
                    target_file="none",
                    findings_count=0,
                    findings=[],
                    action_taken="scan",
                    pr_number=pr_number,
                    is_draft=is_draft
                )
            except Exception as bq_err:
                logger.warning(f"Failed to log skipped PR scan to BigQuery: {bq_err}")
            return

        # 5. Target File Selected
        filepath = target_files[0]
        file_path = git_ws.workspace_path / filepath
        if not file_path.exists():
            logger.warning(f"Target file {filepath} not found in workspace. Aborting scan.")
            update_scan_status(head_sha, status="FAILED", message=f"Vulnerability scan aborted: Target file {filepath} not found")
            append_scan_step(head_sha, "workspace", f"Aborted: Target file {filepath} not found in repository")
            return

        logger.info(f"Target file chosen for CodeMender analysis on PR #{pr_number}: {filepath}")
        append_scan_step(head_sha, "workspace", f"Selected target file for analysis: '{filepath}'")
        code_content = file_path.read_text(encoding="utf-8")

        # 6. Check if task was superseded before proceeding to heavy LLM scan
        if pr_number and active_tasks.get(f"pr-{pr_number}") != run_id:
            logger.info(f"PR scan for SHA {head_sha} was superseded by a newer commit on PR #{pr_number}. Exiting.")
            return

        # 7. Run QA and Semantic Hygiene Pre-Checks
        logger.info("Running QA and Semantic pre-checks...")
        update_scan_status(head_sha, status="PRE_CHECKS", message="Running QA and Static Analysis pre-checks")
        append_scan_step(head_sha, "pre_checks", "Starting QA Intent and Semantic Hygiene pre-check agents...")

        await asyncio.gather(
            run_qa_agent("Fix security issues in PR changeset", code_content, session_id=head_sha, repo_name=repo_name),
            run_semantic_agent(code_content, session_id=head_sha, repo_name=repo_name)
        )
        append_scan_step(head_sha, "pre_checks", "QA and Semantic Hygiene pre-checks completed successfully")

        # 8. Run CodeMender Triage Scan
        logger.info(f"Starting CodeMender Triage scan on PR #{pr_number}...")
        update_scan_status(head_sha, status="RUNNING", message="Scanning code for vulnerabilities (cm find)")

        findings = await run_triage_agent(
            session_id=head_sha,
            filepath=filepath,
            repo_name=repo_name
        )
        logger.info(f"CodeMender Triage scan finished for PR #{pr_number}. Findings count: {len(findings)}")
        update_scan_status(head_sha, status="COMPLETED", message="Vulnerability scan completed; findings list updated.", findings=findings, target_file=filepath)
        append_scan_step(head_sha, "info", f"Scan process completed successfully for PR #{pr_number}.")

        # 9. Log Scan Summary to BigQuery
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=head_sha,
                repo_name=repo_name,
                branch_name=branch,
                event_type="pull_request",
                status="COMPLETED",
                target_file=filepath,
                findings_count=len(findings),
                findings=findings,
                action_taken="scan",
                pr_number=pr_number,
                is_draft=is_draft
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log scan summary to BigQuery: {bq_log_err}")

        # 10. Format Findings and Update In-Place PR Comment
        try:
            draft_label = "Draft " if is_draft else ""
            findings_comment = f"### 🔍 CodeMender Security Scan Results ({draft_label}PR #{pr_number})\n\n"
            findings_comment += f"We scanned the cumulative changes in `{branch}` (`{head_sha[:7]}`) against `{base_branch}`.\n\n"
            findings_comment += f"- **Status:** Completed\n"
            findings_comment += f"- **Target File:** `{filepath}`\n"
            findings_comment += f"- **Vulnerabilities Found:** {len(findings)}\n\n"

            if findings:
                findings_comment += "| ID | Severity | Type | Description |\n"
                findings_comment += "| --- | --- | --- | --- |\n"
                for f in findings:
                    raw_sev = str(f.get("severity", "HIGH")).upper()
                    clean_sev = raw_sev.replace("🔴", "").replace("🟠", "").replace("🟡", "").replace("🔵", "").replace("⚪", "").strip()
                    sev = "CRITICAL" if "CRITICAL" in clean_sev else "HIGH" if "HIGH" in clean_sev else "MEDIUM" if "MEDIUM" in clean_sev else "LOW" if "LOW" in clean_sev else "HIGH"
                    emoji = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵"
                    findings_comment += f"| `{f.get('id')}` | {emoji} **{sev}** | {f.get('vuln_type')} | {f.get('description')} |\n"

                # Append Raw CLI output summary
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
                    logger.warning(f"Failed to fetch find_output from Firestore: {db_err}")

                findings_comment += "\n#### ⚡ Actions you can take directly on this PR:\n"
                findings_comment += "* Reply `/verify <finding_id>` to run sandbox exploit verification (e.g. `/verify all`).\n"
                findings_comment += "* Reply `/fix <finding_id>` to generate a security patch and stage proposed changes.\n"
            else:
                findings_comment += "✅ No security vulnerabilities were detected in this Pull Request."

            if pr_number:
                append_scan_step(head_sha, "gitops", f"Updating scan findings report on GitHub PR #{pr_number}...")
                await update_or_post_pr_comment(repo_name, pr_number, findings_comment, token)
                append_scan_step(head_sha, "gitops", f"Scan findings report successfully updated on GitHub PR #{pr_number}.")
            else:
                append_scan_step(head_sha, "gitops", "Posting scan findings report as commit comment on GitHub...")
                await post_commit_comment(repo_name, head_sha, findings_comment, token)
                append_scan_step(head_sha, "gitops", "Scan findings report successfully posted to GitHub.")
        except Exception as comment_err:
            logger.error(f"Failed to post PR findings comment: {comment_err}")
            append_scan_step(head_sha, "warning", f"Failed to update PR findings comment: {comment_err}")

        # 11. Enforce Merge Gate Status
        try:
            critical_findings = [f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"]
            if critical_findings:
                gate_state = "failure"
                gate_desc = f"Merge Blocked: {len(critical_findings)} CRITICAL vulnerabilities detected. Fix required."
            else:
                gate_state = "success"
                gate_desc = f"Passed: 0 critical vulnerabilities ({len(findings)} total findings)."

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

        # 12. GCS Reports Upload
        try:
            urls = await export_and_upload_reports(head_sha, str(git_ws.workspace_path))
            if urls:
                append_scan_step(head_sha, "reports", f"Generated & uploaded scan reports to GCS: [HTML Report]({urls.get('html')}) | [Markdown Report]({urls.get('md')})")
        except Exception as report_err:
            logger.warning(f"Failed to export & upload reports for PR #{pr_number}: {report_err}")

    except Exception as e:
        logger.error(f"PR scan processing failed for SHA {head_sha}: {e}", exc_info=True)
        update_scan_status(head_sha, status="FAILED", message=f"Vulnerability scan failed: {str(e)}")
        append_scan_step(head_sha, "error", f"Scan processing encountered fatal error: {str(e)}")
    finally:
        release_lock(lock_id)


async def process_push_event(payload: dict):
    """Legacy/Direct Push event compatibility wrapper."""
    return await process_pr_scan_event(payload)



async def process_approve_comment(payload: dict):
    """Asynchronous background worker to process approval comments and commit fixes."""
    pr_number = payload.get("issue", {}).get("number")
    if not pr_number:
        return
    lock_id = f"approve-{pr_number}"
    if not acquire_lock(lock_id):
        logger.warning(f"Aborting approval comment processing: Lock already active for {lock_id}")
        return

    try:
        repo_name = payload.get("repository", {}).get("full_name")
        commenter = payload.get("comment", {}).get("user", {}).get("login", "")

        logger.info(f"Processing PR #{pr_number} approval from commenter '{commenter}' in repo '{repo_name}'...")

        # 1. Fetch proposed patch from Firestore
        from database import get_patch_proposal_by_pr, get_patch_proposal
        patch = get_patch_proposal_by_pr(pr_number)
        token = await get_github_token()
        if not patch:
            try:
                head_sha = await get_pr_head_sha(repo_name, pr_number, token)
                if head_sha:
                    patch = get_patch_proposal(head_sha)
                    if patch:
                        logger.info(f"Resolved patch proposal for parent PR #{pr_number} via head commit SHA {head_sha}")
            except Exception as lookup_err:
                logger.warning(f"Failed to lookup patch by head SHA for PR #{pr_number}: {lookup_err}")

        if not patch:
            await post_pr_comment(repo_name, pr_number, "⚠️ No proposed patch found in database for this pull request.", token)
            return

        if patch.get("is_applied"):
            logger.info(f"Patch for PR #{pr_number} was already applied. Skipping.")
            return

        base_commit_sha = patch.get("commit_sha")
        target_sha = patch.get("patch_commit_sha") or patch.get("commit_sha")
        branch_name = patch.get("branch_name")
        git_diff = patch.get("git_diff")

        if target_sha:
            append_scan_step(target_sha, "gitops", f"Received GitOps PR approval comment (/approve) from '{commenter}' on PR #{pr_number}")

        # 2. Broker token
        token = await get_github_token()

        # 3. Race Condition Protection: Verify branch HEAD matches target commit SHA
        current_head_sha = await get_pr_head_sha(repo_name, pr_number, token)
        if current_head_sha and base_commit_sha and current_head_sha != base_commit_sha:
            logger.warning(f"Stale patch detected for PR #{pr_number}. HEAD SHA: {current_head_sha}, Stored base SHA: {base_commit_sha}")
            msg = (
                "⚠️ **Patch application aborted:** This proposed patch is stale. "
                "The branch has been updated since this patch was generated. "
                "Please wait for the new scan to finish."
            )
            await post_pr_comment(repo_name, pr_number, msg, token)
            if target_sha:
                append_scan_step(target_sha, "gitops", f"Patch application aborted: Stale proposed patch. Branch HEAD ({current_head_sha}) does not match patch base SHA ({base_commit_sha})")
            return

        if target_sha:
            append_scan_step(target_sha, "gitops", "PR verification check passed. Preparing local workspace to apply patch...")

        # 4. Initialize workspace to apply patch (use unique session name to avoid directory collisions)
        workspace_id = f"pr-{pr_number}-{int(time.time())}"
        repo_name = payload.get("repository", {}).get("full_name") or os.getenv("GITHUB_REPOSITORY", "YOUR_ORG/YOUR_REPO")
        git_ws = GitWorkspace(workspace_id, repo=repo_name)
        
        # Clone target branch
        await git_ws.clone_repo(token, branch_name)
        if target_sha:
            append_scan_step(target_sha, "gitops", f"Cloned PR branch '{branch_name}' locally in workspace")

        # 5. Apply the patch
        logger.info(f"Applying git patch to branch '{branch_name}'...")
        patch_branch_name = f"codemender/patch-{base_commit_sha[:8]}" if base_commit_sha else None
        await git_ws.apply_patch(git_diff, patch_branch=patch_branch_name)
        if target_sha:
            append_scan_step(target_sha, "gitops", "Applied proposed security patch changes locally")

        # 6. Commit changes
        logger.info("Committing patch changes...")
        
        pusher_email = BOT_EMAIL
        pusher_name = "CodeMender Agent"
        if target_sha:
            try:
                from database import db
                doc = db.collection("scans").document(target_sha).get()
                if doc.exists:
                    d = doc.to_dict()
                    if d.get("pusher_email"):
                        pusher_email = d.get("pusher_email")
                    if d.get("pusher_name"):
                        pusher_name = d.get("pusher_name")
            except Exception as get_err:
                logger.warning(f"Failed to fetch pusher info from scans doc: {get_err}")
                
        await git_ws._run_command(["git", "config", "user.name", pusher_name])
        await git_ws._run_command(["git", "config", "user.email", pusher_email])
        await git_ws._run_command([
            "git", "commit", "-am", 
            "CodeMender security patch: Applied user approval [skip ci]"
        ])
        if target_sha:
            append_scan_step(target_sha, "gitops", "Committed security patch to branch version history.")

        # 7. Push branch
        logger.info("Pushing patch changes to remote...")
        if os.getenv("MOCK_MODE") == "true":
            await git_ws._run_command(["git", "push", "-f", "origin", branch_name])
        else:
            await git_ws._run_command(["git", "push", "origin", branch_name])
        if target_sha:
            append_scan_step(target_sha, "gitops", "Pushed patch commit to branch remote.")

        # 8. Convert PR to ready and post confirmation
        logger.info("Converting Draft PR to Ready for Review...")
        await convert_draft_pr_to_ready(repo_name, pr_number, token)
        
        success_msg = "✅ **CodeMender security patch successfully applied and pushed to this branch!** Pull Request updated to *Ready for Review*."
        await post_pr_comment(repo_name, pr_number, success_msg, token)

        # 9. Update Firestore & Commit Status Gate
        mark_patch_as_applied(pr_number, commit_sha=base_commit_sha)
        logger.info(f"Successfully completed patch application and cleanup for PR #{pr_number}")
        if target_sha:
            append_scan_step(target_sha, "gitops", f"PR #{pr_number} patch marked as applied. Conversion to Ready for Review complete!")
            try:
                await set_commit_status(
                    repo=repo_name,
                    commit_sha=target_sha,
                    state="success",
                    description="Passed: Security patch applied and approved.",
                    token=token,
                    target_url=f"{os.getenv('DASHBOARD_URL', '')}/scans/{target_sha}" if os.getenv("DASHBOARD_URL") else None
                )
            except Exception as gate_err:
                logger.warning(f"Failed to update commit status gate on patch apply: {gate_err}")

        # 10. Write telemetry directly to BigQuery since the target branch was fast-forward updated
        from datetime import datetime
        try:
            logger.info("Directly triggering telemetry collection for the applied patch...")
            await process_merged_pr_analytics(
                repo_name=repo_name,
                pr_number=pr_number,
                payload={
                    "pull_request": {
                        "merged_at": datetime.utcnow().isoformat() + "Z",
                        "merged_by": {"login": commenter},
                        "base": {"ref": branch_name}
                    }
                }
            )
        except Exception as tel_err:
            logger.error(f"Failed to record direct telemetry for PR #{pr_number}: {tel_err}")

        # Clean up workspace folder
        if git_ws.workspace_path.exists():
            import shutil
            shutil.rmtree(git_ws.workspace_path)

    except Exception as e:
        logger.error(f"Failed to process approval comment: {e}", exc_info=True)
    finally:
        release_lock(lock_id)


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
        
        # 1. Fetch scan document from Firestore linked to this PR
        scans_ref = db.collection("scans")
        query = scans_ref.where("pr_number", "==", pr_number).limit(1)
        docs = query.stream()
        scan_doc = None
        for doc in docs:
            scan_doc = doc
            break
            
        if not scan_doc:
            logger.warning(f"No scan document found for PR #{pr_number}. Cannot compile analytics telemetry.")
            return
            
        scan_data = scan_doc.to_dict()
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
        
    except Exception as ex:
        logger.error(f"Error in process_merged_pr_analytics: {ex}", exc_info=True)


async def verify_findings_task(repo_name: str, commit_sha: str, finding_ids: list[str], is_pr: bool, pr_number: int = None, model: str = None):
    lock_id = f"workspace-{commit_sha}"
    lock_acquired = False
    for _ in range(8):
        if acquire_lock(lock_id):
            lock_acquired = True
            break
        await asyncio.sleep(2)
        
    if not lock_acquired:
        logger.warning(f"Aborting verification task: Lock active for {lock_id} after timeout")
        return
        
    try:
        token = await get_github_token()
        from database import db
        doc_ref = db.collection("scans").document(commit_sha)
        doc = doc_ref.get()
        if not doc.exists:
            msg = "⚠️ CodeMender scan document not found for this commit."
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        scan_data = doc.to_dict()
        findings = scan_data.get("findings", [])
        branch = scan_data.get("branch_name")

        # Parse target IDs (support 'all', specific severity like 'critical'/'high', or specific finding IDs)
        to_verify = []
        target_ids_clean = [f.strip().lower() for f in finding_ids]
        if "all" in target_ids_clean:
            to_verify = findings
        else:
            for f in findings:
                fid = f.get("id", "").lower()
                sev = f.get("severity", "").upper()
                # Match by explicit finding ID or severity substring (CRITICAL, HIGH, MEDIUM, LOW)
                if fid in target_ids_clean or any(t.upper() in sev for t in target_ids_clean if t.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW")):
                    to_verify.append(f)

        if not to_verify:
            msg = f"⚠️ No matching findings found to verify for: {', '.join(finding_ids)}"
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        # Post progress message
        progress_msg = f"<!-- codemender-security-report -->\n⏳ **CodeMender Exploit Verification Started** for finding(s): {', '.join([f.get('id') for f in to_verify])}..."
        try:
            if is_pr and pr_number:
                await update_or_post_pr_comment(repo_name, pr_number, progress_msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, progress_msg, token)
        except Exception as comment_err:
            logger.warning(f"Failed to post initial verification comment to GitHub (continuing verification task): {comment_err}")

        # Mark as VERIFYING
        for f in findings:
            if f.get("id") in [tv.get("id") for tv in to_verify]:
                f["status"] = "VERIFYING"
        update_scan_status(commit_sha, status="RUNNING", message="Verifying exploitability of findings...", findings=findings)

        # Start periodic progress reporting task
        import uuid
        from shared_state import active_tasks
        run_id = str(uuid.uuid4())
        active_tasks[commit_sha] = run_id
        asyncio.create_task(post_periodic_progress(repo_name, commit_sha, pr_number, is_pr, token, task_type="verify", run_id=run_id, findings_count=len(to_verify)))

        await ensure_workspace(commit_sha, branch, repo_name=repo_name)

        results_report = "### 🧪 CodeMender Sandbox Verification Results\n\n"
        results_report += "| Finding ID | Status | Outcome | Confidence |\n"
        results_report += "| --- | --- | --- | --- |\n"

        # Upfront local AST context resolution per unique target file
        cached_local_findings = {}
        for tv in to_verify:
            filepath = tv.get("filepath")
            if filepath and filepath not in cached_local_findings:
                from agents import run_triage_agent
                update_scan_status(commit_sha, status="RUNNING", message=f"Resolving local AST context for {filepath}...")
                append_scan_step(commit_sha, "verify", f"Resolving local AST context for {filepath}...")
                try:
                    cached_local_findings[filepath] = await run_triage_agent(commit_sha, filepath, repo_name=repo_name)
                except Exception as ast_err:
                    logger.warning(f"Failed to resolve local AST findings for {filepath}: {ast_err}")
                    cached_local_findings[filepath] = []
        
        # Map each finding in to_verify to its corresponding local finding ID
        for tv in to_verify:
            fid = tv.get("id")
            filepath = tv.get("filepath")
            vuln_type = str(tv.get("vuln_type") or "").lower()
            cwe_id = str(tv.get("cwe_id") or "").lower()
            local_list = cached_local_findings.get(filepath, [])
            
            matched_local = None
            if local_list:
                # 1. Match by CWE ID if available
                if cwe_id:
                    for lf in local_list:
                        if str(lf.get("cwe_id") or "").lower() == cwe_id:
                            matched_local = lf
                            break
                # 2. Match by substring in vuln_type or title
                if not matched_local and vuln_type:
                    for lf in local_list:
                        lf_type = str(lf.get("vuln_type") or "").lower()
                        lf_title = str(lf.get("title") or "").lower()
                        if vuln_type in lf_type or lf_type in vuln_type or vuln_type in lf_title:
                            matched_local = lf
                            break
                # 3. Fallback: match by external finding ID prefix if present
                if not matched_local:
                    for lf in local_list:
                        if lf.get("id") == fid:
                            matched_local = lf
                            break
                
                if matched_local:
                    tv["local_id"] = matched_local.get("id")
                    logger.info(f"Mapped external finding {fid} ({tv.get('vuln_type')}) -> local finding {tv['local_id']}")
                else:
                    tv["local_id"] = local_list[0].get("id")
                    logger.warning(f"Could not find exact local match for {fid} ({tv.get('vuln_type')}). Falling back to local ID {tv['local_id']}")
            else:
                tv["local_id"] = fid

        async def _verify_single_finding(tv):
            fid = tv.get("id")
            vuln_type = tv.get("vuln_type")
            local_finding_id = tv.get("local_id") or fid
            try:
                update_scan_status(commit_sha, status="RUNNING", message=f"Executing sandbox exploit simulation for {vuln_type or fid} (cm verify)...")
                append_scan_step(commit_sha, "verify", f"Executing sandbox exploit simulation for {fid} ({vuln_type or 'vulnerability'})...")
                verify_out = await cm_verify(commit_sha, local_finding_id, model=model)
                
                # Upload verification artifacts to GCS
                workspace_path = f"/tmp/session-{commit_sha}"
                uploaded_arts = await upload_verification_artifacts(commit_sha, workspace_path, fid)
                
                # Extract exploit confidence & status from .exploit/info.yaml
                confidence = "100%"
                is_verified = False
                info_path = Path(workspace_path) / ".exploit" / "info.yaml"
                report_path = Path(workspace_path) / ".exploit" / "REPORT.md"
                log_path = Path(workspace_path) / ".exploit" / "LOG.md"
                
                if info_path.exists():
                    try:
                        info_content = info_path.read_text(encoding="utf-8")
                        status_val = str(parse_yaml_value(info_content, "status")).strip().lower()
                        extracted = parse_yaml_value(info_content, "confidence")
                        confidence = clean_confidence(extracted)
                        if status_val in ("valid", "verified", "confirmed", "true") or confidence in ("certain", "likely", "100%", "high"):
                            is_verified = True
                    except Exception as parse_err:
                        logger.warning(f"Failed to parse info.yaml: {parse_err}")
                
                if not is_verified and report_path.exists():
                    is_verified = True
                    
                if not is_verified and log_path.exists():
                    try:
                        log_txt = log_path.read_text(encoding="utf-8").lower()
                        if "successfully ran" in log_txt or "confirmed" in log_txt:
                            is_verified = True
                    except Exception:
                        pass
                        
                if not is_verified and verify_out:
                    is_verified = any(kw in verify_out for kw in ["EXPLOIT SUCCESSFUL", "Exploit confirmed", "confirmed", "status: valid", "valid"])
                
                # Report priority: 1. CodeMender sandbox REPORT.md, 2. AI synthesized exploit report
                if report_path.exists():
                    try:
                        exploit_report = report_path.read_text(encoding="utf-8")
                    except Exception:
                        from agents import generate_ai_exploit_report
                        exploit_report = generate_ai_exploit_report(verify_out, session_id=commit_sha, repo_name=repo_name)
                else:
                    from agents import generate_ai_exploit_report
                    exploit_report = generate_ai_exploit_report(verify_out, session_id=commit_sha, repo_name=repo_name)
                
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
                    detail += "\n<details>\n"
                    detail += "<summary>📋 View Raw CodeMender Verification Console Output</summary>\n\n"
                    detail += f"```text\n{verify_out}\n```\n"
                    detail += "</details>\n"
                
                return table_row, detail
            except Exception as ex:
                logger.error(f"Verification failed for {fid}: {ex}")
                for f in findings:
                    if f.get("id") == fid:
                        f["status"] = "VERIFICATION_FAILED"
                table_row = f"| `{fid}` | ❌ **FAILED** | Verification run encountered error. | - |\n"
                err_detail = f"\n### ❌ Verification Error for `{fid}`\n```text\n{ex}\n```\n"
                return table_row, err_detail

        # ========================================================
        # ROUTING GATE: PARALLEL EXECUTION vs. SINGLE FINDING
        # ========================================================
        if len(to_verify) > 1:
            logger.info(f"Running parallel verification across {len(to_verify)} findings (bounded concurrency limit: 2)...")
            sem = asyncio.Semaphore(2)
            async def _bounded_verify(tv):
                async with sem:
                    return await _verify_single_finding(tv)
            results = await asyncio.gather(*[_bounded_verify(tv) for tv in to_verify])
            for table_row, detail in results:
                results_report += table_row
                detail_blocks.append(detail)
        else:
            logger.info("Running single finding verification...")
            table_row, detail = await _verify_single_finding(to_verify[0])
            results_report += table_row
            detail_blocks.append(detail)

        # Append all detail blocks after the table
        if detail_blocks:
            results_report += "\n---\n" + "\n".join(detail_blocks)

        update_scan_status(commit_sha, status="COMPLETED", message="Exploit verification run finished", findings=findings)
        
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch,
                event_type="issue_comment" if is_pr else "commit_comment",
                status="COMPLETED",
                target_file=None,
                findings_count=len(findings),
                findings=findings,
                action_taken="verify"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log verify summary to BigQuery: {bq_log_err}")
        
        # Post results in-place on PR comment
        sanitized_report = sanitize_comment_length(results_report)
        if is_pr and pr_number:
            sticky_final = f"<!-- codemender-security-report -->\n{sanitized_report}\n\n💡 *Reply `/fix all` or `/fix [finding-id]` to generate automated AST remediation patches.*"
            await update_or_post_pr_comment(repo_name, pr_number, sticky_final, token)
        else:
            await post_commit_comment(repo_name, commit_sha, sanitized_report, token)

    except Exception as e:
        logger.error(f"Error in verify_findings_task: {e}", exc_info=True)
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch if 'branch' in locals() else "unknown",
                event_type="issue_comment" if is_pr else "commit_comment",
                status="FAILED",
                target_file=None,
                findings_count=0,
                findings=[],
                action_taken="verify"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log failed verify summary to BigQuery: {bq_log_err}")
    finally:
        release_lock(lock_id)


async def fix_findings_task(repo_name: str, commit_sha: str, finding_ids: list[str], is_pr: bool, pr_number: int = None, model: str = None):
    lock_id = f"workspace-{commit_sha}"
    lock_acquired = False
    for _ in range(8):
        if acquire_lock(lock_id):
            lock_acquired = True
            break
        await asyncio.sleep(2)
        
    if not lock_acquired:
        logger.warning(f"Aborting fix task: Lock active for {lock_id} after timeout")
        return
        
    try:
        token = await get_github_token()
        from database import db
        doc_ref = db.collection("scans").document(commit_sha)
        doc = doc_ref.get()
        if not doc.exists:
            msg = "⚠️ CodeMender scan document not found for this commit."
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        scan_data = doc.to_dict()
        findings = scan_data.get("findings", [])
        branch = scan_data.get("branch_name")

        # Filter target findings (support 'all', specific severity like 'critical'/'high', or specific finding IDs)
        to_fix = []
        target_ids_clean = [f.strip().lower() for f in finding_ids]
        if "all" in target_ids_clean:
            to_fix = findings
        else:
            for f in findings:
                fid = f.get("id", "").lower()
                sev = f.get("severity", "").upper()
                # Match by explicit finding ID or severity substring (CRITICAL, HIGH, MEDIUM, LOW)
                if fid in target_ids_clean or any(t.upper() in sev for t in target_ids_clean if t.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW")):
                    to_fix.append(f)

        if not to_fix:
            msg = f"⚠️ No matching findings found to fix for: {', '.join(finding_ids)}"
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, msg, token)
            return

        progress_msg = f"<!-- codemender-security-report -->\n⏳ **CodeMender Patch Generation Started** for finding(s): {', '.join([f.get('id') for f in to_fix])}..."
        try:
            if is_pr and pr_number:
                await update_or_post_pr_comment(repo_name, pr_number, progress_msg, token)
            else:
                await post_commit_comment(repo_name, commit_sha, progress_msg, token)
        except Exception as comment_err:
            logger.warning(f"Failed to post initial patch progress comment to GitHub (continuing fix task): {comment_err}")

        # Mark as PATCHING
        for f in findings:
            if f.get("id") in [tf.get("id") for tf in to_fix]:
                f["status"] = "PATCHING"
        update_scan_status(commit_sha, status="RUNNING", message="Generating fixes for findings...", findings=findings)

        # Start periodic progress reporting task
        import uuid
        from shared_state import active_tasks
        run_id = str(uuid.uuid4())
        active_tasks[commit_sha] = run_id
        asyncio.create_task(post_periodic_progress(repo_name, commit_sha, pr_number, is_pr, token, task_type="patch", run_id=run_id, findings_count=len(to_fix)))

        # Ensure local checkout is ready
        await ensure_workspace(commit_sha, branch, repo_name=repo_name)
        
        workspace_path = f"/tmp/session-{commit_sha}"
        
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
        
        # Retrieve pusher details from scan doc to sign manual fixes with CLA-compliant identity
        pusher_email = "agent@codemender.ai"
        pusher_name = "CodeMender Agent"
        try:
            from database import db
            doc = db.collection("scans").document(commit_sha).get()
            if doc.exists:
                d = doc.to_dict()
                if d.get("pusher_email"):
                    pusher_email = d.get("pusher_email")
                if d.get("pusher_name"):
                    pusher_name = d.get("pusher_name")
        except Exception as get_err:
            logger.warning(f"Failed to fetch pusher info from scans doc: {get_err}")
            
        await git_ws._run_command(["git", "config", "user.name", pusher_name])
        await git_ws._run_command(["git", "config", "user.email", pusher_email])

        results = []
        cached_local_findings = {}

        # Apply fixes sequentially
        for tf in to_fix:
            fid = tf.get("id")
            target_filepath = tf.get("filepath")
            target_vuln_type = tf.get("vuln_type")
            
            try:
                # Rebuild local database and map finding ID (cached per file across the batch)
                from agents import run_triage_agent
                if target_filepath not in cached_local_findings:
                    append_scan_step(commit_sha, "find", f"Indexing code database for {target_filepath} to map findings...")
                    cached_local_findings[target_filepath] = await run_triage_agent(commit_sha, target_filepath, repo_name=repo_name)
                
                local_findings = cached_local_findings.get(target_filepath)
                
                target_cwe = tf.get("cwe_id", "")
                target_vuln_type = tf.get("vuln_type", "")
                target_title = tf.get("title", "")
                
                local_finding_id = fid
                if local_findings:
                    matched_local = None
                    for lf in local_findings:
                        # 1. Exact or substring CWE match (e.g. CWE-89, CWE-78)
                        if target_cwe and lf.get("cwe_id") and (target_cwe in lf.get("cwe_id") or lf.get("cwe_id") in target_cwe):
                            matched_local = lf
                            break
                        # 2. Case-insensitive substring match on vuln_type / title
                        if target_vuln_type and lf.get("vuln_type") and (target_vuln_type.lower() in lf.get("vuln_type").lower() or lf.get("vuln_type").lower() in target_vuln_type.lower()):
                            matched_local = lf
                            break
                        if target_title and lf.get("title") and (target_title.lower() in lf.get("title").lower() or lf.get("title").lower() in target_title.lower()):
                            matched_local = lf
                            break
                    if matched_local:
                        local_finding_id = matched_local.get("id")
                        logger.info(f"Mapped external finding ID {fid} ({target_cwe} - {target_vuln_type}) to local finding ID {local_finding_id}")
                    else:
                        local_finding_id = local_findings[0].get("id")
                        logger.warning(f"Could not find matching local finding for {target_vuln_type}. Falling back to first local finding ID {local_finding_id}")
                else:
                    logger.warning(f"No local findings found for {target_filepath}. Falling back to external finding ID {fid}")
                
                append_scan_step(commit_sha, "fix", f"Executing CodeMender fix engine (cm fix {local_finding_id} -y)...")
                from cm_tools import _run_cm_cmd, resolve_model
                selected_model = resolve_model("fix", model, commit_sha)
                fix_cmd = ["cm", "fix", local_finding_id, "-y", "--bypass-warning", "--model", selected_model]
                await _run_cm_cmd(fix_cmd, commit_sha)
                
                await git_ws._run_command(["git", "add", "-A"])
                process_status = await asyncio.create_subprocess_exec(
                    "git", "status", "--porcelain",
                    stdout=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                status_out, _ = await process_status.communicate()
                
                if status_out.decode().strip():
                    await git_ws._run_command(["git", "commit", "-m", f"CodeMender: Fix vulnerability {fid} [skip ci]"])
                    results.append((fid, True, "Successfully applied fix"))
                else:
                    results.append((fid, False, "No changes made by fix engine"))
            except Exception as fix_ex:
                logger.error(f"Fix failed for {fid}: {fix_ex}")
                results.append((fid, False, str(fix_ex)))

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
            return

        # Push branch
        await git_ws._run_command(["git", "push", "-f", "origin", patch_branch])

        # Get total diff
        diff_proc = await asyncio.create_subprocess_exec(
            "git", "diff", f"origin/{branch}..{patch_branch}",
            stdout=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        diff_out, _ = await diff_proc.communicate()
        total_diff = diff_out.decode().strip()

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
            "git", "diff", "--name-only", f"origin/{branch}..{patch_branch}",
            stdout=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        files_out, _ = await changed_files_proc.communicate()
        changed_files = files_out.decode().strip().splitlines()
        filename = changed_files[0] if changed_files else "unknown"
        
        patched_code = ""
        patched_file_path = Path(workspace_path) / filename
        if patched_file_path.exists():
            patched_code = patched_file_path.read_text(encoding="utf-8")

        # Get the actual patch commit SHA we just pushed
        patch_commit_sha_proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        sha_out, _ = await patch_commit_sha_proc.communicate()
        patch_commit_sha = sha_out.decode().strip()
        logger.info(f"Retrieved actual patch commit SHA: {patch_commit_sha}")

        # Determine the target PR number (prefer parent PR number if operating on a PR)
        effective_pr_num = pr_number if (is_pr and pr_number) else pr_num

        save_patch_proposal(
            commit_sha=commit_sha,
            branch_name=branch,
            filename=filename,
            git_diff=total_diff,
            patched_code=patched_code,
            pr_number=effective_pr_num,
            patch_commit_sha=patch_commit_sha
        )
        if effective_pr_num:
            update_scan_status(commit_sha, pr_number=effective_pr_num)

        for r in results:
            fid, success, msg = r
            for f in findings:
                if f.get("id") == fid:
                    f["status"] = "PATCHED" if success else "PATCH_FAILED"
        
        if effective_pr_num:
            update_scan_status(commit_sha, status="COMPLETED", message="Patches generated and PR updated", findings=findings)
        else:
            update_scan_status(commit_sha, status="COMPLETED", message="Patches generated and staged on branch", findings=findings)
            
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch,
                event_type="issue_comment" if is_pr else "commit_comment",
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

        if is_pr and pr_number:
            outcome_report = f"### 🛡️ CodeMender Proposed Security Patch\n\n"
            outcome_report += f"Successfully generated proposed fix(es) for finding(s): {', '.join([f'`{fid}`' for fid, success, _ in successful_fixes])}.\n\n"
            if reports_md:
                outcome_report += reports_md
            outcome_report += f"\n<details open>\n<summary><b>🔍 Preview Proposed Code Diff</b></summary>\n\n```diff\n{total_diff}\n```\n</details>\n\n"
            outcome_report += "👉 **Reply with `/approve` on this Pull Request to automatically commit these changes directly to your branch and mark the PR Ready for Review!**\n"
        elif pr_num:
            outcome_report = f"### 🛡️ CodeMender Patches Generated!\n\n"
            outcome_report += f"Successfully created proposed fix(es) and updated the Pull Request!\n\n"
            outcome_report += f"👉 **[Draft Pull Request #{pr_num}]({pr_url})**\n\n"
            if reports_md:
                outcome_report += reports_md
            outcome_report += f"\n<details>\n<summary><b>🔍 Preview Proposed Code Diff</b></summary>\n\n```diff\n{total_diff}\n```\n</details>\n"
            outcome_report += "\nPlease review the diff on the PR and comment `/approve` there to merge."
        else:
            outcome_report = f"### 🛡️ CodeMender Patch Staged on Branch `{patch_branch}`!\n\n"
            outcome_report += f"Successfully generated proposed fix(es) for finding(s): {', '.join([f'`{fid}`' for fid, success, _ in successful_fixes])}.\n\n"
            if reports_md:
                outcome_report += reports_md
            outcome_report += f"\n<details>\n<summary><b>🔍 Preview Proposed Code Diff</b></summary>\n\n```diff\n{total_diff}\n```\n</details>\n"
            outcome_report += "#### ⚡ Next Steps:\n"
            outcome_report += f"* To patch additional findings on this branch, reply here with `/fix <finding_id>`.\n"
            outcome_report += f"* When you are ready to review the changes on GitHub, reply here with `/draft` to open the Draft Pull Request.\n"

        sanitized_outcome = sanitize_comment_length(outcome_report)
        if is_pr and pr_number:
            sticky_outcome = f"<!-- codemender-security-report -->\n{sanitized_outcome}"
            await update_or_post_pr_comment(repo_name, pr_number, sticky_outcome, token)
        else:
            await post_commit_comment(repo_name, commit_sha, sanitized_outcome, token)

    except Exception as ex:
        logger.error(f"Error in fix_findings_task: {ex}", exc_info=True)
        try:
            from database import log_scan_summary
            log_scan_summary(
                commit_sha=commit_sha,
                repo_name=repo_name,
                branch_name=branch if 'branch' in locals() else "unknown",
                event_type="issue_comment" if is_pr else "commit_comment",
                status="FAILED",
                target_file=None,
                findings_count=0,
                findings=[],
                action_taken="fix"
            )
        except Exception as bq_log_err:
            logger.error(f"Failed to log failed fix summary to BigQuery: {bq_log_err}")
    finally:
        release_lock(lock_id)


async def dismiss_findings_task(
    repo_name: str,
    commit_sha: str = None,
    target_ids: list[str] = None,
    reason: str = "Risk accepted by pull request reviewer",
    category: str = "FALSE_POSITIVE",
    actor: str = "Developer",
    is_pr: bool = False,
    pr_number: int = None
):
    """Marks specified findings as DISMISSED in Firestore and streams an audit record to BigQuery."""
    from database import db, insert_analytics_finding_dismissed
    from datetime import datetime, timezone
    
    token = await get_github_token()
    if not commit_sha and is_pr and pr_number:
        try:
            commit_sha = await get_pr_head_sha(repo_name, pr_number, token)
        except Exception:
            from database import get_patch_proposal
            proposal = get_patch_proposal(pr_number)
            if proposal:
                commit_sha = proposal.get("commit_sha")

    if not commit_sha:
        logger.warning("Could not determine commit_sha for dismiss_findings_task.")
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, "⚠️ CodeMender could not determine the head commit SHA for this Pull Request.", token)
        return

    logger.info(f"Starting dismiss_findings_task for commit {commit_sha}, target_ids={target_ids}, actor={actor}, category={category}")
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        logger.warning(f"Scan document for {commit_sha} not found in Firestore.")
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, f"⚠️ CodeMender could not find scan records for commit `{commit_sha[:8]}`.", token)
        return
        
    data = doc.to_dict()
    findings = data.get("findings", [])
    
    target_list = [t.lower() for t in (target_ids or [])]
    dismissed_items = []
    
    for f in findings:
        fid = f.get("id", "")
        sev = f.get("severity", "").lower()
        if "all" in target_list or fid.lower() in target_list or sev in target_list:
            f["status"] = "DISMISSED"
            f["dismissal"] = {
                "dismissed_by": actor,
                "dismissed_at": datetime.now(timezone.utc).isoformat(),
                "category": category,
                "reason": reason
            }
            dismissed_items.append(f)
            
            try:
                insert_analytics_finding_dismissed({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "repo_name": repo_name,
                    "pr_number": pr_number,
                    "commit_sha": commit_sha,
                    "finding_id": fid,
                    "vuln_type": f.get("vuln_type", "Unknown"),
                    "severity": str(f.get("severity", "HIGH")).upper(),
                    "dismissed_by": actor,
                    "category": category,
                    "reason": reason
                })
            except Exception as bq_err:
                logger.warning(f"BigQuery dismissal audit log failed: {bq_err}")

    if not dismissed_items:
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, f"⚠️ None of the target finding ID(s) `{', '.join(target_list)}` were found in scan `{commit_sha[:8]}`.", token)
        return

    # Update Firestore
    doc_ref.update({"findings": findings})
    append_scan_step(commit_sha, "governance", f"Dismissed finding(s): {', '.join([d['id'] for d in dismissed_items])} by @{actor} with category [{category}].")

    # Re-evaluate active critical findings
    active_criticals = [
        f for f in findings 
        if "CRITICAL" in str(f.get("severity", "")).upper() and f.get("status") not in ["FIXED", "DISMISSED"]
    ]
    dismissed_criticals = [
        f for f in findings 
        if "CRITICAL" in str(f.get("severity", "")).upper() and f.get("status") == "DISMISSED"
    ]
    
    # Update GitHub Commit Status check
    if len(active_criticals) == 0:
        desc = f"Gate Passed: All critical findings resolved or approved via risk acceptance ({len(dismissed_criticals)} dismissed)."
        await set_commit_status(repo_name, commit_sha, state="success", description=desc, token=token)
        gate_status_line = "🟢 **PASSED (Merge Gate Unlocked)**"
    else:
        desc = f"Merge Blocked: {len(active_criticals)} active criticals remain ({len(dismissed_criticals)} dismissed)."
        await set_commit_status(repo_name, commit_sha, state="failure", description=desc, token=token)
        gate_status_line = f"🔴 **BLOCKED ({len(active_criticals)} Active Critical Vulnerabilities Remain)**"

    # Post PR Audit Comment
    if is_pr and pr_number:
        comment = "### 🟡 CodeMender Finding(s) Dismissed / Risk Accepted\n\n"
        comment += "The following finding(s) have been manually acknowledged and marked as **DISMISSED** with documented risk acceptance:\n\n"
        comment += "| Finding ID | Severity | Category | Dismissed By | Reason |\n"
        comment += "| --- | --- | --- | --- | --- |\n"
        for item in dismissed_items:
            raw_sev = str(item.get("severity", "HIGH")).upper()
            sev_emoji = "🔴" if "CRITICAL" in raw_sev else "🟠"
            comment += f"| `{item.get('id')}` | {sev_emoji} **{raw_sev}** | `{category}` | @{actor} | {reason} |\n"
        
        comment += "\n---\n\n"
        comment += f"#### 🚦 Security Gate Status:\n"
        comment += f"- **Active Criticals Pending:** {len(active_criticals)}\n"
        comment += f"- **Dismissed / Risk-Accepted Criticals:** {len(dismissed_criticals)}\n"
        comment += f"- **Branch Merge Gate (`security/codemender-gate`):** {gate_status_line}\n"
        
        if len(active_criticals) == 0:
            comment += "\n✨ *All critical findings have been resolved or authorized for merge under documented exemption.*"
            
        await post_pr_comment(repo_name, pr_number, comment, token)


async def process_comment_command_task(repo_name: str, command: str, target_ids: list[str], is_pr: bool, pr_number: int = None, commit_sha: str = None, model: str = None):
    try:
        token = await get_github_token()
        if is_pr and pr_number:
            try:
                commit_sha = await get_pr_head_sha(repo_name, pr_number, token)
            except Exception:
                from database import get_patch_proposal
                proposal = get_patch_proposal(pr_number)
                if proposal:
                    commit_sha = proposal.get("commit_sha")
                    
            if not commit_sha:
                msg = "⚠️ CodeMender could not determine the head commit SHA for this Pull Request branch."
                await post_pr_comment(repo_name, pr_number, msg, token)
                return

        if command == "verify":
            await verify_findings_task(repo_name, commit_sha, target_ids, is_pr, pr_number, model=model)
        elif command == "fix":
            await fix_findings_task(repo_name, commit_sha, target_ids, is_pr, pr_number, model=model)
            
    except Exception as err:
        logger.error(f"Error in process_comment_command_task: {err}", exc_info=True)


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
    if headers.get("X-CodeMender-Auth") == "WIF":
        logger.info("Signature verification bypassed: Authenticated via WIF.")
    elif WEBHOOK_SECRET:
        signature = headers.get("X-Hub-Signature-256", "")
        if not verify_signature(raw_body, signature, WEBHOOK_SECRET):
            logger.warning("Rejecting webhook: Invalid payload signature.")
            return Response(content="Invalid signature", status_code=401)
            
    # 2. Extract Event Type
    event_type = headers.get("X-GitHub-Event", "")
    
    try:
        import json
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to parse JSON payload: {e}")
        return Response(content="Invalid JSON", status_code=400)

    # 3. Route Pushes (Decommissioned in favor of PR-triggered scans)
    if event_type == "push":
        ref = payload.get("ref", "")
        # Scans are now Pull Request-triggered (Draft / Open). Raw branch pushes are ignored to eliminate noise & token waste.
        logger.info(f"Ignoring raw branch push to {ref}. Security scans are initiated on Pull Request creation and sync.")
        return Response(content="Push event ignored; PR-triggered scans active", status_code=200)

    # 4. Route PR Events (opened, reopened, synchronize, ready_for_review)
    elif event_type == "pull_request":
        action = payload.get("action")
        pr_number = payload.get("number")
        pr_data = payload.get("pull_request", {})
        head_sha = pr_data.get("head", {}).get("sha")
        branch = pr_data.get("head", {}).get("ref")
        base_branch = pr_data.get("base", {}).get("ref", "main")
        is_draft = pr_data.get("draft", False)
        pr_title = pr_data.get("title", "")
        pr_url = pr_data.get("html_url", "")
        repo_name = payload.get("repository", {}).get("full_name")
        pusher = pr_data.get("user", {}).get("login", "developer")
        
        if action in ["opened", "reopened", "synchronize", "ready_for_review"]:
            logger.info(f"Processing PR event '{action}' for {'Draft ' if is_draft else ''}PR #{pr_number} (Branch: {branch}, Head SHA: {head_sha})")
            if head_sha:
                update_scan_status(
                    head_sha,
                    branch_name=branch,
                    repo_name=repo_name,
                    status="QUEUED",
                    message=f"Queuing security scan for {'Draft ' if is_draft else ''}PR #{pr_number}",
                    pr_number=pr_number,
                    is_draft=is_draft,
                    pr_title=pr_title,
                    pr_url=pr_url,
                    base_branch=base_branch,
                    pusher_name=pusher
                )
            background_tasks.add_task(process_pr_scan_event, payload)
            logger.info(f"Enqueued PR scan worker task for PR #{pr_number}.")
            return Response(content=f"Accepted pull_request event ({action})", status_code=202)
        else:
            logger.info(f"Ignoring unsupported PR action: '{action}' for PR #{pr_number}")
            return Response(content=f"PR action '{action}' ignored", status_code=200)

    # 5. Route PR Comments (/approve, /verify, /fix triggers)
    elif event_type == "issue_comment":
        action = payload.get("action")
        comment_body = payload.get("comment", {}).get("body", "").strip()
        
        if action == "created":
            if comment_body == "/approve":
                if "pull_request" in payload.get("issue", {}):
                    background_tasks.add_task(process_approve_comment, payload)
                    logger.info("Enqueued approval comment worker task.")
                    return Response(content="Accepted approval comment", status_code=202)
            
            elif comment_body.startswith("/verify"):
                parts = comment_body.split()
                if len(parts) > 1:
                    target_ids = [p.strip(",.;") for p in parts[1:]]
                    pr_number = payload.get("issue", {}).get("number")
                    repo_name = payload.get("repository", {}).get("full_name")
                    background_tasks.add_task(
                        process_comment_command_task,
                        repo_name=repo_name,
                        command="verify",
                        target_ids=target_ids,
                        is_pr=True,
                        pr_number=pr_number
                    )
                    logger.info(f"Enqueued verify command worker task for PR #{pr_number}.")
                    return Response(content="Accepted verify command", status_code=202)
                    
            elif comment_body.startswith("/fix"):
                parts = comment_body.split()
                if len(parts) > 1:
                    target_ids = [p.strip(",.;") for p in parts[1:]]
                    pr_number = payload.get("issue", {}).get("number")
                    repo_name = payload.get("repository", {}).get("full_name")
                    background_tasks.add_task(
                        process_comment_command_task,
                        repo_name=repo_name,
                        command="fix",
                        target_ids=target_ids,
                        is_pr=True,
                        pr_number=pr_number
                    )
                    logger.info(f"Enqueued fix command worker task for PR #{pr_number}.")
                    return Response(content="Accepted fix command", status_code=202)

            elif comment_body in ("/cancel", "/reset"):
                pr_number = payload.get("issue", {}).get("number")
                repo_name = payload.get("repository", {}).get("full_name")
                token = get_github_token()
                try:
                    pr_info = await get_pr_info(repo_name, pr_number, token)
                    head_sha = pr_info.get("head", {}).get("sha")
                    if head_sha:
                        from shared_state import active_tasks
                        active_tasks[head_sha] = "CANCELLED"
                        update_scan_status(head_sha, status="FAILED", message="Task cancelled via /cancel PR comment.")
                        release_lock(f"workspace-{head_sha}")
                        await post_pr_comment(repo_name, pr_number, "🛑 **CodeMender Task Cancelled** — Workspace lock released and all operations stopped.", token)
                except Exception as cancel_err:
                    logger.warning(f"Error handling /cancel command on PR #{pr_number}: {cancel_err}")
                return Response(content="Accepted cancel command", status_code=202)

            elif comment_body.startswith("/dismiss") or comment_body.startswith("/override"):
                import re
                parts = comment_body.split(maxsplit=2)
                if len(parts) > 1:
                    target_ids = [parts[1].strip(",.;")]
                    remainder = parts[2].strip() if len(parts) > 2 else ""
                    category = "FALSE_POSITIVE"
                    reason = remainder
                    
                    cat_match = re.match(r"^\[([A-Za-z0-9_]+)\]\s*(.*)", remainder)
                    if cat_match:
                        category = cat_match.group(1).upper()
                        reason = cat_match.group(2).strip()
                        
                    if not reason:
                        reason = "Risk accepted by pull request reviewer."
                        
                    pr_number = payload.get("issue", {}).get("number")
                    repo_name = payload.get("repository", {}).get("full_name")
                    actor = payload.get("comment", {}).get("user", {}).get("login", "Developer")
                    
                    background_tasks.add_task(
                        dismiss_findings_task,
                        repo_name=repo_name,
                        commit_sha=None,
                        target_ids=target_ids,
                        reason=reason,
                        category=category,
                        actor=actor,
                        is_pr=True,
                        pr_number=pr_number
                    )
                    logger.info(f"Enqueued dismiss command worker task for PR #{pr_number}, finding {target_ids}.")
                    return Response(content="Accepted dismiss command", status_code=202)

            elif comment_body in ("/draft", "/pr"):
                pr_number = payload.get("issue", {}).get("number")
                repo_name = payload.get("repository", {}).get("full_name")
                token = await get_github_token()
                head_sha = None
                try:
                    head_sha = await get_pr_head_sha(repo_name, pr_number, token)
                except Exception:
                    from database import get_patch_proposal
                    proposal = get_patch_proposal(pr_number)
                    if proposal:
                        head_sha = proposal.get("commit_sha")
                
                if head_sha:
                    background_tasks.add_task(
                        create_draft_pr_task,
                        repo_name=repo_name,
                        commit_sha=head_sha,
                        is_pr=True,
                        pr_number=pr_number
                    )
                    logger.info(f"Enqueued Draft PR creation worker task for PR #{pr_number} (commit {head_sha}).")
                    return Response(content="Accepted PR draft command", status_code=202)
                else:
                    msg = "⚠️ CodeMender could not determine the head commit SHA for this Pull Request."
                    await post_pr_comment(repo_name, pr_number, msg, token)
                    return Response(content="Missing head SHA", status_code=400)
                
        return Response(content="Comment event ignored", status_code=200)

    # 5. Route Commit Comments (/verify, /fix, /draft, /dismiss triggers)
    elif event_type == "commit_comment":
        action = payload.get("action")
        comment_body = payload.get("comment", {}).get("body", "").strip()
        commit_sha = payload.get("comment", {}).get("commit_id")
        repo_name = payload.get("repository", {}).get("full_name")
        
        if action == "created" and commit_sha:
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
                import re
                parts = comment_body.split(maxsplit=2)
                if len(parts) > 1:
                    target_ids = [parts[1].strip(",.;")]
                    remainder = parts[2].strip() if len(parts) > 2 else ""
                    category = "FALSE_POSITIVE"
                    reason = remainder
                    cat_match = re.match(r"^\[([A-Za-z0-9_]+)\]\s*(.*)", remainder)
                    if cat_match:
                        category = cat_match.group(1).upper()
                        reason = cat_match.group(2).strip()
                    if not reason:
                        reason = "Risk accepted by commit reviewer."
                    actor = payload.get("comment", {}).get("user", {}).get("login", "Developer")
                    background_tasks.add_task(
                        dismiss_findings_task,
                        repo_name=repo_name,
                        commit_sha=commit_sha,
                        target_ids=target_ids,
                        reason=reason,
                        category=category,
                        actor=actor,
                        is_pr=False
                    )
                    logger.info(f"Enqueued commit dismiss command for commit {commit_sha}, finding {target_ids}.")
                    return Response(content="Accepted commit dismiss command", status_code=202)

            elif comment_body == "/draft" or comment_body == "/pr":
                background_tasks.add_task(
                    create_draft_pr_task,
                    repo_name=repo_name,
                    commit_sha=commit_sha
                )
                logger.info(f"Enqueued manual Draft PR creation worker task for commit {commit_sha}.")
                return Response(content="Accepted commit draft command", status_code=202)
                
        return Response(content="Commit comment event ignored", status_code=200)

    # 6. Route Pull Request Closed/Merged Events (Analytics Streaming)
    elif event_type == "pull_request":
        action = payload.get("action")
        pr = payload.get("pull_request", {})
        merged = pr.get("merged", False)
        
        if action == "closed" and merged:
            pr_number = payload.get("number")
            repo_name = payload.get("repository", {}).get("full_name")
            background_tasks.add_task(
                process_merged_pr_analytics,
                repo_name=repo_name,
                pr_number=pr_number,
                payload=payload
            )
            logger.info(f"Enqueued merged PR analytics task for PR #{pr_number}.")
            return Response(content="Accepted merged PR event", status_code=202)
            
        return Response(content="PR event ignored", status_code=200)

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

@app.post("/api/unlock/{commit_sha}")
async def api_unlock_workspace(commit_sha: str):
    """Releases the workspace lock for a scan session."""
    release_lock(f"workspace-{commit_sha}")
    return {"status": "success", "message": f"Lock released for {commit_sha}"}

@app.post("/api/scans/{commit_sha}/cancel")
async def api_cancel_scan(commit_sha: str):
    """API endpoint to cancel a running scan or verification session."""
    from shared_state import active_tasks
    from database import update_scan_status, append_scan_step, release_lock
    
    release_lock(f"workspace-{commit_sha}")
    
    # 1. Check if the task is actively running in memory
    run_id = active_tasks.get(commit_sha)
    if not run_id:
        # Fallback: Update status to FAILED in Firestore anyway to unlock UI
        update_scan_status(commit_sha, status="FAILED", message="Scan session terminated by user.")
        return {"status": "success", "message": "Scan state updated to failed (no active thread found)."}
        
    # 2. Cancel active loop tracking entry
    active_tasks.pop(commit_sha, None)
    
    # Update status to FAILED in Firestore
    update_scan_status(commit_sha, status="FAILED", message="Scan session cancelled by user.")
    append_scan_step(commit_sha, "info", "Scan task execution cancelled by administrator.")
    
    return {"status": "success", "message": "Scan session cancelled successfully."}


@app.get("/api/analytics/tokens")
async def api_analytics_tokens(range_days: int = 7, start_date: str = None, end_date: str = None):
    """API endpoint to query aggregated token usage and cost metrics from BigQuery."""
    return get_token_analytics(range_days=range_days, start_date=start_date, end_date=end_date)


@app.post("/api/analytics/chat")
async def api_analytics_chat(payload: dict):
    """API endpoint to chat with the BigQuery Analytics agent."""
    from analytics_agent.agent import chat_with_analytics_agent
    message = payload.get("message", "")
    if not message:
        return {"error": "Message parameter is required"}
    response = await chat_with_analytics_agent(message)
    return {"response": response}


async def ensure_workspace(commit_sha: str, branch: str, repo_name: str = None):
    """Ensures that the git repository is checked out locally on the active container filesystem."""
    from git_manager import GitWorkspace
    import os
    import subprocess
    
    # 1. Initialize CodeMender globally if running on a new instance
    codemender_path = os.path.expanduser("~/.codemender")
    if not os.path.exists(codemender_path):
        logger.info("CodeMender configuration path not found. Initializing 'cm init'...")
        subprocess.run(["cm", "init"], input=b"n\n", check=True)
        ensure_codemender_config()
        
    # 2. Restore state database from GCS (if exists)
    try:
        from gcs_helpers import download_state_database
        download_state_database(commit_sha)
    except Exception as db_err:
        logger.error(f"Failed to restore state database from GCS: {db_err}")
        
    # 3. Restore repository workspace
    workspace_path = f"/tmp/session-{commit_sha}"
    if not os.path.exists(workspace_path):
        logger.info(f"Workspace path {workspace_path} not found. Cloning repo {repo_name or 'default'} branch {branch}...")
        token = await get_github_token()
        git_ws = GitWorkspace(commit_sha, repo=repo_name)
        await git_ws.clone_repo(token, branch)
        logger.info(f"Workspace successfully restored for session {commit_sha}.")
    else:
        logger.info(f"Workspace path {workspace_path} already exists. Resetting to clean state...")
        try:
            subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=workspace_path, check=True)
            subprocess.run(["git", "clean", "-fd"], cwd=workspace_path, check=True)
            logger.info(f"Checking out target branch {branch} in existing workspace...")
            subprocess.run(["git", "checkout", branch], cwd=workspace_path, check=True)
            try:
                subprocess.run(["git", "pull", "origin", branch], cwd=workspace_path, check=True)
            except Exception as pull_err:
                logger.warning(f"Failed to pull latest changes for branch {branch}: {pull_err}")
            logger.info(f"Workspace successfully reset and switched to branch {branch}.")
        except Exception as reset_err:
            logger.error(f"Failed to reset/checkout target branch in workspace {workspace_path}: {reset_err}")



@app.post("/api/scans/{commit_sha}/unlock")
async def api_unlock_scan(commit_sha: str):
    """Releases the workspace lock for a scan session."""
    lock_id = f"workspace-{commit_sha}"
    release_lock(lock_id)
    return {"status": "success", "message": f"Lock released for {commit_sha}"}


@app.post("/api/scans/{commit_sha}/verify/{finding_id}")
async def api_verify_finding(commit_sha: str, finding_id: str, background_tasks: BackgroundTasks, force: bool = False):
    """API endpoint to manually trigger sandbox exploit verification for a finding."""
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return {"status": "error", "message": "Scan session not found"}
    scan_data = doc.to_dict()
    findings = scan_data.get("findings", [])
    branch = scan_data.get("branch_name")
    
    # Check if there is an active PR or repo configuration
    repo_name = scan_data.get("repo_name", "YOUR_ORG/YOUR_REPO")
    pr_number = scan_data.get("pr_number")
    is_pr = True if pr_number else False
    
    lock_id = f"workspace-{commit_sha}"
    if force:
        release_lock(lock_id)
    if not acquire_lock(lock_id):
        return {"status": "error", "message": "Another verify or fix operation is currently running for this scan session. Please try again in a few seconds."}

    finding_found = False
    target_filepath = ""
    target_vuln_type = None
    for f in findings:
        if f.get("id") == finding_id:
            f["status"] = "VERIFYING"
            finding_found = True
            target_filepath = f.get("filepath")
            target_vuln_type = f.get("vuln_type")
            break
            
    if not finding_found:
        release_lock(lock_id)
        return {"status": "error", "message": "Finding ID not found in session"}
        
    update_scan_status(commit_sha, status="RUNNING", message=f"Verifying exploit for finding {finding_id}", findings=findings)
    
    # Retrieve token to post comments to GitHub
    token = await get_github_token()
    
    # Post progress message to GitHub commit/PR
    progress_msg = f"⏳ **CodeMender Exploit Verification Started (triggered from dashboard)** for finding: `{finding_id}`..."
    try:
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, progress_msg, token)
        else:
            await post_commit_comment(repo_name, commit_sha, progress_msg, token)
    except Exception as comment_err:
        logger.warning(f"Failed to post manual verify progress message to GitHub: {comment_err}")
        
    # Start periodic progress reporting task in background
    import uuid
    from shared_state import active_tasks
    run_id = str(uuid.uuid4())
    active_tasks[commit_sha] = run_id
    asyncio.create_task(post_periodic_progress(repo_name, commit_sha, pr_number, is_pr, token, task_type="verify", run_id=run_id))
    
    async def run_verify_task():
        try:
            append_scan_step(commit_sha, "verify", f"Starting manual verification request for finding {finding_id}...")
            await ensure_workspace(commit_sha, branch, repo=repo_name)
            
            # Rebuild local CLI database state before verifying & map local finding ID
            from agents import run_triage_agent
            append_scan_step(commit_sha, "find", f"Re-indexing {target_filepath} and mapping finding ID...")
            local_findings = await run_triage_agent(commit_sha, target_filepath, repo_name=repo_name)
            logger.info(f"Local findings during verify task: {local_findings}")
            
            local_finding_id = finding_id
            if local_findings:
                matched_local = None
                if target_vuln_type:
                    for lf in local_findings:
                        if lf.get("vuln_type") == target_vuln_type:
                            matched_local = lf
                            break
                if matched_local:
                    local_finding_id = matched_local.get("id")
                    logger.info(f"Mapped external finding ID {finding_id} ({target_vuln_type}) to local finding ID {local_finding_id}")
                else:
                    local_finding_id = local_findings[0].get("id")
                    logger.warning(f"Could not find matching local finding for vuln_type {target_vuln_type}. Falling back to first local finding ID {local_finding_id}")
            else:
                logger.warning(f"No local findings returned for {target_filepath}. Falling back to original finding ID {finding_id}")
            
            append_scan_step(commit_sha, "verify", f"Spawning sandboxed exploit verification agent for finding {finding_id} (local: {local_finding_id})...")
            verify_out = await cm_verify(commit_sha, local_finding_id)
            
            # Save the verification log
            update_scan_status(commit_sha, logs={"verify_output": verify_out})
            
            # Upload verification artifacts to GCS
            workspace_path = f"/tmp/session-{commit_sha}"
            uploaded_arts = await upload_verification_artifacts(commit_sha, workspace_path, finding_id)
            
            # Extract exploit confidence & status from .exploit/info.yaml
            confidence = "100%"
            is_verified = False
            info_path = Path(workspace_path) / ".exploit" / "info.yaml"
            report_path = Path(workspace_path) / ".exploit" / "REPORT.md"
            log_path = Path(workspace_path) / ".exploit" / "LOG.md"
            
            if info_path.exists():
                try:
                    info_content = info_path.read_text(encoding="utf-8")
                    status_val = str(parse_yaml_value(info_content, "status")).strip().lower()
                    extracted = parse_yaml_value(info_content, "confidence")
                    confidence = clean_confidence(extracted)
                    if status_val in ("valid", "verified", "confirmed", "true") or confidence in ("certain", "likely", "100%", "high"):
                        is_verified = True
                except Exception as parse_err:
                    logger.warning(f"Failed to parse info.yaml: {parse_err}")
            
            if not is_verified and report_path.exists():
                is_verified = True
                
            if not is_verified and log_path.exists():
                try:
                    log_txt = log_path.read_text(encoding="utf-8").lower()
                    if "successfully ran" in log_txt or "confirmed" in log_txt:
                        is_verified = True
                except Exception:
                    pass
                    
            if not is_verified and verify_out:
                is_verified = any(kw in verify_out for kw in ["EXPLOIT SUCCESSFUL", "Exploit confirmed", "confirmed", "status: valid", "valid"])

            doc = doc_ref.get()
            scan_data = doc.to_dict()
            findings = scan_data.get("findings", [])
            
            # Report priority: 1. CodeMender sandbox REPORT.md, 2. AI synthesized exploit report
            if report_path.exists():
                try:
                    exploit_report = report_path.read_text(encoding="utf-8")
                except Exception:
                    from agents import generate_ai_exploit_report
                    exploit_report = generate_ai_exploit_report(verify_out, session_id=commit_sha, repo_name=repo_name)
            else:
                from agents import generate_ai_exploit_report
                exploit_report = generate_ai_exploit_report(verify_out, session_id=commit_sha, repo_name=repo_name)
            
            if is_verified:
                for f in findings:
                    if f.get("id") == finding_id:
                        f["status"] = "VERIFIED"
                        f["exploit_report"] = exploit_report
                update_scan_status(commit_sha, status="COMPLETED", message=f"Vulnerability {finding_id} exploit verified", findings=findings)
                append_scan_step(commit_sha, "verify", f"Vulnerability {finding_id} exploit successfully verified in sandbox.")
                status_text = "✅ **VERIFIED**"
                outcome_text = "Exploit simulation succeeded. Vulnerability is active."
            else:
                for f in findings:
                    if f.get("id") == finding_id:
                        f["status"] = "VERIFICATION_FAILED"
                        f["exploit_report"] = exploit_report
                update_scan_status(commit_sha, status="COMPLETED", message=f"Vulnerability {finding_id} verification failed", findings=findings)
                append_scan_step(commit_sha, "verify", f"Vulnerability {finding_id} verification failed (exploit did not trigger or failed).")
                status_text = "❌ **FAILED**"
                outcome_text = "Exploit execution failed (vulnerability not active or unreachable)."
            
            # Trigger GCS artifacts upload with complete verify logs
            try:
                import re
                session_id_match = re.search(r"Session:\s*([a-zA-Z0-9_-]+)", verify_out, re.IGNORECASE)
                if session_id_match:
                    cm_session_id = session_id_match.group(1)
                    from gcs_helpers import upload_session_artifacts
                    upload_session_artifacts(commit_sha, cm_session_id)
            except Exception as upload_err:
                logger.error(f"Failed to upload GCS artifacts after verification: {upload_err}")
                
            # Prepare results report comment
            results_report = f"### 🧪 CodeMender Sandbox Verification Results (triggered from dashboard)\n\n"
            results_report += "| Finding ID | Status | Outcome | Confidence |\n"
            results_report += "| --- | --- | --- | --- |\n"
            results_report += f"| `{finding_id}` | {status_text} | {outcome_text} | **{confidence if is_verified else '-'}** |\n"
            
            # Build detail section
            detail = f"\n### 🔬 Exploit Verification Report for `{finding_id}`\n"
            if exploit_report:
                detail += "<details>\n"
                detail += "<summary><b>View Exploit Steps & Response Trace (PoC)</b></summary>\n\n"
                detail += f"{exploit_report}\n"
                detail += "</details>\n"
            
            # List GCS links
            if uploaded_arts:
                detail += "\n#### 📁 Verification Research Artifacts (Cloud Storage):\n"
                for art in uploaded_arts:
                    detail += f"- 📄 [{art['name']}]({art['url']})\n"
            
            # Append raw CLI verify console output details
            if verify_out:
                detail += "\n<details>\n"
                detail += "<summary>📋 View Raw CodeMender Verification Console Output</summary>\n\n"
                detail += f"```text\n{verify_out}\n```\n"
                detail += "</details>\n"
                
            results_report += "\n---\n" + detail
            
            # Post results comment
            try:
                if is_pr and pr_number:
                    await post_pr_comment(repo_name, pr_number, results_report, token)
                else:
                    await post_commit_comment(repo_name, commit_sha, results_report, token)
            except Exception as post_err:
                logger.error(f"Failed to post manual verify results comment: {post_err}")
            release_lock(lock_id)
                
        except Exception as e:
            logger.error(f"Manual verify task failed: {e}")
            append_scan_step(commit_sha, "error", f"Verification task failed for {finding_id}: {str(e)}")
            doc = doc_ref.get()
            scan_data = doc.to_dict()
            findings = scan_data.get("findings", [])
            for f in findings:
                if f.get("id") == finding_id:
                    f["status"] = "VERIFICATION_FAILED"
            update_scan_status(commit_sha, status="COMPLETED", message=f"Verification failed for {finding_id}: {str(e)}", findings=findings)
            
            # Post failure comment
            failure_report = f"### 🧪 CodeMender Sandbox Verification Results (triggered from dashboard)\n\n"
            failure_report += "| Finding ID | Status | Outcome | Confidence |\n"
            failure_report += "| --- | --- | --- | --- |\n"
            failure_report += f"| `{finding_id}` | ❌ **FAILED** | Verification run failed or exploit could not be triggered. | - |\n"
            try:
                if is_pr and pr_number:
                    await post_pr_comment(repo_name, pr_number, failure_report, token)
                else:
                    await post_commit_comment(repo_name, commit_sha, failure_report, token)
            except Exception as post_err:
                logger.error(f"Failed to post manual verify failure comment: {post_err}")
            release_lock(lock_id)
            
    background_tasks.add_task(run_verify_task)
    return {"status": "success", "message": "Verification worker enqueued"}

@app.post("/api/scans/{commit_sha}/fix/{finding_id}")
async def api_fix_finding(commit_sha: str, finding_id: str, background_tasks: BackgroundTasks, force: bool = False):
    """API endpoint to manually trigger secure patch generation and Draft PR creation."""
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return {"status": "error", "message": "Scan session not found"}
    scan_data = doc.to_dict()
    findings = scan_data.get("findings", [])
    branch = scan_data.get("branch_name")
    
    repo_name = scan_data.get("repo_name", "YOUR_ORG/YOUR_REPO")
    pr_number = scan_data.get("pr_number")
    is_pr = True if pr_number else False
    
    lock_id = f"workspace-{commit_sha}"
    if force:
        release_lock(lock_id)
    if not acquire_lock(lock_id):
        return {"status": "error", "message": "Another verify or fix operation is currently running for this scan session. Please try again in a few seconds."}

    finding_found = False
    target_filepath = ""
    target_vuln_type = None
    for f in findings:
        if f.get("id") == finding_id:
            f["status"] = "PATCHING"
            finding_found = True
            target_filepath = f.get("filepath")
            target_vuln_type = f.get("vuln_type")
            break
            
    if not finding_found:
        release_lock(lock_id)
        return {"status": "error", "message": "Finding ID not found in session"}
        
    update_scan_status(commit_sha, status="RUNNING", message=f"Generating secure fix patch for {finding_id}", findings=findings)
    
    # Retrieve token to post comments to GitHub
    token = await get_github_token()
    
    # Post progress message to GitHub commit/PR
    progress_msg = f"⏳ **CodeMender Patch Generation Started (triggered from dashboard)** for finding: `{finding_id}`..."
    try:
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, progress_msg, token)
        else:
            await post_commit_comment(repo_name, commit_sha, progress_msg, token)
    except Exception as comment_err:
        logger.warning(f"Failed to post manual fix progress message to GitHub: {comment_err}")
        
    # Start periodic progress reporting task in background
    import uuid
    from shared_state import active_tasks
    run_id = str(uuid.uuid4())
    active_tasks[commit_sha] = run_id
    asyncio.create_task(post_periodic_progress(repo_name, commit_sha, pr_number, is_pr, token, task_type="patch", run_id=run_id))
    
    async def run_fix_task():
        try:
            append_scan_step(commit_sha, "fix", f"Starting manual patch request for finding {finding_id}...")
            await ensure_workspace(commit_sha, branch)
            
            # Rebuild local CLI database state and get local finding ID
            from agents import run_triage_agent
            append_scan_step(commit_sha, "find", f"Re-indexing code database to map finding {finding_id}...")
            local_findings = await run_triage_agent(commit_sha, target_filepath, repo_name=repo_name)
            logger.info(f"Local findings during fix task: {local_findings}")
            
            local_finding_id = finding_id
            if local_findings:
                matched_local = None
                if target_vuln_type:
                    for lf in local_findings:
                        if lf.get("vuln_type") == target_vuln_type:
                            matched_local = lf
                            break
                if matched_local:
                    local_finding_id = matched_local.get("id")
                    logger.info(f"Mapped external finding ID {finding_id} ({target_vuln_type}) to local finding ID {local_finding_id}")
                else:
                    local_finding_id = local_findings[0].get("id")
                    logger.warning(f"Could not find matching local finding for vuln_type {target_vuln_type}. Falling back to first local finding ID {local_finding_id}")
            else:
                logger.warning(f"No local findings found for {target_filepath}. Falling back to external finding ID {finding_id}")
            
            append_scan_step(commit_sha, "fix", f"Triggering patch generation agent for local finding {local_finding_id}...")
            success = await apply_codemender_fix(
                session_id=commit_sha,
                repo_name=repo_name,
                branch=branch,
                github_token=token,
                vuln_id=local_finding_id
            )
            
            doc = doc_ref.get()
            scan_data = doc.to_dict()
            findings = scan_data.get("findings", [])
            for f in findings:
                if f.get("id") == finding_id:
                    f["status"] = "PATCHED" if success else "PATCH_FAILED"
            
            msg = f"Security patch created for {finding_id}" if success else f"Patch generation failed for {finding_id}"
            update_scan_status(commit_sha, status="COMPLETED", message=msg, findings=findings)
            
            if success:
                append_scan_step(commit_sha, "fix", f"Security patch for {finding_id} successfully created and Draft PR submitted.")
            else:
                 append_scan_step(commit_sha, "error", f"Fix agent failed to generate a valid patch for {finding_id}.")
            release_lock(lock_id)
                
        except Exception as e:
            logger.error(f"Manual fix task failed: {e}")
            append_scan_step(commit_sha, "error", f"Patch generation task encountered error: {str(e)}")
            doc = doc_ref.get()
            scan_data = doc.to_dict()
            findings = scan_data.get("findings", [])
            for f in findings:
                if f.get("id") == finding_id:
                    f["status"] = "PATCH_FAILED"
            update_scan_status(commit_sha, status="COMPLETED", message=f"Patch generation failed: {str(e)}", findings=findings)
            release_lock(lock_id)
            
    background_tasks.add_task(run_fix_task)
    return {"status": "success", "message": "Patch generation worker enqueued"}

async def create_draft_pr_task(repo_name: str, commit_sha: str, is_pr: bool = False, pr_number: int = None):
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
            if is_pr and pr_number:
                await post_pr_comment(repo_name, pr_number, msg, token)
            else:
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
        
        # Post success message
        msg = f"🎉 **Draft Pull Request Created Successfully!**\n\n👉 **[Draft Pull Request #{pr_num}]({pr_url})**\n\nComment `/approve` on the PR to commit the fix."
        if is_pr and pr_number:
            await post_pr_comment(repo_name, pr_number, msg, token)
        else:
            await post_commit_comment(repo_name, commit_sha, msg, token)
        
    except Exception as e:
        logger.error(f"Failed to create draft PR for commit {commit_sha}: {e}", exc_info=True)
        try:
            if token:
                if is_pr and pr_number:
                    await post_pr_comment(repo_name, pr_number, f"❌ Failed to create Draft PR: {e}", token)
                else:
                    await post_commit_comment(repo_name, commit_sha, f"❌ Failed to create Draft PR: {e}", token)
        except Exception:
            pass

@app.post("/api/scans/{commit_sha}/draft_pr")
async def api_create_draft_pr(commit_sha: str, background_tasks: BackgroundTasks):
    """API endpoint to manually trigger Draft PR creation for a patch branch."""
    from database import db
    doc_ref = db.collection("scans").document(commit_sha)
    doc = doc_ref.get()
    if not doc.exists:
        return {"status": "error", "message": "Scan session not found"}
        
    scan_data = doc.to_dict()
    repo_name = scan_data.get("repo_name", "YOUR_ORG/YOUR_REPO")
    
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
    repo_name: str
    is_pr: bool = False
    pr_number: int = None

@app.post("/api/scans/{commit_sha}/verify")
async def api_verify_findings(commit_sha: str, req: VerifyRequest, background_tasks: BackgroundTasks):
    """API endpoint to trigger Sandbox Exploit Verification for finding IDs."""
    background_tasks.add_task(
        verify_findings_task,
        repo_name=req.repo_name,
        commit_sha=commit_sha,
        finding_ids=req.finding_ids,
        is_pr=req.is_pr,
        pr_number=req.pr_number
    )
    return {"status": "accepted", "message": "Verification worker enqueued."}


class FixRequest(BaseModel):
    finding_ids: list[str]
    repo_name: str
    is_pr: bool = False
    pr_number: int = None

@app.post("/api/scans/{commit_sha}/fix")
async def api_fix_findings(commit_sha: str, req: FixRequest, background_tasks: BackgroundTasks):
    """API endpoint to trigger secure patch generation for finding IDs."""
    background_tasks.add_task(
        fix_findings_task,
        repo_name=req.repo_name,
        commit_sha=commit_sha,
        finding_ids=req.finding_ids,
        is_pr=req.is_pr,
        pr_number=req.pr_number
    )
class DismissRequest(BaseModel):
    finding_id: str
    category: str = "FALSE_POSITIVE"
    reason: str
    user: str = "Developer"
    repo_name: str = None
    pr_number: int = None

@app.post("/api/scans/{commit_sha}/dismiss-finding")
async def api_dismiss_finding(commit_sha: str, req: DismissRequest, background_tasks: BackgroundTasks):
    """API endpoint to dismiss / manually accept risk for a finding."""
    if not req.reason or len(req.reason.strip()) < 5:
        return Response(
            content=json.dumps({"status": "error", "message": "A valid justification reason is required (min 5 characters)."}),
            status_code=400,
            media_type="application/json"
        )
        
    background_tasks.add_task(
        dismiss_findings_task,
        repo_name=req.repo_name or os.getenv("GITHUB_REPOSITORY", "YOUR_ORG/YOUR_REPO"),
        commit_sha=commit_sha,
        target_ids=[req.finding_id],
        reason=req.reason.strip(),
        category=req.category,
        actor=req.user,
        is_pr=bool(req.pr_number),
        pr_number=req.pr_number
    )
    return {"status": "accepted", "message": f"Dismissal worker enqueued for finding {req.finding_id}."}

@app.get("/api/scans/{commit_sha}/logs/stream")
async def api_stream_logs(commit_sha: str):
    """SSE endpoint streaming live execution log steps of a scan from Firestore."""
    from database import db
    import json
    
    async def log_generator():
        last_step_count = 0
        doc_ref = db.collection("scans").document(commit_sha)
        
        while True:
            doc = doc_ref.get()
            if doc.exists:
                scan_data = doc.to_dict()
                steps = scan_data.get("steps", [])
                
                if len(steps) > last_step_count:
                    for i in range(last_step_count, len(steps)):
                        yield f"data: {json.dumps(steps[i])}\n\n"
                    last_step_count = len(steps)
                    
                status = scan_data.get("status")
                if status in ("COMPLETED", "FAILED") and len(steps) == last_step_count:
                    break
            else:
                yield "data: {\"step\": \"error\", \"message\": \"Scan document not found yet\", \"timestamp\": 0}\n\n"
                
            await asyncio.sleep(2)
            
    return StreamingResponse(log_generator(), media_type="text/event-stream")

@app.post("/api/maintenance/gc")
async def api_maintenance_gc(request: Request, background_tasks: BackgroundTasks):
    """API endpoint to trigger automated maintenance and garbage collection sweep."""
    from maintenance import run_maintenance_sweep
    try:
        summary = run_maintenance_sweep()
        return {"status": "success", "summary": summary}
    except Exception as ex:
        logger.error(f"Maintenance GC failed: {ex}", exc_info=True)
        return Response(content=json.dumps({"status": "error", "message": str(ex)}), status_code=500, media_type="application/json")

# Place at the very end so it doesn't shadow explicit REST endpoints like /github-webhook or /api/patches
disable_ui = str(os.getenv("DISABLE_UI", "false")).strip().lower() in ("true", "1", "yes")
if not disable_ui and os.path.exists("frontend/out"):
    app.mount("/", StaticFiles(directory="frontend/out", html=True), name="static")
else:
    logger.info("Static dashboard serving disabled (DISABLE_UI=true).")



