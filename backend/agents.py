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
import logging
import contextlib
import json
import re
import time
import asyncio
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Initialize official GenAI client using Vertex AI
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")

# Upper bound (seconds) for any single Gemini call: used as the client's HTTP timeout and as the
# asyncio.wait_for guard around every async call.
GEMINI_TIMEOUT_S = float(os.getenv("GEMINI_TIMEOUT_S", "90"))

client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION,
    http_options=types.HttpOptions(timeout=int(GEMINI_TIMEOUT_S * 1000))
)

# Use standard model name for Vertex AI (checking GEMINI_MODEL_NAME first, then GEMINI_MODEL, then fallback)
MODEL_NAME = os.environ.get("GEMINI_MODEL_NAME") or os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

# The dashboard-triggered `cm fix` runs through cm_tools._run_cm_cmd; its deadline is
# CM_FIX_TIMEOUT_SEC (cm_tools.cm_command_timeout).


def _err_text(err: Exception) -> str:
    """Readable error text; asyncio timeouts have an empty str()."""
    if isinstance(err, asyncio.TimeoutError):
        return f"Gemini call timed out after {GEMINI_TIMEOUT_S:.0f}s"
    return str(err)

# Canonical Deterministic Severity Policy Matrix
DETERMINISTIC_SEVERITY_POLICY = {
    # CRITICAL: RCE, SQLi, Command Injection, Auth Bypass
    "sql injection": "CRITICAL", "sqli": "CRITICAL",
    "command injection": "CRITICAL", "remote code execution": "CRITICAL",
    "rce": "CRITICAL", "authentication bypass": "CRITICAL",
    "cwe-89": "CRITICAL", "cwe-78": "CRITICAL", "cwe-287": "CRITICAL",
    # HIGH: IDOR, Mass Assignment, XSS, SSRF, Hardcoded Secrets
    "cross-site scripting": "HIGH", "xss": "HIGH",
    "insecure direct object reference": "HIGH", "idor": "HIGH",
    "server-side request forgery": "HIGH", "ssrf": "HIGH",
    "hardcoded secret": "HIGH", "hardcoded credentials": "HIGH",
    "cwe-79": "HIGH", "cwe-639": "HIGH", "cwe-918": "HIGH", "cwe-798": "HIGH"
}

def normalize_finding_severity(vuln_type: str = "", cwe_id: str = "", raw_severity: str = "") -> str:
    """Normalizes finding severity deterministically based on vulnerability class and CWE."""
    key_type = (vuln_type or "").strip().lower()
    key_cwe = (cwe_id or "").strip().lower()
    if key_type in DETERMINISTIC_SEVERITY_POLICY:
        return DETERMINISTIC_SEVERITY_POLICY[key_type]
    if key_cwe in DETERMINISTIC_SEVERITY_POLICY:
        return DETERMINISTIC_SEVERITY_POLICY[key_cwe]
    cleaned = (raw_severity or "MEDIUM").replace("🔴", "").replace("🟠", "").replace("🟡", "").replace("🔵", "").replace("⚪", "").strip().upper()
    return "CRITICAL" if "CRITICAL" in cleaned else ("HIGH" if "HIGH" in cleaned else ("LOW" if "LOW" in cleaned else "MEDIUM"))


class QAReport(BaseModel):
    matches_intent: bool = Field(description="True if the code matches the user's intent, False otherwise.")
    feedback: str = Field(description="Feedback/review on how well the code aligns with the intent.")

class SemanticReport(BaseModel):
    has_secrets: bool = Field(description="True if the code contains hardcoded secrets or API keys, False otherwise.")
    hygiene_issues: list[str] = Field(description="List of code hygiene, linting, or formatting issues found in the code.")

class IDMapping(BaseModel):
    mapping: dict[str, str] = Field(description="Map of original finding IDs (keys) to new finding IDs (values)")

async def map_finding_ids(original_findings: list[dict], new_findings: list[dict], session_id: str = "", repo_name: str = "") -> dict[str, str]:
    """Uses Gemini to align and map original finding IDs to newly generated finding IDs."""
    if not original_findings or not new_findings:
        return {}
        
    prompt = (
        f"Original findings:\n{json.dumps(original_findings, indent=2)}\n\n"
        f"New findings from current scan:\n{json.dumps(new_findings, indent=2)}\n\n"
        "Align the original findings to the new findings based on their description, type, and filepath. "
        "Return a JSON mapping where the keys are the original finding IDs and the values are the corresponding new finding IDs."
    )
    
    try:
        import time
        start_time = time.time()
        response = await asyncio.wait_for(
            client.aio.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction="You are a data alignment helper. Create a 1-to-1 mapping between original findings and new findings based on matching fields. Output structured JSON.",
                    response_mime_type="application/json",
                    response_schema=IDMapping,
                ),
            ),
            timeout=GEMINI_TIMEOUT_S,
        )
        duration = time.time() - start_time
        try:
            from database import log_token_usage
            usage = response.usage_metadata
            log_token_usage(
                session_id=session_id,
                repo_name=repo_name,
                task_type="map_finding_ids",
                model_name=MODEL_NAME,
                input_tokens=usage.prompt_token_count,
                output_tokens=usage.candidates_token_count,
                cached_tokens=usage.cached_content_token_count or 0,
                thoughts_tokens=getattr(usage, "thoughts_token_count", 0) or 0,
                duration_sec=duration
            )
        except Exception as log_err:
            logger.warning(f"Failed to log token usage: {log_err}")
            
        parsed = json.loads(response.text)
        return parsed.get("mapping", {})
    except Exception as e:
        logger.error(f"Failed to map finding IDs using Gemini: {_err_text(e)}")
        # Fallback: simple match by description substring
        mapping = {}
        for orig in original_findings:
            for new_f in new_findings:
                if orig.get("description") == new_f.get("description") or orig.get("vuln_type") == new_f.get("vuln_type"):
                    mapping[orig.get("id")] = new_f.get("id")
                    break
        return mapping

async def run_qa_agent(intent: str, code: str, session_id: str = "", repo_name: str = "") -> QAReport:
    try:
        import time
        start_time = time.time()
        response = await asyncio.wait_for(
            client.aio.models.generate_content(
                model=MODEL_NAME,
                contents=f"User Intent: {intent}\n\nCode to review:\n{code}",
                config=types.GenerateContentConfig(
                    system_instruction=(
                        "You are a Quality Assurance agent. Analyze the provided code and verify if "
                        "it matches the user's intent. Output a structured JSON matching the provided schema."
                    ),
                    response_mime_type="application/json",
                    response_schema=QAReport,
                ),
            ),
            timeout=GEMINI_TIMEOUT_S,
        )
        duration = time.time() - start_time
        try:
            from database import log_token_usage
            usage = response.usage_metadata
            log_token_usage(
                session_id=session_id,
                repo_name=repo_name,
                task_type="qa_agent",
                model_name=MODEL_NAME,
                input_tokens=usage.prompt_token_count,
                output_tokens=usage.candidates_token_count,
                cached_tokens=usage.cached_content_token_count or 0,
                thoughts_tokens=getattr(usage, "thoughts_token_count", 0) or 0,
                duration_sec=duration
            )
        except Exception as log_err:
            logger.warning(f"Failed to log token usage: {log_err}")
            
        parsed = json.loads(response.text)
        return QAReport(**parsed)
    except Exception as e:
        logger.error(f"QA Agent execution failed: {_err_text(e)}")
        return QAReport(matches_intent=False, feedback=f"QA Agent execution failed: {_err_text(e)}")

async def run_semantic_agent(code: str, session_id: str = "", repo_name: str = "") -> SemanticReport:
    try:
        import time
        start_time = time.time()
        response = await asyncio.wait_for(
            client.aio.models.generate_content(
                model=MODEL_NAME,
                contents=f"Code to review:\n{code}",
                config=types.GenerateContentConfig(
                    system_instruction=(
                        "You are a Static Analysis agent. Scan the provided code for hardcoded secrets, "
                        "hygiene, formatting, and style issues. Output a structured JSON matching the schema."
                    ),
                    response_mime_type="application/json",
                    response_schema=SemanticReport,
                ),
            ),
            timeout=GEMINI_TIMEOUT_S,
        )
        duration = time.time() - start_time
        try:
            from database import log_token_usage
            usage = response.usage_metadata
            log_token_usage(
                session_id=session_id,
                repo_name=repo_name,
                task_type="semantic_agent",
                model_name=MODEL_NAME,
                input_tokens=usage.prompt_token_count,
                output_tokens=usage.candidates_token_count,
                cached_tokens=usage.cached_content_token_count or 0,
                thoughts_tokens=getattr(usage, "thoughts_token_count", 0) or 0,
                duration_sec=duration
            )
        except Exception as log_err:
            logger.warning(f"Failed to log token usage: {log_err}")
            
        parsed = json.loads(response.text)
        return SemanticReport(**parsed)
    except Exception as e:
        logger.error(f"Semantic Agent execution failed: {_err_text(e)}")
        return SemanticReport(has_secrets=False, hygiene_issues=[f"Semantic Agent execution failed: {_err_text(e)}"])

# CodeMender Triage and Patching Handlers
import asyncio
from cm_tools import cm_init, cm_find, cm_verify, cm_fix, count_cli_table_rows, cli_reports_clean_scan
from git_manager import GitWorkspace, get_existing_pr, create_draft_pr
from github_helpers import post_pr_comment
from database import save_patch_proposal
from log_redaction import redact

class Finding(BaseModel):
    id: str = Field(description="The unique ID of the vulnerability.")
    severity: str = Field(description="The severity level of the vulnerability (e.g. CRITICAL, HIGH, MEDIUM, LOW).")
    filepath: str = Field(description="The file path containing the vulnerability.")
    vuln_type: str = Field(description="The type/category of the vulnerability.")
    description: str = Field(description="A brief description of the vulnerability.")

class TriageReport(BaseModel):
    findings: list[Finding] = Field(description="The list of vulnerabilities parsed from the log table.")

class TriageError(Exception):
    """Raised when a CodeMender scan cannot produce a trustworthy result (fail closed).

    Covers cm find failures, empty scanner output, CLI output that could not be parsed, a parsed
    findings count that differs from the CLI findings table, and output with neither a findings
    table nor the CLI's clean-scan line. run_triage_agent returns [] only for a genuinely clean scan.
    """

# The findings-table parser lives in cm_tools (shared with the `cm find` exit-code check); this
# alias keeps the old private name importable.
_count_cli_table_rows = count_cli_table_rows

def _triage_failure(session_id: str, filepath: str, reason: str) -> TriageError:
    """Logs a triage failure, records it on the scan timeline, and returns the error to raise."""
    from database import append_scan_step
    message = f"Triage failed for {filepath}: {reason}"
    logger.error(message)
    append_scan_step(session_id, "error", f"{message}. Scan result is unknown and will not be reported as clean.")
    return TriageError(message)

async def run_triage_agent(session_id: str, filepath: str, repo_name: str = "") -> list[dict]:
    """Runs cm_find on the target file and parses findings into structured JSON using Gemini.

    Returns [] only for a genuinely clean scan: no findings table and the CLI's clean-scan line
    ('No vulnerabilities found!'). Raises TriageError when the scan fails (cm find error, empty
    scanner output), its output cannot be parsed, the parsed findings count differs from the CLI
    findings table row count, or the output has neither a findings table nor the clean-scan line.
    """
    from database import update_scan_status, append_scan_step
    try:
        # 0. Initialize CodeMender workspace
        try:
            await cm_init(session_id)
        except Exception as e:
            logger.warning(f"cm_init failed or already initialized: {e}")

        # 1. Run the local find command directly
        try:
            stdout = await cm_find(session_id, filepath)
        except Exception as e:
            raise _triage_failure(session_id, filepath, f"cm find failed: {e}") from e
        stdout = stdout or ""
        logger.info(f"cm_find stdout:\n{stdout}")
        
        # Save raw scan stdout to Firestore
        update_scan_status(session_id, logs={"find_output": stdout})
        append_scan_step(session_id, "find", "Scanner command executed. Parsing results via triage agent...")
        
        # Empty scanner output is not evidence of a clean scan
        if not stdout.strip():
            raise _triage_failure(session_id, filepath, "cm find returned empty output")

        # The CLI findings table is the source of truth for how many findings exist. Without table
        # rows, only the CLI's explicit clean-scan line counts as clean (no parser call needed).
        table_rows = count_cli_table_rows(stdout)
        if table_rows == 0:
            if cli_reports_clean_scan(stdout):
                append_scan_step(session_id, "find", "Scanner reported no vulnerabilities (clean-scan line present).")
                return []
            raise _triage_failure(
                session_id, filepath,
                "cm find output has no findings table and no clean-scan line ('No vulnerabilities found!')"
            )
            
        # 2. Call Gemini to parse the table stdout
        import time
        start_time = time.time()
        try:
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=MODEL_NAME,
                    contents=f"Parse this cm_find stdout table:\n{stdout}",
                    config=types.GenerateContentConfig(
                        system_instruction=(
                            "You are a structured data parser. Read the tab-separated log table columns printed in the input stdout "
                            "and convert the rows into a structured JSON array. For each row in the table, extract the value "
                            "from the 'ID' column as 'id', the 'SEVERITY' column as 'severity', the 'FILE' column as 'filepath', "
                            "the 'TYPE' column as 'vuln_type', and the 'TITLE' column as 'description'."
                        ),
                        response_mime_type="application/json",
                        response_schema=TriageReport,
                    ),
                ),
                timeout=GEMINI_TIMEOUT_S,
            )
        except Exception as e:
            raise _triage_failure(session_id, filepath, f"triage parser call failed: {_err_text(e)}") from e
        duration = time.time() - start_time
        try:
            from database import log_token_usage
            usage = response.usage_metadata
            log_token_usage(
                session_id=session_id,
                repo_name=repo_name,
                task_type="triage_scan",
                model_name=MODEL_NAME,
                input_tokens=usage.prompt_token_count,
                output_tokens=usage.candidates_token_count,
                cached_tokens=usage.cached_content_token_count or 0,
                thoughts_tokens=getattr(usage, "thoughts_token_count", 0) or 0,
                duration_sec=duration
            )
        except Exception as log_err:
            logger.warning(f"Failed to log token usage: {log_err}")
            
        try:
            parsed = json.loads(response.text)
            report = TriageReport(**parsed)
        except Exception as e:
            raise _triage_failure(session_id, filepath, f"could not parse cm find output: {e}") from e

        if len(report.findings) != table_rows:
            raise _triage_failure(
                session_id, filepath,
                f"parser returned {len(report.findings)} finding(s) but the cm find findings table lists {table_rows} row(s)"
            )

        results = []
        from cm_tools import generate_vulnerability_fingerprint, extract_enclosing_scope
        
        for finding in report.findings:
            d = finding.model_dump()
            d["severity"] = normalize_finding_severity(
                vuln_type=d.get("vuln_type", ""),
                cwe_id=d.get("cwe", ""),
                raw_severity=d.get("severity", "HIGH")
            )
            d["status"] = "DETECTED"
            
            # Extract line number from description or file snippet if available
            line_match = re.search(r':(\d+)', d.get("filepath", ""))
            line_num = int(line_match.group(1)) if line_match else 1
            d["line_number"] = line_num
            
            # Compute canonical structural fingerprint & 6-char display ID
            full_file_path = os.path.join(f"/tmp/session-{session_id}", d.get("filepath", filepath).split(":")[0])
            scope = extract_enclosing_scope(full_file_path, line_num)
            d["enclosing_scope"] = scope
            
            fp, disp_id = generate_vulnerability_fingerprint(
                repo_name=repo_name,
                file_path=d.get("filepath", filepath).split(":")[0],
                enclosing_scope=scope,
                cwe=d.get("cwe") or d.get("vuln_type", "UNKNOWN"),
                vuln_type=d.get("vuln_type", "Unknown"),
                code_sink=d.get("description", "")
            )
            d["fingerprint"] = fp
            d["display_id"] = disp_id
            d["lifecycle_status"] = "NEW"
            results.append(d)
            
        append_scan_step(session_id, "find", f"Triage parser successfully identified {len(results)} vulnerabilities with deterministic fingerprints.")
        return results
    except TriageError:
        raise
    except Exception as e:
        raise _triage_failure(session_id, filepath, f"triage parser encountered error: {e}") from e


def reconcile_pr_findings_delta(
    repo_name: str,
    pr_number: int,
    current_findings: list[dict],
    previous_pr_state: dict = None,
    current_commit_sha: str = "",
    pusher_name: str = ""
) -> tuple[list[dict], dict, list[dict]]:
    """
    Reconciles current commit findings against prior PR scan state.
    
    Categorizes findings into:
      - RESOLVED: Present in previous PR commit, but absent in current scan.
      - PERSISTENT: Present in both previous and current scans (tracks line shift).
      - NEW: Detected in current scan, absent in prior PR commits.
      - DISMISSED: Risk accepted in previous state.
      
    Returns:
        (combined_findings, summary_delta, lifecycle_events)
    """
    previous_pr_state = previous_pr_state or {}
    prev_findings = previous_pr_state.get("active_findings") or previous_pr_state.get("findings") or []
    prev_map = {f.get("fingerprint") or f.get("id"): f for f in prev_findings}
    
    current_map = {f.get("fingerprint") or f.get("id"): f for f in current_findings}
    
    combined_findings = []
    lifecycle_events = []
    
    # 1. Process Current Findings (NEW or PERSISTENT)
    for fp, curr_f in current_map.items():
        finding_copy = dict(curr_f)
        if fp in prev_map:
            old_f = prev_map[fp]
            finding_copy["lifecycle_status"] = "PERSISTENT"
            finding_copy["first_seen_commit"] = old_f.get("first_seen_commit", current_commit_sha)
            finding_copy["previous_line_number"] = old_f.get("line_number")
            finding_copy["exploit_verified"] = old_f.get("exploit_verified", curr_f.get("verified", False))
            
            # Carry over dismissal if previously dismissed (dismiss_finding records status="DISMISSED"
            # plus a `dismissal` dict; older records use lifecycle_status/dismissal_* fields)
            old_dismissal = old_f.get("dismissal") if isinstance(old_f.get("dismissal"), dict) else {}
            if old_f.get("lifecycle_status") == "DISMISSED" or old_f.get("status") == "DISMISSED":
                finding_copy["lifecycle_status"] = "DISMISSED"
                finding_copy["status"] = "DISMISSED"
                finding_copy["dismissal_category"] = old_f.get("dismissal_category") or old_dismissal.get("category")
                finding_copy["dismissal_reason"] = old_f.get("dismissal_reason") or old_dismissal.get("reason")
                if old_dismissal:
                    finding_copy["dismissal"] = old_dismissal
                
            lifecycle_events.append({
                "event_type": "PERSISTED",
                "finding_fingerprint": fp,
                "display_id": finding_copy.get("display_id") or fp[:6],
                "repo_name": repo_name,
                "target_file": finding_copy.get("filepath", ""),
                "line_number": finding_copy.get("line_number"),
                "enclosing_scope": finding_copy.get("enclosing_scope", "global"),
                "cwe": finding_copy.get("cwe") or finding_copy.get("vuln_type", ""),
                "vuln_type": finding_copy.get("vuln_type", ""),
                "severity": finding_copy.get("severity", "HIGH"),
                "lifecycle_status": finding_copy["lifecycle_status"],
                "commit_sha": current_commit_sha,
                "pr_number": pr_number,
                "pusher_name": pusher_name,
                "exploit_verified": finding_copy.get("exploit_verified", False)
            })
        else:
            finding_copy["lifecycle_status"] = "NEW"
            finding_copy["first_seen_commit"] = current_commit_sha
            
            lifecycle_events.append({
                "event_type": "DISCOVERED",
                "finding_fingerprint": fp,
                "display_id": finding_copy.get("display_id") or fp[:6],
                "repo_name": repo_name,
                "target_file": finding_copy.get("filepath", ""),
                "line_number": finding_copy.get("line_number"),
                "enclosing_scope": finding_copy.get("enclosing_scope", "global"),
                "cwe": finding_copy.get("cwe") or finding_copy.get("vuln_type", ""),
                "vuln_type": finding_copy.get("vuln_type", ""),
                "severity": finding_copy.get("severity", "HIGH"),
                "lifecycle_status": "NEW",
                "commit_sha": current_commit_sha,
                "pr_number": pr_number,
                "pusher_name": pusher_name,
                "exploit_verified": False
            })
            
        combined_findings.append(finding_copy)
        
    # 2. Process Resolved Findings (Present in previous, absent in current)
    for fp, old_f in prev_map.items():
        if fp not in current_map and old_f.get("lifecycle_status") != "RESOLVED":
            resolved_f = dict(old_f)
            resolved_f["lifecycle_status"] = "RESOLVED"
            resolved_f["resolved_in_commit"] = current_commit_sha
            resolved_f["status"] = "RESOLVED"
            combined_findings.append(resolved_f)
            
            lifecycle_events.append({
                "event_type": "RESOLVED",
                "finding_fingerprint": fp,
                "display_id": resolved_f.get("display_id") or fp[:6],
                "repo_name": repo_name,
                "target_file": resolved_f.get("filepath", ""),
                "line_number": resolved_f.get("line_number"),
                "enclosing_scope": resolved_f.get("enclosing_scope", "global"),
                "cwe": resolved_f.get("cwe") or resolved_f.get("vuln_type", ""),
                "vuln_type": resolved_f.get("vuln_type", ""),
                "severity": resolved_f.get("severity", "HIGH"),
                "lifecycle_status": "RESOLVED",
                "commit_sha": current_commit_sha,
                "pr_number": pr_number,
                "pusher_name": pusher_name,
                "exploit_verified": resolved_f.get("exploit_verified", False)
            })
            
    summary_delta = {
        "total_active": len([f for f in combined_findings if f.get("lifecycle_status") in ("NEW", "PERSISTENT")]),
        "resolved_count": len([f for f in combined_findings if f.get("lifecycle_status") == "RESOLVED"]),
        "persistent_count": len([f for f in combined_findings if f.get("lifecycle_status") == "PERSISTENT"]),
        "new_count": len([f for f in combined_findings if f.get("lifecycle_status") == "NEW"]),
        "dismissed_count": len([f for f in combined_findings if f.get("lifecycle_status") == "DISMISSED"])
    }
    
    return combined_findings, summary_delta, lifecycle_events


def reconcile_finding_lifecycle(previous_findings: list[dict], current_findings: list[dict], repo_name: str = "", commit_sha: str = "", pusher_name: str = ""):
    """Adapter function providing finding lifecycle reconciliation compatible with main.py calls."""
    previous_pr_state = {"active_findings": previous_findings} if previous_findings else {}
    reconciled, summary, _ = reconcile_pr_findings_delta(
        repo_name=repo_name,
        pr_number=None,
        current_findings=current_findings,
        previous_pr_state=previous_pr_state,
        current_commit_sha=commit_sha,
        pusher_name=pusher_name
    )
    return reconciled, summary



class CommitIdentityError(RuntimeError):
    """Raised when no real committer identity is available; CodeMender never invents one (GEMINI.md)."""

_INVALID_COMMIT_EMAILS = frozenset({"agent@codemender.ai"})

# CodeMender artifacts that must never be swept into a patch commit by `git add -A`.
_GIT_ADD_ARTIFACT_EXCLUDES = (
    ":(exclude).cm_project",
    ":(exclude).exploit",
    ":(exclude).codemender",
    ":(exclude)__pycache__",
    ":(exclude)**/__pycache__",
    ":(exclude)*.pyc",
    ":(exclude)*.pyo",
    ":(exclude)*.class",
)
_ARTIFACT_SUFFIXES = (".pyc", ".pyo", ".class", ".so", ".o", ".a", ".dll", ".dylib")


def _is_ignored_artifact_path(path: str) -> bool:
    norm = (path or "").strip().replace("\\", "/")
    if not norm:
        return True
    parts = [p for p in norm.split("/") if p]
    if any(p in (".codemender", ".cm_project", ".exploit", "__pycache__") for p in parts):
        return True
    return norm.lower().endswith(_ARTIFACT_SUFFIXES)


def _valid_commit_identity(name: str, email: str):
    name = (name or "").strip()
    email = (email or "").strip()
    if not name or "@" not in email or email.lower() in _INVALID_COMMIT_EMAILS:
        return None
    return name, email


async def _resolve_commit_identity(workspace_path: str, pusher_name: str = None, pusher_email: str = None) -> tuple[str, str]:
    """Returns (name, email) for patch commits: the recorded pusher, else the repo HEAD commit author.

    Raises CommitIdentityError when neither is available.
    """
    identity = _valid_commit_identity(pusher_name, pusher_email)
    if identity:
        return identity
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "log", "-1", "--format=%an|%ae",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0:
            name, sep, email = out.decode(errors="ignore").strip().rpartition("|")
            if sep:
                identity = _valid_commit_identity(name, email)
    except Exception as e:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        logger.warning(f"Could not read HEAD commit author in {workspace_path}: {e}")
    if identity:
        return identity
    raise CommitIdentityError(
        "No pusher identity is recorded for this commit and the repository HEAD author is unavailable; "
        "refusing to commit with an invented identity."
    )


async def _git_head_sha(workspace_path: str):
    """Returns the workspace HEAD commit SHA, or None if it cannot be read."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        out, _ = await proc.communicate()
        if proc.returncode != 0:
            return None
        return out.decode(errors="ignore").strip() or None
    except Exception as e:
        logger.warning(f"Could not read HEAD in {workspace_path}: {e}")
        return None


async def apply_codemender_fix(session_id: str, repo_name: str, branch: str, github_token: str, vuln_id: str) -> bool:
    """Runs cm fix in a dryrun workspace, commits, pushes, and creates/comments on the GitHub PR.

    Raises CommitIdentityError (before running cm fix) when no real committer identity is available.
    """
    import shutil
    import os
    from pathlib import Path
    from database import append_scan_step, update_scan_status
    
    workspace_path = f"/tmp/session-{session_id}"
    dryrun_path = f"/tmp/session-{session_id}-dryrun"
    from database import db
    doc_ref = db.collection("scans").document(session_id)
    doc = await asyncio.to_thread(doc_ref.get)
    scan_data = doc.to_dict() if doc.exists else {}
    try:
        commit_name, commit_email = await _resolve_commit_identity(
            workspace_path, scan_data.get("pusher_name"), scan_data.get("pusher_email")
        )
    except CommitIdentityError as identity_err:
        logger.error(f"Refusing to run cm fix for {vuln_id}: {identity_err}")
        append_scan_step(session_id, "error", f"Patch not generated for {vuln_id}: {identity_err}")
        raise
    
    # Pre-configure git credentials so that auto-commit picks them up
    try:
        proc_name = await asyncio.create_subprocess_exec("git", "config", "user.name", commit_name, cwd=workspace_path)
        await proc_name.wait()
        proc_email = await asyncio.create_subprocess_exec("git", "config", "user.email", commit_email, cwd=workspace_path)
        await proc_email.wait()
    except Exception as git_cfg_err:
        logger.warning(f"Failed to pre-configure git credentials in workspace: {git_cfg_err}")
    
    original_code = ""
    patched_code = ""
    filename = ""
    git_diff = ""

    try:
        from cm_tools import resolve_model, _run_cm_cmd, cm_telemetry_context, get_cm_telemetry_context
        fix_model = resolve_model("fix", session_id=session_id)
        append_scan_step(session_id, "fix", f"Executing CodeMender fix engine (cm fix {vuln_id} -y --model {fix_model})...")

        # Record HEAD so an auto-commit by the fix engine can be detected reliably afterwards
        pre_fix_head = await _git_head_sha(workspace_path)

        # 1. Run cm fix in the workspace through the shared hardened CLI runner: own process group,
        #    the CLI semaphore, the CM_FIX_TIMEOUT_SEC deadline (a timeout is never retried),
        #    transient-error retries, model fallback, the allowlisted env (GitHub tokens and webhook
        #    secrets never reach the CLI) and per-attempt token telemetry (logged there, exactly once).
        run_info = {}
        fix_error = None
        telemetry_scope = contextlib.nullcontext()
        if not get_cm_telemetry_context():
            # Dashboard Fix button: attribute the cm token rows to the scan's PR.
            telemetry_scope = cm_telemetry_context(
                pr_number=scan_data.get("pr_number"), event_type="dashboard", is_draft=scan_data.get("is_draft")
            )
        with telemetry_scope:
            try:
                await _run_cm_cmd(
                    ["cm", "fix", vuln_id, "-y", "--bypass-warning", "--model", fix_model], session_id, run_info=run_info
                )
            except Exception as run_err:
                fix_error = run_err
        duration = float(run_info.get("duration") or 0.0)
        logger.info(f"cm fix finished in {duration:.2f}s. Exit code: {run_info.get('returncode')}")
        
        fix_out = (run_info.get("stdout") or "").strip()
        fix_err = (run_info.get("stderr") or "").strip()
        logger.info(f"cm fix stdout:\n{fix_out}")
        logger.info(f"cm fix stderr:\n{fix_err}")

        # Save raw fix agent logs in database
        combined_fix_output = f"{fix_out}\n\n[STDERR]\n{fix_err}" if fix_err else fix_out
        update_scan_status(session_id, logs={"fix_output": combined_fix_output})

        # Parse CodeMender Session ID and upload research artifacts to GCS (blocking client: worker thread)
        cm_session_id = None
        session_id_match = re.search(r"Session:\s*([a-zA-Z0-9_-]+)", fix_out, re.IGNORECASE)
        if session_id_match:
            cm_session_id = session_id_match.group(1)
            logger.info(f"Detected CodeMender fix session ID: {cm_session_id}. Triggering GCS artifacts upload...")
            try:
                from gcs_helpers import upload_session_artifacts
                await asyncio.to_thread(upload_session_artifacts, session_id, cm_session_id)
            except Exception as upload_err:
                logger.error(f"Failed to upload GCS artifacts for fix session: {upload_err}")

        if fix_error is not None:
            if run_info.get("timed_out"):
                append_scan_step(
                    session_id, "error",
                    f"Fix engine timed out after running {duration:.0f}s (limit {float(run_info.get('timeout') or 0):.0f}s) "
                    f"for finding {vuln_id}; timeouts are not retried."
                )
            else:
                append_scan_step(
                    session_id, "error",
                    f"Fix engine failed for finding {vuln_id} (exit code {run_info.get('returncode')}): {redact(str(fix_error))}"
                )
            return False
            
        append_scan_step(session_id, "fix", "Fix engine completed successfully. Generating code patch diff...")



        # 2. Check if CodeMender automatically committed the fix (HEAD moved during cm fix)
        post_fix_head = await _git_head_sha(workspace_path)
        is_auto_committed = bool(pre_fix_head and post_fix_head and post_fix_head != pre_fix_head)
        logger.info(f"Git HEAD checks: pre_fix_head={pre_fix_head}, post_fix_head={post_fix_head} -> is_auto_committed={is_auto_committed}")

        if is_auto_committed:
            # CodeMender auto-committed. Diff against the pre-fix HEAD
            process = await asyncio.create_subprocess_exec(
                "git", "diff", "--name-only", pre_fix_head, "HEAD",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_path
            )
            stdout, stderr = await process.communicate()
            changed_files = stdout.decode(errors="replace").strip().splitlines()
            logger.info(f"git diff name-only (auto): changed_files={changed_files}, stderr={stderr.decode(errors='replace').strip()}")
        else:
            # Check uncommitted working directory changes
            process = await asyncio.create_subprocess_exec(
                "git", "diff", "--name-only",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_path
            )
            stdout, stderr = await process.communicate()
            changed_files = stdout.decode(errors="replace").strip().splitlines()
            logger.info(f"git diff name-only (manual): changed_files={changed_files}, stderr={stderr.decode(errors='replace').strip()}")

        source_changed_files = [f for f in changed_files if not _is_ignored_artifact_path(f)]
        if source_changed_files:
            changed_files = source_changed_files

        if changed_files:
            filename = changed_files[0]
            
            if is_auto_committed:
                # Read patched code from HEAD
                process = await asyncio.create_subprocess_exec(
                    "git", "show", f"HEAD:{filename}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                patched_code = stdout.decode(errors="replace").strip()

                # Read original code from the pre-fix HEAD
                process = await asyncio.create_subprocess_exec(
                    "git", "show", f"{pre_fix_head}:{filename}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                original_code = stdout.decode(errors="replace").strip()

                # Get git diff between the pre-fix HEAD and HEAD
                process = await asyncio.create_subprocess_exec(
                    "git", "diff", pre_fix_head, "HEAD", "--", *changed_files,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                git_diff = stdout.decode(errors="replace").strip()
                logger.info(f"git diff payload (auto): len={len(git_diff)}, stderr={stderr.decode(errors='replace').strip()}")
            else:
                # Read patched code from disk
                patched_file = Path(workspace_path) / filename
                if patched_file.exists():
                    patched_code = patched_file.read_text(encoding="utf-8", errors="replace")

                # Read original code from git HEAD
                process = await asyncio.create_subprocess_exec(
                    "git", "show", f"HEAD:{filename}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                original_code = stdout.decode(errors="replace").strip()

                # Get git diff
                process = await asyncio.create_subprocess_exec(
                    "git", "diff", "--", *changed_files,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                git_diff = stdout.decode(errors="replace").strip()
                logger.info(f"git diff payload (manual): len={len(git_diff)}, stderr={stderr.decode(errors='replace').strip()}")

        if not git_diff:
            logger.warning(f"No git diff generated by cm fix for finding {vuln_id}")
            append_scan_step(session_id, "error", f"No file changes were generated by the fix engine for finding {vuln_id}")
            return False

        patch_branch = f"codemender/patch-{session_id[:8]}"
        append_scan_step(session_id, "gitops", f"Setting up local patch branch '{patch_branch}'...")
        # Remotes are token-free, so branch/remote git commands go through GitWorkspace._run_command:
        # it injects the per-command auth header, redacts errors and raises on a non-zero exit.
        git_ws = GitWorkspace(session_id, repo=repo_name)
        git_ws._remember_token(github_token)
        
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

        try:
            if has_branch:
                # Checkout the existing branch and pull latest
                await git_ws._run_command(["git", "checkout", patch_branch], cwd=workspace_path)
                try:
                    # --ff-only: a failed pull never leaves a half-merged tree for the commit below.
                    await git_ws._run_command(["git", "pull", "--ff-only", "origin", patch_branch], cwd=workspace_path)
                except Exception as pull_err:
                    # Not fatal on its own (e.g. the remote branch was deleted); the push below decides.
                    pull_error = redact(str(pull_err))
                    logger.warning(f"git pull of {patch_branch} failed: {pull_error}")
                    append_scan_step(session_id, "warning", f"Could not update patch branch '{patch_branch}' from origin: {pull_error}")
            else:
                # Create new branch from base (-B also resets a stale local copy left by an earlier
                # attempt whose push failed, so its old content is never pushed as this patch)
                await git_ws._run_command(["git", "checkout", "-B", patch_branch], cwd=workspace_path)
        except Exception as branch_err:
            branch_error = redact(str(branch_err))
            logger.error(f"Could not switch to patch branch {patch_branch}: {branch_error}")
            append_scan_step(session_id, "error", f"Could not switch to patch branch '{patch_branch}'; the patch was not committed: {branch_error}")
            return False

        if not is_auto_committed:
            # Commit the fix manually with the resolved pusher / HEAD-author identity
            process = await asyncio.create_subprocess_exec(
                "git", "config", "user.name", commit_name,
                cwd=workspace_path
            )
            await process.wait()
            process = await asyncio.create_subprocess_exec(
                "git", "config", "user.email", commit_email,
                cwd=workspace_path
            )
            await process.wait()
            
            # Stage all fix changes (including new files), never CodeMender artifacts
            process = await asyncio.create_subprocess_exec(
                "git", "add", "-A", "--", ".", *_GIT_ADD_ARTIFACT_EXCLUDES,
                cwd=workspace_path
            )
            await process.wait()
            if process.returncode != 0:
                append_scan_step(session_id, "error", f"git add failed with exit code {process.returncode}; patch was not committed.")
                return False
            process = await asyncio.create_subprocess_exec(
                "git", "commit", "-m", f"CodeMender: Automatic patch for vulnerability {vuln_id}",
                cwd=workspace_path
            )
            await process.wait()
            if process.returncode != 0:
                append_scan_step(session_id, "error", f"git commit failed with exit code {process.returncode}; patch was not committed.")
                return False
            append_scan_step(session_id, "gitops", "Committed patch changes to local git history.")
        else:
            append_scan_step(session_id, "gitops", "Fix was auto-committed by CodeMender engine.")
        
        # Push the patch branch (authenticated). A failed push means the patch was not submitted:
        # report failure and never record the proposal.
        append_scan_step(session_id, "gitops", f"Pushing patch branch '{patch_branch}' to remote origin...")
        try:
            await git_ws._run_command(["git", "push", "origin", patch_branch], cwd=workspace_path)
        except Exception as push_err:
            push_error = redact(str(push_err))
            logger.error(f"git push of {patch_branch} failed: {push_error}")
            append_scan_step(session_id, "error", f"Push of patch branch '{patch_branch}' failed; the patch was not submitted: {push_error}")
            return False

        # 3. Check if PR exists on GitHub
        pr_number, pr_url = await get_existing_pr(repo_name, patch_branch, github_token)
        if pr_number:
            logger.info(f"Found existing open PR #{pr_number} from head {patch_branch} to base {branch}")
            append_scan_step(session_id, "gitops", f"Found existing open GitHub PR #{pr_number} for this patch branch")
        else:
            logger.info(f"No existing PR found for branch {patch_branch}. PR creation will be deferred.")
            append_scan_step(session_id, "gitops", "No existing PR found. Draft PR creation deferred to developer action.")

        # Get actual patch commit SHA
        process = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "HEAD",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        stdout, _ = await process.communicate()
        patch_commit_sha = stdout.decode().strip()
        logger.info(f"Retrieved actual patch commit SHA: {patch_commit_sha}")

        # 5. Save proposed patch to Firestore (keyed by session_id / commit_sha)
        save_patch_proposal(
            commit_sha=session_id,
            branch_name=branch,
            filename=filename,
            git_diff=git_diff,
            patched_code=patched_code,
            pr_number=pr_number,
            patch_commit_sha=patch_commit_sha
        )
        if pr_number:
            update_scan_status(session_id, pr_number=pr_number)
            append_scan_step(session_id, "gitops", f"Saved proposed patch proposal document to database for PR #{pr_number}")
            
            # 6. Post comment containing patch to PR
            comment_body = f"""### 🛡️ CodeMender Proposed Security Patch
    
We found a security vulnerability in commit **{session_id}** at `{filename}`.
    
#### Proposed Fix Diff:
```diff
{git_diff}
```
    
Reply with `/approve` to automatically commit and apply this patch to your branch!
"""
            await post_pr_comment(repo_name, pr_number, comment_body, github_token)
            logger.info(f"Posted patch proposal comment to PR #{pr_number}")
            append_scan_step(session_id, "gitops", f"Posted proposed patch diff comment to Pull Request #{pr_number}")
        else:
            append_scan_step(session_id, "gitops", "Staged patch files. Waiting for manual Draft PR creation.")

        return True

    except Exception as e:
        logger.error(f"Execution of fix generation or GitHub posting failed: {e}", exc_info=True)
        return False
    finally:
        if os.path.exists(dryrun_path):
            shutil.rmtree(dryrun_path)


_EXPLOIT_REPORT_SYSTEM_INSTRUCTION = (
    "You are a Senior Security Research Engineer. Review the attached sandbox execution trace logs of an exploit agent verifying a vulnerability. "
    "Compile a clear, markdown-formatted Proof of Concept (PoC) Exploit Report.\n\n"
    "Your report MUST contain:\n"
    "1. **Vulnerability Summary**: Brief explanation of the flaw and why it was verified active.\n"
    "2. **Target Endpoint**: URL path and HTTP method target.\n"
    "3. **PoC Payload**: The exact payload (HTTP Body, JSON properties, or shell parameters) used to trigger the exploit.\n"
    "4. **Evidence / Leakage**: The specific response data, headers, or state change that proved the vulnerability is active.\n"
    "5. **Mitigation Recommendation**: Clean code fix guidelines.\n\n"
    "Keep your report concise, formatted with clear headings, and avoid verbose introductions."
)


def _log_exploit_report_usage(response, session_id: str, repo_name: str, duration: float):
    try:
        from database import log_token_usage
        usage = response.usage_metadata
        log_token_usage(
            session_id=session_id,
            repo_name=repo_name,
            task_type="exploit_report_formatter",
            model_name=MODEL_NAME,
            input_tokens=usage.prompt_token_count,
            output_tokens=usage.candidates_token_count,
            cached_tokens=usage.cached_content_token_count or 0,
            thoughts_tokens=getattr(usage, "thoughts_token_count", 0) or 0,
            duration_sec=duration
        )
    except Exception as log_err:
        logger.warning(f"Failed to log token usage: {log_err}")


def generate_ai_exploit_report(verify_output: str, session_id: str = "", repo_name: str = "") -> str:
    """Generates a structured security Markdown PoC Exploit Report using Gemini.

    Synchronous; bounded by the client's GEMINI_TIMEOUT_S HTTP timeout. From async code prefer
    generate_ai_exploit_report_async so the event loop is not blocked.
    """
    logger.info("Generating AI Exploit Verification Report using Gemini...")
    try:
        start_time = time.time()
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=verify_output,
            config=types.GenerateContentConfig(
                system_instruction=_EXPLOIT_REPORT_SYSTEM_INSTRUCTION,
                temperature=0.2
            )
        )
        _log_exploit_report_usage(response, session_id, repo_name, time.time() - start_time)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Failed to generate AI exploit report using Gemini: {_err_text(e)}")
        return f"⚠️ **Exploit Verification Report generation failed:** {_err_text(e)}"


async def generate_ai_exploit_report_async(verify_output: str, session_id: str = "", repo_name: str = "") -> str:
    """Async variant of generate_ai_exploit_report (async client + GEMINI_TIMEOUT_S guard); same return contract."""
    logger.info("Generating AI Exploit Verification Report using Gemini (async)...")
    try:
        start_time = time.time()
        response = await asyncio.wait_for(
            client.aio.models.generate_content(
                model=MODEL_NAME,
                contents=verify_output,
                config=types.GenerateContentConfig(
                    system_instruction=_EXPLOIT_REPORT_SYSTEM_INSTRUCTION,
                    temperature=0.2
                )
            ),
            timeout=GEMINI_TIMEOUT_S,
        )
        _log_exploit_report_usage(response, session_id, repo_name, time.time() - start_time)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Failed to generate AI exploit report using Gemini: {_err_text(e)}")
        return f"⚠️ **Exploit Verification Report generation failed:** {_err_text(e)}"




