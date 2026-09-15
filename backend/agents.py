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

client = genai.Client(
    vertexai=True,
    project=PROJECT_ID,
    location=LOCATION
)

# Use standard model name for Vertex AI (configurable via GEMINI_MODEL)
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

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
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction="You are a data alignment helper. Create a 1-to-1 mapping between original findings and new findings based on matching fields. Output structured JSON.",
                response_mime_type="application/json",
                response_schema=IDMapping,
            ),
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
        logger.error(f"Failed to map finding IDs using Gemini: {e}")
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
        response = client.models.generate_content(
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
        logger.error(f"QA Agent execution failed: {e}")
        return QAReport(matches_intent=False, feedback=f"QA Agent execution failed: {e}")

async def run_semantic_agent(code: str, session_id: str = "", repo_name: str = "") -> SemanticReport:
    try:
        import time
        start_time = time.time()
        response = client.models.generate_content(
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
        logger.error(f"Semantic Agent execution failed: {e}")
        return SemanticReport(has_secrets=False, hygiene_issues=[f"Semantic Agent execution failed: {e}"])

# CodeMender Triage and Patching Handlers
import asyncio
from cm_tools import cm_init, cm_find, cm_verify, cm_fix
from git_manager import get_existing_pr, create_draft_pr
from github_helpers import post_pr_comment
from database import save_patch_proposal

class Finding(BaseModel):
    id: str = Field(description="The unique ID of the vulnerability.")
    severity: str = Field(description="The severity level of the vulnerability (e.g. CRITICAL, HIGH, MEDIUM, LOW).")
    filepath: str = Field(description="The file path containing the vulnerability.")
    vuln_type: str = Field(description="The type/category of the vulnerability.")
    description: str = Field(description="A brief description of the vulnerability.")

class TriageReport(BaseModel):
    findings: list[Finding] = Field(description="The list of vulnerabilities parsed from the log table.")

async def run_triage_agent(session_id: str, filepath: str, repo_name: str = "") -> list[dict]:
    """Runs cm_find on the target file and parses findings into structured JSON using Gemini."""
    from database import update_scan_status, append_scan_step
    try:
        # 0. Initialize CodeMender workspace
        try:
            await cm_init(session_id)
        except Exception as e:
            logger.warning(f"cm_init failed or already initialized: {e}")

        # 1. Run the local find command directly
        stdout = await cm_find(session_id, filepath)
        logger.info(f"cm_find stdout:\n{stdout}")
        
        # Save raw scan stdout to Firestore
        update_scan_status(session_id, logs={"find_output": stdout})
        append_scan_step(session_id, "find", "Scanner command executed. Parsing results via triage agent...")
        
        # If stdout is empty, return early
        if not stdout.strip():
            append_scan_step(session_id, "find", "No raw vulnerabilities found by scanner client.")
            return []
            
        # 2. Call Gemini to parse the table stdout
        import time
        start_time = time.time()
        response = client.models.generate_content(
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
        )
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
            
        parsed = json.loads(response.text)
        report = TriageReport(**parsed)
        results = []
        for finding in report.findings:
            d = finding.model_dump()
            raw_sev = str(d.get("severity", "HIGH")).upper()
            clean_sev = raw_sev.replace("🔴", "").replace("🟠", "").replace("🟡", "").replace("🔵", "").replace("⚪", "").strip()
            d["severity"] = "CRITICAL" if "CRITICAL" in clean_sev else "HIGH" if "HIGH" in clean_sev else "MEDIUM" if "MEDIUM" in clean_sev else "LOW" if "LOW" in clean_sev else "HIGH"
            d["status"] = "DETECTED"
            results.append(d)
            
        append_scan_step(session_id, "find", f"Triage parser successfully identified {len(results)} vulnerabilities.")
        return results
    except Exception as e:
        logger.error(f"Triage Agent execution failed: {e}")
        append_scan_step(session_id, "warning", f"Triage parser encountered error: {str(e)}.")
        return []



async def apply_codemender_fix(session_id: str, repo_name: str, branch: str, github_token: str, vuln_id: str) -> bool:
    """Runs cm fix in a dryrun workspace, commits, pushes, and creates/comments on the GitHub PR."""
    import shutil
    import os
    from pathlib import Path
    from database import append_scan_step, update_scan_status
    
    workspace_path = f"/tmp/session-{session_id}"
    dryrun_path = f"/tmp/session-{session_id}-dryrun"
    from database import db
    doc_ref = db.collection("scans").document(session_id)
    doc = doc_ref.get()
    scan_data = doc.to_dict() if doc.exists else {}
    BOT_EMAIL = scan_data.get("pusher_email") or "agent@codemender.ai"
    BOT_NAME = scan_data.get("pusher_name") or "CodeMender Agent"
    
    # Pre-configure git credentials so that auto-commit picks them up
    try:
        proc_name = await asyncio.create_subprocess_exec("git", "config", "user.name", BOT_NAME, cwd=workspace_path)
        await proc_name.wait()
        proc_email = await asyncio.create_subprocess_exec("git", "config", "user.email", BOT_EMAIL, cwd=workspace_path)
        await proc_email.wait()
    except Exception as git_cfg_err:
        logger.warning(f"Failed to pre-configure git credentials in workspace: {git_cfg_err}")
    
    original_code = ""
    patched_code = ""
    filename = ""
    git_diff = ""

    try:
        append_scan_step(session_id, "fix", f"Executing CodeMender fix engine (cm fix {vuln_id} -y)...")
        start_fix_time = time.time()
        cmd_env = os.environ.copy()
        cm_proj = os.getenv("CODEMENDER_PROJECT_ID", os.getenv("GOOGLE_CLOUD_PROJECT", "YOUR_PROJECT_ID"))
        cmd_env["GOOGLE_CLOUD_PROJECT"] = cm_proj
        cmd_env["GCLOUD_PROJECT"] = cm_proj

        # 1. Run cm fix directly in workspace path
        process = await asyncio.create_subprocess_exec(
            "cm", "fix", vuln_id, "-y", "--bypass-warning",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path,
            env=cmd_env
        )

        stdout, stderr = await process.communicate(input=b"y\n")
        duration = time.time() - start_fix_time
        logger.info(f"cm fix completed in {duration:.2f}s. Exit code: {process.returncode}")
        
        fix_out = stdout.decode().strip()
        fix_err = stderr.decode().strip()
        logger.info(f"cm fix stdout:\n{fix_out}")
        logger.info(f"cm fix stderr:\n{fix_err}")

        # Save raw fix agent logs in database
        combined_fix_output = f"{fix_out}\n\n[STDERR]\n{fix_err}" if fix_err else fix_out
        update_scan_status(session_id, logs={"fix_output": combined_fix_output})

        # Parse and log token usage for cm fix task
        try:
            from database import parse_and_log_cm_session, get_scan_repo_name
            from cm_tools import resolve_model
            fix_model = resolve_model("fix", session_id=session_id)
            repo_name = get_scan_repo_name(session_id)
            parse_and_log_cm_session(
                session_id=session_id,
                repo_name=repo_name,
                task_type="cm_fix",
                model_name=fix_model,
                output_text=combined_fix_output,
                duration_sec=duration
            )
        except Exception as parse_err:
            logger.warning(f"Failed to log cm_fix token usage: {parse_err}")

        # Parse CodeMender Session ID and upload research artifacts to GCS
        import re
        cm_session_id = None
        session_id_match = re.search(r"Session:\s*([a-zA-Z0-9_-]+)", fix_out, re.IGNORECASE)
        if session_id_match:
            cm_session_id = session_id_match.group(1)
            logger.info(f"Detected CodeMender fix session ID: {cm_session_id}. Triggering GCS artifacts upload...")
            try:
                from gcs_helpers import upload_session_artifacts
                upload_session_artifacts(session_id, cm_session_id)
            except Exception as upload_err:
                logger.error(f"Failed to upload GCS artifacts for fix session: {upload_err}")

        # Parse and log token usage to BigQuery
        try:
            from cm_tools import parse_session_token_usage
            from database import log_token_usage
            tokens_data = parse_session_token_usage(combined_output=combined_fix_output, cm_session_id=cm_session_id)
            if tokens_data["input_tokens"] > 0 or tokens_data["output_tokens"] > 0:
                logger.info(f"Logging CodeMender CLI fix tokens -> Input: {tokens_data['input_tokens']}, Output: {tokens_data['output_tokens']}, Cached: {tokens_data['cached_tokens']}, Thoughts: {tokens_data['thoughts_tokens']}, Duration: {duration:.2f}s")
                log_token_usage(
                    session_id=session_id,
                    repo_name=repo_name,
                    task_type="cm_fix",
                    model_name=fix_model,
                    input_tokens=tokens_data["input_tokens"],
                    output_tokens=tokens_data["output_tokens"],
                    cached_tokens=tokens_data["cached_tokens"],
                    thoughts_tokens=tokens_data["thoughts_tokens"],
                    duration_sec=duration
                )
        except Exception as token_err:
            logger.warning(f"Failed to parse and log tokens for cm fix: {token_err}")

        if process.returncode != 0:
            append_scan_step(session_id, "error", f"Fix engine failed with exit code {process.returncode}. Stderr: {fix_err}")
            return False
            
        append_scan_step(session_id, "fix", "Fix engine completed successfully. Generating code patch diff...")



        # 2. Check if CodeMender automatically committed the fix
        # 2. Check if there are uncommitted working directory changes
        process = await asyncio.create_subprocess_exec(
            "git", "status", "--porcelain",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        stdout, _ = await process.communicate()
        has_working_changes = bool(stdout.decode().strip())

        # Check if HEAD~1 exists
        process = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "--verify", "HEAD~1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=workspace_path
        )
        await process.wait()
        has_parent = (process.returncode == 0)

        is_auto_committed = (not has_working_changes) and has_parent
        logger.info(f"Git status checks: has_working_changes={has_working_changes}, has_parent={has_parent} -> is_auto_committed={is_auto_committed}")

        if is_auto_committed:
            # CodeMender auto-committed. Diff against HEAD~1
            process = await asyncio.create_subprocess_exec(
                "git", "diff", "--name-only", "HEAD~1", "HEAD",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_path
            )
            stdout, stderr = await process.communicate()
            changed_files = stdout.decode().strip().splitlines()
            logger.info(f"git diff name-only (auto): changed_files={changed_files}, stderr={stderr.decode().strip()}")
        else:
            # Check uncommitted working directory changes
            process = await asyncio.create_subprocess_exec(
                "git", "diff", "--name-only",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workspace_path
            )
            stdout, stderr = await process.communicate()
            changed_files = stdout.decode().strip().splitlines()
            logger.info(f"git diff name-only (manual): changed_files={changed_files}, stderr={stderr.decode().strip()}")

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
                patched_code = stdout.decode().strip()

                # Read original code from HEAD~1
                process = await asyncio.create_subprocess_exec(
                    "git", "show", f"HEAD~1:{filename}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                original_code = stdout.decode().strip()

                # Get git diff between HEAD~1 and HEAD
                process = await asyncio.create_subprocess_exec(
                    "git", "diff", "HEAD~1", "HEAD", "--", filename,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                git_diff = stdout.decode().strip()
                logger.info(f"git diff payload (auto): len={len(git_diff)}, stderr={stderr.decode().strip()}")
            else:
                # Read patched code from disk
                patched_file = Path(workspace_path) / filename
                if patched_file.exists():
                    patched_code = patched_file.read_text(encoding="utf-8")

                # Read original code from git HEAD
                process = await asyncio.create_subprocess_exec(
                    "git", "show", f"HEAD:{filename}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                original_code = stdout.decode().strip()

                # Get git diff
                process = await asyncio.create_subprocess_exec(
                    "git", "diff", filename,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=workspace_path
                )
                stdout, stderr = await process.communicate()
                git_diff = stdout.decode().strip()
                logger.info(f"git diff payload (manual): len={len(git_diff)}, stderr={stderr.decode().strip()}")

        if not git_diff:
            logger.warning(f"No git diff generated by cm fix for finding {vuln_id}")
            append_scan_step(session_id, "error", f"No file changes were generated by the fix engine for finding {vuln_id}")
            return False

        patch_branch = f"codemender/patch-{session_id[:8]}"
        append_scan_step(session_id, "gitops", f"Setting up local patch branch '{patch_branch}'...")
        
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
            process = await asyncio.create_subprocess_exec(
                "git", "checkout", patch_branch,
                cwd=workspace_path
            )
            await process.wait()
            process = await asyncio.create_subprocess_exec(
                "git", "pull", "origin", patch_branch,
                cwd=workspace_path
            )
            await process.wait()
        else:
            # Create new branch from base
            process = await asyncio.create_subprocess_exec(
                "git", "checkout", "-b", patch_branch,
                cwd=workspace_path
            )
            await process.wait()

        if not is_auto_committed:
            # Commit the fix manually
            process = await asyncio.create_subprocess_exec(
                "git", "config", "user.name", BOT_NAME,
                cwd=workspace_path
            )
            await process.wait()
            process = await asyncio.create_subprocess_exec(
                "git", "config", "user.email", BOT_EMAIL,
                cwd=workspace_path
            )
            await process.wait()
            
            process = await asyncio.create_subprocess_exec(
                "git", "commit", "-am", f"CodeMender: Automatic patch for vulnerability {vuln_id} [skip ci]",
                cwd=workspace_path
            )
            await process.wait()
            append_scan_step(session_id, "gitops", "Committed patch changes to local git history.")
        else:
            append_scan_step(session_id, "gitops", "Fix was auto-committed by CodeMender engine.")
        
        # Push the patch branch
        append_scan_step(session_id, "gitops", f"Pushing patch branch '{patch_branch}' to remote origin...")
        process = await asyncio.create_subprocess_exec(
            "git", "push", "origin", patch_branch,
            cwd=workspace_path
        )
        await process.wait()

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


def generate_ai_exploit_report(verify_output: str, session_id: str = "", repo_name: str = "") -> str:
    """Generates a structured security Markdown PoC Exploit Report using Gemini."""
    logger.info("Generating AI Exploit Verification Report using Gemini...")
    system_instruction = (
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
    
    try:
        import time
        start_time = time.time()
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=verify_output,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2
            )
        )
        duration = time.time() - start_time
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
            
        return response.text.strip()
    except Exception as e:
        logger.error(f"Failed to generate AI exploit report using Gemini: {e}")
        return f"⚠️ **Exploit Verification Report generation failed:** {str(e)}"




