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

import asyncio
import json
import logging
import os
import re
import glob
from pathlib import Path

logger = logging.getLogger(__name__)

# Fallback definition for @tool if the library doesn't export it
try:
    from google.antigravity.tools import tool
except ImportError:
    def tool(func):
        return func

from database import update_scan_status, log_token_usage, get_scan_repo_name, parse_and_log_cm_session

def parse_session_token_usage(combined_output: str = "", log_file_path: str = None, cm_session_id: str = None, max_age_sec: float = 300.0) -> dict:
    """
    Extracts comprehensive token metrics (input, output, cached, thoughts) from CodeMender logs.
    Prioritizes JSONL interaction events from ~/.codemender/logs/sessions/ for exact turn metrics,
    falling back to regular expressions over plain text .log files.
    """
    import time
    input_tokens = 0
    output_tokens = 0
    cached_tokens = 0
    thoughts_tokens = 0
    
    # 1. Detect CodeMender session ID if not explicitly provided
    if not cm_session_id and combined_output:
        sess_match = re.search(r"Session:\s*([a-zA-Z0-9_-]+)", combined_output, re.IGNORECASE)
        if sess_match:
            cm_session_id = sess_match.group(1).strip()
            
    # 2. Check for matching JSONL session logs in ~/.codemender/logs/sessions/
    logs_sessions_dir = os.path.expanduser("~/.codemender/logs/sessions")
    found_jsonl_metrics = False
    
    if os.path.exists(logs_sessions_dir):
        jsonl_candidates = []
        for root, _, files in os.walk(logs_sessions_dir):
            for file in files:
                if file.endswith(".jsonl"):
                    full_path = os.path.join(root, file)
                    mtime = os.path.getmtime(full_path)
                    if time.time() - mtime < max_age_sec:
                        jsonl_candidates.append((mtime, full_path))
        
        jsonl_candidates.sort(key=lambda x: x[0], reverse=True)
        
        target_jsonl_files = []
        if cm_session_id:
            for _, path in jsonl_candidates:
                if cm_session_id in path:
                    target_jsonl_files.append(path)
        
        if not target_jsonl_files and jsonl_candidates:
            target_jsonl_files.append(jsonl_candidates[0][1])
            
        for jsonl_path in target_jsonl_files:
            try:
                with open(jsonl_path, "r", encoding="utf-8") as jf:
                    for line in jf:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            if item.get("type") == "interaction":
                                input_tokens += int(item.get("input", 0))
                                output_tokens += int(item.get("output", 0))
                                cached_tokens += int(item.get("cached", 0))
                                thoughts_tokens += int(item.get("thought", 0))
                                found_jsonl_metrics = True
                        except Exception:
                            pass
            except Exception as e:
                logger.warning(f"Error reading JSONL session file {jsonl_path}: {e}")
                
            if found_jsonl_metrics:
                break
                
    # 3. Fallback: Parse .log plain text files if JSONL was not found
    if not found_jsonl_metrics or (input_tokens == 0 and output_tokens == 0):
        log_content = ""
        if not log_file_path and combined_output:
            log_path_match = re.search(r"Session log:\s*([^\s\n]+)", combined_output)
            if log_path_match:
                log_file_path = log_path_match.group(1).strip()
                
        if log_file_path and os.path.exists(log_file_path):
            try:
                with open(log_file_path, "r", encoding="utf-8") as lf:
                    log_content = lf.read()
            except Exception:
                pass
        else:
            logs_dir = os.path.expanduser("~/.codemender/logs")
            if os.path.exists(logs_dir):
                log_files = glob.glob(os.path.join(logs_dir, "*.log"))
                completed_logs = [lf for lf in log_files if not lf.endswith("_pending.log")]
                completed_logs.sort(key=os.path.getmtime, reverse=True)
                if completed_logs and (time.time() - os.path.getmtime(completed_logs[0]) < max_age_sec):
                    try:
                        with open(completed_logs[0], "r", encoding="utf-8") as lf:
                            log_content = lf.read()
                    except Exception:
                        pass
                        
        if not log_content and combined_output:
            log_content = combined_output
            
        if log_content:
            token_pattern = r"Tokens:\s*([0-9.]+[k]?)\s*in\s*/\s*([0-9.]+[k]?)\s*out"
            matches = re.findall(token_pattern, log_content, re.IGNORECASE)
            
            def to_num(s):
                s = str(s).strip().lower()
                if s.endswith("k"):
                    return int(float(s[:-1]) * 1000)
                return int(float(s))
                
            for inp_str, out_str in matches:
                input_tokens += to_num(inp_str)
                output_tokens += to_num(out_str)
                
            cached_matches = re.findall(r"cached:\s*([0-9.]+[k]?)", log_content, re.IGNORECASE)
            for c_str in cached_matches:
                cached_tokens += to_num(c_str)
                
            thought_matches = re.findall(r"thought[s]?:\s*([0-9.]+[k]?)", log_content, re.IGNORECASE)
            for t_str in thought_matches:
                thoughts_tokens += to_num(t_str)

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cached_tokens": cached_tokens,
        "thoughts_tokens": thoughts_tokens,
        "total_tokens": input_tokens + output_tokens + thoughts_tokens
    }

async def _run_cm_cmd(cmd: list, session_id: str) -> str:
    cwd = f"/tmp/session-{session_id}"
    cmd_str = " ".join(cmd)
    logger.info(f"Running cm command: {cmd_str} in CWD: {cwd}")
    
    from database import append_scan_step
    
    # Update progress status in Firestore
    status_msg = "Running CodeMender task"
    step_type = "info"
    if "verify" in cmd:
        status_msg = "Verifying vulnerability exploitability (cm verify)"
        step_type = "verify"
    elif "find" in cmd:
        status_msg = "Scanning workspace code (cm find)"
        step_type = "find"
    elif "fix" in cmd:
        status_msg = "Generating and validating security patch (cm fix)"
        step_type = "fix"
    elif "init" in cmd:
        status_msg = "Initializing CodeMender workspace (cm init)"
        step_type = "workspace"
        
    max_retries = 3
    retry_delay = 5.0
    stdout, stderr = b"", b""
    import time
    import re
    import random
    import hashlib
    
    # Global concurrency gate for CLI sessions to prevent outbound TLS socket saturation on Cloud Run
    global _CLI_SEMAPHORE
    if "_CLI_SEMAPHORE" not in globals() or _CLI_SEMAPHORE is None:
        _CLI_SEMAPHORE = asyncio.Semaphore(1)
        
    cmd_timeout = 480.0 if ("verify" in cmd or "fix" in cmd) else 360.0
    
    # Calculate isolated port for this workspace session to avoid port clashes
    session_port = 5000 + (int(hashlib.md5(session_id.encode()).hexdigest()[:4], 16) % 1000)
    
    async with _CLI_SEMAPHORE:
        for attempt in range(max_retries):
            update_scan_status(commit_sha=session_id, status="RUNNING", message=status_msg)
            append_scan_step(session_id, step_type, f"Executing CodeMender command: {cmd_str} (Attempt {attempt + 1}/{max_retries})")
            
            cmd_env = os.environ.copy()
            cm_proj = os.getenv("CODEMENDER_PROJECT_ID", os.getenv("GOOGLE_CLOUD_PROJECT", "YOUR_PROJECT_ID"))
            cmd_env["GOOGLE_CLOUD_PROJECT"] = cm_proj
            cmd_env["GCLOUD_PROJECT"] = cm_proj
            cmd_env["PORT"] = str(session_port)  # Isolated workspace port

            process = await asyncio.create_subprocess_exec(
                cmd[0],
                *cmd[1:],
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=cmd_env
            )

            start_time = time.time()
            timeout_occurred = False
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(input=b"y\n"), timeout=cmd_timeout)
            except asyncio.TimeoutError:
                timeout_occurred = True
                logger.warning(f"Command '{cmd_str}' timed out (attempt {attempt + 1}/{max_retries}). Terminating...")
                append_scan_step(session_id, step_type, f"Command timed out (attempt {attempt + 1}/{max_retries}): {cmd_str}")
                try:
                    process.kill()
                except Exception:
                    pass
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
                except Exception:
                    pass
                    
            duration = time.time() - start_time
            
            # Parse and log token usage for this attempt immediately using the unified parser
            try:
                combined_output = stdout.decode(errors="ignore") + "\n" + stderr.decode(errors="ignore")
                log_file_path = None
                log_path_match = re.search(r"Session log:\s*([^\s\n]+)", combined_output)
                if log_path_match:
                    log_file_path = log_path_match.group(1).strip()
                    
                task = "cm_find"
                if "verify" in cmd:
                    task = "cm_verify"
                elif "fix" in cmd:
                    task = "cm_fix"
                elif "init" in cmd:
                    task = "cm_init"
                    
                model = resolve_model(task, requested_model=None, session_id=session_id)
                if "--model" in cmd:
                    try:
                        model_idx = cmd.index("--model")
                        if model_idx + 1 < len(cmd):
                            model = resolve_model(task, requested_model=cmd[model_idx + 1], session_id=session_id)
                    except Exception:
                        pass
                        
                repo_name = get_scan_repo_name(session_id)
                parse_and_log_cm_session(
                    session_id=session_id,
                    repo_name=repo_name,
                    task_type=task,
                    model_name=model,
                    output_text=combined_output,
                    duration_sec=duration,
                    log_file_path=log_file_path
                )
            except Exception as parse_err:
                logger.warning(f"Failed to parse and log CodeMender CLI token usage: {parse_err}")

            # Handle attempt results
            if timeout_occurred:
                if attempt == max_retries - 1:
                    raise RuntimeError(f"CodeMender command '{cmd_str}' timed out after 600 seconds.")
                await asyncio.sleep(retry_delay + random.uniform(1.0, 4.0))
                continue
                
            if process.returncode == 0:
                break
                
            err_msg = stderr.decode(errors="ignore").strip()
            if attempt == max_retries - 1:
                logger.error(f"CM command failed: {cmd_str}. Error: {err_msg}")
                append_scan_step(session_id, step_type, f"Command failed: {cmd_str}. Error: {err_msg}")
                raise RuntimeError(f"CodeMender command failed: {err_msg}")
                
            logger.warning(f"Command failed (attempt {attempt + 1}/{max_retries}). Retrying in {retry_delay}s... Error: {err_msg}")
            append_scan_step(session_id, step_type, f"Command failed (attempt {attempt + 1}/{max_retries}). Retrying: {err_msg}")
            await asyncio.sleep(retry_delay + random.uniform(1.0, 4.0))
            
        stdout_str = stdout.decode().strip()
        return stdout_str


@tool
def resolve_model(task_type: str = "scan", requested_model: str = None, session_id: str = None) -> str:
    """Resolves the Gemini model based on precedence hierarchy:
    1. Explicit requested_model (e.g. from PR flag --model=pro)
    2. .codemender.yaml in workspace (/tmp/session-{session_id}/.codemender.yaml)
    3. Environment variables (CODEMENDER_FIX_MODEL, CODEMENDER_SCAN_MODEL, etc.)
    4. Default fallback: gemini-3.5-flash
    """
    if requested_model:
        req = requested_model.strip().lower()
        if req in ("pro", "gemini-pro", "1.5-pro", "gemini-1.5-pro", "3.1-pro", "gemini-3.1-pro", "3.1-pro-preview", "gemini-3.1-pro-preview"):
            return "gemini-3.1-pro-preview"
        elif req in ("3.5-flash", "gemini-3.5-flash", "flash", "gemini-flash", "3-flash", "gemini-3-flash", "3.0-flash", "gemini-3.0-flash", "gemini-3.0", "3-flash-preview", "gemini-3-flash-preview", "2.5-flash", "gemini-2.5-flash"):
            return "gemini-3.5-flash"
        elif req in ("3.6-flash", "gemini-3.6-flash"):
            return "gemini-3.6-flash"
        elif req in ("3.7-flash", "gemini-3.7-flash"):
            return "gemini-3.7-flash"
        return requested_model.strip()

    # Check .codemender.yaml in workspace if available
    if session_id:
        workspace_cfg = Path(f"/tmp/session-{session_id}") / ".codemender.yaml"
        if workspace_cfg.exists():
            try:
                import yaml
                with open(workspace_cfg, "r") as f:
                    cfg = yaml.safe_load(f) or {}
                models_cfg = cfg.get("models", {})
                if task_type in models_cfg:
                    return models_cfg[task_type]
                if "default" in models_cfg:
                    return models_cfg["default"]
            except Exception:
                pass

    # Check environment variables
    env_task_var = f"CODEMENDER_{task_type.upper()}_MODEL"
    if os.getenv(env_task_var):
        return os.getenv(env_task_var)
    if os.getenv("CODEMENDER_MODEL"):
        return os.getenv("CODEMENDER_MODEL")

    return "gemini-3.5-flash"

@tool
async def cm_init(session_id: str) -> str:
    """Initializes the CodeMender workspace.

    Args:
        session_id: The unique identifier of the active session.
    """
    cmd = ["cm", "init"]
    return await _run_cm_cmd(cmd, session_id)

@tool
async def cm_find(session_id: str, filepath: str, model: str = None) -> str:
    """Finds vulnerabilities in the specified file using the CodeMender CLI.

    Args:
        session_id: The unique identifier of the active session.
        filepath: The path of the file to scan.
        model: Optional model override.
    """
    selected_model = resolve_model("scan", model, session_id)
    cmd = ["cm", "find", filepath, "-y", "--model", selected_model]
    return await _run_cm_cmd(cmd, session_id)

@tool
async def cm_verify(session_id: str, vuln_id: str, model: str = None) -> str:
    """Verifies a vulnerability by running a sandboxed exploit simulation.

    Args:
        session_id: The unique identifier of the active session.
        vuln_id: The vulnerability finding ID.
        model: Optional model override.
    """
    selected_model = resolve_model("verify", model, session_id)
    cmd = ["cm", "verify", vuln_id, "-y", "--bypass-warning", "--model", selected_model]
    return await _run_cm_cmd(cmd, session_id)

@tool
async def cm_fix(session_id: str, vuln_id: str, model: str = None) -> str:
    """Generates and applies a security patch for a vulnerability.

    Args:
        session_id: The unique identifier of the active session.
        vuln_id: The vulnerability finding ID.
        model: Optional model override.
    """
    selected_model = resolve_model("fix", model, session_id)
    cmd = ["cm", "fix", vuln_id, "-y", "--model", selected_model]

    cwd = f"/tmp/session-{session_id}"
    try:
        output = await _run_cm_cmd(cmd, session_id)
        logger.info(f"cm fix completed successfully. Output: {output}")
        
        # Git diff to capture the generated patch
        process = await asyncio.create_subprocess_exec(
            "git",
            "diff",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await process.communicate()
        git_diff = stdout.decode().strip()
        
        return json.dumps({
            "status": "success",
            "git_diff": git_diff
        })
    except Exception as e:
        return json.dumps({
            "status": "error",
            "message": str(e)
        })
