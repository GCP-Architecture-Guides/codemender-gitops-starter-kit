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
import math
import os
import random
import re
import signal
import time
from pathlib import Path

from log_redaction import redact
from task_context import (
    TaskCancelled,
    current_cancel_check,
    get_telemetry_context as get_cm_telemetry_context,
    reset_telemetry_context as reset_cm_telemetry_context,
    set_telemetry_context as set_cm_telemetry_context,
    telemetry_context as cm_telemetry_context,
)

logger = logging.getLogger(__name__)

# Fallback definition for @tool if the library doesn't export it
try:
    from google.antigravity.tools import tool
except ImportError:
    def tool(func):
        return func

from database import update_scan_status, log_token_usage, get_scan_repo_name
import hashlib

def generate_vulnerability_fingerprint(
    repo_name: str,
    file_path: str,
    enclosing_scope: str = "global",
    cwe: str = "",
    vuln_type: str = "",
    code_sink: str = ""
) -> tuple[str, str]:
    """
    Computes a deterministic, collision-resistant, line-shift-invariant fingerprint.
    
    Returns:
        (canonical_fingerprint, display_id)
        Example: ("a3f91c0e8b1248d1", "a3f91c")
    """
    normalized_repo = (repo_name or "default_repo").strip().lower()
    normalized_path = (file_path or "").strip().lower()
    normalized_scope = (enclosing_scope or "global").strip().lower()
    normalized_cwe = (cwe or "UNKNOWN_CWE").strip().upper()
    normalized_type = (vuln_type or "UNKNOWN_TYPE").strip().lower()
    
    # Normalize code sink: collapse multi-space/tabs, strip comments
    clean_sink = re.sub(r'\s+', ' ', (code_sink or "").strip())
    clean_sink = re.sub(r'#.*$', '', clean_sink).strip()
    clean_sink = re.sub(r'//.*$', '', clean_sink).strip()
    
    raw_signature = f"{normalized_repo}:{normalized_path}:{normalized_scope}:{normalized_cwe}:{normalized_type}:{clean_sink}"
    canonical_fingerprint = hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()[:16]
    display_id = canonical_fingerprint[:6]
    
    return canonical_fingerprint, display_id

def extract_enclosing_scope(file_path: str, line_number: int) -> str:
    """
    Extracts the enclosing function, class, or route definition for a given line number
    across polyglot languages (Python, TypeScript, JavaScript, Go, Java).
    """
    if not file_path or not os.path.exists(file_path) or line_number <= 0:
        return "global"
        
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            
        target_idx = min(line_number - 1, len(lines) - 1)
        
        # Backward scan from target line up to line 0 to find the closest enclosing block
        scope_patterns = [
            # Python def / class
            r'^\s*(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(',
            r'^\s*class\s+([a-zA-Z0-9_]+)',
            # JS/TS function, const = arrow, router.get/post
            r'^\s*(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\(',
            r'^\s*(?:const|let|var)\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>',
            r'^\s*(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            # Go func
            r'^\s*func\s+(?:\([^)]+\)\s+)?([a-zA-Z0-9_]+)\s*\(',
            # Java method / class
            r'^\s*(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{',
            r'^\s*(?:public|private|protected)?\s*class\s+([a-zA-Z0-9_]+)'
        ]
        
        for i in range(target_idx, -1, -1):
            line_text = lines[i]
            for pat in scope_patterns:
                match = re.search(pat, line_text)
                if match:
                    return match.group(1).strip()
                    
        return "global"
    except Exception as e:
        logger.debug(f"Could not extract scope from {file_path}:{line_number}: {e}")
        return "global"

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# `cm find` findings table: a header line with ID and SEVERITY columns, then one line per finding.
_TABLE_SPLIT_RE = re.compile(r"\t+|\s{2,}|[|│┃║┆┇┊┋╎╏]")
_TABLE_RULE_RE = re.compile(r"^[\s\-=+|:\u2500-\u257f]+$")
# Line cm 0.16 prints (after an emoji) when a scan completes without findings.
_CLI_CLEAN_SCAN_RE = re.compile(r"^[^\w\n]*No vulnerabilities found!", re.MULTILINE)
_CM_SESSION_ID_RE = re.compile(r"\bSession(?:\s+ID)?:\s*([A-Za-z0-9_-]{6,})", re.IGNORECASE)
_CM_SESSION_LOG_RE = re.compile(r"Session log:\s*(\S+)")
_TOKEN_COUNT = r"([0-9][0-9.,]*\s*[kKmM]?)"
# New CLI summary: "Total tokens consumed: 181.3k (in: 158.5k, cached: 108.7k, out: 4.1k, thinking: 18.6k)"
_CLI_TOTAL_TOKENS_RE = re.compile(r"Total tokens consumed:[^\n(]*\(([^)]*)\)", re.IGNORECASE)
_CLI_TOKEN_FIELD_RE = re.compile(r"\b(input|in|cached|output|out|thinking|thoughts|thought)\s*:\s*" + _TOKEN_COUNT, re.IGNORECASE)
_CLI_TOKEN_FIELD_ALIASES = {
    "in": "input", "input": "input", "out": "output", "output": "output", "cached": "cached",
    "thinking": "thoughts", "thought": "thoughts", "thoughts": "thoughts",
}
# Legacy CLI summary: "Tokens: 89k in / 1k out / 93k total"
_CLI_LEGACY_TOKENS_RE = re.compile(
    r"Tokens:\s*" + _TOKEN_COUNT + r"\s*in\s*/\s*" + _TOKEN_COUNT + r"\s*out(?:\s*/\s*" + _TOKEN_COUNT + r"\s*total)?",
    re.IGNORECASE,
)


def _parse_token_count(value: str) -> int:
    text = str(value).strip().lower().replace(",", "")
    multiplier = 1
    if text.endswith("k"):
        multiplier, text = 1000, text[:-1]
    elif text.endswith("m"):
        multiplier, text = 1000000, text[:-1]
    return int(round(float(text.strip()) * multiplier))


def count_cli_table_rows(stdout: str) -> int:
    """Counts data rows under a findings table header (a line with ID and SEVERITY columns).

    Shared by _run_cm_cmd (does a `cm find` exit 1 carry real findings?) and
    agents.run_triage_agent (does the parsed findings count match the CLI table?).
    """
    lines = _ANSI_ESCAPE_RE.sub("", stdout or "").splitlines()
    for idx, line in enumerate(lines):
        columns = [c.strip().upper() for c in _TABLE_SPLIT_RE.split(line) if c.strip()]
        if "ID" not in columns or "SEVERITY" not in columns:
            continue
        rows = 0
        for row in lines[idx + 1:]:
            stripped = row.strip()
            if not stripped:
                break
            if _TABLE_RULE_RE.match(stripped):
                continue
            if len([c for c in _TABLE_SPLIT_RE.split(stripped) if c.strip()]) < 3:
                break
            rows += 1
        return rows
    return 0


def cli_reports_clean_scan(stdout: str) -> bool:
    """True when `cm find` output carries the CLI's clean-scan line ('No vulnerabilities found!')."""
    text = "\n".join(_ANSI_ESCAPE_RE.sub("", stdout or "").splitlines())
    return bool(_CLI_CLEAN_SCAN_RE.search(text))


def _token_usage_result(input_tokens: int = 0, output_tokens: int = 0, cached_tokens: int = 0,
                        thoughts_tokens: int = 0, source: str = "unavailable") -> dict:
    return {
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "cached_tokens": int(cached_tokens),
        "thoughts_tokens": int(thoughts_tokens),
        "total_tokens": int(input_tokens) + int(output_tokens) + int(thoughts_tokens),
        "source": source,
    }


def _cm_session_log_dirs() -> list:
    """Directories where the CodeMender CLI writes its per-session JSONL logs."""
    candidates = []
    cm_home = os.environ.get("CM_HOME")
    if cm_home:
        cm_home = os.path.expanduser(cm_home)
        candidates += [os.path.join(cm_home, "logs", "sessions"), os.path.join(cm_home, ".codemender", "logs", "sessions")]
    candidates.append(os.path.expanduser("~/.codemender/logs/sessions"))
    dirs, seen = [], set()
    for candidate in candidates:
        real = os.path.realpath(candidate)
        if real not in seen and os.path.isdir(candidate):
            seen.add(real)
            dirs.append(candidate)
    return dirs


def _iter_jsonl_records(path: str, must_contain: tuple):
    """Yields JSON objects from ``path`` whose raw line contains one of ``must_contain``."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if must_contain and not any(needle in line for needle in must_contain):
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    yield record
    except OSError as read_err:
        logger.warning(f"Could not read CodeMender session log {path}: {read_err}")


def _session_id_matches(record_session_id, wanted: set) -> bool:
    if not record_session_id:
        return False
    for session_id in wanted:
        # The CLI sometimes prints only the first 8 characters of the session ID.
        if record_session_id == session_id or (len(session_id) >= 8 and record_session_id.startswith(session_id)):
            return True
    return False


def _collect_jsonl_interactions(session_ids: set) -> list:
    """Returns the CLI's `interaction` usage records for the given CodeMender sessions.

    Records are matched on their own `session_id`. Sibling sessions started by the same CLI
    invocation (same `command_id`, e.g. deep-scan sub-sessions) are included, and duplicated
    records are counted once.
    """
    files = []
    for base in _cm_session_log_dirs():
        for root, _dirs, names in os.walk(base):
            files.extend(os.path.join(root, name) for name in names if name.endswith(".jsonl"))
    if not files:
        return []

    prefixes = tuple(sorted({session_id[:8] for session_id in session_ids}))
    # Files are named session-<timestamp>-<first 8 chars of the session ID>[-n].jsonl. Scan
    # everything if that naming convention ever changes.
    named = [f for f in files if any(prefix in os.path.basename(f) for prefix in prefixes)]

    interactions = {}
    command_ids = set()
    matched_dirs = set()
    for path in named or files:
        for record in _iter_jsonl_records(path, prefixes):
            if not _session_id_matches(record.get("session_id"), session_ids):
                continue
            matched_dirs.add(os.path.dirname(path))
            if record.get("command_id"):
                command_ids.add(record["command_id"])
            if record.get("type") == "interaction":
                interactions[json.dumps(record, sort_keys=True)] = record

    if command_ids:
        needles = tuple(sorted(command_ids))
        for path in files:
            if os.path.dirname(path) not in matched_dirs:
                continue
            for record in _iter_jsonl_records(path, needles):
                if record.get("type") == "interaction" and record.get("command_id") in command_ids:
                    interactions[json.dumps(record, sort_keys=True)] = record
    return list(interactions.values())


def _parse_cli_token_summary(text: str):
    """Parses the token summary the CLI prints for a run: (input, output, cached, thoughts) or None."""
    totals = _CLI_TOTAL_TOKENS_RE.findall(text or "")
    if totals:
        fields = {"input": 0, "output": 0, "cached": 0, "thoughts": 0}
        for name, value in _CLI_TOKEN_FIELD_RE.findall(totals[-1]):
            fields[_CLI_TOKEN_FIELD_ALIASES[name.lower()]] = _parse_token_count(value)
        return fields["input"], fields["output"], fields["cached"], fields["thoughts"]
    legacy = _CLI_LEGACY_TOKENS_RE.findall(text or "")
    if legacy:
        input_tokens = output_tokens = thoughts_tokens = 0
        for in_str, out_str, total_str in legacy:
            run_in, run_out = _parse_token_count(in_str), _parse_token_count(out_str)
            input_tokens += run_in
            output_tokens += run_out
            if total_str:
                thoughts_tokens += max(0, _parse_token_count(total_str) - run_in - run_out)
        return input_tokens, output_tokens, 0, thoughts_tokens
    return None


def parse_session_token_usage(combined_output: str = "", log_file_path: str = None, cm_session_id: str = None, max_age_sec: float = 300.0) -> dict:
    """
    Extracts comprehensive token metrics (input, output, cached, thoughts) from CodeMender logs.
    Sums the CLI's exact per-session `interaction` records from the JSONL logs under
    ~/.codemender/logs/sessions/**, matched by CodeMender session ID (never "newest file").
    Falls back to the token summary the CLI printed for the same run (source "cli_summary");
    with no data it returns zeros and source "unavailable" -- token counts are never estimated.
    Local files only (no network calls). `max_age_sec` is accepted for compatibility and ignored.
    """
    text = _ANSI_ESCAPE_RE.sub("", combined_output or "")

    session_ids = {m.strip() for m in _CM_SESSION_ID_RE.findall(text)}
    if cm_session_id:
        session_ids.add(cm_session_id.strip())
    session_ids.discard("")

    if session_ids:
        try:
            records = _collect_jsonl_interactions(session_ids)
        except Exception as scan_err:
            logger.warning(f"Failed to scan CodeMender JSONL session logs: {scan_err}")
            records = []
        if records:
            totals = {"input": 0, "output": 0, "cached": 0, "thought": 0}
            for record in records:
                for key in totals:
                    try:
                        totals[key] += int(record.get(key) or 0)
                    except (TypeError, ValueError):
                        pass
            return _token_usage_result(totals["input"], totals["output"], totals["cached"], totals["thought"], source="jsonl")
    else:
        logger.info("No CodeMender session ID found in CLI output; skipping JSONL token lookup.")

    summary = _parse_cli_token_summary(text)
    if summary is None:
        if not log_file_path:
            log_path_match = _CM_SESSION_LOG_RE.search(text)
            if log_path_match:
                log_file_path = log_path_match.group(1).strip()
        if log_file_path and os.path.isfile(log_file_path):
            try:
                with open(log_file_path, "r", encoding="utf-8", errors="ignore") as lf:
                    summary = _parse_cli_token_summary(_ANSI_ESCAPE_RE.sub("", lf.read()))
            except OSError:
                summary = None
    if summary is not None:
        return _token_usage_result(*summary, source="cli_summary")
    return _token_usage_result(source="unavailable")

# ---------------------------------------------------------------------------
# CodeMender CLI subprocess execution
# ---------------------------------------------------------------------------

# Environment forwarded to the CodeMender CLI. Everything else -- notably GitHub credentials and
# webhook secrets -- is withheld from the subprocess and the agent it runs.
# CM_DISABLE_SANDBOX is forwarded only as an operator emergency lever (set on the Cloud Run
# service); nothing in the image or this code sets it, so the cm sandbox stays on by default.
# The GO* / CGO_ENABLED settings come from the Dockerfile: `cm verify` must see them to build and
# run single-file Go samples offline (GOPATH mode with the preinstalled github.com/mattn/go-sqlite3).
_CM_ENV_ALLOWLIST = frozenset({
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TZ", "PYTHONUNBUFFERED", "NODE_PATH",
    "GOPATH", "GOCACHE", "GO111MODULE", "GOTOOLCHAIN", "GOFLAGS", "CGO_ENABLED",
    "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "CM_TEAM_ID", "CM_DISABLE_MODEL_FALLBACK", "CM_HOME", "CM_DISABLE_SANDBOX",
    "K_SERVICE", "K_REVISION",
})
# Never forwarded, even when allowlisted.
_CM_ENV_DENY_SUBSTRINGS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "PRIVATE_KEY", "API_KEY", "COOKIE")
# Other CM_* settings pass through unless the name looks credential-like.
_CM_PREFIX_DENY_SUBSTRINGS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "COOKIE")

_CM_MAX_ATTEMPTS = 3
# How often a running cm command checks whether its task was cancelled (plan 3.4).
# Cancel checks are throttled to one Firestore read per 5 s (task_context), so polling every 2 s
# costs nothing extra and lets a shutdown (plan 3.15) stop the CLI within 2 s.
_CM_CANCEL_POLL_SEC = 2.0
_CM_RETRY_BACKOFF_SEC = 5.0  # 5s, 15s, 45s (+ jitter)
_CM_PIPE_DRAIN_GRACE_SEC = 5.0
_CM_ERROR_TAIL_CHARS = 2000
# Untracked CodeMender state that a workspace reset must never delete.
_CM_STATE_EXCLUDES = (".codemender", ".cm_project", ".exploit", ".codemender.yaml")

# Per-run deadline of each CLI command. A timed-out run is never retried (one long run per
# command), so these bound how long find/verify/fix can take. Values are clamped to 60-3000 s.
_CM_TIMEOUT_ENV_VARS = {"cm_find": "CM_FIND_TIMEOUT_SEC", "cm_verify": "CM_VERIFY_TIMEOUT_SEC", "cm_fix": "CM_FIX_TIMEOUT_SEC"}
_CM_TIMEOUT_DEFAULTS_SEC = {"cm_find": 600.0, "cm_verify": 1200.0, "cm_fix": 1200.0}
_CM_OTHER_TIMEOUT_SEC = 360.0  # cm init and any other subcommand (fixed)
_CM_TIMEOUT_MIN_SEC = 60.0
_CM_TIMEOUT_MAX_SEC = 3000.0

# Retry classification reads only the CLI's final error output: the last line starting with
# "Error" among the last _CM_ERROR_TAIL_LINES non-empty lines, else those lines.
_CM_ERROR_TAIL_LINES = 20
_CLI_ERROR_LINE_RE = re.compile(r"^\W*Error\b")

# Extra guidance for the `cm verify` agent (`--context`). CM_VERIFY_CONTEXT overrides it; an empty
# value disables the flag.
_DEFAULT_CM_VERIFY_CONTEXT = (
    "Runtimes are preinstalled and offline: Python 3 with Flask and sqlite3; Node.js with express, "
    "body-parser and sqlite3 (global, NODE_PATH set); Go with github.com/mattn/go-sqlite3 in GOPATH "
    "(run single-file apps with: go run <file>.go); Java 17 with Maven. Package installation is "
    "blocked, so do not install packages. Start the target app directly and wait until its port "
    "accepts connections (retry for up to 15 seconds) before sending exploit requests."
)

_TRANSIENT_CM_ERROR_RE = re.compile(
    r"RESOURCE[_ ]EXHAUSTED|\b429\b|too many requests|rate[ -]?limit|quota exceeded"
    r"|\bUNAVAILABLE\b"
    r"|\b(?:HTTP/\d(?:\.\d)?|status(?: code)?|code|error|returned)\s*[:=]?\s*5\d\d\b"
    r"|\b5\d\d\s+(?:Internal|Bad Gateway|Service Unavailable|Gateway Time-?out)"
    r"|internal server error|bad gateway|gateway time-?out"
    r"|deadline[_ ]exceeded|i/o timeout|tls handshake timeout"
    r"|(?:request|read|connect|connection|operation) timed out|Client\.Timeout"
    r"|connection reset|ECONNRESET|broken pipe|connection aborted|RemoteDisconnected|unexpected EOF|GOAWAY"
    r"|Precondition check failed|FAILED_PRECONDITION",
    re.IGNORECASE,
)
_MODEL_REJECTION_RE = re.compile(
    r"Unsupported model|Requests ending with a model turn are not supported|\bmodel\b[^\n]{0,200}?\bwas not found",
    re.IGNORECASE,
)
_MODEL_FALLBACK_CHAIN = ("gemini-3.7-flash", "gemini-3.5-flash")

# Telemetry attribution (pr_number, event_type, is_draft) for the cm token-usage rows logged by
# _log_cm_attempt_usage lives in task_context (plan 4.2), so database.log_token_usage reads the
# same values; cm_telemetry_context and set_/reset_/get_cm_telemetry_context are aliases of it.


def _cm_subprocess_env(base_env: dict = None) -> dict:
    """Allowlisted environment for every CodeMender CLI subprocess; secrets are never forwarded."""
    source = os.environ if base_env is None else base_env
    env = {}
    for name, value in source.items():
        upper = name.upper()
        if upper.startswith("GITHUB_") or any(s in upper for s in _CM_ENV_DENY_SUBSTRINGS):
            continue
        if name in _CM_ENV_ALLOWLIST or (
            upper.startswith("CM_") and not any(s in upper for s in _CM_PREFIX_DENY_SUBSTRINGS)
        ):
            env[name] = value
    cm_proj = source.get("CODEMENDER_PROJECT_ID") or source.get("GOOGLE_CLOUD_PROJECT")
    if not cm_proj:
        raise RuntimeError("CODEMENDER_PROJECT_ID / GOOGLE_CLOUD_PROJECT is not set; refusing to run cm without an explicit project.")
    env["GOOGLE_CLOUD_PROJECT"] = cm_proj
    env["GCLOUD_PROJECT"] = cm_proj
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def cm_command_timeout(task: str) -> float:
    """Deadline in seconds for one run of a CodeMender CLI task ('cm_find', 'cm_verify', 'cm_fix', ...).

    find/verify/fix read CM_FIND_TIMEOUT_SEC / CM_VERIFY_TIMEOUT_SEC / CM_FIX_TIMEOUT_SEC (defaults
    600 / 1200 / 1200). Values are clamped to 60-3000 s; an unparsable or non-finite value falls
    back to the default. cm init and every other subcommand keep the fixed 360 s.
    """
    default = _CM_TIMEOUT_DEFAULTS_SEC.get(task, _CM_OTHER_TIMEOUT_SEC)
    env_name = _CM_TIMEOUT_ENV_VARS.get(task)
    raw = (os.environ.get(env_name) or "").strip() if env_name else ""
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value):
        logger.warning(f"Ignoring invalid {env_name}={raw!r}; using the default {default:.0f}s.")
        return default
    clamped = min(max(value, _CM_TIMEOUT_MIN_SEC), _CM_TIMEOUT_MAX_SEC)
    if clamped != value:
        logger.warning(f"{env_name}={raw!r} is outside {_CM_TIMEOUT_MIN_SEC:.0f}-{_CM_TIMEOUT_MAX_SEC:.0f}s; using {clamped:.0f}s.")
    return clamped


def cm_verify_context_args() -> list:
    """`--context <text>` argv elements for `cm verify` (never a shell string).

    The text is CM_VERIFY_CONTEXT when that variable is set (an empty value disables the flag),
    else the default runtime guidance (_DEFAULT_CM_VERIFY_CONTEXT).
    """
    text = os.environ.get("CM_VERIFY_CONTEXT")
    if text is None:
        text = _DEFAULT_CM_VERIFY_CONTEXT
    text = text.strip()
    return ["--context", text] if text else []


def _display_cmd(cmd: list) -> str:
    """Printable command line for logs and the scan timeline; a --context value is abbreviated."""
    parts = [str(part) for part in cmd]
    for i in range(len(parts) - 1):
        if parts[i] == "--context":
            parts[i + 1] = f"<{len(parts[i + 1])} chars>"
    return " ".join(parts)


def _cli_final_error_output(text: str) -> str:
    """The CLI's final error output: the last line starting with 'Error' among the last 20
    non-empty lines, else those 20 lines. Earlier output (exploit scripts, mock servers) is ignored."""
    lines = [line.strip() for line in _ANSI_ESCAPE_RE.sub("", text or "").splitlines() if line.strip()]
    tail = lines[-_CM_ERROR_TAIL_LINES:]
    for line in reversed(tail):
        if _CLI_ERROR_LINE_RE.match(line):
            return line
    return "\n".join(tail)


def classify_cm_error(stderr: str, timed_out: bool) -> str:
    """Classifies a failed CodeMender CLI run as 'transient' (retry) or 'permanent' (fail fast).

    Only the CLI's final error output is inspected (see _cli_final_error_output): `cm verify` stderr
    also carries exploit and mock-server output, where phrases like 'connection reset' are normal.
    Transient: 429/RESOURCE_EXHAUSTED, UNAVAILABLE/5xx, connection resets and expired agent sessions
    ('Precondition check failed'). A timeout is permanent: it is never retried (one long run per
    command), since a retry would spend another full timeout window. Everything else is permanent.
    """
    if timed_out:
        return "permanent"
    final_output = _cli_final_error_output(stderr)
    if final_output and _TRANSIENT_CM_ERROR_RE.search(final_output):
        return "transient"
    return "permanent"


def _retry_delay(retry_index: int) -> float:
    """Exponential backoff with jitter: ~5s, ~15s, ~45s for retries 0, 1, 2."""
    return _CM_RETRY_BACKOFF_SEC * (3 ** retry_index) + random.uniform(0.0, 2.0)


def _next_fallback_model(current_model: str, tried_models: set):
    for candidate in _MODEL_FALLBACK_CHAIN:
        if candidate != current_model and candidate not in tried_models:
            return candidate
    return None


def _tail(text: str, limit: int = _CM_ERROR_TAIL_CHARS) -> str:
    text = text or ""
    return text if len(text) <= limit else "..." + text[-limit:]


def _kill_process_group(process) -> None:
    """SIGKILLs the CLI and any children it left behind (they share its process group)."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return
    except (AttributeError, OSError):
        pass
    try:
        process.kill()
    except Exception:
        pass


async def _collect_process_output(process, stdin_data: bytes, timeout: float,
                                  grace: float = _CM_PIPE_DRAIN_GRACE_SEC, cancel_check=None) -> tuple:
    """Feeds stdin, collects output and enforces the deadline. Returns (stdout, stderr, timed_out).

    With ``cancel_check`` (a blocking callable returning who cancelled the task, or None), the
    flag is polled every _CM_CANCEL_POLL_SEC; a cancel kills the CLI and its children and raises
    TaskCancelled (plan 3.4).

    Output is buffered incrementally, so nothing is lost when the deadline fires. A process that
    already exited counts as completed -- even if a child it spawned (e.g. a verification mock
    server) still holds the pipes open, which would otherwise stall until the deadline. Only a
    process still running at the deadline counts as timed out (and is killed with its children).
    """
    out_buf, err_buf = bytearray(), bytearray()

    async def _pump(stream, sink: bytearray):
        if stream is None:
            return
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return
            sink.extend(chunk)

    async def _feed():
        if process.stdin is None:
            return
        try:
            if stdin_data:
                process.stdin.write(stdin_data)
                await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                process.stdin.close()
            except Exception:
                pass

    io_task = asyncio.ensure_future(asyncio.gather(
        _feed(), _pump(process.stdout, out_buf), _pump(process.stderr, err_buf)
    ))
    deadline = time.monotonic() + timeout
    timed_out = False
    last_cancel_poll = time.monotonic()
    try:
        # Poll returncode instead of awaiting process.wait(): wait() only resolves once every pipe
        # is closed, which never happens while a leftover child still holds stdout open.
        while process.returncode is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if cancel_check is not None and time.monotonic() - last_cancel_poll >= _CM_CANCEL_POLL_SEC:
                last_cancel_poll = time.monotonic()
                cancelled_by = await asyncio.to_thread(cancel_check)
                if cancelled_by:
                    _kill_process_group(process)
                    raise TaskCancelled(cancelled_by)
            if io_task.done():
                # Pipes are closed, so wait() resolves as soon as the process exits.
                try:
                    await asyncio.wait_for(process.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    pass
                break
            await asyncio.wait({io_task}, timeout=min(1.0, remaining))

        if process.returncode is None:
            timed_out = True
            _kill_process_group(process)

        await asyncio.wait({io_task}, timeout=grace)
        if not io_task.done():
            if not timed_out:
                logger.warning(
                    "CodeMender CLI exited but child processes still hold its output pipes; "
                    "terminating them and treating the run as completed."
                )
            _kill_process_group(process)
            await asyncio.wait({io_task}, timeout=grace)

        if timed_out and process.returncode is not None and process.returncode >= 0:
            # It exited on its own right at the deadline (a SIGKILLed process reports a negative code).
            timed_out = False
    except BaseException:
        # Cancelled (e.g. request/server shutdown) or failed: never leave the CLI running.
        _kill_process_group(process)
        raise
    finally:
        if not io_task.done():
            io_task.cancel()
        elif not io_task.cancelled():
            io_task.exception()  # Mark retrieved; a pump error only means truncated output.
    return bytes(out_buf), bytes(err_buf), timed_out


async def _reset_fix_workspace(cwd: str) -> None:
    """Discards partial edits of a failed `cm fix` run before it is re-run.

    Tracked files are restored and untracked files removed; CodeMender state (.codemender,
    .cm_project, .exploit) is never deleted.
    """
    clean_cmd = ["git", "clean", "-fd"]
    for path in _CM_STATE_EXCLUDES:
        clean_cmd += ["-e", path]
    for args in (["git", "checkout", "--", "."], clean_cmd):
        try:
            proc = await asyncio.create_subprocess_exec(
                *args, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                _, err = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                raise
            if proc.returncode != 0:
                logger.warning(f"Workspace reset step '{' '.join(args)}' failed: {redact(err.decode(errors='ignore').strip())}")
        except Exception as reset_err:
            logger.warning(f"Workspace reset step '{' '.join(args)}' failed: {redact(str(reset_err))}")


async def _log_cm_attempt_usage(session_id: str, task: str, model: str, combined_output: str,
                                duration: float, log_file_path: str = None) -> None:
    """Logs one attempt's exact CLI token usage to BigQuery; logs nothing when it is unavailable.

    The row carries pr_number / event_type / is_draft from the active cm telemetry context
    (cm_telemetry_context) when the task entry point set them.
    """
    try:
        usage = await asyncio.to_thread(parse_session_token_usage, combined_output, log_file_path)
        if usage.get("source") == "unavailable":
            logger.info(f"No CodeMender token usage found for '{task}' (session {session_id}); nothing logged.")
            return
        attribution = {k: v for k, v in get_cm_telemetry_context().items() if v is not None}
        repo_name = await asyncio.to_thread(get_scan_repo_name, session_id)
        logger.info(
            f"Logging CodeMender CLI token usage for '{task}' (Model: {model}, Source: {usage['source']}) -> "
            f"Input: {usage['input_tokens']:,}, Output: {usage['output_tokens']:,}, "
            f"Cached: {usage['cached_tokens']:,}, Thoughts: {usage['thoughts_tokens']:,}, Duration: {duration:.2f}s, "
            f"PR: {attribution.get('pr_number')}, Event: {attribution.get('event_type')}"
        )
        await asyncio.to_thread(
            log_token_usage,
            session_id=session_id,
            repo_name=repo_name,
            task_type=task,
            model_name=model,
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            cached_tokens=usage["cached_tokens"],
            thoughts_tokens=usage["thoughts_tokens"],
            duration_sec=duration,
            **attribution,
        )
    except Exception as parse_err:
        logger.warning(f"Failed to parse and log CodeMender CLI token usage: {parse_err}")


async def _run_cm_cmd(cmd: list, session_id: str, run_info: dict = None) -> str:
    """Runs a CodeMender CLI command in /tmp/session-{session_id} and returns its stripped stdout.

    Hardened runner shared by every cm call: own process group (a timeout or cancellation also kills
    children such as mock servers), the process-wide CLI semaphore, the per-command deadline
    (cm_command_timeout; a timed-out run is never retried), retries of transient errors only,
    model fallback on upstream model rejection, and per-attempt token telemetry.
    Raises RuntimeError when the command fails. When ``run_info`` is a dict it receives the last
    attempt's stdout, stderr, returncode, timed_out, duration, timeout, model and command, also on
    failure.
    """
    cwd = f"/tmp/session-{session_id}"
    cmd = list(cmd)  # Model fallback edits a copy, never the caller's list.
    cmd_str = _display_cmd(cmd)
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

    task = "cm_find"
    if "verify" in cmd:
        task = "cm_verify"
    elif "fix" in cmd:
        task = "cm_fix"
    elif "init" in cmd:
        task = "cm_init"
        
    max_retries = _CM_MAX_ATTEMPTS
    stdout, stderr = b"", b""
    # Set by the worker's TaskSession: a cancelled task starts no new attempt and stops a running one.
    cancel_check = current_cancel_check()
    
    # Global concurrency gate for CLI sessions to prevent outbound TLS socket saturation on Cloud Run
    global _CLI_SEMAPHORE
    if "_CLI_SEMAPHORE" not in globals() or _CLI_SEMAPHORE is None:
        max_concurrent = int(os.environ.get('MAX_CONCURRENT_CLI', '10'))
        _CLI_SEMAPHORE = asyncio.Semaphore(max_concurrent)
        
    # find/verify/fix: CM_*_TIMEOUT_SEC; init and other subcommands keep the fixed default.
    timeout_task = task if any(sub in cmd for sub in ("find", "verify", "fix")) else "cm_other"
    cmd_timeout = cm_command_timeout(timeout_task)
    
    # Calculate isolated port for this workspace session to avoid port clashes
    session_port = 5000 + (int(hashlib.md5(session_id.encode()).hexdigest()[:4], 16) % 1000)
    
    async with _CLI_SEMAPHORE:
        attempt = 0  # Failed attempts consumed so far; model fallbacks do not count.
        tried_models = set()
        while True:
            if cancel_check is not None:
                cancelled_by = await asyncio.to_thread(cancel_check)
                if cancelled_by:
                    raise TaskCancelled(cancelled_by)
            await asyncio.to_thread(update_scan_status, commit_sha=session_id, status="RUNNING", message=status_msg)
            await asyncio.to_thread(
                append_scan_step, session_id, step_type,
                f"Executing CodeMender command: {cmd_str} (Attempt {attempt + 1}/{max_retries}, timeout {cmd_timeout:.0f}s)"
            )
            
            cmd_env = _cm_subprocess_env()
            cmd_env["PORT"] = str(session_port)  # Isolated workspace port

            process = await asyncio.create_subprocess_exec(
                cmd[0],
                *cmd[1:],
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=cmd_env,
                # Own process group: a timeout also kills children the CLI started (mock servers).
                start_new_session=True,
            )

            start_time = time.monotonic()
            stdout, stderr, timeout_occurred = await _collect_process_output(process, b"y\n", cmd_timeout, cancel_check=cancel_check)
            duration = time.monotonic() - start_time
            stdout_text = stdout.decode(errors="ignore")
            err_msg = stderr.decode(errors="ignore").strip()

            # Parse and log token usage for this attempt (every attempt is billed)
            model_idx = cmd.index("--model") if "--model" in cmd[:-1] else -1
            model = cmd[model_idx + 1] if model_idx >= 0 else resolve_model(task, requested_model=None, session_id=session_id)
            if run_info is not None:
                run_info.update({
                    "stdout": stdout_text, "stderr": err_msg, "returncode": process.returncode,
                    "timed_out": timeout_occurred, "duration": duration, "timeout": cmd_timeout,
                    "model": model, "command": cmd_str,
                })

            if timeout_occurred:
                logger.warning(
                    f"Command '{cmd_str}' timed out after running {duration:.0f}s (limit {cmd_timeout:.0f}s, "
                    f"attempt {attempt + 1}/{max_retries}); process terminated. Timeouts are not retried."
                )
                await asyncio.to_thread(
                    append_scan_step, session_id, step_type,
                    f"Command timed out after running {duration:.0f}s (limit {cmd_timeout:.0f}s); not retried: {cmd_str}"
                )

            combined_output = stdout_text + "\n" + err_msg
            log_path_match = _CM_SESSION_LOG_RE.search(combined_output)
            await _log_cm_attempt_usage(
                session_id, task, model, combined_output, duration,
                log_path_match.group(1).strip() if log_path_match else None,
            )

            # `cm find` exits 1 when it reports findings. Exit 1 only counts as a completed scan
            # when the findings table has rows; progress text (e.g. "Found 1 source files") does not.
            find_reported = (
                "find" in cmd and process.returncode == 1 and count_cli_table_rows(stdout_text) > 0
            )
            if not timeout_occurred and (process.returncode == 0 or find_reported):
                break

            # Upstream rejected the model: re-run on a fallback model without consuming an attempt.
            if not timeout_occurred and model_idx >= 0 and _MODEL_REJECTION_RE.search(err_msg):
                tried_models.add(model)
                fallback_m = _next_fallback_model(model, tried_models)
                if fallback_m:
                    logger.warning(f"Upstream server rejected model {model}. Resiliently falling back to {fallback_m} for CLI invocation.")
                    await asyncio.to_thread(
                        append_scan_step, session_id, step_type,
                        f"Model {model} was rejected upstream; re-running with {fallback_m}."
                    )
                    cmd[model_idx + 1] = fallback_m
                    cmd_str = _display_cmd(cmd)
                    if task == "cm_fix":
                        await _reset_fix_workspace(cwd)
                    continue

            if timeout_occurred:
                error_detail = f"timed out after running {duration:.0f}s (limit {cmd_timeout:.0f}s)"
            else:
                error_detail = redact(_tail(err_msg or stdout_text.strip()))
            # Timeouts classify as permanent: one long run per command, never retried.
            error_kind = classify_cm_error(err_msg or stdout_text, timeout_occurred)
            attempt += 1
            if error_kind == "permanent" or attempt >= max_retries:
                logger.error(f"CM command failed ({error_kind}, attempt {attempt}/{max_retries}): {cmd_str}. Error: {error_detail}")
                await asyncio.to_thread(append_scan_step, session_id, step_type, f"Command failed: {cmd_str}. Error: {error_detail}")
                if timeout_occurred:
                    raise RuntimeError(
                        f"CodeMender command '{cmd_str}' timed out after running {duration:.0f} seconds "
                        f"(limit {cmd_timeout:.0f}s, attempt {attempt}/{max_retries}); timeouts are not retried."
                    )
                raise RuntimeError(f"CodeMender command failed: {error_detail}")
                
            delay = _retry_delay(attempt - 1)
            logger.warning(f"Command failed with a transient error (attempt {attempt}/{max_retries}). Retrying in {delay:.0f}s... Error: {error_detail}")
            await asyncio.to_thread(
                append_scan_step, session_id, step_type,
                f"Command failed (attempt {attempt}/{max_retries}). Retrying in {delay:.0f}s: {error_detail}"
            )
            await asyncio.sleep(delay)
            if task == "cm_fix":
                # Never let a retried fix start from a half-applied patch.
                await _reset_fix_workspace(cwd)
            
        stdout_str = stdout.decode(errors="replace").strip()
        return stdout_str


@tool
def resolve_model(task_type: str = "scan", requested_model: str = None, session_id: str = None) -> str:
    """Resolves the Gemini model based on precedence hierarchy:
    1. Explicit requested_model (e.g. from PR flag --model=pro)
    2. .codemender.yaml in workspace (/tmp/session-{session_id}/.codemender.yaml)
    3. Environment variables (CODEMENDER_FIX_MODEL, CODEMENDER_SCAN_MODEL, etc.)
    4. Default fallback: gemini-3.8-flash
    """
    if requested_model:
        req = requested_model.strip().lower()
        if req in ("pro", "gemini-pro", "1.5-pro", "gemini-1.5-pro", "3.1-pro", "gemini-3.1-pro", "3.1-pro-preview", "gemini-3.1-pro-preview"):
            return "gemini-3.1-pro-preview"
        elif req in ("3.8-flash", "gemini-3.8-flash", "3.8", "flash-3.8"):
            return "gemini-3.8-flash"
        elif req in ("3.7-flash", "gemini-3.7-flash"):
            return "gemini-3.7-flash"
        elif req in ("3.6-flash", "gemini-3.6-flash"):
            return "gemini-3.6-flash"
        elif req in ("3.5-flash", "gemini-3.5-flash", "flash", "gemini-flash", "3-flash", "gemini-3-flash", "3.0-flash", "gemini-3.0-flash", "gemini-3.0", "3-flash-preview", "gemini-3-flash-preview", "2.5-flash", "gemini-2.5-flash"):
            return "gemini-3.8-flash"
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
    if os.getenv("GEMINI_MODEL_NAME"):
        return os.getenv("GEMINI_MODEL_NAME")

    return "gemini-3.8-flash"

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
    # Runtime guidance for the verification agent (CM_VERIFY_CONTEXT; separate argv elements).
    cmd = ["cm", "verify", vuln_id, "-y", "--bypass-warning", "--model", selected_model, *cm_verify_context_args()]
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
