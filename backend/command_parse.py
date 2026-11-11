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
"""Pure parsing of CodeMender comment commands and their finding targets (no I/O).

Rules shared by PR comments, commit comments and the finding selection of /verify and /fix:
- Only the first line of a comment is a command; the command word is case-insensitive.
- Targets are `all` / `*`, a severity (`critical`, `high`, `medium`, `low`), or finding IDs.
- An ID matches a finding's id, display_id or fingerprint exactly (case-insensitive). A fingerprint
  prefix only counts when it is hex and at least MIN_PREFIX_LEN long, so `/fix 1` or an ordinary
  word such as "add" never selects findings by accident.
"""

import re

from command_auth import command_name

SEVERITY_KEYWORDS = ("critical", "high", "medium", "low")
SCOPE_KEYWORDS = ("all", "*")
TARGET_KEYWORDS = frozenset(SEVERITY_KEYWORDS + SCOPE_KEYWORDS)
MIN_PREFIX_LEN = 6

VERIFY_COMMANDS = frozenset({"verify", "verify-all"})
FIX_COMMANDS = frozenset({"fix", "fix-all", "remediate", "remediate-all"})
CANCEL_COMMANDS = frozenset({"cancel", "reset"})
DRAFT_COMMANDS = frozenset({"draft", "pr"})

ID_HINT = ("Use the 8-character ID from the report's ID column (for example `a387f7c8`), "
           "or `critical`, `high`, `medium`, `low` or `all`.")
APPROVE_USAGE = "`/approve` takes no arguments. Reply with exactly `/approve` to apply the proposed patch."

_HEX = re.compile(r"^[0-9a-f]+$")
_GATE_RE = re.compile(r"^/(?:override|dismiss)-gate(?=\s|$)(?:\s+\[([A-Za-z0-9_]+)\])?\s*(.*)$", re.IGNORECASE)
_ITEM_RE = re.compile(
    r"^/(dismiss|override)(?=\s|$)(?:\s+(?!\[)([A-Za-z0-9_-]+))?(?:\s+\[([A-Za-z0-9_]+)\])?\s*(.*)$",
    re.IGNORECASE,
)


def first_line(comment_body) -> str:
    text = str(comment_body or "").strip()
    return text.splitlines()[0].strip() if text else ""


def split_command(comment_body) -> tuple:
    """('/Fix critical, high\\nthanks') -> ('fix', ['critical', 'high']); (None, []) for ordinary comments."""
    line = first_line(comment_body)
    command = command_name(line)
    if not command:
        return None, []
    args = [token.strip(",.;") for token in line.split()[1:]]
    return command, [arg for arg in args if arg]


def is_id_like(token) -> bool:
    """A hex token long enough to be matched as a fingerprint prefix."""
    text = str(token or "").lower()
    return len(text) >= MIN_PREFIX_LEN and bool(_HEX.match(text))


def normalize_targets(args) -> list:
    """Keywords lower-cased; IDs kept as typed (matching is case-insensitive)."""
    return [arg.lower() if arg.lower() in TARGET_KEYWORDS else arg for arg in args]


def route_comment(comment_body) -> tuple:
    """Returns (action, targets, usage_error).

    action is one of 'approve', 'verify', 'fix', 'dismiss', 'cancel', 'draft', or None (not ours).
    usage_error is a reply for a malformed slash command; nothing must be enqueued then.
    Bare words (no slash) only route when every argument is a keyword or an ID-like token, so an
    ordinary sentence such as "fix the typo" or "approve after CI" is never treated as a command.
    """
    line = first_line(comment_body)
    command, args = split_command(line)
    if not command:
        return None, [], None
    slash = line.startswith("/")
    if not slash and any(arg.lower() not in TARGET_KEYWORDS and not is_id_like(arg) for arg in args):
        return None, [], None

    if command == "approve":
        if not args or [arg.lower() for arg in args] == ["all"]:
            return "approve", [], None
        return None, [], (APPROVE_USAGE if slash else None)
    if command in VERIFY_COMMANDS or command in FIX_COMMANDS:
        action = "verify" if command in VERIFY_COMMANDS else "fix"
        if command.endswith("-all") or not args:
            return action, ["all"], None
        return action, normalize_targets(args), None
    if slash and command.startswith(("dismiss", "override")):
        return "dismiss", [], None
    if slash and command in CANCEL_COMMANDS:
        return "cancel", [], None
    if slash and command in DRAFT_COMMANDS and not args:
        return "draft", [], None
    return None, [], None


def _is_active(finding: dict) -> bool:
    if str(finding.get("lifecycle_status", "")).upper() == "RESOLVED":
        return False
    return str(finding.get("status", "")).upper() not in ("RESOLVED", "DISMISSED")


def _severity(finding: dict) -> str:
    raw = str(finding.get("severity", "")).upper()
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if severity in raw:
            return severity
    return ""


def _matches_id(finding: dict, token: str) -> bool:
    wanted = token.lower()
    fingerprint = str(finding.get("fingerprint", "")).lower()
    if wanted in (str(finding.get("id", "")).lower(), str(finding.get("display_id", "")).lower(), fingerprint):
        return True
    return is_id_like(wanted) and bool(fingerprint) and fingerprint.startswith(wanted)


def select_findings(findings, targets) -> tuple:
    """Returns (selected findings in their original order, tokens that matched nothing).

    `all` / `*` and severities select open findings only; explicit IDs select the named findings.
    """
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    chosen, unmatched = set(), []
    for raw in targets or []:
        token = str(raw or "").strip(",.;")
        if not token:
            continue
        keyword = token.lower()
        if keyword in SCOPE_KEYWORDS:
            hits = [i for i, f in enumerate(findings) if _is_active(f)]
        elif keyword in SEVERITY_KEYWORDS:
            hits = [i for i, f in enumerate(findings) if _is_active(f) and _severity(f) == keyword.upper()]
        else:
            hits = [i for i, f in enumerate(findings) if _matches_id(f, token)]
            if not hits:
                unmatched.append(token)
        chosen.update(hits)
    return [f for i, f in enumerate(findings) if i in chosen], unmatched


def no_match_message(verb: str, targets, unmatched) -> str:
    shown = ", ".join(f"`{t}`" for t in (unmatched or targets or [])) or "(none)"
    return f"⚠️ No matching findings found to {verb} for: {shown}. {ID_HINT}"


def parse_dismiss(comment_body):
    """Parses /dismiss, /override and /override-gate. Returns None when the syntax is invalid.

    Result: {"gate": bool, "target_id": str | None, "category": str | None, "reason": str}.
    A gate override ("/override-gate", "/dismiss-gate", or "gate" as the ID) targets every finding;
    an item dismissal without an ID returns target_id None, and the caller must refuse it instead
    of dismissing everything.
    """
    line = first_line(comment_body)
    match = _GATE_RE.match(line)
    if match:
        category, reason = match.groups()
        return {"gate": True, "target_id": "all", "category": category, "reason": (reason or "").strip()}
    match = _ITEM_RE.match(line)
    if not match:
        return None
    _cmd, target_id, category, reason = match.groups()
    if target_id and target_id.lower() == "gate":
        return {"gate": True, "target_id": "all", "category": category, "reason": (reason or "").strip()}
    return {"gate": False, "target_id": target_id, "category": category, "reason": (reason or "").strip()}
