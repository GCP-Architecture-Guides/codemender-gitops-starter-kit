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

"""Server-side re-validation of relayed GitHub events (review item D4, plan 1.6).

Events relayed by the GitHub Actions workflow (the WIF path) are authenticated by Cloud Run IAM,
but their bodies are not signed by GitHub: anyone who can run a workflow in the repository can
mint a relay token and POST an arbitrary body (for example a forged '/approve' claiming OWNER).
The webhook therefore treats an event body as a hint and re-reads the objects it acts on from the
GitHub API with its own token:

- issue_comment: the comment by id (author, body and issue must match) and the issue/PR it is on.
- commit_comment: the comment by id (author, body and commit must match).
- pull_request, scan actions: the PR by number. It must be open, in this repository, and its live
  head must equal the event's head; otherwise the event is stale (the newer push sends its own
  event) and is ignored.
- pull_request, closed: the PR must really be closed, with the same merged flag.

GitHub's copies then replace the relayed ones (``apply_authoritative``), so downstream code never
acts on relayed fields such as author_association, the PR author or the head SHA.

The comparison functions are pure; ``validate_relayed_event`` takes an injected ``get_json``
coroutine (url -> (status, json)) so it can be tested without network access.
"""

from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

GetJson = Callable[[str], Awaitable[tuple]]

GITHUB_API = "https://api.github.com"

# pull_request actions that start a scan.
SCAN_ACTIONS = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})


@dataclass(frozen=True)
class EventCheck:
    """Outcome of a validation step.

    ok=False with status 200 means "ignore the event" (stale/closed), 4xx means the event body
    does not match GitHub, 503 means GitHub could not be asked. ``replacements`` maps payload
    keys to GitHub's copies of those objects.
    """
    ok: bool
    status_code: int = 200
    reason: str = ""
    replacements: dict = field(default_factory=dict)


def _norm_text(text) -> str:
    return str(text or "").replace("\r\n", "\n").strip()


def _login(obj) -> str:
    return str(((obj or {}).get("user") or {}).get("login") or "").strip().lower()


def upstream_failure(status) -> Optional[EventCheck]:
    """503 when the GitHub read failed on our side (network, auth, rate limit, 5xx), else None.

    404 is not an upstream failure: it means the object named in the event does not exist.
    """
    if not status or status in (401, 403, 429) or int(status) >= 500:
        return EventCheck(False, 503, f"could not read the event's subject from GitHub (HTTP {status or 'error'})")
    return None


def compare_comment(payload_comment: dict, api_comment: Optional[dict],
                    issue_number=None, commit_sha: Optional[str] = None) -> EventCheck:
    """The relayed comment must be the comment GitHub has (same id, author, body and target)."""
    if not api_comment:
        return EventCheck(False, 403, "comment not found via the GitHub API")
    if str(api_comment.get("id")) != str((payload_comment or {}).get("id")):
        return EventCheck(False, 403, "comment id mismatch")
    api_login = _login(api_comment)
    if not api_login or api_login != _login(payload_comment):
        return EventCheck(False, 403, "comment author mismatch")
    if _norm_text(api_comment.get("body")) != _norm_text((payload_comment or {}).get("body")):
        return EventCheck(False, 403, "comment body does not match GitHub's copy")
    if issue_number is not None:
        issue_url = str(api_comment.get("issue_url") or "")
        if not issue_url.endswith(f"/issues/{issue_number}"):
            return EventCheck(False, 403, "comment does not belong to this issue or pull request")
    if commit_sha is not None and str(api_comment.get("commit_id") or "") != str(commit_sha):
        return EventCheck(False, 403, "comment does not belong to this commit")
    return EventCheck(True, replacements={"comment": api_comment})


def compare_issue(payload_issue: dict, api_issue: Optional[dict]) -> EventCheck:
    """The issue/PR a comment is on, as GitHub has it (PR flag and author come from this copy)."""
    if not api_issue:
        return EventCheck(False, 403, "issue or pull request not found via the GitHub API")
    if str(api_issue.get("number")) != str((payload_issue or {}).get("number")):
        return EventCheck(False, 403, "issue number mismatch")
    return EventCheck(True, replacements={"issue": api_issue})


def compare_pull_request(payload_pr: dict, api_pr: Optional[dict], repo_name: str,
                         action: Optional[str] = None) -> EventCheck:
    """The relayed PR must exist in this repo and be in the state the event claims.

    Scan actions need an open PR whose live head is the event's head. 'closed' needs a closed PR
    with the same merged flag.
    """
    if not api_pr:
        return EventCheck(False, 403, "pull request not found via the GitHub API")
    if str(api_pr.get("number")) != str((payload_pr or {}).get("number")):
        return EventCheck(False, 403, "pull request number mismatch")
    base_repo = str((((api_pr.get("base") or {}).get("repo")) or {}).get("full_name") or "").lower()
    if base_repo != str(repo_name or "").lower():
        return EventCheck(False, 403, "pull request belongs to a different repository")

    if action == "closed":
        if api_pr.get("state") != "closed":
            return EventCheck(False, 403, "pull request is not closed")
        if bool(api_pr.get("merged")) != bool((payload_pr or {}).get("merged")):
            return EventCheck(False, 403, "pull request merged flag does not match GitHub")
        return EventCheck(True, replacements={"pull_request": api_pr})

    if api_pr.get("state") != "open":
        return EventCheck(False, 200, "pull request is not open; event ignored")
    payload_head = str(((payload_pr or {}).get("head") or {}).get("sha") or "")
    api_head = str((api_pr.get("head") or {}).get("sha") or "")
    if not payload_head or payload_head != api_head:
        return EventCheck(False, 200, "stale event: the pull request head has moved; event ignored")
    return EventCheck(True, replacements={"pull_request": api_pr})


def needs_validation(event_type: str, payload: dict, command: Optional[str]) -> bool:
    """Events that start work or write records: scans, merges and slash commands."""
    action = (payload or {}).get("action")
    if event_type == "pull_request":
        return action in SCAN_ACTIONS or action == "closed"
    if event_type in ("issue_comment", "commit_comment"):
        return action == "created" and bool(command)
    return False


async def validate_relayed_event(event_type: str, payload: dict, get_json: GetJson) -> EventCheck:
    """Re-reads the event's subject from the GitHub API and compares it with the relayed payload."""
    repo = ((payload or {}).get("repository") or {}).get("full_name")
    if not repo:
        return EventCheck(False, 400, "payload has no repository")
    base = f"{GITHUB_API}/repos/{repo}"

    if event_type == "pull_request":
        pr = dict(payload.get("pull_request") or {})
        number = pr.get("number") or payload.get("number")
        if not number:
            return EventCheck(False, 400, "pull_request payload has no number")
        pr["number"] = number
        status, body = await get_json(f"{base}/pulls/{number}")
        failure = upstream_failure(status)
        if failure:
            return failure
        return compare_pull_request(pr, body if status == 200 else None, repo, payload.get("action"))

    if event_type == "issue_comment":
        comment = payload.get("comment") or {}
        issue = payload.get("issue") or {}
        if not comment.get("id") or not issue.get("number"):
            return EventCheck(False, 400, "issue_comment payload has no comment id or issue number")
        status, body = await get_json(f"{base}/issues/comments/{comment['id']}")
        failure = upstream_failure(status)
        if failure:
            return failure
        comment_check = compare_comment(comment, body if status == 200 else None, issue_number=issue["number"])
        if not comment_check.ok:
            return comment_check
        status, body = await get_json(f"{base}/issues/{issue['number']}")
        failure = upstream_failure(status)
        if failure:
            return failure
        issue_check = compare_issue(issue, body if status == 200 else None)
        if not issue_check.ok:
            return issue_check
        return EventCheck(True, replacements={**comment_check.replacements, **issue_check.replacements})

    if event_type == "commit_comment":
        comment = payload.get("comment") or {}
        if not comment.get("id") or not comment.get("commit_id"):
            return EventCheck(False, 400, "commit_comment payload has no comment id or commit id")
        status, body = await get_json(f"{base}/comments/{comment['id']}")
        failure = upstream_failure(status)
        if failure:
            return failure
        return compare_comment(comment, body if status == 200 else None, commit_sha=comment["commit_id"])

    return EventCheck(True)


def apply_authoritative(payload: dict, replacements: dict) -> dict:
    """Replaces relayed objects with GitHub's copies so downstream code never acts on forged fields."""
    if replacements:
        payload.update(replacements)
    return payload
