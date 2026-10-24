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

import os
import time
import hmac
import hashlib
import jwt
import httpx
import logging
from typing import Optional, Dict, Any, List

from log_redaction import redact

logger = logging.getLogger(__name__)


def verify_signature(payload: bytes, signature_header: str, secret: str) -> bool:
    """Verifies that the webhook payload is signed with the correct secret."""
    if not signature_header or not secret:
        return False
    
    parts = signature_header.split("=")
    if len(parts) != 2 or parts[0] != "sha256":
        return False
    
    expected_signature = parts[1]
    computed_signature = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed_signature, expected_signature)


def resolve_context_token(context: str = "pr", project_id: Optional[str] = None) -> str:
    """
    Resolves the GitHub token for pull-request operations: GITHUB_PR_TOKEN or GITHUB_TOKEN from
    the environment, else Secret Manager in this deployment's project.

    `context` is kept for call compatibility; only 'pr' exists since the fleet engine was removed.
    There is deliberately no default project and no gcloud CLI fallback: either could resolve a
    token from whichever project the local gcloud configuration happens to point at.
    """
    token = os.getenv("GITHUB_PR_TOKEN") or os.getenv("GITHUB_TOKEN")
    if token:
        return token

    proj = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not proj:
        logger.warning("GOOGLE_CLOUD_PROJECT is not set; cannot read the GitHub token from Secret Manager.")
        return ""
    try:
        from google.cloud import secretmanager
        client = secretmanager.SecretManagerServiceClient()
        for sec_name in ("codemender-github-pat", "GITHUB_PR_TOKEN", "GITHUB_TOKEN"):
            try:
                secret_path = f"projects/{proj}/secrets/{sec_name}/versions/latest"
                resp = client.access_secret_version(request={"name": secret_path})
                val = resp.payload.data.decode("UTF-8").strip()
                if val:
                    return val
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"Could not load the GitHub token from Secret Manager: {e}")
    return ""


async def get_github_token(context: str = "pr") -> str:
    """Brokers the GitHub token for PR operations. Falls back to GitHub App credentials when no token is set."""
    if os.getenv("MOCK_MODE") == "true":
        return "mock_token"

    token = resolve_context_token(context=context)
    if token:
        return token
        
    app_id = os.getenv("GITHUB_APP_ID")
    private_key = os.getenv("GITHUB_APP_PRIVATE_KEY")
    installation_id = os.getenv("GITHUB_APP_INSTALLATION_ID")
    
    if not app_id or not private_key or not installation_id:
         raise RuntimeError("GitHub authentication configuration is missing (neither GITHUB_TOKEN nor GITHUB_APP_* set)")
         
    # Handle private key formatting (e.g. replace escaped newlines from env)
    formatted_key = private_key.replace("\\n", "\n")
    
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": app_id
    }
    
    # Generate signed JWT using RS256
    jwt_token = jwt.encode(payload, formatted_key, algorithm="RS256")
    
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {jwt_token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers)
        if response.status_code != 201:
            raise RuntimeError(f"Failed to get GitHub App installation token: {response.status_code} - {response.text}")
        
        data = response.json()
        return data["token"]


async def post_pr_comment(repo: str, pr_number: int, body: str, token: str):
    """Posts a comment on a GitHub pull request via the REST API.

    Every comment body passes through log_redaction.redact (plan 3.10): reports embed CLI output
    and exception text, which can carry tokens.
    """
    body = redact(body)
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK POST PR COMMENT #{pr_number}]:\n{body}")
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "body": body
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=data, headers=headers)
        if response.status_code != 201:
            raise RuntimeError(f"Failed to post PR comment: {response.status_code} - {response.text}")
        logger.info(f"Successfully posted PR comment to PR #{pr_number} on {repo}")


async def post_commit_comment(repo: str, commit_sha: str, body: str, token: str):
    """Posts a commit comment on GitHub for non-PR pushes (body redacted, plan 3.10)."""
    body = redact(body)
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK POST COMMIT COMMENT {commit_sha[:7]}]:\n{body}")
        return

    url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}/comments"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {"body": body}

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=data, headers=headers)
        if response.status_code != 201:
            logger.warning(f"Failed to post commit comment: {response.status_code} - {response.text}")
        else:
            logger.info(f"Successfully posted commit comment to commit {commit_sha[:7]} on {repo}")


async def get_pr_head_sha(repo: str, pr_number: int, token: str) -> str:
    """Fetches the latest head commit SHA of a pull request."""
    if os.getenv("MOCK_MODE") == "true":
        return "mock_head_sha"

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to get PR head SHA: {response.status_code} - {response.text}")
        
        pr_data = response.json()
        return pr_data["head"]["sha"]


async def convert_draft_pr_to_ready(repo: str, pr_number: int, token: str):
    """Converts a Draft PR into a standard 'Ready for Review' PR via GitHub GraphQL API."""
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK CONVERT PR #{pr_number} TO READY FOR REVIEW]")
        return

    # 1. Fetch Node ID of the PR via REST API
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.warning(f"Failed to fetch PR node_id for PR #{pr_number}: {resp.status_code}")
            return
        node_id = resp.json().get("node_id")

    if not node_id:
        logger.warning(f"No node_id found for PR #{pr_number}")
        return

    # 2. Execute GraphQL Mutation markPullRequestReadyForReview
    graphql_url = "https://api.github.com/graphql"
    mutation = {
        "query": """
        mutation ($pullRequestId: ID!) {
          markPullRequestReadyForReview(input: {pullRequestId: $pullRequestId}) {
            pullRequest {
              isDraft
            }
          }
        }
        """,
        "variables": {"pullRequestId": node_id}
    }
    
    async with httpx.AsyncClient() as client:
        graphql_resp = await client.post(graphql_url, json=mutation, headers=headers)
        if graphql_resp.status_code == 200:
            logger.info(f"Successfully converted PR #{pr_number} from Draft to Ready for Review.")
        else:
            logger.warning(f"GraphQL conversion failed for PR #{pr_number}: {graphql_resp.status_code} - {graphql_resp.text}")


async def set_commit_status(repo: str, commit_sha: str, state: str, description: str, token: str, context: str = "security/codemender-gate", target_url: str = None):
    """
    Sets a GitHub commit status check (e.g. security/codemender-gate).
    state must be one of: 'pending', 'success', 'failure', 'error'.
    """
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK COMMIT STATUS {commit_sha[:7]}]: context='{context}', state='{state}', desc='{description}'")
        return
    url = f"https://api.github.com/repos/{repo}/statuses/{commit_sha}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "state": state,                 # "pending" | "success" | "failure" | "error"
        "description": description[:140], # GitHub enforces 140 character limit
        "context": context
    }
    if target_url:
        data["target_url"] = target_url
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=headers)
            if response.status_code != 201:
                logger.warning(f"Failed to set commit status on {commit_sha}: {response.status_code} - {response.text}")
            else:
                logger.info(f"Successfully updated GitHub status on {commit_sha}: [{state.upper()}] - {description}")
    except Exception as e:
        logger.error(f"Error setting GitHub commit status on {commit_sha}: {e}")


async def update_or_post_pr_comment(repo: str, pr_number: int, body: str, token: str, tag: str = "<!-- codemender-security-report -->"):
    """Edits the PR's single CodeMender report comment in place, or posts it when there is none.

    The report is found by its hidden tag on every page of the PR's comments (plan 3.12; the old
    lookup read only the first 30, so busy PRs got a new report on each scan). The body is
    redacted (plan 3.10) and carries the tag exactly once.
    """
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK UPDATE/POST PR COMMENT #{pr_number}]:\n{body}")
        return

    tagged_body = redact(body if tag in (body or "") else f"{tag}\n{body}")
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            comment_id = await _find_comment_with_marker(client, repo, pr_number, tag, token)
            if comment_id:
                patch_url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
                patch_res = await client.patch(patch_url, json={"body": tagged_body}, headers=_api_headers(token))
                if patch_res.status_code == 200:
                    logger.info(f"Successfully updated in-place PR comment {comment_id} on PR #{pr_number}")
                    return
                logger.warning(f"Failed to patch PR comment {comment_id}: {patch_res.status_code}")
        # No existing report (or the edit failed): post a new one.
        await post_pr_comment(repo, pr_number, tagged_body, token)
    except Exception as e:
        logger.error(f"Error in update_or_post_pr_comment for PR #{pr_number}: {e}")


def _api_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }


async def _get_collaborator_access(repo: str, username: str, token: str) -> Dict[str, Any]:
    """GET /collaborators/{username}/permission. Any failure returns {} so that callers fail closed."""
    if not username:
        return {}
    url = f"https://api.github.com/repos/{repo}/collaborators/{username}/permission"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=_api_headers(token))
        if response.status_code != 200:
            logger.warning(f"Could not read repository role for '{username}' on {repo}: HTTP {response.status_code}")
            return {}
        return response.json() or {}
    except Exception as e:
        logger.warning(f"Error reading repository role for '{username}' on {repo}: {e}")
        return {}


async def get_collaborator_role(repo: str, username: str, token: str) -> str:
    """Returns the user's role on the repository (role_name, else permission, else 'none').

    Any lookup failure returns 'none' so that callers fail closed.
    """
    if os.getenv("MOCK_MODE") == "true":
        return "admin"
    data = await _get_collaborator_access(repo, username, token)
    return str(data.get("role_name") or data.get("permission") or "none").lower()


async def get_collaborator_permission(repo: str, username: str, token: str) -> str:
    """Returns the user's base permission on the repository: admin, write, read or none.

    Unlike role_name, this is always one of the four base levels (maintain reports 'write',
    triage reports 'read', custom roles report their base). Lookup failures return 'none'.
    """
    if os.getenv("MOCK_MODE") == "true":
        return "admin"
    data = await _get_collaborator_access(repo, username, token)
    return str(data.get("permission") or "none").lower()


async def github_get_json(url: str) -> tuple:
    """GETs a GitHub REST API URL with the service token. Returns (status, json-or-None).

    Network or token errors return (0, None). Only https://api.github.com/ URLs are fetched, so
    the token is never sent to another host.
    """
    if not str(url).startswith("https://api.github.com/"):
        raise ValueError("github_get_json only fetches https://api.github.com/ URLs")
    try:
        token = await get_github_token()
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=_api_headers(token))
        if response.status_code != 200:
            return response.status_code, None
        return 200, response.json()
    except Exception as e:
        logger.warning(f"GitHub API read failed for {url}: {type(e).__name__}")
        return 0, None


# Progress comment ids per (repo, pr_number, key), so heartbeats edit one comment in place.
_progress_comment_ids: Dict[tuple, int] = {}


def _progress_marker(key: str) -> str:
    return f"<!-- codemender-progress:{key} -->"


def get_progress_comment_id(repo: str, pr_number: int, key: str) -> Optional[int]:
    """Returns the cached id of a progress comment posted by this process, if any (no API call)."""
    return _progress_comment_ids.get((repo, str(pr_number), key))


async def _find_comment_with_marker(client: httpx.AsyncClient, repo: str, pr_number: int, marker: str, token: str, max_pages: int = 10) -> Optional[int]:
    """Searches the PR's issue comments page by page for a hidden marker."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    for page in range(1, max_pages + 1):
        response = await client.get(url, headers=_api_headers(token), params={"per_page": 100, "page": page})
        if response.status_code != 200:
            logger.warning(f"Failed to list comments on PR #{pr_number}: {response.status_code}")
            return None
        comments = response.json() or []
        for comment in comments:
            if marker in (comment.get("body") or ""):
                return comment.get("id")
        if len(comments) < 100:
            return None
    return None


async def upsert_progress_comment(repo: str, pr_number: int, key: str, body: str, token: str) -> Optional[int]:
    """Creates or edits the single progress comment identified by `key` on a PR. Returns its id."""
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK UPSERT PROGRESS COMMENT #{pr_number} ({key})]:\n{body}")
        return None

    marker = _progress_marker(key)
    full_body = redact(f"{marker}\n{body}")
    cache_key = (repo, str(pr_number), key)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            comment_id = _progress_comment_ids.get(cache_key)
            if comment_id is None:
                comment_id = await _find_comment_with_marker(client, repo, pr_number, marker, token)

            if comment_id:
                patch_url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
                response = await client.patch(patch_url, json={"body": full_body}, headers=_api_headers(token))
                if response.status_code == 200:
                    _progress_comment_ids[cache_key] = comment_id
                    return comment_id
                _progress_comment_ids.pop(cache_key, None)
                if response.status_code != 404:
                    logger.warning(f"Failed to edit progress comment {comment_id} on PR #{pr_number}: {response.status_code}")
                    return None
                # 404: the comment was deleted, so post a fresh one below.

            post_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
            response = await client.post(post_url, json={"body": full_body}, headers=_api_headers(token))
            if response.status_code != 201:
                logger.warning(f"Failed to post progress comment on PR #{pr_number}: {response.status_code}")
                return None
            comment_id = response.json().get("id")
            if comment_id:
                _progress_comment_ids[cache_key] = comment_id
            return comment_id
    except Exception as e:
        logger.error(f"Error upserting progress comment '{key}' on PR #{pr_number}: {e}")
        return None


async def delete_comment(repo: str, comment_id: int, token: str) -> bool:
    """Deletes an issue/PR comment. Returns True when this call deleted it."""
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK DELETE COMMENT {comment_id}]")
        return True

    url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.delete(url, headers=_api_headers(token))
        if response.status_code in (204, 404):
            for cache_key, cached_id in list(_progress_comment_ids.items()):
                if cached_id == comment_id:
                    _progress_comment_ids.pop(cache_key, None)
        if response.status_code == 204:
            return True
        logger.warning(f"Failed to delete comment {comment_id} on {repo}: {response.status_code}")
    except Exception as e:
        logger.error(f"Error deleting comment {comment_id} on {repo}: {e}")
    return False


async def get_pull_request(repo: str, pr_number: int, token: str) -> Dict[str, Any]:
    """Fetches the live pull request (head ref/sha/repo, author, draft state) from the GitHub API."""
    if os.getenv("MOCK_MODE") == "true":
        return {
            "number": pr_number,
            "draft": False,
            "user": {"login": "developer"},
            "head": {"ref": "mock-branch", "sha": "mock_head_sha", "repo": {"full_name": repo}}
        }

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(url, headers=_api_headers(token))
    if response.status_code != 200:
        raise RuntimeError(f"Failed to get PR #{pr_number}: {response.status_code}")
    return response.json()


async def get_commit_author(repo: str, commit_sha: str, token: str) -> Optional[tuple]:
    """Returns (name, email) of a commit's git author, or None when unavailable."""
    if os.getenv("MOCK_MODE") == "true":
        return None

    url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=_api_headers(token))
        if response.status_code != 200:
            logger.warning(f"Failed to read author of commit {commit_sha[:8]} on {repo}: {response.status_code}")
            return None
        author = (response.json().get("commit") or {}).get("author") or {}
        name, email = (author.get("name") or "").strip(), (author.get("email") or "").strip()
        return (name, email) if name and email else None
    except Exception as e:
        logger.warning(f"Error reading author of commit {commit_sha[:8]} on {repo}: {e}")
        return None
