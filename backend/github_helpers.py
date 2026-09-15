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
import time
import hmac
import hashlib
import jwt
import httpx
import logging

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

async def get_github_token() -> str:
    """Brokers a GitHub token. Falls back to GITHUB_TOKEN if App credentials are missing."""
    if os.getenv("MOCK_MODE") == "true":
        return "mock_token"

    token = os.getenv("GITHUB_TOKEN")
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
            raise RuntimeError(f"Failed to fetch installation token: {response.status_code} - {response.text}")
        return response.json().get("token")


async def post_pr_comment(repo: str, pr_number: int, body: str, token: str):
    """Posts a comment on a GitHub Pull Request (using the Issues endpoint) with retries."""
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK POST COMMENT ON PR #{pr_number}]:\n{body}")
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {"body": body}
    
    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(url, json=data, headers=headers)
                if response.status_code == 201:
                    return response.json()
                elif response.status_code in [500, 502, 503, 504] and attempt < 3:
                    logger.warning(f"GitHub API returned {response.status_code} on attempt {attempt}/3. Retrying in {attempt * 2}s...")
                    await asyncio.sleep(attempt * 2)
                    continue
                else:
                    raise RuntimeError(f"Failed to post PR comment: {response.status_code} - {response.text}")
        except httpx.RequestError as req_err:
            if attempt < 3:
                logger.warning(f"Network error posting PR comment on attempt {attempt}/3: {req_err}. Retrying...")
                await asyncio.sleep(attempt * 2)
                continue
            raise RuntimeError(f"Failed to post PR comment after 3 attempts: {req_err}")


async def post_commit_comment(repo: str, commit_sha: str, body: str, token: str):
    """Posts a comment on a specific commit SHA."""
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK POST COMMENT ON COMMIT {commit_sha}]:\n{body}")
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
            raise RuntimeError(f"Failed to post commit comment: {response.status_code} - {response.text}")


async def get_pr_head_sha(repo: str, pr_number: int, token: str) -> str:
    """Fetches the current HEAD commit SHA of a Pull Request branch from GitHub."""
    if os.getenv("MOCK_MODE") == "true":
        try:
            from database import get_patch_proposal_by_pr
            patch = get_patch_proposal_by_pr(pr_number)
            if patch and patch.get("commit_sha"):
                return patch["commit_sha"]
        except Exception as e:
            logger.warning(f"Failed to fetch mock patch SHA: {e}")
        return "mock_commit_sha_123456"

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"Failed to fetch PR details: {response.status_code} - {response.text}")
        return response.json()["head"]["sha"]


async def convert_draft_pr_to_ready(repo: str, pr_number: int, token: str):
    """Converts a draft pull request to 'Ready for Review' by patching draft=False."""
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK CONVERT DRAFT PR #{pr_number} TO READY FOR REVIEW]")
        return

    # 1. Fetch the GraphQL node_id for the PR via REST GET
    get_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        get_res = await client.get(get_url, headers=headers)
        if get_res.status_code != 200:
            raise RuntimeError(f"Failed to fetch PR node_id for draft conversion: {get_res.status_code} - {get_res.text}")
        
        node_id = get_res.json().get("node_id")
        if not node_id:
            raise RuntimeError(f"PR node_id is missing from REST API response for PR #{pr_number}")
            
        # 2. Run markPullRequestReadyForReview GraphQL mutation
        gql_url = "https://api.github.com/graphql"
        gql_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        mutation = {
            "query": """
            mutation($prId: ID!) {
                markPullRequestReadyForReview(input: {pullRequestId: $prId}) {
                    pullRequest {
                        id
                        isDraft
                    }
                }
            }
            """,
            "variables": {"prId": node_id}
        }
        
        gql_res = await client.post(gql_url, json=mutation, headers=gql_headers)
        if gql_res.status_code != 200:
            raise RuntimeError(f"GraphQL request failed with HTTP {gql_res.status_code}: {gql_res.text}")
            
        gql_data = gql_res.json()
        if "errors" in gql_data:
            raise RuntimeError(f"GraphQL mutation failed: {gql_data['errors']}")
            
        logger.info(f"Successfully converted PR #{pr_number} (Node ID: {node_id}) from Draft to Ready for Review.")


async def set_commit_status(repo: str, commit_sha: str, state: str, description: str, token: str, target_url: str = None, context: str = "security/codemender-gate"):
    """
    Creates or updates a commit status check on GitHub (pending, success, failure, error)
    to enforce repository branch protection merge gates.
    """
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK COMMIT STATUS {commit_sha}]: state={state}, desc={description}")
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
    """
    Finds and updates an existing CodeMender comment on the PR in-place to prevent comment spam,
    or creates a new comment if none exists.
    """
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK UPDATE/POST PR COMMENT #{pr_number}]:\n{body}")
        return

    tagged_body = f"{tag}\n{body}"
    list_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(list_url, headers=headers)
            if res.status_code == 200:
                comments = res.json()
                for c in comments:
                    c_body = c.get("body", "")
                    if tag in c_body or "### 🔍 CodeMender Security Scan" in c_body:
                        comment_id = c.get("id")
                        patch_url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
                        patch_res = await client.patch(patch_url, json={"body": tagged_body}, headers=headers)
                        if patch_res.status_code == 200:
                            logger.info(f"Successfully updated in-place PR comment {comment_id} on PR #{pr_number}")
                            return
                        else:
                            logger.warning(f"Failed to patch PR comment {comment_id}: {patch_res.status_code} - {patch_res.text}")
                            break

            # If no existing comment found or patch failed, post a new comment
            await post_pr_comment(repo, pr_number, tagged_body, token)
    except Exception as e:
        logger.error(f"Error in update_or_post_pr_comment for PR #{pr_number}: {e}")

