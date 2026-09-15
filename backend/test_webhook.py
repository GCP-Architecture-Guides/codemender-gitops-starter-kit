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

import hmac
import hashlib
import json
import httpx
import os
import sys

import subprocess

# Simulation configuration
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://localhost:8000/github-webhook")
SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "mock_secret")

def compute_signature(payload_bytes: bytes, secret: str) -> str:
    computed = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return f"sha256={computed}"

def get_gcloud_identity_token() -> str:
    try:
        res = subprocess.run(
            ["gcloud", "auth", "print-identity-token"],
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception as e:
        print(f"⚠️ Failed to get gcloud identity token: {e}")
        return ""

async def send_mock_webhook(event_type: str, payload: dict):
    payload_bytes = json.dumps(payload).encode("utf-8")
    signature = compute_signature(payload_bytes, SECRET)
    
    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": event_type,
        "X-Hub-Signature-256": signature,
        "X-GitHub-Delivery": f"mock-delivery-{event_type}-{hash(payload_bytes)}"
    }
    
    if WEBHOOK_URL.startswith("https://"):
        token = get_gcloud_identity_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
            print("🔑 Attached Google OIDC Identity Token for Authentication.")
    
    print(f"\n🚀 Sending mock {event_type} webhook to {WEBHOOK_URL}...")
    async with httpx.AsyncClient() as client:
        response = await client.post(WEBHOOK_URL, content=payload_bytes, headers=headers, timeout=60.0)
        print(f"Response Status: {response.status_code}")
        print(f"Response Body: {response.text}")
        return response

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backend/test_webhook.py [push | approve | merge]")
        sys.exit(1)
        
    action = sys.argv[1]
    
    import asyncio
    
    if action == "push":
        import time
        commit_sha = f"mock_sha_{int(time.time())}"
        push_payload = {
            "after": commit_sha,
            "ref": "refs/heads/feature/add-vulnerable-route",
            "repository": {
                "full_name": os.getenv("GITHUB_REPOSITORY", "YOUR_ORG/YOUR_REPO")
            },
            "head_commit": {
                "message": "Add vulnerable routes/search.ts file"
            },
            "pusher": {
                "name": "dev-user"
            }
        }
        asyncio.run(send_mock_webhook("push", push_payload))
        
    elif action == "approve":
        # Simulate developer commenting '/approve' on the Pull Request
        comment_payload = {
            "action": "created",
            "issue": {
                "number": 1,
                "pull_request": {
                    "html_url": f"https://github.com/{os.getenv('GITHUB_REPOSITORY', 'YOUR_ORG/YOUR_REPO')}/pull/1"
                }
            },
            "comment": {
                "body": "/approve",
                "user": {
                    "login": "dev-user"
                }
            },
            "repository": {
                "full_name": os.getenv("GITHUB_REPOSITORY", "YOUR_ORG/YOUR_REPO")
            }
        }
        asyncio.run(send_mock_webhook("issue_comment", comment_payload))
    elif action == "merge":
        # Simulate GitHub PR merged webhook event
        merge_payload = {
            "action": "closed",
            "number": 1,
            "pull_request": {
                "number": 1,
                "merged": True,
                "merged_at": "2026-08-07T15:30:00Z",
                "merged_by": {
                    "login": "dev-user"
                },
                "base": {
                    "ref": "master"
                }
            },
            "repository": {
                "full_name": os.getenv("GITHUB_REPOSITORY", "YOUR_ORG/YOUR_REPO")
            }
        }
        asyncio.run(send_mock_webhook("pull_request", merge_payload))
    else:
        print(f"Unknown action: {action}. Choose 'push', 'approve', or 'merge'.")
