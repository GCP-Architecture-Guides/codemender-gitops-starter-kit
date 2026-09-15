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
import asyncio
import logging
from pathlib import Path
import httpx

logger = logging.getLogger(__name__)

class GitWorkspace:
    def __init__(self, session_id: str, repo: str = None):
        self.session_id = session_id
        self.workspace_path = Path(f"/tmp/session-{session_id}")
        self.repo = repo or os.getenv("GITHUB_REPOSITORY", "YOUR_ORG/YOUR_REPO")

    async def _run_command(self, cmd: list, cwd: str = None) -> tuple:
        """Helper to run a command asynchronously using create_subprocess_exec."""
        # Convert Path objects to strings for subprocess compatibility
        exec_cwd = str(cwd) if cwd else str(self.workspace_path)
        logger.info(f"Running command: {' '.join(cmd)} in CWD: {exec_cwd}")
        
        process = await asyncio.create_subprocess_exec(
            cmd[0],
            *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=exec_cwd
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            err_msg = stderr.decode().strip()
            logger.error(f"Command failed: {' '.join(cmd)}. Error: {err_msg}")
            raise RuntimeError(f"Git command failed: {err_msg}")
            
        return stdout.decode().strip(), stderr.decode().strip()

    async def clone_repo(self, github_token: str, branch: str = "main"):
        """Clones the target repository to the workspace path."""
        # Ensure parent /tmp directory exists
        os.makedirs(self.workspace_path.parent, exist_ok=True)
        
        # Remove workspace path if it already exists to avoid clone errors
        if self.workspace_path.exists():
            import shutil
            shutil.rmtree(self.workspace_path)
            
        if os.getenv("MOCK_MODE") == "true":
            # Set up bare mock origin repository in /tmp/mock_github_repo if not present
            mock_origin = Path("/tmp/mock_github_repo")
            if not mock_origin.exists():
                mock_origin.mkdir(parents=True, exist_ok=True)
                proc = await asyncio.create_subprocess_exec("git", "init", "--bare", cwd=str(mock_origin))
                await proc.communicate()

            # Set up mock git repository locally to simulate a clean clone
            os.makedirs(self.workspace_path, exist_ok=True)
            await self._run_command(["git", "init"])
            try:
                await self._run_command(["git", "config", "user.name", "CodeMender Bot"])
                await self._run_command(["git", "config", "user.email", "agent@codemender.ai"])
            except Exception:
                pass
            
            # Setup origin remote pointing to bare mock repo
            await self._run_command(["git", "remote", "add", "origin", str(mock_origin)])

            # Write a mock vulnerable search route file inside the workspace
            filepath = "routes/search.ts"
            file_path = self.workspace_path / filepath
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(
                "const express = require('express');\n"
                "const router = express.Router();\n"
                "const db = require('../models');\n\n"
                "router.get('/search', async (req, res) => {\n"
                "  const query = req.query.q;\n"
                "  // Vulnerable SQL Injection Query\n"
                "  const results = await db.sequelize.query(\n"
                "    \"SELECT * FROM Products WHERE name LIKE '%\" + query + \"%'\"\n"
                "  );\n"
                "  res.json(results);\n"
                "});\n\n"
                "module.exports = router;\n",
                encoding="utf-8"
            )
            
            await self._run_command(["git", "add", "."])
            await self._run_command(["git", "commit", "-m", "Initial commit of mock search route"])

            # Setup target branch
            if branch and branch != "main" and branch != "master":
                await self._run_command(["git", "checkout", "-b", branch])

            logger.info(f"MOCK_MODE: Initialized local mock workspace, committed search route, and checked out branch '{branch}'.")
            return

        url = f"https://x-access-token:{github_token}@github.com/{self.repo}.git"
        logger.info(f"Cloning repository '{self.repo}' (branch: '{branch}') into {self.workspace_path}...")
        cmd = ["git", "clone", "--branch", branch, url, str(self.workspace_path)]
        
        # Run in parent directory because the target directory doesn't exist yet
        await self._run_command(cmd, cwd=self.workspace_path.parent)

    async def write_and_commit(self, filename: str, code: str):
        """Writes the user's code to the file, creates a branch, commits, and pushes it."""
        if not self.workspace_path.exists():
            raise RuntimeError("Workspace path does not exist. Did you run clone_repo first?")

        # 1. Write the file contents
        file_path = self.workspace_path / filename
        # Ensure subdirectories inside workspace exist if filename contains paths
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(code, encoding="utf-8")

        branch_name = f"demo/session-{self.session_id}"

        # 2. Checkout to a new branch
        await self._run_command(["git", "checkout", "-b", branch_name])

        # 3. Git add the file
        await self._run_command(["git", "add", "."])

        # 4. Commit changes
        # Ensure git user is configured if not already done globally
        try:
            await self._run_command(["git", "config", "user.name", "mgaur10"])
            await self._run_command(["git", "config", "user.email", "46466824+mgaur10@users.noreply.github.com"])
        except Exception:
            # Non-fatal if config is already set
            pass
            
        await self._run_command(["git", "commit", "-m", "User submission"])

        # 5. Push branch to origin
        await self._run_command(["git", "push", "origin", branch_name])

    async def apply_patch(self, patch_text: str, patch_branch: str = None):
        """Applies a patch text or checks out from remote patch branch into workspace."""
        if patch_branch:
            try:
                await self._run_command(["git", "fetch", "origin", patch_branch])
                await self._run_command(["git", "checkout", f"origin/{patch_branch}", "--", "."])
                logger.info(f"Successfully applied patch changes directly from remote branch {patch_branch}")
                return
            except Exception as branch_err:
                logger.warning(f"Failed to apply patch from remote branch {patch_branch}: {branch_err}. Falling back to git apply diff...")

        patch_file = self.workspace_path / "patch.diff"
        normalized_patch = patch_text if patch_text.endswith("\n") else patch_text + "\n"
        patch_file.write_text(normalized_patch, encoding="utf-8")
        try:
            try:
                await self._run_command(["git", "apply", "--3way", "patch.diff"])
            except Exception:
                await self._run_command(["git", "apply", "patch.diff"])
        finally:
            if patch_file.exists():
                patch_file.unlink()



async def get_existing_pr(repo: str, branch: str, github_token: str) -> tuple[int | None, str | None]:
    """Queries the GitHub REST API to see if a PR already exists for the given branch."""
    if os.getenv("MOCK_MODE") == "true":
        # In mock mode, we assume PR #1 already exists
        return 1, "https://github.com/mock/pr/1"

    # head param must be format owner:branch
    owner = repo.split("/")[0]
    url = f"https://api.github.com/repos/{repo}/pulls"
    params = {
        "head": f"{owner}:{branch}",
        "state": "open"
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params=params)
        if response.status_code == 200:
            prs = response.json()
            if prs:
                pr = prs[0]
                return pr.get("number"), pr.get("html_url")
        return None, None


async def create_draft_pr(repo: str, patch_branch: str, base_branch: str, github_token: str) -> tuple[str, int]:
    """Uses httpx to open a Draft PR on GitHub, returning (html_url, pr_number)."""
    if os.getenv("MOCK_MODE") == "true":
        return "https://github.com/mock/pr/1", 1

    url = f"https://api.github.com/repos/{repo}/pulls"
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    data = {
        "title": f"CodeMender Analysis - Base {base_branch}",
        "head": patch_branch,
        "base": base_branch,
        "draft": True,
        "body": f"Automated CodeMender security analysis for proposed fixes targeting branch `{base_branch}`."
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=data, headers=headers)
        if response.status_code != 201:
            raise RuntimeError(f"Failed to create Draft PR: {response.status_code} - {response.text}")
            
        pr_data = response.json()
        return pr_data.get("html_url", ""), pr_data.get("number")
