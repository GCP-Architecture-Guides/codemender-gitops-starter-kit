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
import re
import base64
import asyncio
import logging
from pathlib import Path

from log_redaction import redact

logger = logging.getLogger(__name__)

# Git subcommands that contact the remote and therefore need credentials.
_GIT_NETWORK_SUBCOMMANDS = frozenset({"clone", "fetch", "pull", "push", "ls-remote", "remote", "submodule"})
# Git global options that consume the following argument (skipped when locating the subcommand).
_GIT_GLOBAL_OPTS_WITH_VALUE = frozenset({"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env"})

# CodeMender local state inside a checkout: never staged, committed or cleaned.
CODEMENDER_STATE_PATHS = (".codemender", ".cm_project", ".exploit")
_BUILD_ARTIFACT_EXCLUDE_PATHSPECS = (
    ":(exclude)__pycache__",
    ":(exclude)**/__pycache__",
    ":(exclude)*.pyc",
    ":(exclude)*.pyo",
    ":(exclude)*.class",
)
_STATE_EXCLUDE_PATHSPECS = tuple(f":(exclude){p}" for p in CODEMENDER_STATE_PATHS) + _BUILD_ARTIFACT_EXCLUDE_PATHSPECS

# Markers that make GitHub skip workflow runs (and with them the GitHub Actions WIF relay).
_CI_SKIP_MARKERS_RE = re.compile(
    r"[ \t]*\[(?:skip ci|ci skip|no ci|skip actions|actions skip)\]|^skip-checks:\s*true[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)

# GitHub tokens are held only in process memory, keyed by workspace path, so every GitWorkspace
# object pointing at the same checkout can authenticate network commands. They are never
# written to .git/config or embedded in a remote URL.
_WORKSPACE_TOKENS: dict = {}

# Merge-gate reason when the scan checkout cannot be pinned to the PR head (ensure_exact_head).
HEAD_MISMATCH_REASON = "PR head moved or commit unavailable; re-scan the current head"
# Local branch used for the pinned checkout when the clone has no current branch (detached HEAD).
DEFAULT_SCAN_BRANCH = "codemender-scan"
_FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")


class HeadMismatchError(RuntimeError):
    """The checkout could not be placed at the exact commit whose merge gate is being decided."""


def _positive_int(value):
    """Returns ``value`` as a positive int (PR number), else None."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def build_git_auth_env(token: str) -> dict:
    """Returns per-command env vars that authenticate git HTTPS calls to github.com.

    Uses GIT_CONFIG_COUNT/KEY/VALUE (git >= 2.31), so the credential is never persisted in
    .git/config or placed in a remote URL.
    """
    if not token:
        return {}
    basic = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        "GIT_TERMINAL_PROMPT": "0",
    }


def strip_ci_skip_markers(message: str) -> str:
    """Removes [skip ci]-style markers so CodeMender commits still trigger workflows."""
    return _CI_SKIP_MARKERS_RE.sub("", message or "").strip()


def _git_subcommand(cmd: list):
    """Returns the git subcommand of ``cmd`` (e.g. 'push'), or None for non-git commands."""
    if not cmd or os.path.basename(str(cmd[0])) != "git":
        return None
    args = [str(a) for a in cmd[1:]]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _GIT_GLOBAL_OPTS_WITH_VALUE:
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            return arg
    return None


class GitWorkspace:
    def __init__(self, session_id: str, repo: str = None):
        self.session_id = session_id
        self.workspace_path = Path(f"/tmp/session-{session_id}")
        if not repo:
            # GEMINI.md "Dynamic Repository Target Identity": always pass repo= from the webhook
            # payload; never fall back to a static/env default or a placeholder.
            raise ValueError("GitWorkspace requires an explicit repo ('owner/name').")
        self.repo = repo
        self._github_token = None

    def _remote_url(self) -> str:
        """Token-free HTTPS remote; credentials are supplied per command via env."""
        return f"https://github.com/{self.repo}.git"

    def _remember_token(self, github_token: str):
        if github_token:
            self._github_token = github_token
            _WORKSPACE_TOKENS[str(self.workspace_path)] = github_token

    async def _resolve_token(self):
        """Token for this checkout: own token, the in-memory registry, else the token broker."""
        token = self._github_token or _WORKSPACE_TOKENS.get(str(self.workspace_path))
        if token or os.getenv("MOCK_MODE") == "true":
            return token
        try:
            # Checkout was cloned by another code path or process: broker a fresh token.
            from github_helpers import get_github_token
            token = await get_github_token()
        except Exception as token_err:
            logger.warning(f"No GitHub token available for authenticated git command: {redact(str(token_err))}")
            return None
        self._remember_token(token)
        return token

    async def _command_env(self, cmd: list):
        """Subprocess env for ``cmd``: auth header config only for git commands that hit the remote."""
        if _git_subcommand(cmd) not in _GIT_NETWORK_SUBCOMMANDS:
            return None
        token = await self._resolve_token()
        if not token:
            return None
        env = os.environ.copy()
        env.update(build_git_auth_env(token))
        return env

    async def _run_command(self, cmd: list, cwd: str = None) -> tuple:
        """Helper to run a command asynchronously using create_subprocess_exec."""
        # Convert Path objects to strings for subprocess compatibility
        exec_cwd = str(cwd) if cwd else str(self.workspace_path)
        printable_cmd = redact(" ".join(str(part) for part in cmd))
        logger.info(f"Running command: {printable_cmd} in CWD: {exec_cwd}")
        
        process = await asyncio.create_subprocess_exec(
            cmd[0],
            *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=exec_cwd,
            env=await self._command_env(cmd)
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            err_msg = redact(stderr.decode(errors="replace").strip())
            logger.error(f"Command failed: {printable_cmd}. Error: {err_msg}")
            raise RuntimeError(f"Git command failed: {err_msg}")
            
        return stdout.decode(errors="replace").strip(), stderr.decode(errors="replace").strip()

    async def clone_repo(self, github_token: str, branch: str = "main"):
        """Clones the target repository to the workspace path."""
        # Keep the token in memory only; git receives it per command, never via the URL.
        self._remember_token(github_token)

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
            
            await self._run_command(["git", "add", "-A"])
            # Identity applies to this mock seed commit only (not persisted in .git/config);
            # patch commits must use the pusher identity configured by the caller.
            await self._run_command([
                "git", "-c", "user.name=CodeMender Bot", "-c", "user.email=agent@codemender.ai",
                "commit", "-m", "Initial commit of mock search route"
            ])

            # Setup target branch
            if branch and branch != "main" and branch != "master":
                await self._run_command(["git", "checkout", "-b", branch])

            logger.info(f"MOCK_MODE: Initialized local mock workspace, committed search route, and checked out branch '{branch}'.")
            return

        is_sha = bool(re.match(r"^[0-9a-fA-F]{40}$", branch))
        # Token-free remote: .git/config never contains credentials (auth is per-command env).
        url = self._remote_url()
        logger.info(f"Cloning repository '{self.repo}' (target: '{branch}', is_sha={is_sha}) into {self.workspace_path}...")
        
        if is_sha:
            cmd = ["git", "clone", url, str(self.workspace_path)]
            await self._run_command(cmd, cwd=self.workspace_path.parent)
            await self._run_command(["git", "checkout", branch], cwd=self.workspace_path)
        else:
            cmd = ["git", "clone", "--branch", branch, url, str(self.workspace_path)]
            await self._run_command(cmd, cwd=self.workspace_path.parent)

    async def _head_sha(self) -> str:
        stdout, _ = await self._run_command(["git", "rev-parse", "HEAD"])
        return stdout.strip().lower()

    async def _has_commit(self, sha: str) -> bool:
        """True when the commit object is already in the local clone (no network access)."""
        try:
            await self._run_command(["git", "cat-file", "-e", f"{sha}^{{commit}}"])
            return True
        except (RuntimeError, OSError):
            return False

    async def _fetch_exact_commit(self, sha: str, pr_number=None):
        """Fetches ``sha`` by id, else the PR head ref; raises HeadMismatchError if it is still missing."""
        try:
            await self._run_command(["git", "fetch", "--no-tags", "origin", sha])
        except (RuntimeError, OSError) as fetch_err:
            pr = _positive_int(pr_number)
            if pr is None:
                raise HeadMismatchError(f"Commit {sha[:12]} could not be fetched from origin.") from fetch_err
            logger.warning(f"Fetching commit {sha[:12]} by id failed; trying refs/pull/{pr}/head.")
            try:
                await self._run_command(["git", "fetch", "--no-tags", "origin", f"refs/pull/{pr}/head"])
                fetch_head, _ = await self._run_command(["git", "rev-parse", "FETCH_HEAD"])
            except (RuntimeError, OSError) as pr_err:
                raise HeadMismatchError(
                    f"Commit {sha[:12]} could not be fetched by id or via refs/pull/{pr}/head."
                ) from pr_err
            fetch_head = fetch_head.strip().lower()
            if fetch_head != sha:
                # Still usable when sha is an ancestor of the moved head (now present locally).
                logger.warning(f"PR #{pr} head is now {fetch_head[:12]}, not {sha[:12]}.")
        if not await self._has_commit(sha):
            raise HeadMismatchError(f"Commit {sha[:12]} is not available from origin.")

    async def ensure_exact_head(self, head_sha: str, pr_number=None) -> None:
        """Guarantees the checkout is exactly ``head_sha``, the commit whose merge gate is decided.

        clone_repo(token, branch) checks out the branch tip, which can already be past the
        webhook's head SHA (or, for a fork PR, be a same-named branch of the base repository).
        When HEAD differs, the commit is taken from the local clone if present, else fetched by id
        (`git fetch origin <sha>`), else via `refs/pull/<pr_number>/head`. Every fetch goes
        through _run_command, so the per-command auth header applies.

        Pinning uses `git checkout -B <current branch> <head_sha>` (DEFAULT_SCAN_BRANCH when HEAD
        is detached) instead of a detached HEAD: the local branch keeps its name and upstream, so
        the cumulative diff (origin/<base>...HEAD), ensure_workspace's later `git checkout
        <branch>` + `git pull`, and patch branches created from HEAD behave as before; only the
        commit the branch starts from changes.

        Raises HeadMismatchError when the commit is unavailable or HEAD cannot be verified after
        the checkout. MOCK_MODE clones are synthetic, so the check is skipped there.
        """
        expected = str(head_sha or "").strip().lower()
        if not _FULL_SHA_RE.fullmatch(expected):
            raise HeadMismatchError(f"Refusing to pin the checkout to {head_sha!r}: not a full commit SHA.")
        if os.getenv("MOCK_MODE") == "true":
            logger.info(f"MOCK_MODE: synthetic clone, skipping the exact-head check for {expected[:12]}.")
            return

        try:
            current = await self._head_sha()
        except (RuntimeError, OSError) as err:
            raise HeadMismatchError(f"Could not read HEAD of {self.workspace_path}.") from err
        if current == expected:
            return

        logger.warning(f"Checkout HEAD {current[:12]} is not the PR head {expected[:12]}; pinning the scan to {expected[:12]}.")
        if not await self._has_commit(expected):
            await self._fetch_exact_commit(expected, pr_number)

        try:
            branch, _ = await self._run_command(["git", "branch", "--show-current"])
            branch = branch.strip() or DEFAULT_SCAN_BRANCH
            await self._run_command(["git", "checkout", "-B", branch, expected])
            pinned = await self._head_sha()
        except (RuntimeError, OSError) as err:
            raise HeadMismatchError(f"Could not check out {expected[:12]}.") from err
        if pinned != expected:
            raise HeadMismatchError(f"HEAD is {pinned[:12]} after checkout, expected {expected[:12]}.")
        logger.info(f"Pinned {self.workspace_path} to {expected[:12]} on local branch '{branch}'.")

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

        # 3. Stage all changes (new files included, CodeMender local state excluded)
        await self._run_command(["git", "add", "-A", "--", ".", *_STATE_EXCLUDE_PATHSPECS])

        # 4. Commit changes
        # The commit identity must be configured by the caller beforehand (set_committer_identity
        # with the pusher's name/email from Firestore); no identity is hard-coded here.
        await self._run_command(["git", "commit", "-m", "User submission"])

        # 5. Push branch to origin
        await self._run_command(["git", "push", "origin", branch_name])

    async def set_committer_identity(self, name: str, email: str):
        """Sets the git committer identity dynamically to comply with Google CLA / corporate agreements."""
        if name:
            try:
                await self._run_command(["git", "config", "user.name", name])
            except Exception:
                pass
        if email:
            try:
                await self._run_command(["git", "config", "user.email", email])
            except Exception:
                pass

    async def commit_all(self, message: str) -> str:
        """Stages every change with `git add -A` (CodeMender local state excluded) and commits it.

        Use instead of `git commit -am`, which silently drops files created by a fix. The commit
        identity must already be configured by the caller (see set_committer_identity). CI-skip
        markers are stripped so workflow-based checks and the WIF relay still run.
        Returns the new HEAD SHA.
        """
        await self._run_command(["git", "add", "-A", "--", ".", *_STATE_EXCLUDE_PATHSPECS])
        await self._run_command(["git", "commit", "-m", strip_ci_skip_markers(message)])
        stdout, _ = await self._run_command(["git", "rev-parse", "HEAD"])
        return stdout.strip()

    async def get_cumulative_diff_files(self, base_branch: str = "main") -> list[str]:
        """Resolves all modified files across multi-commit PRs using triple-dot merge-base."""
        if not self.workspace_path.exists():
            return []
        try:
            # Ensure base branch ref is fetched
            await self._run_command(["git", "fetch", "origin", base_branch])
        except Exception:
            pass
        try:
            cmd = ["git", "diff", "--name-only", f"origin/{base_branch}...HEAD"]
            stdout, _ = await self._run_command(cmd)
            return [f.strip() for f in stdout.splitlines() if f.strip()]
        except Exception as e:
            logger.warning(f"Cumulative diff failed against origin/{base_branch}...HEAD: {e}. Falling back to standard diff.")
            try:
                stdout, _ = await self._run_command(["git", "diff", "--name-only", "HEAD~1"])
                return [f.strip() for f in stdout.splitlines() if f.strip()]
            except Exception:
                return []

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
    import httpx

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
    import httpx

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
