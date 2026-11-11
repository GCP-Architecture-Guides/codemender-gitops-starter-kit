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

"""Real-git tests for GitWorkspace.get_cumulative_diff_files, the PR scan's file selection.

Regression: files deleted by the PR were "selected for analysis" and listed as scan
targets in the report. Deleted files have nothing left to scan, so the cumulative merge-base diff
now leaves them out while keeping every commit of a multi-commit PR. Local repositories only:
no network, no GitHub, no token broker.
"""

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from git_manager import GitWorkspace  # noqa: E402

HAS_GIT = shutil.which("git") is not None


def _isolated_git_env():
    env = dict(os.environ)
    env.update({
        "MOCK_MODE": "false",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
    })
    return env


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


@unittest.skipUnless(HAS_GIT, "git not installed")
class CumulativeDiffFilesTest(unittest.TestCase):

    def setUp(self):
        broker = types.ModuleType("github_helpers")

        async def _no_token(*_args, **_kwargs):
            return None  # local remote: no credentials needed

        broker.get_github_token = _no_token
        for patcher in (mock.patch.dict(os.environ, _isolated_git_env()),
                        mock.patch.dict(sys.modules, {"github_helpers": broker})):
            patcher.start()
            self.addCleanup(patcher.stop)
        root = Path(tempfile.mkdtemp(prefix="cm-diff-files-"))
        self.addCleanup(shutil.rmtree, root, True)
        origin = root / "origin.git"
        _git(root, "init", "-q", "--bare", "-b", "main", str(origin))
        self.work = root / "work"
        _git(root, "clone", "-q", str(origin), str(self.work))
        _git(self.work, "checkout", "-q", "-b", "main")
        for name in ("app.py", "removed.py", "kept.py", "renamed_from.py"):
            (self.work / name).write_text(f"# {name}\nprint('{name}')\n")
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-q", "-m", "base")
        _git(self.work, "push", "-q", "origin", "main")
        _git(self.work, "checkout", "-q", "-b", "feature")
        # Two commits, so the merge-base diff must cover both.
        (self.work / "app.py").write_text("import os\nos.system(input())\n")
        (self.work / "removed.py").unlink()
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-q", "-m", "modify app.py, delete removed.py")
        (self.work / "added.py").write_text("print('new')\n")
        _git(self.work, "mv", "renamed_from.py", "renamed_to.py")
        _git(self.work, "add", "-A")
        _git(self.work, "commit", "-q", "-m", "add added.py, rename renamed_from.py")
        self.ws = GitWorkspace(f"unittest-{uuid.uuid4().hex[:12]}", repo="o/r")
        self.ws.workspace_path = self.work

    def test_deleted_files_are_not_selected(self):
        files = asyncio.run(self.ws.get_cumulative_diff_files("main"))
        self.assertNotIn("removed.py", files)
        self.assertNotIn("renamed_from.py", files)

    def test_added_modified_and_renamed_files_from_every_commit_are_selected(self):
        files = asyncio.run(self.ws.get_cumulative_diff_files("main"))
        self.assertEqual(sorted(files), ["added.py", "app.py", "renamed_to.py"])

    def test_a_deletion_only_pr_selects_nothing(self):
        _git(self.work, "checkout", "-q", "-b", "delete-only", "main")
        (self.work / "removed.py").unlink()
        _git(self.work, "commit", "-q", "-am", "delete removed.py")
        self.assertEqual(asyncio.run(self.ws.get_cumulative_diff_files("main")), [])


if __name__ == "__main__":
    unittest.main()
