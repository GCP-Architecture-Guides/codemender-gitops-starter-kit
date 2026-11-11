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

"""Real-git tests for GitWorkspace.apply_patch, the step /approve uses to apply a stored proposal.

Regression: the fix task stored `diff.strip()`, which drops trailing blank context lines, so the
last hunk was shorter than its header and `git apply` rejected it ("corrupt patch"). The task now
stores the raw diff, and apply_patch falls back to `git apply --recount` for proposals stored
before that change. Local repositories only: no network, no GitHub, no token broker.
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

# The last change sits right before the file's trailing blank lines, so the final hunk ends in
# blank context lines: exactly the shape that `.strip()` truncated.
BASE = "def ping(host):\n    command = f'ping -c 1 {host}'\n    return command\n\n\n"
PATCHED = "def ping(host):\n    command = ['ping', '-c', '1', host]\n    return command\n\n\n"


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


def _git(cwd, *args, check=True):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check)


@unittest.skipUnless(HAS_GIT, "git not installed")
class ApplyPatchTest(unittest.TestCase):

    def setUp(self):
        broker = types.ModuleType("github_helpers")

        async def _no_broker(*_args, **_kwargs):
            raise AssertionError("token broker must not be called in unit tests")

        broker.get_github_token = _no_broker
        for patcher in (mock.patch.dict(os.environ, _isolated_git_env()),
                        mock.patch.dict(sys.modules, {"github_helpers": broker})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.repo = Path(tempfile.mkdtemp(prefix="cm-apply-patch-"))
        self.addCleanup(shutil.rmtree, self.repo, True)
        _git(self.repo, "init", "-q", "-b", "feature")
        (self.repo / "app.py").write_text(BASE)
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "base")
        (self.repo / "app.py").write_text(PATCHED)
        self.raw_diff = _git(self.repo, "diff").stdout
        _git(self.repo, "checkout", "--", ".")
        self.ws = GitWorkspace(f"unittest-{uuid.uuid4().hex[:12]}", repo="o/r")
        self.ws.workspace_path = self.repo

    def _apply(self, text):
        asyncio.run(self.ws.apply_patch(text))
        return (self.repo / "app.py").read_text()

    def test_fixture_reproduces_the_corrupt_patch(self):
        self.assertTrue(self.raw_diff.endswith(" \n \n"), "last hunk must end in blank context lines")
        (self.repo / "trimmed.diff").write_text(self.raw_diff.strip() + "\n")
        result = _git(self.repo, "apply", "--check", "trimmed.diff", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corrupt patch", result.stderr)

    def test_raw_diff_applies(self):
        self.assertEqual(self._apply(self.raw_diff), PATCHED)

    def test_trimmed_diff_from_older_proposals_still_applies(self):
        self.assertEqual(self._apply(self.raw_diff.strip()), PATCHED)

    def test_patch_file_is_removed_after_apply(self):
        self._apply(self.raw_diff.strip())
        self.assertFalse((self.repo / "patch.diff").exists())

    def test_a_diff_for_other_content_is_still_rejected(self):
        (self.repo / "app.py").write_text("def ping(host):\n    return host\n")
        _git(self.repo, "commit", "-q", "-am", "diverged")
        with self.assertRaises(RuntimeError):
            asyncio.run(self.ws.apply_patch(self.raw_diff.strip()))
        self.assertEqual((self.repo / "app.py").read_text(), "def ping(host):\n    return host\n")


class StoredDiffSourceTest(unittest.TestCase):
    """The fix task must persist the untrimmed diff; only the comment preview is trimmed."""

    def test_fix_task_saves_the_raw_diff(self):
        source = Path(__file__).resolve().parents[1].joinpath("main.py").read_text(encoding="utf-8")
        self.assertIn('stored_diff = diff_out.decode(errors="replace")\n', source)
        self.assertIn("git_diff=stored_diff,", source)
        self.assertNotIn("git_diff=total_diff", source)


if __name__ == "__main__":
    unittest.main()
