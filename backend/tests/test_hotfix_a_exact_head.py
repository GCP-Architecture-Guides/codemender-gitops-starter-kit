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

"""Stdlib-only tests for GitWorkspace.ensure_exact_head (scan pinned to the PR head SHA).

The stubbed tests replace _run_command; the real-git tests use local repositories only (no
network, no GitHub, no token broker).
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

import git_manager  # noqa: E402
from gate_policy import MAX_DESCRIPTION_CHARS, decide_gate  # noqa: E402
from git_manager import (  # noqa: E402
    DEFAULT_SCAN_BRANCH,
    HEAD_MISMATCH_REASON,
    GitWorkspace,
    HeadMismatchError,
)

HEAD_SHA = "a" * 40
TIP_SHA = "b" * 40
NEWER_SHA = "c" * 40
HAS_GIT = shutil.which("git") is not None
# Built at runtime so no token-shaped literal sits in the source.
FAKE_TOKEN = "ghs_" + "P1nP1nP1nP" * 3


class FakeGit:
    """Scripted stand-in for GitWorkspace._run_command (records every command)."""

    def __init__(self, head, present=(), fetchable=(), pr_refs=None, branch="feature", checkout_moves_head=True):
        self.head = head
        self.present = set(present) | {head}
        self.fetchable = set(fetchable)
        self.pr_refs = dict(pr_refs or {})  # "refs/pull/N/head" -> (fetch_head, objects it brings)
        self.branch = branch
        self.checkout_moves_head = checkout_moves_head
        self.fetch_head = None
        self.calls = []

    async def __call__(self, cmd, cwd=None):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        args = cmd[1:]
        if args == ["rev-parse", "HEAD"]:
            return self.head, ""
        if args[:2] == ["cat-file", "-e"]:
            if args[2].split("^")[0] in self.present:
                return "", ""
            raise RuntimeError("Git command failed: fatal: Not a valid object name")
        if args[:3] == ["fetch", "--no-tags", "origin"]:
            ref = args[3]
            if ref in self.fetchable:
                self.present.add(ref)
                self.fetch_head = ref
                return "", ""
            if ref in self.pr_refs:
                self.fetch_head, objects = self.pr_refs[ref]
                self.present |= set(objects)
                return "", ""
            raise RuntimeError("Git command failed: fatal: couldn't find remote ref")
        if args == ["rev-parse", "FETCH_HEAD"]:
            return self.fetch_head, ""
        if args == ["branch", "--show-current"]:
            return self.branch, ""
        if args[:2] == ["checkout", "-B"]:
            if self.checkout_moves_head:
                self.head = args[3]
            return "", ""
        raise AssertionError(f"unexpected git command: {cmd}")

    def ran(self, *prefix):
        return [c for c in self.calls if c[1:1 + len(prefix)] == list(prefix)]


class EnsureExactHeadStubbedTest(unittest.TestCase):

    def setUp(self):
        for patcher in (
            mock.patch.dict(os.environ, {"MOCK_MODE": "false"}),
            # Every git call must go through _run_command (stubbed here): fail on any direct exec.
            mock.patch.object(git_manager.asyncio, "create_subprocess_exec", side_effect=AssertionError("direct subprocess")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.ws = GitWorkspace(f"unittest-{uuid.uuid4().hex[:12]}", repo="YOUR_ORG/YOUR_REPO")

    def _run(self, fake, head_sha=HEAD_SHA, pr_number=None):
        self.ws._run_command = fake
        return asyncio.run(self.ws.ensure_exact_head(head_sha, pr_number=pr_number))

    def test_tip_equal_to_head_needs_no_fetch_or_checkout(self):
        fake = FakeGit(head=HEAD_SHA)
        self._run(fake, head_sha=HEAD_SHA.upper(), pr_number=7)
        self.assertEqual(fake.calls, [["git", "rev-parse", "HEAD"]])

    def test_commit_already_in_clone_is_pinned_without_network(self):
        fake = FakeGit(head=TIP_SHA, present={HEAD_SHA})
        self._run(fake, pr_number=7)
        self.assertEqual(fake.ran("fetch"), [])
        self.assertEqual(fake.ran("checkout"), [["git", "checkout", "-B", "feature", HEAD_SHA]])
        self.assertEqual(fake.head, HEAD_SHA)

    def test_tip_differs_and_fetch_by_id_succeeds(self):
        fake = FakeGit(head=TIP_SHA, fetchable={HEAD_SHA})
        self._run(fake, pr_number=7)
        self.assertEqual(fake.ran("fetch"), [["git", "fetch", "--no-tags", "origin", HEAD_SHA]])
        self.assertEqual(fake.ran("checkout"), [["git", "checkout", "-B", "feature", HEAD_SHA]])
        self.assertEqual(fake.calls[-1], ["git", "rev-parse", "HEAD"])  # re-verified after checkout
        self.assertEqual(fake.head, HEAD_SHA)

    def test_falls_back_to_pull_ref_when_fetch_by_id_fails(self):
        fake = FakeGit(head=TIP_SHA, pr_refs={"refs/pull/7/head": (HEAD_SHA, {HEAD_SHA})})
        self._run(fake, pr_number="7")
        self.assertEqual(fake.ran("fetch"), [
            ["git", "fetch", "--no-tags", "origin", HEAD_SHA],
            ["git", "fetch", "--no-tags", "origin", "refs/pull/7/head"],
        ])
        self.assertEqual(fake.ran("rev-parse", "FETCH_HEAD"), [["git", "rev-parse", "FETCH_HEAD"]])
        self.assertEqual(fake.head, HEAD_SHA)

    def test_moved_pr_head_still_pins_the_requested_commit_when_reachable(self):
        fake = FakeGit(head=TIP_SHA, pr_refs={"refs/pull/7/head": (NEWER_SHA, {NEWER_SHA, HEAD_SHA})})
        self._run(fake, pr_number=7)
        self.assertEqual(fake.head, HEAD_SHA)

    def test_fetch_failure_raises_head_mismatch(self):
        fake = FakeGit(head=TIP_SHA, pr_refs={"refs/pull/7/head": (NEWER_SHA, {NEWER_SHA})})
        with self.assertRaises(HeadMismatchError):
            self._run(fake, pr_number=7)
        self.assertEqual(fake.ran("checkout"), [])
        self.assertEqual(fake.head, TIP_SHA)

    def test_both_fetches_failing_raises_head_mismatch(self):
        fake = FakeGit(head=TIP_SHA)
        with self.assertRaises(HeadMismatchError):
            self._run(fake, pr_number=7)
        self.assertEqual(len(fake.ran("fetch")), 2)
        self.assertEqual(fake.ran("checkout"), [])

    def test_without_pr_number_there_is_no_pull_ref_fallback(self):
        for pr_number in (None, "", "abc", 0, -3):
            with self.subTest(pr_number=pr_number):
                fake = FakeGit(head=TIP_SHA)
                with self.assertRaises(HeadMismatchError):
                    self._run(fake, pr_number=pr_number)
                self.assertEqual(fake.ran("fetch"), [["git", "fetch", "--no-tags", "origin", HEAD_SHA]])

    def test_detached_clone_pins_on_the_default_scan_branch(self):
        fake = FakeGit(head=TIP_SHA, present={HEAD_SHA}, branch="")
        self._run(fake)
        self.assertEqual(fake.ran("checkout"), [["git", "checkout", "-B", DEFAULT_SCAN_BRANCH, HEAD_SHA]])

    def test_checkout_that_does_not_reach_head_raises(self):
        fake = FakeGit(head=TIP_SHA, present={HEAD_SHA}, checkout_moves_head=False)
        with self.assertRaises(HeadMismatchError):
            self._run(fake)

    def test_failed_checkout_raises_head_mismatch(self):
        fake = FakeGit(head=TIP_SHA, present={HEAD_SHA})

        async def failing(cmd, cwd=None):
            if cmd[1:3] == ["checkout", "-B"]:
                raise RuntimeError("Git command failed: error: Your local changes would be overwritten")
            return await fake(cmd, cwd)

        with self.assertRaises(HeadMismatchError):
            self._run(failing)

    def test_unreadable_head_raises_head_mismatch(self):
        async def broken(cmd, cwd=None):
            raise RuntimeError("Git command failed: fatal: not a git repository")

        with self.assertRaises(HeadMismatchError):
            self._run(broken)

    def test_invalid_sha_is_rejected_before_any_git_call(self):
        for bad in ("", None, "main", "abc123", "g" * 40, "a" * 39, "a" * 41):
            with self.subTest(bad=bad):
                fake = FakeGit(head=TIP_SHA)
                with self.assertRaises(HeadMismatchError):
                    self._run(fake, head_sha=bad)
                self.assertEqual(fake.calls, [])

    def test_mock_mode_skips_the_pin(self):
        fake = FakeGit(head=TIP_SHA)
        with mock.patch.dict(os.environ, {"MOCK_MODE": "true"}):
            self._run(fake)
        self.assertEqual(fake.calls, [])

    def test_head_mismatch_is_a_runtime_error_and_gates_as_error(self):
        self.assertTrue(issubclass(HeadMismatchError, RuntimeError))
        state, description = decide_gate([], error=HEAD_MISMATCH_REASON)
        self.assertEqual(state, "error")
        self.assertIn(HEAD_MISMATCH_REASON, description)
        self.assertLessEqual(len(description), MAX_DESCRIPTION_CHARS)

    def test_fetch_commands_get_the_per_command_auth_header(self):
        self.ws._remember_token(FAKE_TOKEN)
        self.addCleanup(git_manager._WORKSPACE_TOKENS.pop, str(self.ws.workspace_path), None)
        for cmd in (["git", "fetch", "--no-tags", "origin", HEAD_SHA],
                    ["git", "fetch", "--no-tags", "origin", "refs/pull/7/head"]):
            with self.subTest(cmd=cmd):
                env = asyncio.run(self.ws._command_env(cmd))
                self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        for cmd in (["git", "cat-file", "-e", f"{HEAD_SHA}^{{commit}}"], ["git", "checkout", "-B", "x", HEAD_SHA]):
            with self.subTest(cmd=cmd):
                self.assertIsNone(asyncio.run(self.ws._command_env(cmd)))


def _isolated_git_env():
    """Environment that ignores the developer's global/system git config."""
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
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def _commit(repo, name, content):
    Path(repo, name).write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"write {name}")
    return _git(repo, "rev-parse", "HEAD")


@unittest.skipUnless(HAS_GIT, "git not installed")
class EnsureExactHeadRealGitTest(unittest.TestCase):

    def setUp(self):
        for patcher in (
            mock.patch.dict(os.environ, _isolated_git_env()),
            # Never reach the real token broker (Secret Manager / gcloud) from unit tests.
            mock.patch.dict(sys.modules, {"github_helpers": self._broker_stub()}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        tmp = tempfile.mkdtemp(prefix="cm-exact-head-")
        self.addCleanup(shutil.rmtree, tmp, True)
        self.src, self.clone = Path(tmp, "src"), Path(tmp, "clone")
        self.src.mkdir()
        _git(self.src, "init", "-q", "-b", "feature")
        _git(self.src, "config", "uploadpack.allowAnySHA1InWant", "true")
        self.first = _commit(self.src, "app.py", "print('scanned commit')\n")
        self.second = _commit(self.src, "app.py", "print('branch moved on')\n")

    @staticmethod
    def _broker_stub():
        broker = types.ModuleType("github_helpers")

        async def _no_broker(*_args, **_kwargs):
            raise AssertionError("token broker must not be called in unit tests")

        broker.get_github_token = _no_broker
        return broker

    def _workspace(self, *clone_args):
        _git(self.src.parent, "clone", "-q", *clone_args, str(self.src), str(self.clone))
        ws = GitWorkspace(f"unittest-{uuid.uuid4().hex[:12]}", repo="o/r")
        ws.workspace_path = self.clone
        ws._remember_token(FAKE_TOKEN)
        self.addCleanup(git_manager._WORKSPACE_TOKENS.pop, str(self.clone), None)
        return ws

    def test_branch_tip_is_pinned_back_to_the_webhook_head(self):
        ws = self._workspace("--branch", "feature")
        self.assertEqual(_git(self.clone, "rev-parse", "HEAD"), self.second)
        asyncio.run(ws.ensure_exact_head(self.first, pr_number=3))
        self.assertEqual(_git(self.clone, "rev-parse", "HEAD"), self.first)
        self.assertEqual(_git(self.clone, "branch", "--show-current"), "feature")
        self.assertEqual(Path(self.clone, "app.py").read_text(), "print('scanned commit')\n")
        self.assertEqual(_git(self.clone, "status", "--porcelain"), "")

    def test_commit_missing_from_the_clone_is_fetched_by_id(self):
        ws = self._workspace("--single-branch", "--branch", "feature")
        _git(self.src, "checkout", "-q", "-b", "other")
        other = _commit(self.src, "other.py", "print('only on another ref')\n")
        asyncio.run(ws.ensure_exact_head(other))
        self.assertEqual(_git(self.clone, "rev-parse", "HEAD"), other)
        self.assertTrue(Path(self.clone, "other.py").exists())

    def test_unavailable_commit_raises_and_leaves_the_checkout_alone(self):
        ws = self._workspace("--branch", "feature")
        with self.assertRaises(HeadMismatchError):
            asyncio.run(ws.ensure_exact_head("d" * 40, pr_number=5))
        self.assertEqual(_git(self.clone, "rev-parse", "HEAD"), self.second)


if __name__ == "__main__":
    unittest.main()
