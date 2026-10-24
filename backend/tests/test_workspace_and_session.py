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
"""Plan 3.2 (verify/fix on the scanned commit) and 3.5 (one task owns the cm state at a time)."""
import asyncio
import os
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
import task_context  # noqa: E402

SHA = "a" * 40


class _FakeWorkspace:
    instances = []

    def __init__(self, session_id, repo=None):
        self.session_id, self.repo = session_id, repo
        self.commands, self.pinned, self.cloned = [], None, None
        _FakeWorkspace.instances.append(self)

    async def clone_repo(self, token, branch="main"):
        self.cloned = branch

    async def _run_command(self, cmd, cwd=None):
        self.commands.append(cmd)
        return "", ""

    async def ensure_exact_head(self, head_sha, pr_number=None):
        self.pinned = (head_sha, pr_number)


class EnsureWorkspaceTest(unittest.TestCase):
    def setUp(self):
        _FakeWorkspace.instances = []
        self.home = tempfile.mkdtemp(prefix="cm-home-")
        self.sha = uuid.uuid4().hex + "abcdefgh"  # 40 hex chars; /tmp/session-<sha> does not exist

        async def token(*_a, **_k):
            return "t"

        patches = [
            mock.patch.dict(os.environ, {"HOME": self.home}),
            mock.patch("git_manager.GitWorkspace", _FakeWorkspace),
            mock.patch.object(main, "get_github_token", token),
            mock.patch.object(main, "ensure_codemender_config", lambda: None),
            mock.patch("gcs_helpers.download_state_database", lambda sha: False),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_fresh_workspace_is_pinned_to_the_scanned_commit(self):
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            asyncio.run(main.ensure_workspace(self.sha, "feature", repo_name="o/r", pr_number=7))
        ws = _FakeWorkspace.instances[-1]
        self.assertEqual(ws.cloned, "feature")
        self.assertEqual(ws.pinned, (self.sha, 7))
        self.assertFalse(any("pull" in cmd for cmd in ws.commands), ws.commands)
        self.assertEqual(run.call_args.kwargs["timeout"], 360.0)

    def test_existing_workspace_is_reset_and_pinned_without_pulling(self):
        os.makedirs(f"/tmp/session-{self.sha}")
        self.addCleanup(lambda: os.rmdir(f"/tmp/session-{self.sha}"))
        with mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)):
            asyncio.run(main.ensure_workspace(self.sha, "feature", repo_name="o/r", pr_number=7))
        ws = _FakeWorkspace.instances[-1]
        self.assertIn(["git", "checkout", "feature"], ws.commands)
        self.assertFalse(any("pull" in cmd for cmd in ws.commands), ws.commands)
        self.assertEqual(ws.pinned, (self.sha, 7))

    def test_cm_init_timeout_fails_the_task(self):
        with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["cm", "init"], 360)):
            with self.assertRaisesRegex(RuntimeError, "cm init timed out"):
                asyncio.run(main.ensure_workspace(self.sha, "feature", repo_name="o/r"))


class TaskSessionTest(unittest.TestCase):
    def test_sessions_are_serialized_and_registered(self):
        events = []

        async def worker(name, sha, hold):
            session = task_context.TaskSession(sha, "scan", lock_id=f"workspace-{sha}", owner=name)
            try:
                await session.start()
                events.append(("start", name, sorted(task_context.IN_FLIGHT)))
                await asyncio.sleep(hold)
                events.append(("end", name))
            finally:
                session.finish()

        async def scenario():
            await asyncio.gather(worker("one", "s1", 0.05), worker("two", "s2", 0.0))

        asyncio.run(scenario())
        self.assertEqual([e[:2] for e in events], [("start", "one"), ("end", "one"), ("start", "two"), ("end", "two")])
        self.assertEqual(events[0][2], ["s1"])
        self.assertEqual(events[2][2], ["s2"])
        self.assertEqual(task_context.IN_FLIGHT, {})

    def test_cancel_check_is_scoped_to_the_session(self):
        seen = []

        async def scenario():
            check = lambda: None  # noqa: E731
            session = task_context.TaskSession("s3", "verify", owner="o", cancel_check=check)
            try:
                await session.start()
                seen.append(task_context.current_cancel_check() is check)
            finally:
                session.finish()
                session.finish()  # idempotent
            seen.append(task_context.current_cancel_check())

        asyncio.run(scenario())
        self.assertEqual(seen, [True, None])


class DashboardDelegationTest(unittest.TestCase):
    def setUp(self):
        scan = {"repo_name": "YOUR_ORG/YOUR_REPO", "pr_number": 7, "branch_name": "feature",
                "findings": [{"id": "f1", "severity": "CRITICAL"}]}
        snap = types.SimpleNamespace(exists=True, to_dict=lambda: dict(scan))
        fake_db = types.SimpleNamespace(collection=lambda _n: types.SimpleNamespace(
            document=lambda _k: types.SimpleNamespace(get=lambda: snap)))

        async def verified(_request):
            return "alice@example.com"

        self.verify_task, self.fix_task = mock.AsyncMock(), mock.AsyncMock()
        self.busy = False
        patches = [
            mock.patch.object(sys.modules["database"], "db", fake_db, create=True),
            mock.patch.object(main, "get_iap_user_email", verified),
            mock.patch.object(main, "ALLOWED_REPOS", frozenset({"YOUR_ORG/YOUR_REPO"})),
            mock.patch.object(main, "verify_findings_task", self.verify_task),
            mock.patch.object(main, "fix_findings_task", self.fix_task),
            mock.patch.object(main, "is_lock_held", lambda _lock_id: self.busy),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = TestClient(main.app)

    def test_single_finding_routes_use_the_shared_tasks(self):
        for path, task in ((f"/api/scans/{SHA}/verify/f1", self.verify_task), (f"/api/scans/{SHA}/fix/f1", self.fix_task)):
            with self.subTest(path=path):
                resp = self.client.post(path)
                self.assertEqual(resp.json()["status"], "success")
                kwargs = task.call_args.kwargs
                self.assertEqual((kwargs["finding_ids"], kwargs["pr_number"], kwargs["is_pr"]), (["f1"], 7, True))
                self.assertEqual(kwargs["event_type"], "dashboard")

    def test_busy_workspace_is_reported_without_enqueueing(self):
        self.busy = True
        resp = self.client.post(f"/api/scans/{SHA}/verify/f1")
        self.assertEqual(resp.json()["status"], "error")
        self.verify_task.assert_not_called()


if __name__ == "__main__":
    unittest.main()
