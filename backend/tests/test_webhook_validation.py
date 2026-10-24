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
"""Plan 1.6 at the webhook: relayed events are re-read from GitHub before anything runs.

Covers E2E test T6 (a forged OWNER /approve is rejected) at the handler level, plus the
push-access gate for slash commands and stale PR events.
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()

REPO = "your-org/your-repo"
BASE = f"https://api.github.com/repos/{REPO}"
HEAD = "a" * 40


def _comment(body="/fix all", login="alice", assoc="COLLABORATOR"):
    return {"id": 101, "user": {"login": login}, "body": body, "author_association": assoc,
            "issue_url": f"{BASE}/issues/7"}


def _issue():
    return {"number": 7, "user": {"login": "bob"}, "pull_request": {"url": f"{BASE}/pulls/7"}}


def _pr(head=HEAD, title="real title"):
    return {"number": 7, "state": "open", "draft": False, "title": title,
            "user": {"login": "bob"}, "html_url": "https://github.com/x/pull/7",
            "head": {"sha": head, "ref": "feature"},
            "base": {"ref": "main", "repo": {"full_name": REPO}}}


def _comment_event(comment):
    return {"action": "created", "repository": {"full_name": REPO}, "issue": _issue(), "comment": comment}


class WebhookEventValidationTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.routes = {}
        self.api_calls = []
        self.permission = "write"

        async def fake_get_json(url):
            self.api_calls.append(url)
            return self.routes.get(url, (404, None))

        async def fake_permission(_repo, _user, _token):
            return self.permission

        async def fake_token(*_args, **_kwargs):
            return "test-token"

        self.claimed = set()
        self.claim_store_up = True

        def fake_claim(comment_id, event_type, _repo):
            if not self.claim_store_up:
                return None
            key = (event_type, str(comment_id))
            if key in self.claimed:
                return False
            self.claimed.add(key)
            return True

        self.tasks = {name: mock.AsyncMock() for name in
                      ("process_approve_comment", "process_comment_command_task", "process_pr_scan_event")}
        patches = [
            mock.patch.object(main, "WIF_AUTH_ENABLED", True),
            mock.patch.object(main, "ALLOWED_REPOS", frozenset({REPO})),
            mock.patch.object(main, "github_get_json", fake_get_json),
            mock.patch.object(main, "get_collaborator_permission", fake_permission),
            mock.patch.object(main, "get_github_token", fake_token),
            mock.patch.object(main, "claim_comment_event", fake_claim),
            mock.patch.object(main, "is_scan_in_flight", lambda _sha: False),
            mock.patch.object(main, "update_scan_status", lambda *a, **k: None),
            mock.patch.dict(os.environ, {"MOCK_MODE": "false"}),
        ] + [mock.patch.object(main, name, task) for name, task in self.tasks.items()]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _post(self, event_type, payload):
        return self.client.post(
            "/github-webhook",
            content=json.dumps(payload),
            headers={"X-GitHub-Event": event_type, "X-CodeMender-Auth": "WIF",
                     "Content-Type": "application/json"},
        )

    def test_forged_owner_approve_is_rejected(self):
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment(body="nice work", assoc="NONE"))
        resp = self._post("issue_comment", _comment_event(_comment(body="/approve", assoc="OWNER")))
        self.assertEqual(resp.status_code, 403)
        self.tasks["process_approve_comment"].assert_not_called()

    def test_relayed_association_is_replaced_by_githubs(self):
        # Same comment, but the relay claims OWNER while GitHub says NONE.
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment(assoc="NONE"))
        self.routes[f"{BASE}/issues/7"] = (200, _issue())
        resp = self._post("issue_comment", _comment_event(_comment(assoc="OWNER")))
        self.assertEqual(resp.status_code, 403)
        self.tasks["process_comment_command_task"].assert_not_called()

    def test_member_without_write_access_is_rejected(self):
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment(assoc="MEMBER"))
        self.routes[f"{BASE}/issues/7"] = (200, _issue())
        self.permission = "read"
        resp = self._post("issue_comment", _comment_event(_comment(assoc="MEMBER")))
        self.assertEqual(resp.status_code, 403)
        self.tasks["process_comment_command_task"].assert_not_called()

    def test_genuine_command_from_a_writer_is_accepted(self):
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment())
        self.routes[f"{BASE}/issues/7"] = (200, _issue())
        resp = self._post("issue_comment", _comment_event(_comment()))
        self.assertEqual(resp.status_code, 202)
        self.tasks["process_comment_command_task"].assert_called_once()
        kwargs = self.tasks["process_comment_command_task"].call_args.kwargs
        self.assertEqual((kwargs["repo_name"], kwargs["command"], kwargs["pr_number"]), (REPO, "fix", 7))

    def test_github_unreachable_fails_closed(self):
        self.routes[f"{BASE}/issues/comments/101"] = (0, None)
        resp = self._post("issue_comment", _comment_event(_comment()))
        self.assertEqual(resp.status_code, 503)
        self.tasks["process_comment_command_task"].assert_not_called()

    def test_a_comment_runs_once_even_when_redelivered(self):
        # Plan 3.11: redeliveries, workflow re-runs and replays carry the same comment id.
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment())
        self.routes[f"{BASE}/issues/7"] = (200, _issue())
        first = self._post("issue_comment", _comment_event(_comment()))
        second = self._post("issue_comment", _comment_event(_comment()))
        self.assertEqual((first.status_code, second.status_code), (202, 200))
        self.tasks["process_comment_command_task"].assert_called_once()

    def test_dedupe_store_down_fails_closed(self):
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment())
        self.routes[f"{BASE}/issues/7"] = (200, _issue())
        self.claim_store_up = False
        resp = self._post("issue_comment", _comment_event(_comment()))
        self.assertEqual(resp.status_code, 503)
        self.tasks["process_comment_command_task"].assert_not_called()

    def test_rejected_commands_are_not_recorded(self):
        # A refused command must not burn the comment id (it was never run).
        self.routes[f"{BASE}/issues/comments/101"] = (200, _comment(assoc="MEMBER"))
        self.routes[f"{BASE}/issues/7"] = (200, _issue())
        self.permission = "read"
        self.assertEqual(self._post("issue_comment", _comment_event(_comment(assoc="MEMBER"))).status_code, 403)
        self.assertEqual(self.claimed, set())

    def test_ordinary_comment_needs_no_api_call(self):
        resp = self._post("issue_comment", _comment_event(_comment(body="thanks, looks good")))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.api_calls, [])

    def test_stale_pr_event_is_ignored(self):
        self.routes[f"{BASE}/pulls/7"] = (200, _pr(head="b" * 40))
        payload = {"action": "synchronize", "number": 7, "repository": {"full_name": REPO}, "pull_request": _pr()}
        resp = self._post("pull_request", payload)
        self.assertEqual(resp.status_code, 200)
        self.tasks["process_pr_scan_event"].assert_not_called()

    def test_current_pr_event_is_scanned_with_githubs_pr_object(self):
        self.routes[f"{BASE}/pulls/7"] = (200, _pr(title="real title"))
        payload = {"action": "opened", "number": 7, "repository": {"full_name": REPO},
                   "pull_request": _pr(title="forged title")}
        resp = self._post("pull_request", payload)
        self.assertEqual(resp.status_code, 202)
        self.tasks["process_pr_scan_event"].assert_called_once()
        scanned_payload = self.tasks["process_pr_scan_event"].call_args.args[0]
        self.assertEqual(scanned_payload["pull_request"]["title"], "real title")


REAL_CLAIM = main.claim_comment_event


class _FakeFirestore:
    """Minimal stand-in for create() semantics: fails when the document already exists."""

    def __init__(self, fail_with=None):
        self.docs = {}
        self.fail_with = fail_with

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, key):
                self.key = (name, key)

            def create(self, data):
                from google.api_core.exceptions import AlreadyExists
                if db.fail_with:
                    raise db.fail_with
                if self.key in db.docs:
                    raise AlreadyExists("document exists")
                db.docs[self.key] = data

        class _Collection:
            def document(self, key):
                return _Doc(key)

        return _Collection()


class ClaimCommentEventTest(unittest.TestCase):
    def _claim(self, db, comment_id=101):
        with mock.patch.dict(REAL_CLAIM.__globals__, {"db": db}):
            return REAL_CLAIM(comment_id, "issue_comment", REPO)

    def test_first_claim_wins_and_repeats_are_refused(self):
        db = _FakeFirestore()
        self.assertIs(self._claim(db), True)
        self.assertIs(self._claim(db), False)
        self.assertIs(self._claim(db, comment_id=102), True)

    def test_store_errors_and_missing_client_return_none(self):
        self.assertIsNone(self._claim(_FakeFirestore(fail_with=RuntimeError("unavailable"))))
        self.assertIsNone(self._claim(None))


if __name__ == "__main__":
    unittest.main()
