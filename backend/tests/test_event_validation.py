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
"""Plan 1.6 (review D4): relayed events are re-validated against the GitHub API."""
import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from event_validation import (  # noqa: E402
    apply_authoritative,
    compare_comment,
    compare_issue,
    compare_pull_request,
    needs_validation,
    upstream_failure,
    validate_relayed_event,
)

REPO = "YOUR_ORG/YOUR_REPO"
BASE = f"https://api.github.com/repos/{REPO}"


def _comment(cid=101, login="alice", body="/fix all", issue=7, assoc="MEMBER"):
    return {
        "id": cid,
        "user": {"login": login},
        "body": body,
        "author_association": assoc,
        "issue_url": f"{BASE}/issues/{issue}",
    }


def _issue(number=7, author="bob", is_pr=True):
    issue = {"number": number, "user": {"login": author}}
    if is_pr:
        issue["pull_request"] = {"url": f"{BASE}/pulls/{number}"}
    return issue


def _pr(number=7, head="a" * 40, state="open", repo=REPO, merged=False):
    return {"number": number, "state": state, "merged": merged, "head": {"sha": head, "ref": "feature"},
            "base": {"ref": "main", "repo": {"full_name": repo}}}


def _fake_get_json(routes, calls=None):
    async def get_json(url):
        if calls is not None:
            calls.append(url)
        return routes.get(url, (404, None))
    return get_json


def _comment_event(comment, issue=None):
    return {"action": "created", "repository": {"full_name": REPO},
            "issue": issue or _issue(), "comment": comment}


class CompareCommentTest(unittest.TestCase):
    def test_matching_comment_is_accepted_and_api_copy_returned(self):
        api = _comment(assoc="COLLABORATOR")
        check = compare_comment(_comment(), api, issue_number=7)
        self.assertTrue(check.ok)
        self.assertIs(check.replacements["comment"], api)

    def test_forgeries_are_rejected_with_403(self):
        cases = {
            "missing": (_comment(), None),
            "id": (_comment(cid=1), _comment(cid=2)),
            "author": (_comment(login="mallory"), _comment(login="alice")),
            "body": (_comment(body="/approve"), _comment(body="looks good")),
            "issue": (_comment(issue=7), _comment(issue=8)),
        }
        for name, (payload, api) in cases.items():
            with self.subTest(name):
                check = compare_comment(payload, api, issue_number=7)
                self.assertFalse(check.ok)
                self.assertEqual(check.status_code, 403)

    def test_issue_number_is_matched_exactly(self):
        # /issues/17 must not satisfy issue 7.
        self.assertFalse(compare_comment(_comment(issue=17), _comment(issue=17), issue_number=7).ok)

    def test_crlf_and_whitespace_differences_are_not_forgeries(self):
        self.assertTrue(compare_comment(_comment(body="/fix all\r\n"), _comment(body="/fix all"), issue_number=7).ok)

    def test_commit_comment_must_target_the_commit(self):
        payload = {**_comment(), "commit_id": "c" * 40}
        self.assertTrue(compare_comment(payload, {**_comment(), "commit_id": "c" * 40}, commit_sha="c" * 40).ok)
        self.assertFalse(compare_comment(payload, {**_comment(), "commit_id": "d" * 40}, commit_sha="c" * 40).ok)


class CompareIssueTest(unittest.TestCase):
    def test_issue_copy_replaces_the_relayed_one(self):
        api = _issue(author="bob")
        check = compare_issue(_issue(author="mallory"), api)
        self.assertTrue(check.ok)
        self.assertIs(check.replacements["issue"], api)

    def test_missing_or_other_issue_is_rejected(self):
        self.assertEqual(compare_issue(_issue(), None).status_code, 403)
        self.assertEqual(compare_issue(_issue(number=7), _issue(number=8)).status_code, 403)


class ComparePullRequestTest(unittest.TestCase):
    def test_open_pr_with_matching_head_is_accepted(self):
        check = compare_pull_request(_pr(), _pr(), REPO, "synchronize")
        self.assertTrue(check.ok)
        self.assertIn("pull_request", check.replacements)

    def test_stale_or_closed_events_are_ignored_with_200(self):
        for name, api in {"moved": _pr(head="b" * 40), "closed": _pr(state="closed")}.items():
            with self.subTest(name):
                check = compare_pull_request(_pr(), api, REPO, "synchronize")
                self.assertFalse(check.ok)
                self.assertEqual(check.status_code, 200)

    def test_missing_or_foreign_pr_is_rejected_with_403(self):
        for name, api in {"missing": None, "other repo": _pr(repo="someone/else"),
                          "number": _pr(number=8), "no base repo": {**_pr(), "base": {}}}.items():
            with self.subTest(name):
                check = compare_pull_request(_pr(), api, REPO, "opened")
                self.assertFalse(check.ok)
                self.assertEqual(check.status_code, 403)

    def test_closed_event_must_match_githubs_state_and_merged_flag(self):
        merged = _pr(state="closed", merged=True)
        self.assertTrue(compare_pull_request(merged, merged, REPO, "closed").ok)
        for name, api in {"still open": _pr(), "not merged": _pr(state="closed", merged=False)}.items():
            with self.subTest(name):
                check = compare_pull_request(merged, api, REPO, "closed")
                self.assertFalse(check.ok)
                self.assertEqual(check.status_code, 403)


class NeedsValidationTest(unittest.TestCase):
    def test_events_that_start_work_or_write_records(self):
        self.assertTrue(needs_validation("pull_request", {"action": "synchronize"}, None))
        self.assertTrue(needs_validation("pull_request", {"action": "closed"}, None))
        self.assertFalse(needs_validation("pull_request", {"action": "labeled"}, None))
        self.assertTrue(needs_validation("issue_comment", {"action": "created"}, "fix"))
        self.assertTrue(needs_validation("commit_comment", {"action": "created"}, "verify"))
        self.assertFalse(needs_validation("issue_comment", {"action": "created"}, None))
        self.assertFalse(needs_validation("issue_comment", {"action": "edited"}, "fix"))
        self.assertFalse(needs_validation("push", {}, None))


class UpstreamFailureTest(unittest.TestCase):
    def test_our_side_failures_are_503(self):
        for status in (0, None, 401, 403, 429, 500, 502):
            with self.subTest(status=status):
                self.assertEqual(upstream_failure(status).status_code, 503)

    def test_success_and_not_found_are_not_upstream_failures(self):
        self.assertIsNone(upstream_failure(200))
        self.assertIsNone(upstream_failure(404))


class ValidateRelayedEventTest(unittest.TestCase):
    def _run(self, event_type, payload, routes, calls=None):
        return asyncio.run(validate_relayed_event(event_type, payload, _fake_get_json(routes, calls)))

    def test_forged_owner_approve_is_rejected(self):
        payload = _comment_event(_comment(body="/approve", assoc="OWNER"))
        routes = {f"{BASE}/issues/comments/101": (200, _comment(body="nice work", assoc="NONE"))}
        check = self._run("issue_comment", payload, routes)
        self.assertFalse(check.ok)
        self.assertEqual(check.status_code, 403)

    def test_genuine_comment_takes_githubs_comment_and_issue(self):
        payload = _comment_event(_comment(assoc="OWNER"), issue=_issue(author="mallory", is_pr=True))
        routes = {f"{BASE}/issues/comments/101": (200, _comment(assoc="CONTRIBUTOR")),
                  f"{BASE}/issues/7": (200, _issue(author="bob", is_pr=True))}
        check = self._run("issue_comment", payload, routes)
        self.assertTrue(check.ok)
        apply_authoritative(payload, check.replacements)
        self.assertEqual(payload["comment"]["author_association"], "CONTRIBUTOR")
        self.assertEqual(payload["issue"]["user"]["login"], "bob")

    def test_missing_issue_is_rejected(self):
        payload = _comment_event(_comment())
        routes = {f"{BASE}/issues/comments/101": (200, _comment())}
        self.assertEqual(self._run("issue_comment", payload, routes).status_code, 403)

    def test_pull_request_event_takes_githubs_pr_object(self):
        payload = {"action": "opened", "number": 7, "repository": {"full_name": REPO},
                   "pull_request": {**_pr(), "title": "forged title"}}
        routes = {f"{BASE}/pulls/7": (200, {**_pr(), "title": "real title"})}
        check = self._run("pull_request", payload, routes)
        self.assertTrue(check.ok)
        apply_authoritative(payload, check.replacements)
        self.assertEqual(payload["pull_request"]["title"], "real title")

    def test_commit_comment_is_checked_against_its_commit(self):
        comment = {**_comment(), "commit_id": "c" * 40}
        payload = {"action": "created", "repository": {"full_name": REPO}, "comment": comment}
        ok_routes = {f"{BASE}/comments/101": (200, dict(comment))}
        self.assertTrue(self._run("commit_comment", payload, ok_routes).ok)
        bad_routes = {f"{BASE}/comments/101": (200, {**comment, "commit_id": "d" * 40})}
        self.assertEqual(self._run("commit_comment", payload, bad_routes).status_code, 403)

    def test_not_found_is_403_and_upstream_errors_are_503(self):
        payload = _comment_event(_comment())
        self.assertEqual(self._run("issue_comment", payload, {}).status_code, 403)
        down = {f"{BASE}/issues/comments/101": (502, None)}
        self.assertEqual(self._run("issue_comment", payload, down).status_code, 503)

    def test_malformed_payloads_are_400_without_api_calls(self):
        calls = []
        cases = {
            "no repository": ("issue_comment", {"comment": _comment(), "issue": _issue()}),
            "no comment id": ("issue_comment", _comment_event({"body": "/fix"})),
            "no commit id": ("commit_comment", {"action": "created", "repository": {"full_name": REPO},
                                                "comment": _comment()}),
            "no pr number": ("pull_request", {"action": "opened", "repository": {"full_name": REPO},
                                              "pull_request": {}}),
        }
        for name, (event_type, payload) in cases.items():
            with self.subTest(name):
                self.assertEqual(self._run(event_type, payload, {}, calls).status_code, 400)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
