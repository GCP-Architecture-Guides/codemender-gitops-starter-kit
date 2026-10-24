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

"""Stdlib-only tests for request_guards (WEBHOOK_ONLY, dashboard targets, error ids)."""

import asyncio
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from command_auth import parse_allowed_repos  # noqa: E402
from request_guards import (  # noqa: E402
    WEBHOOK_ONLY_PATHS,
    WebhookOnlyMiddleware,
    error_payload,
    is_error_result,
    is_path_allowed_for_webhook_only,
    new_error_id,
    normalize_pr_number,
    resolve_scan_target,
    scrub_error_result,
)

# Built at runtime so no token-shaped literal sits in the source.
FAKE_TOKEN = "ghp_" + "L34kL34kL3" * 3


class WebhookOnlyPathTest(unittest.TestCase):

    def test_exact_webhook_and_health_paths_are_allowed(self):
        self.assertEqual(WEBHOOK_ONLY_PATHS, frozenset({"/github-webhook", "/webhook", "/health"}))
        for path in ("/github-webhook", "/webhook", "/health"):
            with self.subTest(path=path):
                self.assertTrue(is_path_allowed_for_webhook_only(path))

    def test_everything_else_is_refused(self):
        for path in (
            "/", "", None, "/api/scans", "/api/scans/abc/fix/f1", "/api/v1/fleet/scan",
            "/api/maintenance/gc", "/index.html", "/_next/static/app.js", "/scans/abc",
            "/github-webhook/", "/health/", "/webhook/", "/HEALTH", "/Webhook", "//webhook",
            "/github-webhook/../api/scans", "/github-webhook?x=1", " /health", b"/health",
        ):
            with self.subTest(path=path):
                self.assertFalse(is_path_allowed_for_webhook_only(path))


class _RecordingApp:
    def __init__(self):
        self.scopes = []

    async def __call__(self, scope, receive, send):
        self.scopes.append(scope)
        await send({"type": "http.response.start", "status": 202, "headers": []})
        await send({"type": "http.response.body", "body": b"inner"})


def _drive(middleware, scope):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    return sent


class WebhookOnlyMiddlewareTest(unittest.TestCase):

    def test_disallowed_http_path_gets_404_without_reaching_the_app(self):
        inner = _RecordingApp()
        sent = _drive(WebhookOnlyMiddleware(inner), {"type": "http", "path": "/api/scans/abc/fix", "method": "POST"})
        self.assertEqual(inner.scopes, [])
        self.assertEqual(sent[0]["type"], "http.response.start")
        self.assertEqual(sent[0]["status"], 404)
        self.assertIn((b"content-type", b"application/json"), sent[0]["headers"])
        self.assertEqual(sent[1], {"type": "http.response.body", "body": b'{"detail":"Not Found"}'})

    def test_allowed_path_passes_through_unchanged(self):
        inner = _RecordingApp()
        scope = {"type": "http", "path": "/github-webhook", "method": "POST"}
        sent = _drive(WebhookOnlyMiddleware(inner), scope)
        self.assertEqual(inner.scopes, [scope])
        self.assertEqual(sent[0]["status"], 202)

    def test_lifespan_is_not_intercepted(self):
        inner = _RecordingApp()
        _drive(WebhookOnlyMiddleware(inner), {"type": "lifespan"})
        self.assertEqual(inner.scopes, [{"type": "lifespan"}])

    def test_websocket_on_other_path_is_closed(self):
        inner = _RecordingApp()
        sent = _drive(WebhookOnlyMiddleware(inner), {"type": "websocket", "path": "/ws"})
        self.assertEqual(inner.scopes, [])
        self.assertEqual(sent, [{"type": "websocket.close", "code": 1008}])


class ResolveScanTargetTest(unittest.TestCase):

    RECORD = {"repo_name": "YOUR_ORG/YOUR_REPO", "pr_number": 42, "branch_name": "feature"}
    ENROLLED = parse_allowed_repos("YOUR_ORG/YOUR_REPO")

    def test_missing_record_is_404(self):
        target = resolve_scan_target(None, self.ENROLLED)
        self.assertEqual(target.status_code, 404)
        self.assertFalse(target.allowed)

    def test_record_without_repository_is_409_not_a_static_fallback(self):
        for record in ({}, {"repo_name": "  "}, {"repo_name": None, "pr_number": 3}):
            with self.subTest(record=record):
                target = resolve_scan_target(record, frozenset())
                self.assertEqual(target.status_code, 409)
                self.assertIsNone(target.repo_name)

    def test_repo_and_pr_come_from_the_record(self):
        target = resolve_scan_target(self.RECORD, self.ENROLLED)
        self.assertTrue(target.allowed)
        self.assertEqual((target.repo_name, target.pr_number), ("YOUR_ORG/YOUR_REPO", 42))

    def test_unenrolled_repository_is_403(self):
        record = dict(self.RECORD, repo_name="evil/repo")
        self.assertEqual(resolve_scan_target(record, self.ENROLLED).status_code, 403)

    def test_empty_allowlist_allows_every_repository(self):
        record = dict(self.RECORD, repo_name="any/repo")
        target = resolve_scan_target(record, parse_allowed_repos(""))
        self.assertTrue(target.allowed)
        self.assertEqual(target.repo_name, "any/repo")

    def test_403_wins_over_a_body_mismatch(self):
        record = dict(self.RECORD, repo_name="evil/repo")
        target = resolve_scan_target(record, self.ENROLLED, body_repo_name="YOUR_ORG/YOUR_REPO")
        self.assertEqual(target.status_code, 403)

    def test_matching_body_values_are_accepted(self):
        target = resolve_scan_target(self.RECORD, self.ENROLLED, body_repo_name=" Cloud-GTM/CodeMender-GitOps ", body_pr_number="42")
        self.assertTrue(target.allowed)
        self.assertEqual(target.pr_number, 42)

    def test_blank_body_values_are_ignored(self):
        target = resolve_scan_target(self.RECORD, self.ENROLLED, body_repo_name="", body_pr_number=None)
        self.assertTrue(target.allowed)

    def test_body_repository_mismatch_is_400(self):
        target = resolve_scan_target(self.RECORD, frozenset(), body_repo_name="other/repo")
        self.assertEqual(target.status_code, 400)
        self.assertIsNone(target.repo_name)

    def test_body_pr_mismatch_is_400(self):
        for body_pr in (7, "7", "abc", 0):
            with self.subTest(body_pr=body_pr):
                self.assertEqual(resolve_scan_target(self.RECORD, self.ENROLLED, body_pr_number=body_pr).status_code, 400)

    def test_body_pr_for_a_record_without_pr_is_400(self):
        record = {"repo_name": "YOUR_ORG/YOUR_REPO"}
        self.assertEqual(resolve_scan_target(record, self.ENROLLED, body_pr_number=5).status_code, 400)
        target = resolve_scan_target(record, self.ENROLLED)
        self.assertTrue(target.allowed)
        self.assertIsNone(target.pr_number)

    def test_pr_number_normalization(self):
        self.assertIsNone(normalize_pr_number(None))
        self.assertIsNone(normalize_pr_number("  "))
        self.assertEqual(normalize_pr_number(" 12 "), 12)
        self.assertEqual(normalize_pr_number(12), 12)
        self.assertEqual(normalize_pr_number("x1"), "x1")
        self.assertEqual(resolve_scan_target({"repo_name": "o/r", "pr_number": "12"}, frozenset()).pr_number, 12)


class ErrorPayloadTest(unittest.TestCase):

    def test_error_id_is_short_hex_and_unique(self):
        first, second = new_error_id(), new_error_id()
        self.assertRegex(first, re.compile(r"^[0-9a-f]{8}$"))
        self.assertNotEqual(first, second)

    def test_payload_is_generic_and_carries_the_id(self):
        payload = error_payload("abcd1234")
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_id"], "abcd1234")
        self.assertIn("abcd1234", payload["message"])
        self.assertTrue(payload["message"].startswith("Internal server error"))

    def test_scrub_replaces_exception_text_and_keeps_other_keys(self):
        raw = {"status": "error", "message": f"403 Forbidden: Authorization: Bearer {FAKE_TOKEN}", "summary": {"total": 0}, "repos": []}
        self.assertTrue(is_error_result(raw))
        scrubbed = scrub_error_result(raw, "deadbeef")
        self.assertNotIn(FAKE_TOKEN, str(scrubbed))
        self.assertNotIn("Forbidden", scrubbed["message"])
        self.assertEqual(scrubbed["error_id"], "deadbeef")
        self.assertEqual((scrubbed["summary"], scrubbed["repos"]), ({"total": 0}, []))
        self.assertIn(FAKE_TOKEN, raw["message"])  # the input is not mutated

    def test_non_error_results_are_returned_unchanged(self):
        for result in ({"status": "success", "summary": {}}, {"status": "error"}, [], None, "text"):
            with self.subTest(result=result):
                self.assertFalse(is_error_result(result))
                self.assertIs(scrub_error_result(result, "deadbeef"), result)


if __name__ == "__main__":
    unittest.main()
