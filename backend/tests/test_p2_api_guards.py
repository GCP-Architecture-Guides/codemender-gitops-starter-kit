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

"""Stdlib-only tests for the Phase 2 request guards: cross-site guard, dashboard dismissal
checks and gate, intervention resolution checks."""

import asyncio
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from command_auth import parse_allowed_repos  # noqa: E402
from request_guards import (  # noqa: E402
    CrossSiteGuardMiddleware,
    api_error_payload,
    check_dismissal_target,
    check_intervention_record,
    dismissal_gate_decision,
    is_cross_site_request,
    is_wildcard_finding_id,
    normalize_origin,
    parse_origins,
    validate_dismissal_request,
    validate_intervention_resolution,
)

DASH = "codemender.example.com"


class OriginParsingTest(unittest.TestCase):

    def test_normalize_origin(self):
        self.assertEqual(normalize_origin("HTTPS://Dash.Example.com:443"), "https://dash.example.com")
        self.assertEqual(normalize_origin("http://localhost:3000/"), "http://localhost:3000")
        self.assertEqual(normalize_origin("http://[::1]:8000"), "http://[::1]:8000")
        for bad in (None, "", "null", "*", "ftp://x.com", "https://x.com/path", "https://u:p@x.com",
                    "https://x.com?q=1", "https://x.com:99999", "x.com"):
            with self.subTest(bad=bad):
                self.assertIsNone(normalize_origin(bad))

    def test_parse_origins_drops_wildcards_and_junk(self):
        self.assertEqual(
            parse_origins(" http://localhost:3000 , *, https://Dash.example.com:443,,null"),
            frozenset({"http://localhost:3000", "https://dash.example.com"}),
        )
        self.assertEqual(parse_origins(""), frozenset())
        self.assertEqual(parse_origins(None), frozenset())


class CrossSiteRequestTest(unittest.TestCase):

    def test_same_origin_dashboard_calls_pass(self):
        headers = {"origin": f"https://{DASH}", "host": DASH, "sec-fetch-site": "same-origin"}
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                self.assertFalse(is_cross_site_request(method, headers))

    def test_same_host_without_fetch_metadata_passes(self):
        self.assertFalse(is_cross_site_request("POST", {"origin": f"https://{DASH}", "host": DASH}))
        self.assertFalse(is_cross_site_request("POST", {"origin": f"https://{DASH}", "host": f"{DASH}:443"}))
        self.assertFalse(is_cross_site_request(
            "POST", {"origin": f"https://{DASH}", "host": "internal:8080", "x-forwarded-host": DASH}))

    def test_same_origin_fetch_metadata_passes_even_if_a_proxy_rewrote_host(self):
        headers = {"origin": f"https://{DASH}", "host": "codemender-dashboard-1.us-central1.run.app",
                   "sec-fetch-site": "same-origin"}
        self.assertFalse(is_cross_site_request("POST", headers))

    def test_webhooks_relays_and_schedulers_without_origin_pass(self):
        for headers in (
            {"host": "codemender-webhook.run.app", "x-github-event": "pull_request"},
            {"host": "codemender-webhook.run.app", "x-codemender-auth": "WIF", "authorization": "Bearer x"},
            {"host": "codemender-backend.run.app", "user-agent": "Google-Cloud-Scheduler"},
            {},
        ):
            with self.subTest(headers=headers):
                self.assertFalse(is_cross_site_request("POST", headers))

    def test_cross_site_browser_requests_are_refused(self):
        cases = (
            {"origin": "https://evil.example.net", "host": DASH, "sec-fetch-site": "cross-site"},
            {"origin": "https://evil.example.net", "host": DASH},
            {"host": DASH, "sec-fetch-site": "cross-site"},
            {"origin": "https://sub.codemender.example.com", "host": DASH, "sec-fetch-site": "same-site"},
            {"origin": "null", "host": DASH},
            {"origin": "https://codemender.example.com:8443", "host": DASH},
            {"origin": "http://codemender.example.com", "host": f"{DASH}:443"},
        )
        for headers in cases:
            with self.subTest(headers=headers):
                self.assertTrue(is_cross_site_request("POST", headers))

    def test_safe_methods_are_never_blocked(self):
        headers = {"origin": "https://evil.example.net", "host": DASH, "sec-fetch-site": "cross-site"}
        for method in ("GET", "HEAD", "OPTIONS", None):
            with self.subTest(method=method):
                self.assertFalse(is_cross_site_request(method, headers))

    def test_allowlisted_origin_passes_even_cross_site(self):
        allowed = parse_origins("http://localhost:3000")
        headers = {"origin": "http://localhost:3000", "host": "localhost:8000", "sec-fetch-site": "cross-site"}
        self.assertFalse(is_cross_site_request("POST", headers, allowed))
        self.assertTrue(is_cross_site_request("POST", headers, frozenset()))

    def test_websocket_handshakes_are_checked_like_writes(self):
        self.assertTrue(is_cross_site_request("GET", {"origin": "https://evil.example.net", "host": DASH}, websocket=True))
        self.assertFalse(is_cross_site_request("GET", {"origin": f"https://{DASH}", "host": DASH}, websocket=True))
        self.assertFalse(is_cross_site_request(None, {"host": DASH}, websocket=True))


class _App:
    def __init__(self):
        self.calls = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})


def _drive(middleware, scope):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(middleware(scope, receive, send))
    return sent


def _scope(scope_type="http", method="POST", headers=None):
    raw = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {"type": scope_type, "path": "/api/scans/abc/dismiss", "headers": raw}
    if scope_type == "http":
        scope["method"] = method
    return scope


class CrossSiteGuardMiddlewareTest(unittest.TestCase):

    def test_cross_site_post_gets_403_before_the_app(self):
        app = _App()
        sent = _drive(CrossSiteGuardMiddleware(app), _scope(headers={"Origin": "https://evil.example.net", "Host": DASH}))
        self.assertEqual(app.calls, 0)
        self.assertEqual(sent[0]["status"], 403)
        self.assertIn(b"Cross-site", sent[1]["body"])

    def test_same_origin_post_and_webhook_reach_the_app(self):
        for headers in ({"Origin": f"https://{DASH}", "Host": DASH}, {"Host": DASH, "X-GitHub-Event": "push"}):
            with self.subTest(headers=headers):
                app = _App()
                sent = _drive(CrossSiteGuardMiddleware(app), _scope(headers=headers))
                self.assertEqual(app.calls, 1)
                self.assertEqual(sent[0]["status"], 200)

    def test_cross_site_websocket_is_closed_before_accept(self):
        app = _App()
        sent = _drive(CrossSiteGuardMiddleware(app), _scope("websocket", headers={"Origin": "https://evil.example.net", "Host": DASH}))
        self.assertEqual(app.calls, 0)
        self.assertEqual(sent, [{"type": "websocket.close", "code": 1008}])

    def test_lifespan_and_allowlisted_origins_pass_through(self):
        app = _App()
        _drive(CrossSiteGuardMiddleware(app), {"type": "lifespan"})
        self.assertEqual(app.calls, 1)
        app = _App()
        _drive(CrossSiteGuardMiddleware(app, parse_origins("http://localhost:3000")),
               _scope(headers={"Origin": "http://localhost:3000", "Host": "localhost:8000"}))
        self.assertEqual(app.calls, 1)


def _finding(fid, severity="CRITICAL", status="DETECTED", lifecycle=None):
    f = {"id": fid, "severity": severity, "status": status}
    if lifecycle:
        f["lifecycle_status"] = lifecycle
    return f


class DismissalRequestTest(unittest.TestCase):

    def test_identity_is_required_first(self):
        check = validate_dismissal_request(None, "all", "")
        self.assertEqual(check.status_code, 401)
        self.assertIn("identity", check.detail.lower())

    def test_wildcards_missing_ids_and_short_reasons_are_refused(self):
        for fid, reason in (("all", "a valid reason here"), ("GATE", "a valid reason here"), (" * ", "a valid reason here"),
                            ("", "a valid reason here"), (None, "a valid reason here"), ("f1", "too short"), ("f1", None)):
            with self.subTest(fid=fid, reason=reason):
                self.assertEqual(validate_dismissal_request("a@b.c", fid, reason).status_code, 400)

    def test_valid_request_carries_the_verified_identity(self):
        check = validate_dismissal_request("alice@example.com", "f1", "False positive: test fixture")
        self.assertTrue(check.allowed)
        self.assertEqual(check.identity, "alice@example.com")

    def test_is_wildcard_finding_id(self):
        self.assertTrue(is_wildcard_finding_id("All"))
        self.assertFalse(is_wildcard_finding_id("a1b2c3"))


class DismissalTargetTest(unittest.TestCase):

    def setUp(self):
        self.allowed = parse_allowed_repos("your-org/your-repo")
        self.now = time.time()

    def test_scan_target_errors_pass_through(self):
        self.assertEqual(check_dismissal_target(None, self.allowed, self.now).status_code, 404)
        self.assertEqual(check_dismissal_target({"status": "COMPLETED"}, self.allowed, self.now).status_code, 409)
        self.assertEqual(check_dismissal_target({"repo_name": "evil/repo", "status": "COMPLETED"}, self.allowed, self.now).status_code, 403)

    def test_recent_in_flight_scan_is_busy(self):
        for status in ("QUEUED", "CLONING", "PRE_CHECKS", "RUNNING", "running"):
            with self.subTest(status=status):
                record = {"repo_name": "your-org/your-repo", "status": status, "updated_at": self.now - 60}
                check = check_dismissal_target(record, self.allowed, self.now)
                self.assertEqual(check.status_code, 409)
                self.assertIn("busy", check.detail)

    def test_stale_in_flight_or_terminal_scan_is_allowed(self):
        for status, updated in (("RUNNING", self.now - 3 * 3600), ("COMPLETED", self.now), ("FAILED", self.now),
                                ("DEFERRED", self.now), ("RUNNING", None)):
            with self.subTest(status=status, updated=updated):
                record = {"repo_name": "your-org/your-repo", "status": status, "updated_at": updated, "pr_number": 7}
                check = check_dismissal_target(record, self.allowed, self.now)
                self.assertTrue(check.allowed)
                self.assertEqual(check.repo_name, "your-org/your-repo")
                self.assertEqual(check.scan_status, status.upper())


class DismissalGateDecisionTest(unittest.TestCase):

    def test_completed_scan_uses_decide_gate(self):
        state, desc = dismissal_gate_decision("COMPLETED", [_finding("a", status="DISMISSED"), _finding("b", "HIGH")])
        self.assertEqual(state, "success")
        state, desc = dismissal_gate_decision("completed", [_finding("a", status="DISMISSED"), _finding("b")])
        self.assertEqual(state, "failure")
        self.assertIn("1 unresolved CRITICAL", desc)

    def test_resolved_lifecycle_and_fixed_follow_the_scan_rule(self):
        # RESOLVED (lifecycle) no longer blocks; FIXED/PATCHED still block, exactly like the scan worker.
        self.assertEqual(dismissal_gate_decision("COMPLETED", [_finding("a", lifecycle="RESOLVED")])[0], "success")
        self.assertEqual(dismissal_gate_decision("COMPLETED", [_finding("a", status="FIXED")])[0], "failure")
        self.assertEqual(dismissal_gate_decision("COMPLETED", [_finding("a", status="PATCHED")])[0], "failure")

    def test_failed_running_or_deferred_scans_never_turn_green(self):
        all_dismissed = [_finding("a", status="DISMISSED")]
        for status in ("FAILED", "ERROR", "RUNNING", "QUEUED", "CLONING", "PRE_CHECKS", "DEFERRED", "", None):
            with self.subTest(status=status):
                state, reason = dismissal_gate_decision(status, all_dismissed)
                self.assertIsNone(state)
                self.assertIn("Gate unchanged", reason)

    def test_bad_findings_value_is_treated_as_empty(self):
        self.assertEqual(dismissal_gate_decision("COMPLETED", None)[0], "success")


class InterventionChecksTest(unittest.TestCase):

    def test_reviewer_identity_required(self):
        self.assertEqual(validate_intervention_resolution(None, "APPROVE").status_code, 401)
        self.assertEqual(validate_intervention_resolution("", "APPROVE").status_code, 401)

    def test_action_must_be_approve_or_reject(self):
        for action in ("", None, "MAYBE", "approved"):
            with self.subTest(action=action):
                self.assertEqual(validate_intervention_resolution("a@b.c", action).status_code, 400)
        decision = validate_intervention_resolution("a@b.c", " reject ")
        self.assertTrue(decision.allowed)
        self.assertEqual((decision.identity, decision.value), ("a@b.c", "REJECT"))

    def test_record_checks(self):
        self.assertEqual(check_intervention_record(None).status_code, 404)
        self.assertEqual(check_intervention_record({"status": "APPROVED"}).status_code, 409)
        self.assertTrue(check_intervention_record({"status": "PENDING"}).allowed)
        self.assertTrue(check_intervention_record({}).allowed)

    def test_error_payload_has_both_ui_keys(self):
        self.assertEqual(api_error_payload("nope"), {"status": "error", "message": "nope", "detail": "nope"})


if __name__ == "__main__":
    unittest.main()
