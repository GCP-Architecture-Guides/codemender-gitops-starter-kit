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
"""Scan/verify/fix status semantics."""
import asyncio
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()
import gcs_helpers  # noqa: E402  (imported lazily by main; patched below)

FAKE_TOKEN = "ghp_" + "F4k3F4k3F4" * 3 + "abcdef"

REPO = "your-org/your-repo"
HEAD = "a" * 40
NEWER = "b" * 40


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))

    def last_with(self, key):
        for args, kwargs in reversed(self.calls):
            if key in kwargs:
                return kwargs
        return None


def _db_with(record):
    snap = types.SimpleNamespace(exists=record is not None, to_dict=lambda: json.loads(json.dumps(record or {})))
    return types.SimpleNamespace(collection=lambda _n: types.SimpleNamespace(
        document=lambda _k: types.SimpleNamespace(get=lambda: snap)))


class _Base(unittest.TestCase):
    def patch(self, target, attr, value, create=False):
        p = mock.patch.object(target, attr, value, create=create)
        p.start()
        self.addCleanup(p.stop)
        return value

    def setUp(self):
        self.updates = _Recorder()
        database = sys.modules["database"]

        async def token(*_a, **_k):
            return "t"

        self.patch(main, "acquire_lock", lambda lock_id, *a, **k: "owner-1")
        self.patch(main, "start_lock_renewal", lambda *a, **k: types.SimpleNamespace(cancel=lambda: None))
        self.patch(main, "release_lock", lambda *a, **k: True)
        self.patch(main, "get_github_token", token)
        self.patch(main, "update_scan_status", self.updates)
        self.patch(main, "append_scan_step", lambda *a, **k: None)
        self.patch(main, "finish_progress_comment", mock.AsyncMock())
        self.patch(main, "log_scan_summary", lambda *a, **k: None)
        self.patch(main, "make_cancel_check", lambda sha, started: (lambda: None))
        for name in ("update_scan_status", "append_scan_step", "log_scan_summary", "log_vulnerability_inventory"):
            self.patch(database, name, self.updates if name == "update_scan_status" else (lambda *a, **k: None), create=True)


class ScanWorkerHarness(_Base):
    """process_pr_scan_event with every external call faked (no tests of its own)."""

    def setUp(self):
        super().setUp()
        self.workspace = tempfile.mkdtemp(prefix="session-")
        Path(self.workspace, "app.py").write_text("print(1)\n")
        workspace = self.workspace
        self.changed_files = ["app.py"]
        harness = self

        class _FakeGitWS:
            def __init__(self, session_id, repo=None):
                self.workspace_path = Path(workspace)

            async def clone_repo(self, token, branch="main"):
                return None

            async def ensure_exact_head(self, sha, pr_number=None):
                return None

            async def get_cumulative_diff_files(self, base_branch="main"):
                return list(harness.changed_files)

        self.findings = [{"id": "f1", "severity": "CRITICAL", "status": "NEW"}]
        self.live_head = HEAD
        self.statuses = mock.AsyncMock()
        self.comments = mock.AsyncMock()
        self.promote = mock.AsyncMock()

        async def get_pr(_repo, _number, _token):
            return {"state": "open", "head": {"sha": self.live_head}}

        self.patch(main, "GitWorkspace", _FakeGitWS)
        self.patch(main, "ensure_codemender_config", lambda: None)
        self.patch(main, "run_triage_agent", mock.AsyncMock(side_effect=lambda **kw: list(self.findings)))
        self.patch(main, "reconcile_finding_lifecycle",
                   lambda previous_findings, current_findings, **kw: (current_findings, {"total_active": len(current_findings)}))
        self.patch(main, "set_commit_status", self.statuses)
        self.patch(main, "get_pull_request", get_pr)
        self.patch(main, "update_or_post_pr_comment", self.comments)
        self.patch(main, "convert_draft_pr_to_ready", self.promote)
        self.patch(sys.modules["database"], "db", None, create=True)
        self.patch(gcs_helpers, "upload_codemender_state_bundle", lambda *a, **k: False)

    def _run(self, draft=True):
        payload = {"number": 7, "repository": {"full_name": REPO},
                   "pull_request": {"number": 7, "head": {"sha": HEAD, "ref": "feature"}, "base": {"ref": "main"},
                                    "draft": draft, "title": "t", "html_url": "u", "user": {"login": "bob"}}}
        asyncio.run(main.process_pr_scan_event(payload, run_id=None))

    def _gate(self):
        return [c.kwargs for c in self.statuses.call_args_list if c.kwargs.get("state") != "pending"][-1]


class ScanWorkerTest(ScanWorkerHarness):
    def test_finished_scan_stamps_the_record(self):
        self._run()
        start = self.updates.last_with("scan_completed_at")
        self.assertIsNotNone(start)
        first = next(k for _, k in self.updates.calls if k.get("active_task") == "scan")
        self.assertIsNone(first["scan_completed_at"])
        final = [k for _, k in self.updates.calls if k.get("status") == "COMPLETED"][-1]
        self.assertTrue(final["scan_completed_at"])
        self.assertIsNone(final["active_task"])
        self.assertEqual(self._gate()["state"], "failure")

    def test_superseded_scan_keeps_its_gate_but_leaves_the_pr_alone(self):
        self.findings = []  # a clean result that would otherwise promote the draft
        self.live_head = NEWER
        self._run(draft=True)
        self.assertEqual(self._gate()["state"], "success")
        self.comments.assert_not_called()
        self.promote.assert_not_called()

    def test_current_clean_scan_publishes_and_promotes(self):
        self.findings = []
        self._run(draft=True)
        self.comments.assert_called_once()
        self.promote.assert_called_once()


class ScanErrorReportTest(ScanWorkerHarness):
    """The report says the gate is 'error' only when GitHub accepted that status."""

    def _fail_scan(self, gate_accepted):
        self.statuses.return_value = gate_accepted
        self.patch(main, "run_triage_agent",
                   mock.AsyncMock(side_effect=main.TriageError("Triage failed for app.py: boom")))
        self._run()
        self.assertEqual(self._gate()["state"], "error")
        return self.comments.call_args.args[2]

    def test_accepted_error_gate_is_reported(self):
        body = self._fail_scan(gate_accepted=True)
        self.assertIn("Triage failed for app.py: boom", body)
        self.assertIn("The merge gate is set to `error`", body)

    def test_rejected_error_gate_is_not_claimed(self):
        body = self._fail_scan(gate_accepted=False)
        self.assertIn("Triage failed for app.py: boom", body)
        self.assertNotIn("The merge gate is set to `error`", body)
        self.assertIn("could not set the merge gate to `error`", body)


class VerifyErrorDetailTest(unittest.TestCase):
    """str() of a failed cm run is now cm's final error line; the /verify error block
    keeps showing the run's output tail."""

    def test_cm_failure_shows_its_output_tail(self):
        cm_command_error = main.cm_verify.__globals__["CmCommandError"]  # the real cm_tools class
        error = cm_command_error("exploit did not run", f"mock server log\nError: exploit did not run {FAKE_TOKEN}")
        self.assertEqual(str(error), "CodeMender command failed: exploit did not run")
        block = main.verify_error_detail("f1", error)
        self.assertIn("### ❌ Verification Error for `f1`", block)
        self.assertIn("CodeMender command failed: mock server log", block)
        self.assertNotIn(FAKE_TOKEN, block)

    def test_other_errors_show_their_message(self):
        block = main.verify_error_detail("f1", RuntimeError(f"clone failed token={FAKE_TOKEN}"))
        self.assertIn("clone failed", block)
        self.assertNotIn(FAKE_TOKEN, block)


class VerifyHarness(_Base):
    """verify_findings_task with every external call faked (no tests of its own)."""

    def setUp(self):
        super().setUp()
        self.comments = self.patch(main, "post_pr_comment", mock.AsyncMock())
        self.patch(main, "upsert_progress_comment", mock.AsyncMock())

        async def no_heartbeat(*_a, **_k):
            return None

        self.patch(main, "post_periodic_progress", no_heartbeat)

    def _record(self, status="COMPLETED", completed=True, finding_status="NEW"):
        return {"status": status, "repo_name": REPO, "pr_number": 7, "branch_name": "feature",
                "scan_completed_at": 1.0 if completed else None,
                "findings": [{"id": "f1", "severity": "CRITICAL", "status": finding_status}]}


class VerifyTaskStateTest(VerifyHarness):
    def test_no_finished_scan_means_nothing_runs(self):
        self.patch(sys.modules["database"], "db", _db_with(self._record(status="FAILED", completed=False)), create=True)
        ensure = self.patch(main, "ensure_workspace", mock.AsyncMock())
        asyncio.run(main.verify_findings_task(REPO, HEAD, ["f1"], True, 7))
        ensure.assert_not_called()
        self.assertIn("no finished scan", self.comments.call_args.args[2])
        self.assertIsNone(self.updates.last_with("active_task"))

    def test_failed_run_restores_the_record_it_found(self):
        self.patch(sys.modules["database"], "db", _db_with(self._record()), create=True)
        self.patch(main, "ensure_workspace", mock.AsyncMock(side_effect=RuntimeError(f"clone failed token={FAKE_TOKEN}")))
        asyncio.run(main.verify_findings_task(REPO, HEAD, ["f1"], True, 7))
        marked = next(k for _, k in self.updates.calls if k.get("active_task") == "verify")
        self.assertEqual(marked["status_before_task"], "COMPLETED")
        final = self.updates.calls[-1][1]
        self.assertEqual(final["status"], "COMPLETED")
        self.assertIsNone(final["active_task"])
        self.assertEqual(final["findings"][0]["status"], "NEW")
        self.assertIn("clone failed", final["error_message"])
        self.assertNotIn(FAKE_TOKEN, final["error_message"])


class RestoreHelperTest(unittest.TestCase):
    def test_only_transient_findings_are_reset_and_failed_scans_stay_failed(self):
        updates = _Recorder()
        findings = [{"id": "a", "status": "VERIFYING"}, {"id": "b", "status": "VERIFIED"}]
        with mock.patch.object(main, "update_scan_status", updates):
            main.restore_after_failed_task(HEAD, findings, {"a": "NEW", "b": "NEW"}, "FAILED", ("VERIFYING",), None)
        kwargs = updates.calls[-1][1]
        self.assertEqual([f["status"] for f in kwargs["findings"]], ["NEW", "VERIFIED"])
        self.assertEqual(kwargs["status"], "FAILED")


class SupersededOwnershipTest(unittest.TestCase):
    def test_a_newer_run_for_the_same_commit_keeps_the_record(self):
        updates = _Recorder()
        with mock.patch.object(main, "update_scan_status", updates), \
                mock.patch.dict("shared_state.active_tasks", {HEAD: "run-new"}, clear=True):
            asyncio.run(main.mark_scan_superseded(REPO, HEAD, 7, "run-old"))
            self.assertEqual(updates.calls, [])
            asyncio.run(main.mark_scan_superseded(REPO, HEAD, 7, "run-new"))
        self.assertEqual(updates.calls[-1][1]["status"], "SUPERSEDED")


class ReadyForReviewTest(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.scan = mock.AsyncMock()
        self.record = None

        async def load(_sha):
            return self.record

        async def fake_get_json(url):
            pr = {"number": 7, "state": "open", "draft": False, "title": "t", "html_url": "u", "user": {"login": "bob"},
                  "head": {"sha": HEAD, "ref": "feature"}, "base": {"ref": "main", "repo": {"full_name": REPO}}}
            return 200, pr

        for target, attr, value in (
            (main, "WIF_AUTH_ENABLED", True), (main, "ALLOWED_REPOS", frozenset({REPO})),
            (main, "github_get_json", fake_get_json), (main, "load_scan_record", load),
            (main, "process_pr_scan_event", self.scan), (main, "is_scan_in_flight", lambda _s: False),
            (main, "update_scan_status", lambda *a, **k: None),
        ):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        env = mock.patch.dict(os.environ, {"MOCK_MODE": "false"})
        env.start()
        self.addCleanup(env.stop)

    def _post(self, action):
        payload = {"action": action, "number": 7, "repository": {"full_name": REPO},
                   "pull_request": {"number": 7, "head": {"sha": HEAD, "ref": "feature"}, "base": {"ref": "main"}}}
        return self.client.post("/github-webhook", content=json.dumps(payload),
                                headers={"X-GitHub-Event": "pull_request", "X-CodeMender-Auth": "WIF"})

    def test_finished_head_is_not_scanned_again(self):
        self.record = {"status": "COMPLETED", "findings": [], "scan_completed_at": 1.0, "repo_name": REPO, "pr_number": 7}
        self.assertEqual(self._post("ready_for_review").status_code, 200)
        self.scan.assert_not_called()

    def test_unscanned_head_and_other_actions_are_scanned(self):
        self.assertEqual(self._post("ready_for_review").status_code, 202)
        self.record = {"status": "COMPLETED", "findings": [], "scan_completed_at": 1.0, "repo_name": REPO, "pr_number": 7}
        self.assertEqual(self._post("synchronize").status_code, 202)
        self.assertEqual(self.scan.call_count, 2)


class CommentDismissalTest(_Base):
    def setUp(self):
        super().setUp()
        self.comments = self.patch(main, "post_pr_comment", mock.AsyncMock())
        self.statuses = self.patch(main, "set_commit_status", mock.AsyncMock())
        self.promote = self.patch(main, "convert_draft_pr_to_ready", mock.AsyncMock())

        async def head(*_a):
            return HEAD

        self.patch(main, "get_pr_head_sha", head)
        self.patch(main, "ALLOWED_REPOS", frozenset({REPO}))
        self.dismiss = self.patch(main, "dismiss_finding", mock.Mock(return_value={
            "success": True, "dismissed_count": 1, "findings": [{"id": "f1", "severity": "CRITICAL", "status": "DISMISSED"}],
            "dismissal": {"category": "FALSE_POSITIVE"}, "dismissed_items": []}))

    def _run(self, record):
        async def load(_sha):
            return record

        with mock.patch.object(main, "load_scan_record", load):
            asyncio.run(main.process_dismiss_command_task(REPO, "alice", "/dismiss f1 [FALSE_POSITIVE] verified unreachable", True, 7))

    def test_busy_commit_refuses_the_dismissal(self):
        import time
        self._run({"status": "RUNNING", "updated_at": time.time(), "repo_name": REPO, "pr_number": 7, "findings": []})
        self.dismiss.assert_not_called()
        self.assertIn("Dismissal not applied", self.comments.call_args.args[2])

    def test_completed_scan_clears_the_gate_and_promotes(self):
        self._run({"status": "COMPLETED", "updated_at": 0, "repo_name": REPO, "pr_number": 7, "findings": []})
        self.assertEqual(self.statuses.call_args.kwargs["state"], "success")
        self.promote.assert_called_once()

    def test_failed_scan_leaves_the_gate_alone(self):
        self._run({"status": "FAILED", "updated_at": 0, "repo_name": REPO, "pr_number": 7, "findings": []})
        self.statuses.assert_not_called()
        self.promote.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class ClosedFindingsTest(VerifyHarness):
    """Closed or already-patched findings are left alone."""

    def test_verify_does_not_reopen_a_dismissed_finding(self):
        self.patch(sys.modules["database"], "db", _db_with(self._record(finding_status="DISMISSED")), create=True)
        ensure = self.patch(main, "ensure_workspace", mock.AsyncMock())
        asyncio.run(main.verify_findings_task(REPO, HEAD, ["f1"], True, 7))
        ensure.assert_not_called()
        self.assertIn("Not re-verified", self.comments.call_args.args[2])
        self.assertIsNone(self.updates.last_with("active_task"))

    def test_fix_keyword_skips_findings_the_pending_proposal_patches(self):
        self.patch(sys.modules["database"], "db", _db_with(self._record(finding_status="PATCHED")), create=True)
        ensure = self.patch(main, "ensure_workspace", mock.AsyncMock())
        asyncio.run(main.fix_findings_task(REPO, HEAD, ["critical"], True, 7))
        ensure.assert_not_called()
        self.assertIn("already patches `f1`", self.comments.call_args.args[2])

    def test_fix_explicit_id_still_regenerates(self):
        self.patch(sys.modules["database"], "db", _db_with(self._record(finding_status="PATCHED")), create=True)
        ensure = self.patch(main, "ensure_workspace", mock.AsyncMock(side_effect=RuntimeError("stop here")))
        asyncio.run(main.fix_findings_task(REPO, HEAD, ["f1"], True, 7))
        ensure.assert_called_once()


class FixReportSourceTest(unittest.TestCase):
    """Guards for paths that need a full git workspace to exercise."""

    def setUp(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        self.fix_task = source.split("async def _fix_findings_task")[1].split("\nasync def ")[0]

    def test_failed_fix_resets_the_workspace(self):
        self.assertIn("await _reset_fix_workspace(str(workspace_path))", self.fix_task)

    def test_proposal_lists_findings_that_were_not_fixed(self):
        self.assertEqual(self.fix_task.count("outcome_report += not_fixed_md"), 3)
        self.assertIn("#### ⚠️ Not fixed", self.fix_task)

    def test_no_change_rerun_keeps_patched(self):
        self.assertIn('str(prior_finding_status.get(fid) or "").upper() == "PATCHED"', self.fix_task)


class ApproveClosedPullRequestTest(_Base):
    """/approve never pushes to a closed or merged PR (no re-scan would follow)."""

    def test_closed_or_merged_pr_is_refused_before_any_git_work(self):
        comments = self.patch(main, "post_pr_comment", mock.AsyncMock())
        workspace = self.patch(main, "GitWorkspace", mock.Mock(side_effect=AssertionError("no clone for a closed PR")))
        payload = {"issue": {"number": 7}, "repository": {"full_name": REPO}, "comment": {"user": {"login": "alice"}}}
        for info, word in (({"state": "closed", "merged": True}, "merged"), ({"state": "closed", "merged": False}, "closed")):
            with self.subTest(word=word):
                async def get_pr(_repo, _number, _token, info=info):
                    return dict(info, head={"sha": HEAD, "ref": "feature", "repo": {"full_name": REPO}})

                self.patch(main, "get_pull_request", get_pr)
                asyncio.run(main.process_approve_comment(payload))
                self.assertIn(f"is {word}", comments.call_args.args[2])
        workspace.assert_not_called()


class QueuedTaskAnnouncementTest(_Base):
    """Work waiting for this instance's cm lock is announced, not silent."""

    def setUp(self):
        super().setUp()
        self.statuses = self.patch(main, "set_commit_status", mock.AsyncMock())
        self.progress = self.patch(main, "upsert_progress_comment", mock.AsyncMock())

    def _announce(self, *args, hold=True):
        from task_context import cm_state_lock

        async def scenario():
            lock = cm_state_lock()
            if hold:
                await lock.acquire()
            try:
                await main.announce_queued_task(*args)
            finally:
                if hold:
                    lock.release()

        asyncio.run(scenario())

    def test_idle_instance_posts_nothing(self):
        self._announce(REPO, 7, HEAD, "scan", "u", hold=False)
        self._announce(REPO, 7, HEAD, "verify", hold=False)
        self.statuses.assert_not_called()
        self.progress.assert_not_called()

    def test_queued_scan_gets_a_pending_gate(self):
        self._announce(REPO, 7, HEAD, "scan", "u")
        kwargs = self.statuses.call_args.kwargs
        self.assertEqual(kwargs["state"], "pending")
        self.assertIn("queued", kwargs["description"])
        self.assertLessEqual(len(kwargs["description"]), 140)

    def test_queued_verify_and_fix_get_their_progress_comment(self):
        for task, label in (("verify", "Exploit Verification"), ("patch", "Patch Generation")):
            with self.subTest(task=task):
                self._announce(REPO, 7, HEAD, task)
                args = self.progress.call_args.args
                self.assertEqual(args[2], main.progress_key(task, HEAD))
                self.assertIn(f"CodeMender {label} queued", args[3])

    def test_failures_are_swallowed(self):
        self.statuses.side_effect = RuntimeError("GitHub down")
        self._announce(REPO, 7, HEAD, "scan", "u")  # must not raise


class VerificationOutputRecordTest(_Base):
    """A verify stores the log and PoC files the dashboard shows."""

    def test_log_and_artifacts_are_stored_for_the_dashboard(self):
        store = {"artifacts": [{"name": "REPORT.html", "url": "u0"}]}
        written = {}

        class _Doc:
            def get(self):
                return types.SimpleNamespace(exists=True, to_dict=lambda: dict(store))

            def set(self, data, merge=False):
                written.update(data)

        fake_db = types.SimpleNamespace(collection=lambda _n: types.SimpleNamespace(document=lambda _k: _Doc()))
        self.patch(sys.modules["database"], "db", fake_db, create=True)
        main.record_verification_output(HEAD, {"f1": "out one", "f2": "out two"},
                                        [{"name": ".exploit/f1/exploit.sh", "url": "u1"}, {"name": "REPORT.html", "url": "u0b"}])
        log = self.updates.last_with("logs")["logs"]["verify_output"]
        self.assertIn("=== f1 ===\nout one", log)
        self.assertIn("=== f2 ===\nout two", log)
        self.assertEqual({a["name"]: a["url"] for a in written["artifacts"]},
                         {"REPORT.html": "u0b", ".exploit/f1/exploit.sh": "u1"})

    def test_failures_never_raise(self):
        self.patch(main, "update_scan_status", mock.Mock(side_effect=RuntimeError("firestore down")))
        main.record_verification_output(HEAD, {"f1": "x"}, [])

    def test_verify_task_records_its_output(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        verify_task = source.split("async def _verify_findings_task")[1].split("\nasync def ")[0]
        self.assertIn("record_verification_output, commit_sha, dict(verify_logs)", verify_task)


class StalePrHeadMessageTest(_Base):
    """Dashboard actions only on the PR head (older cards stay clickable)."""

    def _message(self, head, pr_number=7):
        async def get_head(_repo, _number, _token):
            if isinstance(head, Exception):
                raise head
            return head

        self.patch(main, "get_pr_head_sha", get_head)
        return asyncio.run(main.stale_pr_head_message(REPO, pr_number, HEAD))

    def test_old_card_is_refused_with_the_new_head(self):
        message = self._message(NEWER)
        self.assertIn(HEAD[:7], message)
        self.assertIn(NEWER[:7], message)

    def test_head_card_no_pr_and_github_errors_pass(self):
        self.assertIsNone(self._message(HEAD))
        self.assertIsNone(self._message(NEWER, pr_number=None))
        self.assertIsNone(self._message(RuntimeError("GitHub down")))

    def test_every_dashboard_action_is_guarded(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        for endpoint in ("api_verify_finding", "api_fix_finding", "api_verify_findings", "api_fix_findings",
                         "api_dismiss_finding"):
            with self.subTest(endpoint=endpoint):
                body = source.split(f"async def {endpoint}(")[1].split("\nasync def ")[0]
                self.assertIn("stale_pr_head_message(", body)


class ResultContentAndDraftTest(unittest.TestCase):
    """Verify confidence reporting and Draft PR bookkeeping."""

    def test_unknown_confidence_is_not_reported_as_certain(self):
        self.assertEqual(main.clean_confidence(""), "n/a")
        self.assertEqual(main.clean_confidence(None), "n/a")
        self.assertEqual(main.clean_confidence("90"), "90%")
        self.assertEqual(main.clean_confidence("high"), "80%")

    def test_draft_pr_keeps_the_original_pr_number(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        task = source.split("async def create_draft_pr_task")[1].split("\nasync def ")[0]
        self.assertIn('if (record or {}).get("pr_number"):\n            patches_ref.set({"patch_pr_number": pr_num}, merge=True)', task)
        self.assertNotIn('patches_ref.set({"pr_number": pr_num}, merge=True)', task)

    def test_draft_command_targets_the_pr_head(self):
        source = Path(main.__file__).read_text(encoding="utf-8")
        router = source.split('elif route == "draft":')[1].split("return Response(")[0]
        self.assertLess(router.index("get_pr_head_sha("), router.index('where("pr_number"'))
