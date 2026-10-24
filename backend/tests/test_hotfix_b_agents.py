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

"""Tests for hotfix B in agents.py: triage fails closed (H4b), dashboard fix push is honest (H5).

No network, no Gemini, no GitHub and no real `cm`: Gemini and GitHub helpers are mocked, a fake
`cm` script stands in for the CLI and pushes go to a stubbed GitWorkspace._run_command.
"""

import asyncio
import contextlib
import json
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

# Obviously fake credential, built at runtime so no token-shaped literal sits in the source.
FAKE_TOKEN = "ghs_" + "AgentsH0tf" * 3
HAS_GIT = shutil.which("git") is not None


def _ensure_database_stub():
    """agents/cm_tools import Firestore/BigQuery helpers from `database`; stub them (no Google Cloud)."""
    module = sys.modules.get("database")
    if module is None:
        module = types.ModuleType("database")
        sys.modules["database"] = module
    for name in ("update_scan_status", "log_token_usage", "get_scan_repo_name", "append_scan_step",
                 "save_patch_proposal"):
        if not hasattr(module, name):
            setattr(module, name, lambda *args, **kwargs: None)
    return module


def _github_helpers_stub():
    """github_helpers needs PyJWT/Secret Manager; unit tests must never reach GitHub anyway."""
    module = types.ModuleType("github_helpers")

    async def _no_github(*_args, **_kwargs):
        raise AssertionError("GitHub must not be called from unit tests")

    module.post_pr_comment = _no_github
    module.get_github_token = _no_github
    module.update_or_post_pr_comment = _no_github
    return module


@contextlib.contextmanager
def _temporary_modules(modules: dict):
    """Installs stub modules, then restores exactly those sys.modules entries."""
    saved = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        yield
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


_ensure_database_stub()
with _temporary_modules({"github_helpers": _github_helpers_stub()}):
    import agents  # noqa: E402
import cm_tools  # noqa: E402
import git_manager  # noqa: E402

TABLE_STDOUT = (
    "   Found 1 source files\n"
    "📊 Deep Scan Sifter Complete: 1 files in 1 batches (0 pruned at Tier 0, 1 succeeded, 0 failed) in 2m24s\n"
    "\n"
    "🔒 Found 3 vulnerabilities:\n"
    "\n"
    "ID        SEVERITY    TYPE                FILE               TITLE                       CONFIDENCE\n"
    "────────  ────────    ────                ────               ─────                       ──────────\n"
    "d60761e6  🔴 CRITICAL  SQL INJECTION       vulnerable_app.py  SQL Injection in login      100%\n"
    "12eea4e5  🟡 MEDIUM    CROSS-SITE SCRIPTING  vulnerable_app.py  Reflected XSS in receipt  100%\n"
    "810f393c  🔴 CRITICAL  OS COMMAND INJECTION  vulnerable_app.py  Command injection in ping  95%\n"
    "\n"
    "Summary: 2 CRITICAL, 1 MEDIUM\n"
)
CLEAN_STDOUT = "   Found 1 source files\n\n✅ No vulnerabilities found!\n"
UNKNOWN_STDOUT = (
    "   Found 1 source files\n"
    "📊 Deep Scan Sifter Complete: 1 files in 1 batches (0 pruned at Tier 0, 0 succeeded, 1 failed) in 1s\n"
)


def _finding(finding_id: str) -> dict:
    return {"id": finding_id, "severity": "CRITICAL", "filepath": "vulnerable_app.py",
            "vuln_type": "SQL Injection", "description": f"Finding {finding_id}"}


def _fake_gemini(findings: list):
    usage = types.SimpleNamespace(prompt_token_count=10, candidates_token_count=5,
                                  cached_content_token_count=0, thoughts_token_count=0)
    response = types.SimpleNamespace(text=json.dumps({"findings": findings}), usage_metadata=usage)
    generate = mock.AsyncMock(return_value=response)
    client = types.SimpleNamespace(aio=types.SimpleNamespace(models=types.SimpleNamespace(generate_content=generate)))
    return client, generate


class RunTriageAgentFailClosedTest(unittest.TestCase):
    def setUp(self):
        self.session_id = f"unittest-triage-{uuid.uuid4().hex[:10]}"
        self.steps = []
        database = sys.modules["database"]
        for name, value in (
            ("append_scan_step", lambda *args, **kwargs: self.steps.append(args)),
            ("update_scan_status", lambda *args, **kwargs: None),
            ("log_token_usage", lambda *args, **kwargs: None),
        ):
            patcher = mock.patch.object(database, name, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _triage(self, stdout: str, findings: list):
        client, generate = _fake_gemini(findings)
        with mock.patch.object(agents, "cm_init", mock.AsyncMock(return_value="")), \
                mock.patch.object(agents, "cm_find", mock.AsyncMock(return_value=stdout)), \
                mock.patch.object(agents, "client", client):
            result = asyncio.run(agents.run_triage_agent(self.session_id, "vulnerable_app.py", repo_name="o/r"))
        return result, generate

    def _error_steps(self):
        return [step for step in self.steps if len(step) > 1 and step[1] == "error"]

    def test_parser_shared_with_cm_tools(self):
        self.assertIs(agents._count_cli_table_rows, cm_tools.count_cli_table_rows)
        self.assertEqual(agents.count_cli_table_rows(TABLE_STDOUT), 3)

    def test_matching_count_returns_findings(self):
        results, generate = self._triage(TABLE_STDOUT, [_finding("d60761e6"), _finding("12eea4e5"), _finding("810f393c")])
        self.assertEqual([r["id"] for r in results], ["d60761e6", "12eea4e5", "810f393c"])
        self.assertTrue(all(r["fingerprint"] and r["status"] == "DETECTED" for r in results))
        generate.assert_awaited_once()

    def test_partial_parse_raises_with_both_counts(self):
        with self.assertRaises(agents.TriageError) as err:
            self._triage(TABLE_STDOUT, [_finding("d60761e6"), _finding("12eea4e5")])
        self.assertIn("2 finding(s)", str(err.exception))
        self.assertIn("3 row(s)", str(err.exception))
        self.assertTrue(self._error_steps())

    def test_padded_parse_raises(self):
        findings = [_finding(f) for f in ("d60761e6", "12eea4e5", "810f393c", "deadbeef")]
        with self.assertRaises(agents.TriageError) as err:
            self._triage(TABLE_STDOUT, findings)
        self.assertIn("4 finding(s)", str(err.exception))
        self.assertIn("3 row(s)", str(err.exception))

    def test_empty_parse_of_a_table_raises(self):
        with self.assertRaises(agents.TriageError):
            self._triage(TABLE_STDOUT, [])

    def test_clean_marker_returns_empty_without_parser_call(self):
        results, generate = self._triage(CLEAN_STDOUT, [_finding("hallucinated")])
        self.assertEqual(results, [])
        generate.assert_not_awaited()
        self.assertFalse(self._error_steps())

    def test_unknown_output_without_table_or_marker_raises(self):
        with self.assertRaises(agents.TriageError) as err:
            self._triage(UNKNOWN_STDOUT, [])
        self.assertIn("no findings table", str(err.exception))
        self.assertTrue(self._error_steps())

    def test_unknown_output_is_not_rescued_by_the_parser(self):
        with self.assertRaises(agents.TriageError):
            self._triage(UNKNOWN_STDOUT, [_finding("d60761e6")])


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(HAS_GIT, "git not installed")
class ApplyCodemenderFixPushTest(unittest.TestCase):
    """H5: the dashboard fix pushes through GitWorkspace._run_command and reports push failures."""

    REPO = "o/r"

    def setUp(self):
        self.session_id = f"unittest-fix-{uuid.uuid4().hex[:12]}"
        self.workspace = f"/tmp/session-{self.session_id}"
        self.patch_branch = f"codemender/patch-{self.session_id[:8]}"
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

        # A fake `cm` first on PATH (never the real CLI) and git isolated from the developer config.
        bin_dir = Path(self._tmp.name, "bin")
        bin_dir.mkdir()
        fake_cm = bin_dir / "cm"
        fake_cm.write_text("#!/bin/sh\nprintf 'def handler(q):\\n    return sanitize(q)\\n' > app.py\necho 'Fix applied'\n")
        fake_cm.chmod(0o755)
        env_patcher = mock.patch.dict(os.environ, {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": self._tmp.name,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "MOCK_MODE": "false",
        })
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("CM_HOME", None)

        os.makedirs(self.workspace)
        self.addCleanup(shutil.rmtree, self.workspace, True)
        self.addCleanup(git_manager._WORKSPACE_TOKENS.pop, self.workspace, None)
        _git(self.workspace, "init", "-q")
        _git(self.workspace, "checkout", "-q", "-b", "main")
        _git(self.workspace, "config", "user.name", "Seed")
        _git(self.workspace, "config", "user.email", "seed@example.invalid")
        Path(self.workspace, "app.py").write_text("def handler(q):\n    return q\n")
        _git(self.workspace, "add", "app.py")
        _git(self.workspace, "commit", "-q", "-m", "init")

        # Firestore scan record with the pusher identity; GitHub and proposal storage are mocked.
        self.steps = []
        snapshot = types.SimpleNamespace(exists=True, to_dict=lambda: {
            "pusher_name": "Dev Pusher", "pusher_email": "dev@example.invalid"})
        fake_db = mock.MagicMock()
        fake_db.collection.return_value.document.return_value.get.return_value = snapshot
        database = sys.modules["database"]
        self.save_patch_proposal = mock.Mock()
        self.get_existing_pr = mock.AsyncMock(return_value=(None, None))
        self.post_pr_comment = mock.AsyncMock()
        for patcher in (
            mock.patch.object(database, "db", fake_db, create=True),
            mock.patch.object(database, "append_scan_step", lambda *a, **k: self.steps.append(a), create=True),
            mock.patch.object(database, "update_scan_status", lambda *a, **k: None, create=True),
            mock.patch.object(database, "get_scan_repo_name", lambda *a, **k: self.REPO, create=True),
            mock.patch.object(agents, "save_patch_proposal", self.save_patch_proposal),
            mock.patch.object(agents, "get_existing_pr", self.get_existing_pr),
            mock.patch.object(agents, "post_pr_comment", self.post_pr_comment),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        # Local git commands run for real; the push is stubbed (no network).
        self.git_calls = []
        self.push_error = None
        original_run_command = git_manager.GitWorkspace._run_command
        test = self

        async def fake_run_command(workspace, cmd, cwd=None):
            test.git_calls.append((workspace, list(cmd), cwd))
            if list(cmd[:2]) == ["git", "push"]:
                if test.push_error:
                    raise RuntimeError(test.push_error)
                return "", ""
            return await original_run_command(workspace, cmd, cwd=cwd)

        run_patcher = mock.patch.object(git_manager.GitWorkspace, "_run_command", fake_run_command)
        run_patcher.start()
        self.addCleanup(run_patcher.stop)

    def _fix(self):
        return asyncio.run(agents.apply_codemender_fix(
            session_id=self.session_id, repo_name=self.REPO, branch="main",
            github_token=FAKE_TOKEN, vuln_id="d60761e6",
        ))

    def _push_calls(self):
        return [call for call in self.git_calls if call[1][:2] == ["git", "push"]]

    def _assert_no_token_in_git_argv(self):
        for _, cmd, _ in self.git_calls:
            for arg in cmd:
                self.assertNotIn(FAKE_TOKEN, str(arg))
                self.assertNotIn("x-access-token", str(arg))

    def test_push_failure_returns_false_and_records_nothing(self):
        self.push_error = (
            "Git command failed: remote: Permission denied. fatal: unable to access "
            f"'https://x-access-token:{FAKE_TOKEN}@github.com/o/r.git/': The requested URL returned error: 403"
        )
        with self.assertLogs("agents", level="ERROR") as captured:
            self.assertFalse(self._fix())

        pushes = self._push_calls()
        self.assertEqual(len(pushes), 1)
        workspace, cmd, cwd = pushes[0]
        self.assertEqual(cmd, ["git", "push", "origin", self.patch_branch])
        self.assertEqual(cwd, self.workspace)
        self.assertEqual(workspace.repo, self.REPO)
        self.assertEqual(str(workspace.workspace_path), self.workspace)
        self.assertEqual(asyncio.run(workspace._resolve_token()), FAKE_TOKEN)
        self._assert_no_token_in_git_argv()

        self.save_patch_proposal.assert_not_called()
        self.get_existing_pr.assert_not_awaited()
        self.post_pr_comment.assert_not_awaited()

        push_errors = [s for s in self.steps if s[1] == "error" and "not submitted" in s[2]]
        self.assertEqual(len(push_errors), 1)
        self.assertIn("***", push_errors[0][2])
        for step in self.steps:
            self.assertNotIn(FAKE_TOKEN, " ".join(str(part) for part in step))
        self.assertNotIn(FAKE_TOKEN, "\n".join(captured.output))

    def test_successful_push_records_the_proposal(self):
        self.assertTrue(self._fix())
        self.assertEqual(len(self._push_calls()), 1)
        self.assertEqual(_git(self.workspace, "rev-parse", "--abbrev-ref", "HEAD"), self.patch_branch)
        self.assertIn(["git", "checkout", "-B", self.patch_branch], [cmd for _, cmd, _ in self.git_calls])
        self._assert_no_token_in_git_argv()
        self.get_existing_pr.assert_awaited_once_with(self.REPO, self.patch_branch, FAKE_TOKEN)
        self.save_patch_proposal.assert_called_once()
        kwargs = self.save_patch_proposal.call_args.kwargs
        self.assertEqual(kwargs["patch_commit_sha"], _git(self.workspace, "rev-parse", "HEAD"))
        self.assertEqual(kwargs["filename"], "app.py")
        self.assertIn("sanitize", kwargs["git_diff"])


if __name__ == "__main__":
    unittest.main()
