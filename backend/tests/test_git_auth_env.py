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

"""Stdlib-only tests for git_manager token hygiene (no network, no GitHub calls)."""

import asyncio
import base64
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
from git_manager import GitWorkspace, build_git_auth_env, strip_ci_skip_markers  # noqa: E402

# Obviously fake credential, built at runtime so no token-shaped literal sits in the source.
FAKE_TOKEN = "ghs_" + "T0k3nT0k3n" * 3
HAS_GIT = shutil.which("git") is not None


def _isolated_git_env(extra=None):
    """Environment that ignores the developer's global/system git config."""
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
    })
    env.update(extra or {})
    return env


class BuildGitAuthEnvTest(unittest.TestCase):
    def test_header_is_passed_via_git_config_env(self):
        env = build_git_auth_env(FAKE_TOKEN)
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        scheme, _, encoded = env["GIT_CONFIG_VALUE_0"].partition(" basic ")
        self.assertEqual(scheme, "AUTHORIZATION:")
        self.assertEqual(base64.b64decode(encoded).decode(), f"x-access-token:{FAKE_TOKEN}")
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_raw_token_never_appears_in_env_values(self):
        for value in build_git_auth_env(FAKE_TOKEN).values():
            self.assertNotIn(FAKE_TOKEN, value)
            self.assertNotIn("@github.com", value)

    def test_empty_token_yields_no_auth(self):
        self.assertEqual(build_git_auth_env(""), {})
        self.assertEqual(build_git_auth_env(None), {})

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_git_honours_the_env_config(self):
        env = _isolated_git_env(build_git_auth_env(FAKE_TOKEN))
        with tempfile.TemporaryDirectory() as tmp:
            out = subprocess.run(
                ["git", "config", "--get", "http.https://github.com/.extraheader"],
                cwd=tmp, env=env, capture_output=True, text=True, check=True,
            ).stdout.strip()
        self.assertEqual(out, build_git_auth_env(FAKE_TOKEN)["GIT_CONFIG_VALUE_0"])


class GitSubcommandTest(unittest.TestCase):
    def test_subcommand_detection_skips_global_options(self):
        sub = git_manager._git_subcommand
        self.assertEqual(sub(["git", "push", "origin", "b"]), "push")
        self.assertEqual(sub(["git", "-c", "user.name=x", "-C", "/tmp", "fetch", "origin"]), "fetch")
        self.assertEqual(sub(["git", "--no-pager", "log"]), "log")
        self.assertIsNone(sub(["cm", "find", "x.py"]))
        self.assertIsNone(sub([]))


class StripCiSkipMarkersTest(unittest.TestCase):
    def test_markers_removed(self):
        self.assertEqual(strip_ci_skip_markers("CodeMender: Fix vulnerability abc [skip ci]"), "CodeMender: Fix vulnerability abc")
        self.assertEqual(strip_ci_skip_markers("[ci skip] Patch"), "Patch")
        self.assertEqual(strip_ci_skip_markers("Patch\n\nskip-checks: true"), "Patch")
        self.assertEqual(strip_ci_skip_markers("Plain message"), "Plain message")


class GitWorkspaceRepoIdentityTest(unittest.TestCase):
    """GEMINI.md 'Dynamic Repository Target Identity': repo= is mandatory, with no env or placeholder fallback."""

    def test_missing_repo_is_rejected_even_with_env_default(self):
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "YOUR_ORG/YOUR_REPO"}):
            with self.assertRaises(ValueError):
                GitWorkspace("unittest-no-repo")
            with self.assertRaises(ValueError):
                GitWorkspace("unittest-no-repo", repo="")

    def test_explicit_repo_is_used(self):
        ws = GitWorkspace("unittest-repo", repo="YOUR_ORG/YOUR_REPO")
        self.assertEqual(ws.repo, "YOUR_ORG/YOUR_REPO")
        self.assertEqual(ws._remote_url(), "https://github.com/YOUR_ORG/YOUR_REPO.git")


class GitWorkspaceAuthTest(unittest.TestCase):
    def setUp(self):
        self.session_id = f"unittest-{uuid.uuid4().hex[:12]}"
        patcher = mock.patch.dict(os.environ, {"MOCK_MODE": "false"})
        patcher.start()
        self.addCleanup(patcher.stop)
        # Never reach the real token broker (Secret Manager / gcloud) from unit tests.
        broker = types.ModuleType("github_helpers")

        async def _no_broker(*_args, **_kwargs):
            raise AssertionError("token broker must not be called in unit tests")

        broker.get_github_token = _no_broker
        modules_patcher = mock.patch.dict(sys.modules, {"github_helpers": broker})
        modules_patcher.start()
        self.addCleanup(modules_patcher.stop)

    def tearDown(self):
        git_manager._WORKSPACE_TOKENS.pop(f"/tmp/session-{self.session_id}", None)
        shutil.rmtree(f"/tmp/session-{self.session_id}", ignore_errors=True)

    def test_clone_uses_tokenless_url_and_keeps_token_in_memory(self):
        ws = GitWorkspace(self.session_id, repo="YOUR_ORG/YOUR_REPO")
        calls = []

        async def fake_run(cmd, cwd=None):
            calls.append(list(cmd))
            return "", ""

        ws._run_command = fake_run
        asyncio.run(ws.clone_repo(FAKE_TOKEN, "main"))

        clone_cmd = calls[0]
        self.assertEqual(clone_cmd[:2], ["git", "clone"])
        self.assertIn("https://github.com/YOUR_ORG/YOUR_REPO.git", clone_cmd)
        for call in calls:
            for arg in call:
                self.assertNotIn(FAKE_TOKEN, str(arg))
                self.assertNotIn("x-access-token", str(arg))

        # Another GitWorkspace on the same checkout (e.g. a later push) finds the in-memory token.
        other = GitWorkspace(self.session_id, repo="YOUR_ORG/YOUR_REPO")
        self.assertEqual(asyncio.run(other._resolve_token()), FAKE_TOKEN)

    def test_auth_env_only_for_remote_commands(self):
        ws = GitWorkspace(self.session_id, repo="o/r")
        ws._remember_token(FAKE_TOKEN)
        push_env = asyncio.run(ws._command_env(["git", "push", "origin", "branch"]))
        self.assertEqual(push_env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        self.assertIsNone(asyncio.run(ws._command_env(["git", "status"])))
        self.assertIsNone(asyncio.run(ws._command_env(["git", "commit", "-m", "x"])))

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_clone_with_auth_env_leaves_git_config_credential_free(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _isolated_git_env()):
            src = Path(tmp, "src")
            src.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=src, check=True)
            Path(src, "README.md").write_text("hello\n")
            subprocess.run(["git", "add", "-A"], cwd=src, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=src, check=True)

            ws = GitWorkspace(self.session_id, repo="o/r")
            ws._remember_token(FAKE_TOKEN)
            dest = Path(tmp, "dest")
            asyncio.run(ws._run_command(["git", "clone", "-q", str(src), str(dest)], cwd=tmp))
            config = Path(dest, ".git", "config").read_text()
        encoded = build_git_auth_env(FAKE_TOKEN)["GIT_CONFIG_VALUE_0"].split()[-1]
        self.assertNotIn(FAKE_TOKEN, config)
        self.assertNotIn(encoded, config)
        self.assertNotIn("extraheader", config)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_run_command_redacts_logs_and_errors(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _isolated_git_env()):
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            ws = GitWorkspace(self.session_id, repo="o/r")
            ws.workspace_path = Path(tmp)
            with self.assertLogs("git_manager", level="INFO") as captured:
                with self.assertRaises(RuntimeError) as err:
                    # git echoes the unknown revision (our fake token) back on stderr.
                    asyncio.run(ws._run_command(["git", "rev-parse", FAKE_TOKEN]))
        self.assertNotIn(FAKE_TOKEN, str(err.exception))
        self.assertIn("***", str(err.exception))
        joined = "\n".join(captured.output)
        self.assertNotIn(FAKE_TOKEN, joined)
        self.assertIn("Running command: git rev-parse ***", joined)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_commit_all_stages_new_files_but_not_codemender_state(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _isolated_git_env()):
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            Path(tmp, "app.py").write_text("print('v1')\n")
            subprocess.run(["git", "add", "app.py"], cwd=tmp, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp, check=True)

            Path(tmp, "app.py").write_text("print('v2')\n")
            Path(tmp, "sanitizer.py").write_text("def clean(x):\n    return x\n")
            Path(tmp, ".cm_project").write_text('{"project_id": "p"}\n')
            Path(tmp, ".exploit").mkdir()
            Path(tmp, ".exploit", "exploit.sh").write_text("echo hi\n")

            ws = GitWorkspace(self.session_id, repo="o/r")
            ws.workspace_path = Path(tmp)
            sha = asyncio.run(ws.commit_all("CodeMender: fix [skip ci]"))

            files = subprocess.run(["git", "show", "--name-only", "--format=", sha], cwd=tmp,
                                   capture_output=True, text=True, check=True).stdout.split()
            subject = subprocess.run(["git", "log", "-1", "--format=%s"], cwd=tmp,
                                     capture_output=True, text=True, check=True).stdout.strip()
            config = Path(tmp, ".git", "config").read_text()
        self.assertEqual(sorted(files), ["app.py", "sanitizer.py"])
        self.assertEqual(subject, "CodeMender: fix")
        self.assertNotIn("extraheader", config)


if __name__ == "__main__":
    unittest.main()
