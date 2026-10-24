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

"""Stdlib-only tests for the CodeMender CLI subprocess environment allowlist."""

import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _ensure_database_stub():
    """cm_tools imports Firestore/BigQuery helpers from `database`; stub them (no Google Cloud)."""
    module = sys.modules.get("database")
    if module is None:
        module = types.ModuleType("database")
        sys.modules["database"] = module
    for name in ("update_scan_status", "log_token_usage", "get_scan_repo_name", "append_scan_step"):
        if not hasattr(module, name):
            setattr(module, name, lambda *args, **kwargs: None)


_ensure_database_stub()
import cm_tools  # noqa: E402

# Obviously fake credential, built at runtime so no token-shaped literal sits in the source.
FAKE_TOKEN = "ghp_" + "F4k3F4k3F4" * 3

BASE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
    "PYTHONUNBUFFERED": "1",
    "NODE_PATH": "/usr/local/lib/node_modules",
    "GOOGLE_CLOUD_LOCATION": "global",
    "GOOGLE_APPLICATION_CREDENTIALS": "/secrets/adc.json",
    "CLOUDSDK_CORE_PROJECT": "YOUR_PROJECT_ID",
    "K_SERVICE": "codemender-backend",
    "K_REVISION": "codemender-backend-00042",
    "CM_DISABLE_SANDBOX": "true",
    "CM_TEAM_ID": "team-1",
    "CM_DISABLE_MODEL_FALLBACK": "1",
    "CM_HOME": "/root/.codemender",
    "CM_LOG_LEVEL": "debug",
    "CM_API_KEY": "not-forwarded",
    "CM_AUTH_TOKEN": "not-forwarded",
    "CM_CLIENT_SECRET": "not-forwarded",
    "CM_CREDENTIALS_FILE": "not-forwarded",
    "CM_BASIC_AUTH": "not-forwarded",
    "CM_SESSION_COOKIE": "not-forwarded",
    "CM_DB_PASSWD": "not-forwarded",
    "GITHUB_TOKEN": FAKE_TOKEN,
    "GITHUB_FLEET_TOKEN": FAKE_TOKEN,
    "GITHUB_PR_TOKEN": FAKE_TOKEN,
    "GITHUB_WEBHOOK_SECRET": "whsec-not-forwarded",
    "GITHUB_APP_ID": "12345",
    "GITHUB_APP_INSTALLATION_ID": "67890",
    "GITHUB_APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----not-forwarded",
    "DB_PASSWORD": "not-forwarded",
    "SOME_SECRET": "not-forwarded",
    "SERVICE_PRIVATE_KEY": "not-forwarded",
    "MY_ACCESS_TOKEN": "not-forwarded",
    "RANDOM_SETTING": "not-forwarded",
    "PORT": "8080",
    "CODEMENDER_PROJECT_ID": "YOUR_PROJECT_ID",
    "GOOGLE_CLOUD_PROJECT": "some-other-project",
}


class CmSubprocessEnvTest(unittest.TestCase):
    def test_cm_disable_sandbox_survives_and_github_token_does_not(self):
        env = cm_tools._cm_subprocess_env(BASE_ENV)
        self.assertEqual(env.get("CM_DISABLE_SANDBOX"), "true")
        self.assertNotIn("GITHUB_TOKEN", env)

    def test_runtime_and_cloud_settings_are_kept(self):
        env = cm_tools._cm_subprocess_env(BASE_ENV)
        for name in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TZ", "PYTHONUNBUFFERED", "NODE_PATH",
                     "GOOGLE_CLOUD_LOCATION", "GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CORE_PROJECT",
                     "K_SERVICE", "K_REVISION", "CM_TEAM_ID", "CM_DISABLE_MODEL_FALLBACK", "CM_HOME"):
            self.assertEqual(env.get(name), BASE_ENV[name], name)

    def test_github_credentials_and_secrets_are_dropped(self):
        env = cm_tools._cm_subprocess_env(BASE_ENV)
        for name in ("GITHUB_TOKEN", "GITHUB_FLEET_TOKEN", "GITHUB_PR_TOKEN", "GITHUB_WEBHOOK_SECRET",
                     "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY",
                     "DB_PASSWORD", "SOME_SECRET", "SERVICE_PRIVATE_KEY", "MY_ACCESS_TOKEN"):
            self.assertNotIn(name, env)
        for value in env.values():
            self.assertNotIn(FAKE_TOKEN, value)
            self.assertNotIn("not-forwarded", value)

    def test_other_cm_settings_pass_unless_credential_like(self):
        env = cm_tools._cm_subprocess_env(BASE_ENV)
        self.assertEqual(env.get("CM_LOG_LEVEL"), "debug")
        for name in ("CM_API_KEY", "CM_AUTH_TOKEN", "CM_CLIENT_SECRET", "CM_CREDENTIALS_FILE",
                     "CM_BASIC_AUTH", "CM_SESSION_COOKIE", "CM_DB_PASSWD"):
            self.assertNotIn(name, env)

    def test_unlisted_variables_are_dropped(self):
        env = cm_tools._cm_subprocess_env(BASE_ENV)
        for name in ("RANDOM_SETTING", "PORT", "CODEMENDER_PROJECT_ID"):
            self.assertNotIn(name, env)

    def test_project_override(self):
        env = cm_tools._cm_subprocess_env(BASE_ENV)
        self.assertEqual(env["GOOGLE_CLOUD_PROJECT"], "YOUR_PROJECT_ID")
        self.assertEqual(env["GCLOUD_PROJECT"], "YOUR_PROJECT_ID")
        env = cm_tools._cm_subprocess_env({"PATH": "/usr/bin", "GOOGLE_CLOUD_PROJECT": "YOUR_PROJECT_ID"})
        self.assertEqual(env["GCLOUD_PROJECT"], "YOUR_PROJECT_ID")

    def test_missing_project_fails_fast(self):
        # No placeholder or ambient project: cm must never run against an unintended project.
        with self.assertRaises(RuntimeError):
            cm_tools._cm_subprocess_env({"PATH": "/usr/bin"})

    def test_defaults_to_process_environment(self):
        with mock.patch.dict(os.environ, BASE_ENV, clear=True):
            env = cm_tools._cm_subprocess_env()
        self.assertEqual(env.get("CM_DISABLE_SANDBOX"), "true")
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("GITHUB_WEBHOOK_SECRET", env)


if __name__ == "__main__":
    unittest.main()
