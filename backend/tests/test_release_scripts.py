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
"""Plan 1.3: static checks on the deploy and release scripts.

Lessons B2/F4/F8: images tagged :latest, deploys that moved traffic, and scripts that changed
the global gcloud configuration. These tests keep the scripts on the release procedure.
"""
import os
import re
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEPLOY = os.path.join(REPO_ROOT, "deploy.sh")
RELEASE = os.path.join(REPO_ROOT, "scripts", "release.sh")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def _tracked(pattern):
    out = subprocess.run(["git", "ls-files", pattern], cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    return [os.path.join(REPO_ROOT, p) for p in out.stdout.split() if p]


def _code_lines(path):
    """Lines that are not shell comments."""
    return [line for line in _read(path).splitlines() if not line.lstrip().startswith("#")]


class ScriptSyntaxTest(unittest.TestCase):
    def test_shell_scripts_parse_with_the_system_bash(self):
        for script in _tracked("*.sh"):
            with self.subTest(script=os.path.relpath(script, REPO_ROOT)):
                result = subprocess.run(["/bin/bash", "-n", script], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


class ReleaseRulesTest(unittest.TestCase):
    def test_no_script_changes_global_gcloud_configuration(self):
        for script in _tracked("*.sh"):
            for line in _code_lines(script):
                if re.search(r"gcloud\s+config\s+set\b", line):
                    self.assertIn("--configuration", line, f"{os.path.relpath(script, REPO_ROOT)}: {line.strip()}")

    def test_images_are_never_tagged_latest(self):
        for script in (DEPLOY, RELEASE):
            for line in _code_lines(script):
                self.assertNotRegex(line, r"codemender-backend:latest|IMAGE[A-Z_]*=.*:latest")

    def test_release_deploys_without_traffic_and_promotes_to_explicit_revisions(self):
        code = "\n".join(_code_lines(RELEASE))
        deploy_line = next(line for line in code.splitlines() if re.search(r"run_gc deploy ", line))
        self.assertIn("--no-traffic", deploy_line)
        self.assertIn("--tag=", deploy_line)
        self.assertIn("--to-revisions=", code)
        self.assertNotIn("--to-latest", code)

    def test_builds_come_from_a_clean_committed_head(self):
        code = "\n".join(_code_lines(RELEASE))
        build = code[code.index("cmd_build()"):code.index("cmd_deploy()")]
        self.assertIn("require_clean_head", build)
        self.assertIn("git archive", build)
        self.assertIn('--tag="$IMAGE"', build)

    def test_bootstrap_never_redeploys_existing_services(self):
        code = "\n".join(_code_lines(DEPLOY))
        create = code[code.index("create_service()"):]
        self.assertLess(create.index("services describe"), create.index("run deploy"))
        self.assertNotIn("--token ", code, "tokens must come from stdin, not argv")

    def test_no_tracked_file_puts_a_token_in_a_git_url(self):
        # Tests are exempt: the redaction tests build such URLs on purpose.
        tests_dir = os.path.join(REPO_ROOT, "backend", "tests") + os.sep
        for path in _tracked("*.py") + _tracked("*.sh"):
            if path.startswith(tests_dir):
                continue
            text = _read(path)
            with self.subTest(path=os.path.relpath(path, REPO_ROOT)):
                self.assertIsNone(re.search(r"https://x-access-token:\{", text))


if __name__ == "__main__":
    unittest.main()
