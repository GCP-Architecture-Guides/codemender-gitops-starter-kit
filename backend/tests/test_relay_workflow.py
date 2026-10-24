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
"""Plan 1.5 / 4.4: the relay workflow's trust model, checked statically."""
import os
import re
import unittest

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
RELAY = os.path.join(WORKFLOWS, "codemender-wif.yml")


def _load():
    with open(RELAY, encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)
    # PyYAML (YAML 1.1) reads the bare key `on` as True.
    triggers = workflow.get("on", workflow.get(True))
    return workflow, triggers


class RelayWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow, self.triggers = _load()
        self.job = self.workflow["jobs"]["codemender-trigger"]

    def test_only_main_copy_runs_for_pull_requests(self):
        self.assertNotIn("pull_request", self.triggers, "pull_request runs the PR's own copy of the workflow")
        self.assertIn("pull_request_target", self.triggers)
        self.assertEqual(self.triggers["issue_comment"]["types"], ["created"])

    def test_merged_prs_are_relayed_for_analytics(self):
        self.assertIn("closed", self.triggers["pull_request_target"]["types"])

    def test_no_pr_code_is_checked_out(self):
        uses = [step.get("uses", "") for step in self.job["steps"]]
        self.assertFalse(any(u.startswith("actions/checkout") for u in uses), uses)

    def test_only_same_repository_prs_are_relayed(self):
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", self.job["if"])

    def test_shell_never_interpolates_event_fields(self):
        for step in self.job["steps"]:
            run = step.get("run", "")
            self.assertIsNone(re.search(r"\$\{\{\s*github\.event", run), run)

    def test_event_header_maps_back_to_pull_request(self):
        relay = next(step for step in self.job["steps"] if "run" in step)
        self.assertIn("'pull_request'", relay["env"]["EVENT_NAME"])
        self.assertIn("X-GitHub-Event: ${EVENT_NAME}", relay["run"])

    def test_minimal_permissions(self):
        self.assertEqual(self.workflow["permissions"], {"id-token": "write", "contents": "read"})

    def test_single_relay_workflow(self):
        # Two relays would double-deliver every event (the legacy codemender.yml was removed).
        relays = []
        for name in os.listdir(WORKFLOWS):
            with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as handle:
                if "X-CodeMender-Auth" in handle.read():
                    relays.append(name)
        self.assertEqual(relays, ["codemender-wif.yml"])


if __name__ == "__main__":
    unittest.main()
