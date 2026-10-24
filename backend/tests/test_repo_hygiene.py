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
"""Plan 2.6 (GEMINI.md 'Gitignored Test Samples'): vulnerable samples are never tracked."""
import os
import re
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE_NAME = re.compile(r"(?i)(^|/)vulnerable[^/]*\.(py|go|js|ts|java|tf|php|rb)$")


class RepoHygieneTest(unittest.TestCase):
    def test_no_vulnerable_samples_are_tracked(self):
        tracked = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True,
                                 check=True).stdout.splitlines()
        samples = [p for p in tracked if SAMPLE_NAME.search(p)]
        self.assertEqual(samples, [], "move vulnerable samples into the gitignored vulnerable-samples/")

    def test_samples_folder_is_ignored(self):
        result = subprocess.run(["git", "check-ignore", "-q", "vulnerable-samples/example.py"], cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
