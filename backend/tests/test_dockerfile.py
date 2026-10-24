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
"""Plan 1.2: static checks on the runtime image definition (no Docker needed).

The image can only be exercised on a no-traffic Cloud Run tag, so these tests pin the
hardening properties in the Dockerfile itself.
"""
import os
import re
import unittest

DOCKERFILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Dockerfile")


def _instructions():
    """(keyword, argument) pairs of the final stage, with line continuations joined."""
    with open(DOCKERFILE, encoding="utf-8") as handle:
        text = handle.read().replace("\\\n", " ")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    pairs = [(line.split(None, 1)[0].upper(), line.split(None, 1)[1] if " " in line else "") for line in lines]
    last_from = max(i for i, (kw, _) in enumerate(pairs) if kw == "FROM")
    return pairs[last_from:]


class RuntimeImageTest(unittest.TestCase):
    def setUp(self):
        self.stage = _instructions()

    def test_runs_as_an_unprivileged_user(self):
        users = [arg for kw, arg in self.stage if kw == "USER"]
        self.assertTrue(users, "the runtime stage must set USER")
        self.assertNotIn(users[-1].split(":")[0], ("root", "0"))
        keywords = [kw for kw, _ in self.stage]
        self.assertLess(keywords.index("USER"), keywords.index("CMD"))
        self.assertNotIn("RUN", keywords[keywords.index("USER"):], "no RUN steps after switching user")

    def test_home_is_set_after_every_root_build_step(self):
        # A root RUN with HOME pointing at the user's home could leave root-owned files there.
        keywords = [(kw, arg) for kw, arg in self.stage]
        home_index = next(i for i, (kw, arg) in enumerate(keywords) if kw == "ENV" and arg.startswith("HOME="))
        later_runs = [arg for kw, arg in keywords[home_index:] if kw == "RUN"]
        self.assertTrue(all(arg.startswith("chown") for arg in later_runs), later_runs)

    def test_no_paths_under_root_home(self):
        for kw, arg in self.stage:
            if kw in ("ENV", "RUN"):
                self.assertNotIn("/root/", arg, f"{kw} {arg[:80]}")

    def test_cm_download_is_checksum_verified(self):
        args = dict(arg.split("=", 1) for kw, arg in self.stage if kw == "ARG" and "=" in arg)
        self.assertRegex(args.get("CM_CLI_SHA256", ""), r"^[0-9a-f]{64}$")
        cm_run = next(arg for kw, arg in self.stage if kw == "RUN" and "cm-linux-amd64.zip" in arg)
        self.assertRegex(cm_run, r"sha256sum -c")
        self.assertLess(cm_run.index("sha256sum"), cm_run.index("unzip"))

    def test_git_safe_directory_is_system_wide(self):
        runs = " ".join(arg for kw, arg in self.stage if kw == "RUN")
        self.assertIsNone(re.search(r"git config --global", runs))
        self.assertIn("git config --system --add safe.directory", runs)


if __name__ == "__main__":
    unittest.main()
