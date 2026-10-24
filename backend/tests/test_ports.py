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
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

"""The app port never collides with ports that cm verification uses (plan 5.3, 5.5)."""
import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCKERFILE = os.path.join(REPO_ROOT, "Dockerfile")

# cm verification sessions bind 5000-5999, and exploit scripts start sample apps on the usual
# framework defaults (Flask 5000, Express/React 3000, Django 8000, Spring 8080, ...).
CM_SESSION_PORTS = range(5000, 6000)
COMMON_SAMPLE_APP_PORTS = {80, 443, 3000, 4200, 5000, 5001, 8000, 8008, 8080, 8081, 8443, 8888, 9000}


class AppPortTest(unittest.TestCase):
    def test_dockerfile_port_is_clear_of_verification_ports(self):
        with open(DOCKERFILE, encoding="utf-8") as handle:
            text = handle.read()
        exposed = {int(port) for port in re.findall(r"^EXPOSE\s+(\d+)", text, re.MULTILINE)}
        defaults = {int(port) for port in re.findall(r"\$\{PORT:-(\d+)\}", text)}
        self.assertEqual(exposed, {9080})
        self.assertEqual(defaults, {9080})
        for port in exposed | defaults:
            self.assertNotIn(port, CM_SESSION_PORTS)
            self.assertNotIn(port, COMMON_SAMPLE_APP_PORTS)

    def test_create_only_deploy_script_uses_the_same_port(self):
        with open(os.path.join(REPO_ROOT, "deploy.sh"), encoding="utf-8") as handle:
            ports = {int(port) for port in re.findall(r"--port=(\d+)", handle.read())}
        self.assertEqual(ports - {9080}, set())


if __name__ == "__main__":
    unittest.main()
