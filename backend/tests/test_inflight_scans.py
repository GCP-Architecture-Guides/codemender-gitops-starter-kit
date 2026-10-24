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

"""release.sh promote preflight: scripts/inflight_scans.py (conflict review C2)."""
import contextlib
import importlib.util
import io
import json
import os
import unittest
import urllib.error
from unittest import mock

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                      "scripts", "inflight_scans.py")
spec = importlib.util.spec_from_file_location("inflight_scans", SCRIPT)
inflight_scans = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inflight_scans)

TOKEN = "fake-access-token-" + "x9" * 12
NOW = 1_800_000_000.0


def _doc(sha, status, updated_at_field, task="scan"):
    return {"document": {"name": f"projects/p/databases/(default)/documents/scans/{sha}",
                         "fields": {"status": {"stringValue": status}, "repo_name": {"stringValue": "your-org/your-repo"},
                                    "active_task": {"stringValue": task}, "updated_at": updated_at_field}}}


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class InflightScansTest(unittest.TestCase):
    def test_query_asks_for_every_in_flight_status(self):
        where = inflight_scans.build_query()["structuredQuery"]["where"]["fieldFilter"]
        self.assertEqual(where["op"], "IN")
        self.assertEqual([v["stringValue"] for v in where["value"]["arrayValue"]["values"]],
                         ["QUEUED", "CLONING", "PRE_CHECKS", "RUNNING"])

    def test_rows_split_on_heartbeat_age(self):
        response = [
            _doc("a" * 40, "RUNNING", {"doubleValue": NOW - 60}),
            _doc("b" * 40, "CLONING", {"doubleValue": NOW - 7200}),
            _doc("c" * 40, "RUNNING", {"timestampValue": "2027-01-15T06:00:00.123456789Z"}, task="verify"),
            {"readTime": "2027-01-15T08:00:00Z"},
        ]
        running, stale = inflight_scans.parse_rows(response, NOW, 1800)
        self.assertEqual([row["sha"][0] for row in running], ["a"])
        self.assertEqual(sorted(row["sha"][0] for row in stale), ["b", "c"])

    def _main(self, payload=None, error=None):
        def urlopen(request, timeout=None, context=None):
            self.assertEqual(request.headers["Authorization"], f"Bearer {TOKEN}")
            if error:
                raise error
            return _Resp(json.dumps(payload).encode())

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(inflight_scans.urllib.request, "urlopen", urlopen), \
                mock.patch.object(inflight_scans.time, "time", lambda: NOW), \
                mock.patch("sys.stdin", io.StringIO(TOKEN + "\n")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = inflight_scans.main(["inflight_scans.py", "your-gcp-project-id"])
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        return code

    def test_exit_codes(self):
        self.assertEqual(self._main([{"readTime": "x"}]), 0)
        self.assertEqual(self._main([_doc("b" * 40, "RUNNING", {"doubleValue": NOW - 7200})]), 0)
        self.assertEqual(self._main([_doc("a" * 40, "RUNNING", {"doubleValue": NOW - 30})]), 3)
        self.assertEqual(self._main(error=urllib.error.HTTPError("u", 403, "Forbidden", {}, None)), 2)

    def test_missing_token_fails_closed(self):
        with mock.patch("sys.stdin", io.StringIO("")), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(inflight_scans.main(["inflight_scans.py", "p"]), 2)


if __name__ == "__main__":
    unittest.main()
