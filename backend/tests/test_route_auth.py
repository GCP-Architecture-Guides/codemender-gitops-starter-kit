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
"""Plan 1.7: every state-changing dashboard route needs a verified IAP identity.

Covers review items D7 (routes with no app-level auth) and B9 (forgeable dashboard identity).
"""
import os
import sys
import unittest
from unittest import mock

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

from tests.main_loader import import_real_main  # noqa: E402

main = import_real_main()

GUARDED_POSTS = {
    "/api/scans/abc123/cancel": None,
    "/api/maintenance/gc": None,
    "/api/analytics/chat": {"message": "hi"},
    "/api/scans/abc123/verify/f1": None,
    "/api/scans/abc123/fix/f1": None,
    "/api/scans/abc123/draft_pr": None,
    "/api/scans/abc123/verify": {"finding_ids": ["f1"]},
    "/api/scans/abc123/fix": {"finding_ids": ["f1"]},
    "/submit": {"session_id": "s1", "code": "print(1)"},
}


async def _verified(_request):
    return "alice@example.com"


class RouteAuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)

    def _post(self, path, body=None, **kwargs):
        if body is None:
            return self.client.post(path, **kwargs)
        return self.client.post(path, json=body, **kwargs)

    def test_guarded_routes_reject_callers_without_identity(self):
        for path, body in GUARDED_POSTS.items():
            with self.subTest(path=path):
                self.assertEqual(self._post(path, body).status_code, 401)

    def test_forged_identity_header_is_not_an_identity(self):
        headers = {"X-Goog-Authenticated-User-Email": "accounts.google.com:admin@example.com"}
        with mock.patch.dict(os.environ, {"ALLOW_DIRECT_DASHBOARD_USER": "true"}):
            for path, body in GUARDED_POSTS.items():
                with self.subTest(path=path):
                    self.assertEqual(self._post(path, body, headers=headers).status_code, 401)

    def test_websocket_requires_identity(self):
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/s1"):
                pass

    def test_verified_identity_passes_the_identity_gate(self):
        # Past the identity gate, the next check (scan target / payload) decides; never 401.
        with mock.patch.object(main, "get_iap_user_email", _verified):
            for path in ("/api/scans/abc123/cancel", "/api/scans/abc123/verify"):
                with self.subTest(path=path):
                    body = GUARDED_POSTS[path]
                    self.assertNotEqual(self._post(path, body).status_code, 401)

    def test_maintenance_accepts_allowlisted_scheduler_oidc(self):
        async def no_iap(_request):
            return None

        async def scheduler(_request, audience, allowed):
            return "scheduler@your-gcp-project-id.iam.gserviceaccount.com" if audience and allowed else None

        async def token():
            return "token"

        env = {"MAINTENANCE_OIDC_AUDIENCE": "https://example.run.app",
               "MAINTENANCE_INVOKERS": "scheduler@your-gcp-project-id.iam.gserviceaccount.com"}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(main, "get_iap_user_email", no_iap), \
                mock.patch.object(main, "verify_google_oidc", scheduler), \
                mock.patch.object(main, "get_github_token", token), \
                mock.patch("maintenance.run_maintenance_sweep", return_value={"status": "ok"}):
            resp = self.client.post("/api/maintenance/gc")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok", "gates_set": 0})

    def test_health_stays_open(self):
        self.assertEqual(self.client.get("/health").status_code, 200)


if __name__ == "__main__":
    unittest.main()
