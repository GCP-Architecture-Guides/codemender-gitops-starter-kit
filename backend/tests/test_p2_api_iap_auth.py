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

"""Tests for iap_auth: IAP JWT and Google OIDC verification (google-auth calls are stubbed)."""

import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import iap_auth  # noqa: E402

AUDIENCE = "/projects/YOUR_PROJECT_NUMBER/global/backendServices/7102880719443424037"


class _Req:
    def __init__(self, headers):
        self.headers = headers


def _iap_claims(email="Alice@Example.com", iss=iap_auth.IAP_ISSUER):
    return {"iss": iss, "aud": AUDIENCE, "email": email, "sub": "accounts.google.com:123"}


class VerifyIapJwtTest(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch.object(iap_auth, "_get_transport_request", return_value="transport")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_audience_configured_means_no_identity_and_no_verification(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": ""}), \
                mock.patch("google.oauth2.id_token.verify_token") as verify:
            self.assertIsNone(iap_auth.verify_iap_jwt("tok"))
            verify.assert_not_called()

    def test_valid_token_uses_iap_certs_and_configured_audience(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                mock.patch("google.oauth2.id_token.verify_token", return_value=_iap_claims()) as verify:
            claims = iap_auth.verify_iap_jwt("tok")
        self.assertEqual(claims["email"], "Alice@Example.com")
        args, kwargs = verify.call_args
        self.assertEqual(args[0], "tok")
        self.assertEqual(args[1], "transport")
        self.assertEqual(kwargs["audience"], AUDIENCE)
        self.assertEqual(kwargs["certs_url"], "https://www.gstatic.com/iap/verify/public_key")

    def test_several_audiences_are_passed_as_a_list(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": f"{AUDIENCE}, /projects/1/locations/x/services/y"}), \
                mock.patch("google.oauth2.id_token.verify_token", return_value=_iap_claims()) as verify:
            self.assertIsNotNone(iap_auth.verify_iap_jwt("tok"))
        self.assertEqual(verify.call_args.kwargs["audience"], [AUDIENCE, "/projects/1/locations/x/services/y"])

    def test_explicit_audience_overrides_env(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": ""}), \
                mock.patch("google.oauth2.id_token.verify_token", return_value=_iap_claims()) as verify:
            self.assertIsNotNone(iap_auth.verify_iap_jwt("tok", audience="/projects/9/x"))
        self.assertEqual(verify.call_args.kwargs["audience"], "/projects/9/x")

    def test_wrong_issuer_is_rejected(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                mock.patch("google.oauth2.id_token.verify_token", return_value=_iap_claims(iss="https://accounts.google.com")):
            self.assertIsNone(iap_auth.verify_iap_jwt("tok"))

    def test_verification_errors_are_rejected(self):
        for exc in (ValueError("bad signature"), RuntimeError("certs fetch failed")):
            with self.subTest(exc=type(exc).__name__), \
                    mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                    mock.patch("google.oauth2.id_token.verify_token", side_effect=exc):
                self.assertIsNone(iap_auth.verify_iap_jwt("tok"))

    def test_empty_token_is_rejected(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                mock.patch("google.oauth2.id_token.verify_token") as verify:
            self.assertIsNone(iap_auth.verify_iap_jwt(""))
            self.assertIsNone(iap_auth.verify_iap_jwt(None))
            verify.assert_not_called()


class GetIapUserEmailTest(unittest.TestCase):

    def test_returns_normalized_email_without_accounts_prefix(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                mock.patch.object(iap_auth, "verify_iap_jwt",
                                  return_value=_iap_claims(email="accounts.google.com:Alice@Example.com")) as verify:
            email = asyncio.run(iap_auth.get_iap_user_email(_Req({"X-Goog-IAP-JWT-Assertion": "jwt"})))
        self.assertEqual(email, "alice@example.com")
        verify.assert_called_once_with("jwt")

    def test_lowercase_header_name_is_accepted(self):
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                mock.patch.object(iap_auth, "verify_iap_jwt", return_value=_iap_claims()):
            email = asyncio.run(iap_auth.get_iap_user_email(_Req({"x-goog-iap-jwt-assertion": "jwt"})))
        self.assertEqual(email, "alice@example.com")

    def test_missing_header_unset_audience_or_invalid_token_give_none(self):
        cases = (
            ({}, AUDIENCE, _iap_claims()),
            ({"X-Goog-IAP-JWT-Assertion": "jwt"}, "", _iap_claims()),
            ({"X-Goog-IAP-JWT-Assertion": "jwt"}, AUDIENCE, None),
            ({"X-Goog-IAP-JWT-Assertion": "jwt"}, AUDIENCE, _iap_claims(email="")),
        )
        for headers, audience, claims in cases:
            with self.subTest(headers=headers, audience=audience, claims=claims), \
                    mock.patch.dict(os.environ, {"IAP_AUDIENCE": audience}), \
                    mock.patch.object(iap_auth, "verify_iap_jwt", return_value=claims):
                self.assertIsNone(asyncio.run(iap_auth.get_iap_user_email(_Req(headers))))

    def test_unsigned_identity_headers_are_ignored(self):
        headers = {"X-Goog-Authenticated-User-Email": "accounts.google.com:admin@example.com"}
        with mock.patch.dict(os.environ, {"IAP_AUDIENCE": AUDIENCE}), \
                mock.patch.object(iap_auth, "verify_iap_jwt") as verify:
            self.assertIsNone(asyncio.run(iap_auth.get_iap_user_email(_Req(headers))))
            verify.assert_not_called()

    def test_direct_dashboard_flag_never_creates_an_identity(self):
        # The removed ALLOW_DIRECT_DASHBOARD_USER fallback trusted a forgeable header or a default user.
        env = {"IAP_AUDIENCE": AUDIENCE, "ALLOW_DIRECT_DASHBOARD_USER": "true",
               "DIRECT_DASHBOARD_DEFAULT_USER": "demo-operator@codemender.local"}
        for headers in ({}, {"X-Goog-Authenticated-User-Email": "accounts.google.com:admin@example.com"}):
            with self.subTest(headers=headers), mock.patch.dict(os.environ, env), \
                    mock.patch.object(iap_auth, "verify_iap_jwt") as verify:
                self.assertIsNone(asyncio.run(iap_auth.get_iap_user_email(_Req(headers))))
                verify.assert_not_called()


class VerifyGoogleOidcTest(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch.object(iap_auth, "_get_transport_request", return_value="transport")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, headers, audience="https://backend/api/v1/cron/evaluate-slas",
             allowed="scheduler@proj.iam.gserviceaccount.com", claims=None, side_effect=None):
        claims = claims if claims is not None else {
            "iss": "https://accounts.google.com", "email": "scheduler@proj.iam.gserviceaccount.com",
            "email_verified": True,
        }
        with mock.patch("google.oauth2.id_token.verify_oauth2_token",
                        return_value=claims, side_effect=side_effect) as verify:
            result = asyncio.run(iap_auth.verify_google_oidc(_Req(headers), audience, allowed))
        return result, verify

    def test_valid_token_from_allowlisted_account(self):
        result, verify = self._run({"Authorization": "Bearer tok"})
        self.assertEqual(result, "scheduler@proj.iam.gserviceaccount.com")
        args, kwargs = verify.call_args
        self.assertEqual(args[0], "tok")
        self.assertEqual(kwargs["audience"], "https://backend/api/v1/cron/evaluate-slas")

    def test_empty_audience_or_allowlist_denies_everyone(self):
        for audience, allowed in (("", "a@b.c"), ("aud", ""), (None, None)):
            with self.subTest(audience=audience, allowed=allowed):
                result, verify = self._run({"Authorization": "Bearer tok"}, audience=audience, allowed=allowed)
                self.assertIsNone(result)
                verify.assert_not_called()

    def test_missing_or_non_bearer_authorization_is_rejected(self):
        for headers in ({}, {"Authorization": ""}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}):
            with self.subTest(headers=headers):
                result, verify = self._run(headers)
                self.assertIsNone(result)
                verify.assert_not_called()

    def test_unverified_or_unlisted_email_is_rejected(self):
        for claims in (
            {"email": "scheduler@proj.iam.gserviceaccount.com", "email_verified": False},
            {"email": "scheduler@proj.iam.gserviceaccount.com"},
            {"email": "other@proj.iam.gserviceaccount.com", "email_verified": True},
        ):
            with self.subTest(claims=claims):
                result, _ = self._run({"Authorization": "Bearer tok"}, claims=claims)
                self.assertIsNone(result)

    def test_verification_failure_is_rejected(self):
        result, _ = self._run({"Authorization": "Bearer tok"}, side_effect=ValueError("expired"))
        self.assertIsNone(result)

    def test_allowlist_is_case_insensitive_and_comma_separated(self):
        result, _ = self._run({"Authorization": "bearer tok"},
                              allowed=" X@Y.z , Scheduler@proj.iam.gserviceaccount.com ")
        self.assertEqual(result, "scheduler@proj.iam.gserviceaccount.com")


class HelpersTest(unittest.TestCase):

    def test_normalize_email(self):
        self.assertEqual(iap_auth.normalize_email(" accounts.google.com:Bob@Ex.com "), "bob@ex.com")
        for bad in (None, "", "bob", "accounts.google.com:", "a b@c.d"):
            with self.subTest(bad=bad):
                self.assertIsNone(iap_auth.normalize_email(bad))

    def test_parse_email_allowlist(self):
        self.assertEqual(iap_auth.parse_email_allowlist("A@x.io, ,b@y.io,notanemail"), frozenset({"a@x.io", "b@y.io"}))
        self.assertEqual(iap_auth.parse_email_allowlist(""), frozenset())
        self.assertEqual(iap_auth.parse_email_allowlist(None), frozenset())


if __name__ == "__main__":
    unittest.main()
