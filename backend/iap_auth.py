# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# you may obtain a copy of the License at
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

"""Verified caller identity for dashboard and scheduler requests.

- IAP: the external HTTPS load balancer in front of the dashboard signs every request it forwards
  with an ES256 JWT in ``X-Goog-IAP-JWT-Assertion``. Its audience is the load balancer's backend
  service (env ``IAP_AUDIENCE``). When ``IAP_AUDIENCE`` is unset, no identity is available and
  callers must refuse identity-bearing actions.
- OIDC: Cloud Scheduler and other Google service accounts send a Google-signed ID token as
  ``Authorization: Bearer <token>``.

Identity never comes from request bodies, and never from unsigned headers such as
``X-Goog-Authenticated-User-Email``: any client can send those.
"""

import asyncio
import logging
import os
import threading

logger = logging.getLogger(__name__)

IAP_JWT_HEADER = "X-Goog-IAP-JWT-Assertion"
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"
IAP_ISSUER = "https://cloud.google.com/iap"
_ACCOUNTS_PREFIX = "accounts.google.com:"

_transport_request = None
_transport_lock = threading.Lock()


def _get_transport_request():
    """Shared google-auth transport (one HTTP session reused for every certificate fetch)."""
    global _transport_request
    if _transport_request is None:
        with _transport_lock:
            if _transport_request is None:
                import google.auth.transport.requests
                _transport_request = google.auth.transport.requests.Request()
    return _transport_request


def parse_list(raw) -> list:
    """'a, b,,c' -> ['a', 'b', 'c']; an iterable is cleaned the same way; None -> []."""
    if raw is None:
        return []
    items = str(raw).split(",") if isinstance(raw, str) else list(raw)
    return [str(item).strip() for item in items if str(item or "").strip()]


def parse_email_allowlist(raw) -> frozenset:
    """Comma list (or iterable) of e-mail addresses, normalized; empty means nobody is allowed."""
    return frozenset(e for e in (normalize_email(item) for item in parse_list(raw)) if e)


def iap_audiences(raw=None) -> list:
    """Accepted IAP JWT audiences: env IAP_AUDIENCE (comma list). Empty means identity is unavailable."""
    return parse_list(os.getenv("IAP_AUDIENCE", "") if raw is None else raw)


def normalize_email(value):
    """Lower-cased address without IAP's 'accounts.google.com:' prefix, or None when not an e-mail."""
    text = str(value or "").strip()
    if text.lower().startswith(_ACCOUNTS_PREFIX):
        text = text[len(_ACCOUNTS_PREFIX):]
    text = text.strip().lower()
    if not text or "@" not in text or any(ch.isspace() for ch in text):
        return None
    return text


def _header(request, name: str):
    headers = getattr(request, "headers", None) or {}
    value = headers.get(name)
    if value is None:
        value = headers.get(name.lower())
    return value


def verify_iap_jwt(token, audience=None):
    """Claims of a valid IAP JWT, else None (blocking: certificate fetch + signature check).

    ``audience`` defaults to env IAP_AUDIENCE. With no audience configured nothing is verified and
    None is returned: google-auth skips the audience check when it is given None.
    """
    audiences = iap_audiences() if audience is None else parse_list(audience)
    if not token or not audiences:
        return None
    try:
        from google.oauth2 import id_token
        claims = id_token.verify_token(
            token,
            _get_transport_request(),
            audience=audiences[0] if len(audiences) == 1 else audiences,
            certs_url=IAP_CERTS_URL,
        )
    except Exception as err:
        # Never log the token itself.
        logger.warning(f"Rejected IAP JWT ({type(err).__name__}).")
        return None
    if not isinstance(claims, dict) or claims.get("iss") != IAP_ISSUER:
        logger.warning("Rejected IAP JWT: unexpected issuer.")
        return None
    return claims


async def get_iap_user_email(request):
    """Verified e-mail of the IAP-authenticated user behind ``request`` (HTTP or WebSocket), else None.

    The JWT check runs in a worker thread so the event loop never blocks on the certificate fetch.
    There is no fallback: unsigned headers (``X-Goog-Authenticated-User-Email``) and default users
    are never accepted, whatever ``ALLOW_DIRECT_DASHBOARD_USER`` says, because any client can send them.
    """
    token = _header(request, IAP_JWT_HEADER)
    if not token or not iap_audiences():
        return None
    claims = await asyncio.to_thread(verify_iap_jwt, token)
    if not claims:
        return None
    return normalize_email(claims.get("email"))


def _verify_oauth2_token(token: str, audiences: list):
    try:
        from google.oauth2 import id_token
        return id_token.verify_oauth2_token(
            token,
            _get_transport_request(),
            audience=audiences[0] if len(audiences) == 1 else audiences,
        )
    except Exception as err:
        logger.warning(f"Rejected Google OIDC token ({type(err).__name__}).")
        return None


async def verify_google_oidc(request, audience, allowed_emails):
    """E-mail of a Google-signed ``Authorization: Bearer`` ID token whose audience matches and whose
    verified e-mail is in ``allowed_emails``; None otherwise.

    An empty audience or an empty allowlist denies every caller.
    """
    audiences = parse_list(audience)
    allowed = parse_email_allowlist(allowed_emails)
    if not audiences or not allowed:
        return None
    scheme, _, token = str(_header(request, "Authorization") or "").strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return None
    claims = await asyncio.to_thread(_verify_oauth2_token, token, audiences)
    if not isinstance(claims, dict):
        return None
    if claims.get("email_verified") not in (True, "true", "True"):
        logger.warning("Rejected Google OIDC token: e-mail not verified.")
        return None
    email = normalize_email(claims.get("email"))
    if not email or email not in allowed:
        logger.warning(f"Rejected Google OIDC token for '{email}': not in the allowlist.")
        return None
    return email
