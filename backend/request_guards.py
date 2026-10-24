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

"""Pure request guards for the HTTP API (stdlib only: no FastAPI, Firestore or GitHub calls).

- WEBHOOK_ONLY mode: the webhook service serves only the GitHub webhook routes and the health
  probe; every other path gets 404 before any route or the static dashboard mount runs.
- Dashboard actions: the target repository and PR come from the stored scan record, never from
  the request body, and the repository must be enrolled (ALLOWED_REPOS).
- Error responses: a generic message plus a short error id; exception text stays in the logs.
- Cross-site guard: state-changing requests and WebSocket handshakes sent by a browser from
  another site are refused (the dashboard UI is same-origin).
- Dashboard dismissals: the merge gate is recomputed with the scan worker's rule and never turns
  a failed or unfinished scan green.
"""

import urllib.parse
import uuid
from dataclasses import dataclass

from command_auth import is_repo_allowed
from gate_policy import decide_gate, should_skip_duplicate_scan

# Exact paths served when WEBHOOK_ONLY is on (no prefixes, no trailing-slash variants).
WEBHOOK_ONLY_PATHS = frozenset({"/github-webhook", "/webhook", "/health"})

GENERIC_ERROR_MESSAGE = "Internal server error"

_NOT_FOUND_BODY = b'{"detail":"Not Found"}'


def is_path_allowed_for_webhook_only(path) -> bool:
    """True only for the exact webhook and health paths."""
    return isinstance(path, str) and path in WEBHOOK_ONLY_PATHS


class WebhookOnlyMiddleware:
    """ASGI middleware: 404 for every HTTP request whose path is not in WEBHOOK_ONLY_PATHS.

    A plain ASGI middleware (not BaseHTTPMiddleware): it wraps the router and the static mount
    alike, passes the lifespan protocol through, and does not touch BackgroundTasks of allowed
    requests. WebSocket connections on other paths are closed before they are accepted.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        if scope_type in ("http", "websocket") and not is_path_allowed_for_webhook_only(scope.get("path")):
            if scope_type == "http":
                await send({
                    "type": "http.response.start",
                    "status": 404,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(_NOT_FOUND_BODY)).encode("ascii")),
                    ],
                })
                await send({"type": "http.response.body", "body": _NOT_FOUND_BODY})
            else:
                await send({"type": "websocket.close", "code": 1008})
            return
        await self.app(scope, receive, send)


def new_error_id() -> str:
    """Short id that ties a generic error response to the server-side log line with the details."""
    return uuid.uuid4().hex[:8]


def error_payload(error_id: str, message: str = GENERIC_ERROR_MESSAGE) -> dict:
    """Response body for a failed request: generic text plus the error id, never exception text."""
    return {"status": "error", "message": f"{message} (error id: {error_id})", "error_id": error_id}


def is_error_result(result) -> bool:
    """True for helper results shaped {'status': 'error', 'message': ...}."""
    return isinstance(result, dict) and str(result.get("status") or "").lower() == "error" and "message" in result


def scrub_error_result(result, error_id: str, message: str = GENERIC_ERROR_MESSAGE):
    """Copy of an error result with its 'message' (exception text) replaced; other results unchanged.

    Every other key is kept, so dashboards still get the empty summaries they render on failure.
    """
    if not is_error_result(result):
        return result
    scrubbed = dict(result)
    scrubbed.update(error_payload(error_id, message))
    return scrubbed


@dataclass(frozen=True)
class ScanTarget:
    """Decision for a dashboard action on scans/{sha}: proceed only when status_code == 200."""

    status_code: int
    message: str = ""
    repo_name: str | None = None
    pr_number: int | None = None

    @property
    def allowed(self) -> bool:
        return self.status_code == 200


def normalize_pr_number(value):
    """int for numeric PR numbers, None when blank; anything else is kept and never equals an int."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return text


def resolve_scan_target(scan_record, allowed_repos, body_repo_name=None, body_pr_number=None) -> ScanTarget:
    """Target repository and PR for a dashboard action, taken from the stored scan record.

    The request body never chooses the target; a body repo_name / pr_number is only compared
    with the record. Checks, in order:
      404 the scan record is missing (None)
      409 the record has no repo_name (no static fallback repository)
      403 the repository is not enrolled (an empty allowlist allows every repository)
      400 the body names a different repository or PR than the record
    """
    if not isinstance(scan_record, dict):
        return ScanTarget(404, "Scan not found")
    repo_name = str(scan_record.get("repo_name") or "").strip()
    if not repo_name:
        return ScanTarget(409, "Scan record has no repository; re-run the scan from GitHub")
    if not is_repo_allowed(repo_name, allowed_repos):
        return ScanTarget(403, "Repository not enrolled")
    pr_number = normalize_pr_number(scan_record.get("pr_number"))
    body_repo = str(body_repo_name or "").strip()
    if body_repo and body_repo.lower() != repo_name.lower():
        return ScanTarget(400, "repo_name does not match the scan record")
    body_pr = normalize_pr_number(body_pr_number)
    if body_pr is not None and body_pr != pr_number:
        return ScanTarget(400, "pr_number does not match the scan record")
    return ScanTarget(200, "", repo_name, pr_number)


# ---------------------------------------------------------------------------------------------
# Cross-site request guard
# ---------------------------------------------------------------------------------------------

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CROSS_SITE_BODY = b'{"detail":"Cross-site request refused"}'


def _host_port(host, port, scheme: str):
    default_port = 443 if scheme == "https" else 80
    return (host or "").lower(), (port or default_port)


def normalize_origin(value):
    """'HTTPS://Dash.Example.com:443' -> 'https://dash.example.com'.

    None for anything that is not exactly scheme://host[:port] with an http(s) scheme, including
    the opaque origin 'null' (sandboxed iframes, file:// pages).
    """
    text = str(value or "").strip()
    if not text or text.lower() == "null":
        return None
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    host, effective_port = _host_port(parsed.hostname, port, scheme)
    shown_host = f"[{host}]" if ":" in host else host
    if effective_port == (443 if scheme == "https" else 80):
        return f"{scheme}://{shown_host}"
    return f"{scheme}://{shown_host}:{effective_port}"


def parse_origins(raw) -> frozenset:
    """DASHBOARD_ORIGINS ('https://a.example.com,http://localhost:3000') -> normalized origins.

    Invalid entries (and '*') are dropped: a wildcard must never be allowlisted.
    """
    return frozenset(o for o in (normalize_origin(item) for item in str(raw or "").split(",")) if o)


def _origin_matches_host(origin: str, host_values) -> bool:
    """True when the request's Host (or X-Forwarded-Host) names the same host and port as ``origin``."""
    parsed = urllib.parse.urlsplit(origin)
    target = _host_port(parsed.hostname, parsed.port, parsed.scheme)
    for raw in host_values:
        for candidate in str(raw or "").split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                host = urllib.parse.urlsplit(f"//{candidate}")
                if _host_port(host.hostname, host.port, parsed.scheme) == target:
                    return True
            except ValueError:
                continue
    return False


def is_cross_site_request(method, headers, allowed_origins=frozenset(), websocket: bool = False) -> bool:
    """True when a browser sent a state-changing request (or WebSocket handshake) from another site.

    ``headers`` maps lower-case header names to values. Rules, in order:
      - safe methods (GET/HEAD/OPTIONS) pass; WebSocket handshakes are always checked
      - an allowlisted Origin (DASHBOARD_ORIGINS) passes
      - Sec-Fetch-Site: cross-site is refused; Sec-Fetch-Site: same-origin passes (browsers set
        Sec-Fetch-* themselves and pages cannot forge them, so this holds even when a proxy
        rewrites the Host header)
      - no Origin header passes: not a cross-site browser request (GitHub webhooks, the Actions
        relay, curl and Cloud Scheduler send none)
      - an opaque or malformed Origin is refused
      - otherwise the Origin must name the same host as Host / X-Forwarded-Host
    """
    if not websocket and str(method or "").upper() not in STATE_CHANGING_METHODS:
        return False
    raw_origin = headers.get("origin")
    origin = normalize_origin(raw_origin)
    if origin and origin in (allowed_origins or ()):
        return False
    fetch_site = str(headers.get("sec-fetch-site") or "").strip().lower()
    if fetch_site == "cross-site":
        return True
    if fetch_site == "same-origin":
        return False
    if raw_origin is None:
        return False
    if origin is None:
        return True
    return not _origin_matches_host(origin, (headers.get("host"), headers.get("x-forwarded-host")))


def _scope_headers(scope) -> dict:
    headers = {}
    for key, value in scope.get("headers") or []:
        try:
            name = key.decode("latin-1").lower()
            headers.setdefault(name, value.decode("latin-1"))
        except (AttributeError, UnicodeDecodeError):
            continue
    return headers


class CrossSiteGuardMiddleware:
    """ASGI middleware refusing cross-site browser requests (CSRF and cross-site WebSocket hijacking).

    The dashboard UI is served from the same origin as the API, so a state-changing request whose
    Origin names another site can only come from a third-party page riding the user's IAP cookie.
    HTTP requests get 403; WebSocket handshakes are closed before they are accepted. Requests
    without an Origin header (webhooks, relays, schedulers) are untouched.
    """

    def __init__(self, app, allowed_origins=frozenset()):
        self.app = app
        self.allowed_origins = frozenset(allowed_origins or ())

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        if scope_type in ("http", "websocket"):
            websocket = scope_type == "websocket"
            if is_cross_site_request(scope.get("method"), _scope_headers(scope), self.allowed_origins, websocket=websocket):
                if websocket:
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    await send({
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(_CROSS_SITE_BODY)).encode("ascii")),
                        ],
                    })
                    await send({"type": "http.response.body", "body": _CROSS_SITE_BODY})
                return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------------------------
# Dashboard dismissal: merge gate
# ---------------------------------------------------------------------------------------------

# Finding ids that dismiss every finding at once in database.dismiss_finding. The dashboard
# dismisses one finding at a time; the bulk form stays a maintainer-only PR command.
DASHBOARD_WILDCARD_FINDING_IDS = frozenset({"all", "gate", "*"})


def is_wildcard_finding_id(finding_id) -> bool:
    return str(finding_id or "").strip().lower() in DASHBOARD_WILDCARD_FINDING_IDS


def dismissal_gate_decision(scan_status, findings, unscanned_count: int = 0):
    """Merge gate after a dashboard dismissal: (state, description), or (None, reason) to leave it.

    The state comes from the scan worker's own rule, gate_policy.decide_gate(findings), and only
    for a scan record whose status is COMPLETED. Every other status leaves the gate untouched:
    a FAILED/ERROR scan keeps its 'error' gate, and a QUEUED/CLONING/PRE_CHECKS/RUNNING or
    DEFERRED scan gets its gate from its own worker. A dismissal therefore never turns a failed or
    unfinished scan green. ``unscanned_count`` (the record's unscanned_files) keeps a partial scan
    blocked even when every scanned CRITICAL is dismissed (plan 3.1).
    """
    status = str(scan_status or "").strip().upper()
    if status != "COMPLETED":
        return None, f"Gate unchanged: the scan status is {status or 'unknown'}, not COMPLETED."
    return decide_gate(findings if isinstance(findings, list) else [], unscanned_count=unscanned_count)


DISMISS_MIN_REASON_CHARS = 10

IDENTITY_REQUIRED_MESSAGE = (
    "Your identity could not be verified. Open the dashboard through its IAP-protected URL and try again."
)


@dataclass(frozen=True)
class DismissalCheck:
    """Decision for a dashboard dismissal step: proceed only when status_code == 200."""

    status_code: int
    detail: str = ""
    identity: str | None = None
    repo_name: str | None = None
    scan_status: str = ""

    @property
    def allowed(self) -> bool:
        return self.status_code == 200


def validate_dismissal_request(identity, finding_id, reason) -> DismissalCheck:
    """First checks of a dashboard dismissal, before any Firestore access.

      401 no verified identity (the body's `user` field is never used)
      400 missing finding id, a bulk id ('all', 'gate', '*'), or a justification under 10 characters
    """
    if not identity:
        return DismissalCheck(401, IDENTITY_REQUIRED_MESSAGE)
    fid = str(finding_id or "").strip()
    if not fid:
        return DismissalCheck(400, "finding_id is required")
    if is_wildcard_finding_id(fid):
        return DismissalCheck(400, "The dashboard dismisses one finding at a time; 'all', 'gate' and '*' are not accepted.")
    if len(str(reason or "").strip()) < DISMISS_MIN_REASON_CHARS:
        return DismissalCheck(400, "Justification reason must be at least 10 characters long to comply with risk acceptance policies.")
    return DismissalCheck(200, identity=identity)


def check_dismissal_target(scan_record, allowed_repos, now) -> DismissalCheck:
    """Target checks of a dashboard dismissal, on the stored scan record.

    resolve_scan_target's 404/409/403, then 409 while a scan, verification or fix of the commit is
    in flight (recently updated QUEUED/CLONING/PRE_CHECKS/RUNNING): that worker writes the findings
    back when it finishes and would silently undo the dismissal.
    """
    target = resolve_scan_target(scan_record, allowed_repos)
    if not target.allowed:
        return DismissalCheck(target.status_code, target.message)
    status = str(scan_record.get("status") or "").strip().upper()
    if should_skip_duplicate_scan(status, scan_record.get("updated_at"), now):
        return DismissalCheck(
            409,
            f"This commit is busy ({status}): a scan, verification or fix is running. "
            "Dismiss the finding again when it finishes.",
        )
    return DismissalCheck(200, repo_name=target.repo_name, scan_status=status)


# ---------------------------------------------------------------------------------------------
# Generic API decisions and error bodies
# ---------------------------------------------------------------------------------------------

def api_error_payload(message: str) -> dict:
    """JSON error body readable by both dashboard conventions (data.message and data.detail)."""
    return {"status": "error", "message": message, "detail": message}


@dataclass(frozen=True)
class GuardDecision:
    """Outcome of a request check: proceed only when status_code == 200."""

    status_code: int
    detail: str = ""
    identity: str | None = None
    value: object = None

    @property
    def allowed(self) -> bool:
        return self.status_code == 200


# Accepted actions and the status each one writes (agent_db_models.resolve_human_intervention).
INTERVENTION_RESOLUTIONS = {"APPROVE": "APPROVED", "REJECT": "REJECTED"}


def validate_intervention_resolution(reviewer, action) -> GuardDecision:
    """401 without a verified reviewer, 400 unless action is APPROVE or REJECT; value = the action."""
    if not reviewer:
        return GuardDecision(401, IDENTITY_REQUIRED_MESSAGE)
    normalized = str(action or "").strip().upper()
    if normalized not in INTERVENTION_RESOLUTIONS:
        return GuardDecision(400, "action must be APPROVE or REJECT")
    return GuardDecision(200, identity=reviewer, value=normalized)


def check_intervention_record(record) -> GuardDecision:
    """404 for a missing intervention, 409 when it is no longer PENDING (the first decision stands)."""
    if not isinstance(record, dict):
        return GuardDecision(404, "Intervention not found")
    status = str(record.get("status") or "").strip().upper()
    if status and status != "PENDING":
        return GuardDecision(409, f"Intervention is already resolved ({status})")
    return GuardDecision(200)
