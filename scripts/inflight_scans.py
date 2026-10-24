#!/usr/bin/env python3
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
"""Lists CodeMender tasks that are still running (release.sh promote preflight, conflict review C2).

Usage: gcloud auth print-access-token | scripts/inflight_scans.py PROJECT_ID

The OAuth access token is read from stdin only (never argv or the environment) and is never
printed. The project's Firestore is queried over REST for scan records whose status is in flight.
A record counts as running when its heartbeat (updated_at) is newer than CM_STALE_TASK_SEC
(default 600 s); older ones are reported as stale, and the in-process sweep closes those out.

Exit codes: 0 = nothing running, 3 = something is running, 2 = the check itself failed.
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

IN_FLIGHT_STATUSES = ("QUEUED", "CLONING", "PRE_CHECKS", "RUNNING")
DEFAULT_STALE_SEC = 600.0


def build_query() -> dict:
    """runQuery body: scans whose status is one of IN_FLIGHT_STATUSES (at most 100)."""
    return {"structuredQuery": {
        "from": [{"collectionId": "scans"}],
        "where": {"fieldFilter": {
            "field": {"fieldPath": "status"},
            "op": "IN",
            "value": {"arrayValue": {"values": [{"stringValue": s} for s in IN_FLIGHT_STATUSES]}},
        }},
        "limit": 100,
    }}


def _value(field):
    """Decodes the Firestore REST value types a scan record uses."""
    if not isinstance(field, dict):
        return None
    if "stringValue" in field:
        return field["stringValue"]
    if "integerValue" in field:
        return int(field["integerValue"])
    if "doubleValue" in field:
        return float(field["doubleValue"])
    if "booleanValue" in field:
        return bool(field["booleanValue"])
    if "timestampValue" in field:
        text = field["timestampValue"].replace("Z", "+00:00")
        if "." in text:  # trim nanoseconds to the microseconds fromisoformat accepts; keep the offset
            head, rest = text.split(".", 1)
            end = 0
            while end < len(rest) and rest[end].isdigit():
                end += 1
            text = f"{head}.{rest[:end][:6]}{rest[end:]}"
        return datetime.fromisoformat(text).timestamp()
    return None


def parse_rows(response, now: float, stale_after: float):
    """Splits runQuery results into (running, stale) rows."""
    running, stale = [], []
    for item in response or []:
        doc = item.get("document") if isinstance(item, dict) else None
        if not doc:
            continue  # runQuery returns readTime-only items when nothing matches
        fields = doc.get("fields", {})
        heartbeat = _value(fields.get("updated_at"))
        row = {
            "sha": doc.get("name", "").rsplit("/", 1)[-1],
            "status": _value(fields.get("status")),
            "task": _value(fields.get("active_task")) or "scan",
            "repo": _value(fields.get("repo_name")) or "?",
            "age": None if heartbeat is None else max(0.0, now - heartbeat),
        }
        (running if row["age"] is not None and row["age"] < stale_after else stale).append(row)
    return running, stale


def _stale_seconds() -> float:
    try:
        return float(os.environ.get("CM_STALE_TASK_SEC") or DEFAULT_STALE_SEC)
    except ValueError:
        return DEFAULT_STALE_SEC


def main(argv) -> int:
    project = argv[1] if len(argv) > 1 else ""
    if not project:
        print("usage: gcloud auth print-access-token | inflight_scans.py PROJECT_ID", file=sys.stderr)
        return 2
    token = sys.stdin.read().strip()
    if not token:
        print("error: no access token on stdin", file=sys.stderr)
        return 2
    url = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents:runQuery"
    request = urllib.request.Request(
        url, data=json.dumps(build_query()).encode(), method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "x-goog-user-project": project},
    )
    context = None
    try:  # python.org builds on macOS ship without a CA bundle; certifi (in the venv) provides one
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as resp:
            response = json.load(resp)
    except urllib.error.HTTPError as err:
        print(f"error: Firestore query failed: HTTP {err.code}", file=sys.stderr)
        return 2
    except Exception as err:  # network, JSON
        reason = getattr(err, "reason", "")
        print(f"error: Firestore query failed: {type(err).__name__} {reason}".rstrip(), file=sys.stderr)
        return 2

    running, stale = parse_rows(response, time.time(), _stale_seconds())
    for row in running:
        print(f"  RUNNING {row['sha'][:12]} {row['status']:<10} {row['task']:<6} {row['repo']} (heartbeat {int(row['age'])}s ago)")
    for row in stale:
        age = "no heartbeat" if row["age"] is None else f"no heartbeat for {int(row['age'] // 60)} min"
        print(f"  stale   {row['sha'][:12]} {row['status']:<10} {row['task']:<6} {row['repo']} ({age}; the sweep closes it out)")
    if running:
        print(f"{len(running)} task(s) running.")
        return 3
    print("No task running." + (f" {len(stale)} stale record(s)." if stale else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
