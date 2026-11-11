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
"""Findings table of the pinned PR security report. Pure functions, no I/O.

Rows come from the reconciled findings of a scan: RESOLVED (fixed since the previous head of
the PR), NEW / PERSISTENT (still open) and DISMISSED (risk accepted). Only open findings ask
the reader to act.
"""

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
TABLE_HEADER = (
    "| Status | ID | Severity | Type | Location | Description |\n"
    "| :--- | :--- | :--- | :--- | :--- | :--- |\n"
)


def normalize_severity(raw) -> str:
    """CRITICAL / HIGH / MEDIUM / LOW from a raw (possibly emoji-decorated) severity; HIGH if unknown."""
    text = str(raw or "").upper()
    for severity in SEVERITIES:
        if severity in text:
            return severity
    return "HIGH"


def lifecycle_of(finding: dict) -> str:
    """RESOLVED, DISMISSED, NEW or PERSISTENT. Findings without a lifecycle keep the historical
    PERSISTENT label."""
    lifecycle = str(finding.get("lifecycle_status") or "").upper()
    status = str(finding.get("status") or "").upper()
    if "RESOLVED" in (lifecycle, status):
        return "RESOLVED"
    if "DISMISSED" in (lifecycle, status):
        return "DISMISSED"
    return "NEW" if lifecycle == "NEW" else "PERSISTENT"


def _location(finding: dict, default_path: str, resolved: bool = False) -> str:
    location = f"`{finding.get('filepath') or default_path}`"
    if resolved:
        return location + " (Fixed)"
    line = finding.get("line_number")
    if line:
        location += f":{line}"
        previous = finding.get("previous_line_number")
        if previous and previous != line:
            location += f" *(was :{previous})*"
    return location


def _dismissal_category(finding: dict) -> str:
    dismissal = finding.get("dismissal") if isinstance(finding.get("dismissal"), dict) else {}
    return str(finding.get("dismissal_category") or dismissal.get("category") or "").strip()


def render_findings_table(findings, default_path: str) -> tuple[str, int]:
    """Returns (markdown table, number of open findings). The table is "" when nothing is listed.

    Order: RESOLVED, then open (NEW / PERSISTENT), then DISMISSED.
    """
    resolved, open_findings, dismissed = [], [], []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        state = lifecycle_of(finding)
        if state == "RESOLVED":
            resolved.append(finding)
        elif state == "DISMISSED":
            dismissed.append(finding)
        else:
            open_findings.append((state, finding))

    rows = []
    for finding in resolved:
        severity = normalize_severity(finding.get("severity"))
        rows.append(
            f"| ✅ **RESOLVED** | `{finding.get('id')}` | ~~{severity}~~ | {finding.get('vuln_type')} | "
            f"{_location(finding, default_path, resolved=True)} | {finding.get('description')} |"
        )
    for state, finding in open_findings:
        severity = normalize_severity(finding.get("severity"))
        tag = "🆕 **NEW**" if state == "NEW" else "⚠️ **PERSISTENT**"
        rows.append(
            f"| {tag} | `{finding.get('id')}` | {SEVERITY_EMOJI[severity]} **{severity}** | "
            f"{finding.get('vuln_type')} | {_location(finding, default_path)} | {finding.get('description')} |"
        )
    for finding in dismissed:
        severity = normalize_severity(finding.get("severity"))
        category = _dismissal_category(finding)
        note = f" *(risk accepted: {category})*" if category else " *(risk accepted)*"
        rows.append(
            f"| 🟡 **DISMISSED** | `{finding.get('id')}` | ⚪ {severity} | {finding.get('vuln_type')} | "
            f"{_location(finding, default_path)} | {finding.get('description')}{note} |"
        )

    if not rows:
        return "", 0
    return TABLE_HEADER + "\n".join(rows) + "\n", len(open_findings)
