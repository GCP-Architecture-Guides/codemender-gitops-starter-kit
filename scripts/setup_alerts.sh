#!/usr/bin/env bash
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
# ==============================================================================
# Log-based metrics and alert policies for the CodeMender services (plan 6.4, queue Q12)
# ==============================================================================
#   scripts/setup_alerts.sh              dry run: prints the metrics and policy files, changes nothing
#   APPLY=true scripts/setup_alerts.sh   creates them (changes Cloud Monitoring: approve first)
#   NOTIFICATION_CHANNEL=projects/.../notificationChannels/ID adds a channel to every policy;
#   without it, incidents only show in the console.
#
# Alerts (each fires on any occurrence in 5 minutes unless noted):
#   codemender_stale_closeouts     the sweep closed out work whose heartbeat stopped (a worker died)
#   codemender_shutdown_closeouts  a task was interrupted by a service restart
#   codemender_lock_refusals       more than 3 workspace-lease refusals in 5 minutes
#   codemender_schema_drops        a BigQuery row lost a column the live table doesn't have
#   codemender_github_auth_errors  GitHub answered 401/403 (token expired, revoked or under-scoped)
#   codemender_vertex_429          Vertex AI quota / rate limiting
#   Cloud Run 5xx                  built-in request_count metric, response_code_class 5xx
# ==============================================================================
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-your-gcp-project-id}"
export CLOUDSDK_ACTIVE_CONFIG_NAME="${CLOUDSDK_ACTIVE_CONFIG_NAME:-codemender-gitops}"
SCOPE='resource.type="cloud_run_revision" AND resource.labels.service_name=~"^codemender-(webhook|backend|dashboard)$"'
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

run() {
    if [[ "${APPLY:-false}" == "true" ]]; then
        echo "+ $*"
        "$@"
    else
        echo "[dry run] $*"
    fi
}

# metric NAME THRESHOLD DESCRIPTION FILTER
metric() {
    local name="$1" threshold="$2" description="$3" filter="$4"
    if gcloud logging metrics describe "$name" --project="$PROJECT_ID" >/dev/null 2>&1; then
        echo "Log-based metric exists: $name"
    else
        run gcloud logging metrics create "$name" --project="$PROJECT_ID" \
            --description="$description" --log-filter="${SCOPE} AND (${filter})"
    fi
    policy "$name" "$description" \
        "metric.type=\"logging.googleapis.com/user/${name}\" AND resource.type=\"cloud_run_revision\"" "$threshold"
}

# policy NAME DESCRIPTION MONITORING_FILTER THRESHOLD
policy() {
    local name="$1" description="$2" filter="$3" threshold="$4" file
    file="$WORK/${name}.json"
    python3 - "$name" "$description" "$filter" "$threshold" "${NOTIFICATION_CHANNEL:-}" > "$file" <<'PY'
import json, sys
name, description, flt, threshold, channel = sys.argv[1:6]
print(json.dumps({
    "displayName": f"CodeMender: {name}",
    "documentation": {"content": description, "mimeType": "text/markdown"},
    "combiner": "OR",
    "conditions": [{
        "displayName": description,
        "conditionThreshold": {
            "filter": flt,
            "comparison": "COMPARISON_GT",
            "thresholdValue": float(threshold),
            "duration": "0s",
            "aggregations": [{"alignmentPeriod": "300s", "perSeriesAligner": "ALIGN_SUM",
                              "crossSeriesReducer": "REDUCE_SUM"}],
        },
    }],
    "notificationChannels": [channel] if channel else [],
}, indent=1))
PY
    if [[ "${APPLY:-false}" == "true" ]]; then
        for i in {1..12}; do
            if run gcloud alpha monitoring policies create --project="$PROJECT_ID" --policy-from-file="$file" 2>/dev/null; then
                break
            fi
            echo "Waiting for metric $name to become available..."
            sleep 5
        done
    else
        echo "[dry run] policy CodeMender: $name -> $(tr -d '\n ' < "$file" | cut -c1-160)..."
    fi
}

metric codemender_stale_closeouts 0 "The maintenance sweep closed out work whose heartbeat stopped" \
    'textPayload:"Closed out stale"'
metric codemender_shutdown_closeouts 0 "A task was interrupted by a service restart" \
    'textPayload:"interrupted by a service restart"'
metric codemender_lock_refusals 3 "Workspace lease refusals" \
    'textPayload:"Lock already active" OR textPayload:"Lock active for"'
metric codemender_schema_drops 0 "BigQuery rows lost columns missing from the live table" \
    'textPayload:"has no column(s)"'
metric codemender_github_auth_errors 0 "GitHub answered 401/403" \
    'textPayload=~"(?i)github.*\b(401|403)\b"'
metric codemender_vertex_429 0 "Vertex AI quota or rate limiting" \
    'textPayload=~"RESOURCE_EXHAUSTED|\b429\b"'
policy cloud_run_5xx "CodeMender services answered with 5xx" \
    'metric.type="run.googleapis.com/request_count" AND resource.type="cloud_run_revision" AND resource.labels.service_name=monitoring.regex.full_match("codemender-(webhook|backend|dashboard)") AND metric.labels.response_code_class="5xx"' 0
