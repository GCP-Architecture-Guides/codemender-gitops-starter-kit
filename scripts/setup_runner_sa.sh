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
# Least-privilege runtime service account for the CodeMender services (plan 1.4, queue Q8)
# ==============================================================================
#   scripts/setup_runner_sa.sh              dry run: prints every command, changes nothing
#   APPLY=true scripts/setup_runner_sa.sh   runs them (changes IAM: approve first)
#
# Today every service runs as the default compute SA, which holds project-wide Secret Manager,
# Storage admin, Firestore owner and Artifact Registry writer roles. cm runs under the same
# identity, so this account grants only what the app and the cm CLI use:
#   project  roles/datastore.user, roles/aiplatform.user, roles/logging.logWriter,
#            roles/bigquery.jobUser, roles/serviceusage.serviceUsageConsumer
#   bucket   roles/storage.objectAdmin on gs://${PROJECT_ID}-artifacts (state bundles, reports)
#   dataset  roles/bigquery.dataEditor on ${PROJECT_ID}:codemender_analytics
#   secrets  roles/secretmanager.secretAccessor on GITHUB_TOKEN and GITHUB_WEBHOOK_SECRET only
#            (Cloud Run reads mounted secrets as the revision's service account)
# EXTRA_ROLES (space separated project roles) adds a role the E2E run shows is missing, for
# example roles/cloudaicompanion.user if the cm CLI needs it.
#
# The switch itself is a release, so the previous revision (compute SA) stays the rollback:
#   DEPLOY_FLAGS="--service-account=<SA_EMAIL>" scripts/release.sh deploy, smoke, promote
# ==============================================================================
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-your-gcp-project-id}"
SA_NAME="${SA_NAME:-codemender-runner}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
BUCKET="gs://${PROJECT_ID}-artifacts"
DATASET="${PROJECT_ID}:codemender_analytics"
SECRETS=(GITHUB_TOKEN GITHUB_WEBHOOK_SECRET GITHUB_FLEET_TOKEN)
PROJECT_ROLES=(roles/datastore.user roles/aiplatform.user roles/logging.logWriter roles/bigquery.jobUser
               roles/serviceusage.serviceUsageConsumer)
EXTRA=()
read -r -a EXTRA <<< "${EXTRA_ROLES:-}"

# This project's gcloud configuration, for this process only (never changes global gcloud state).
export CLOUDSDK_ACTIVE_CONFIG_NAME="${CLOUDSDK_ACTIVE_CONFIG_NAME:-codemender-gitops}"

run() {
    if [[ "${APPLY:-false}" == "true" ]]; then
        echo "+ $*"
        "$@"
    else
        echo "[dry run] $*"
    fi
}

if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" >/dev/null 2>&1; then
    echo "Service account exists: $SA_EMAIL"
else
    run gcloud iam service-accounts create "$SA_NAME" --project="$PROJECT_ID" \
        --display-name="CodeMender runtime (least privilege)"
fi

for role in "${PROJECT_ROLES[@]}" ${EXTRA[@]+"${EXTRA[@]}"}; do
    run gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${SA_EMAIL}" \
        --role="$role" --condition=None --quiet
done
run gcloud storage buckets add-iam-policy-binding "$BUCKET" --project="$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" --role=roles/storage.objectAdmin
run gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${SA_EMAIL}" \
    --role=roles/bigquery.dataEditor --condition=None --quiet
for secret in "${SECRETS[@]}"; do
    run gcloud secrets add-iam-policy-binding "$secret" --project="$PROJECT_ID" \
        --member="serviceAccount:${SA_EMAIL}" --role=roles/secretmanager.secretAccessor
done

echo "Next: DEPLOY_FLAGS=\"--service-account=${SA_EMAIL}\" scripts/release.sh deploy, then smoke and promote."
