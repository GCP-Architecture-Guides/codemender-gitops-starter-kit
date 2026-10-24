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
# CodeMender one-time bootstrap (plan 1.3)
# ==============================================================================
# Creates what is missing and never modifies what already exists:
#   - required APIs, the Firestore (default) database, the artifacts bucket
#   - Secret Manager secrets GITHUB_TOKEN and GITHUB_WEBHOOK_SECRET
#   - the Cloud Run services codemender-webhook, codemender-backend and codemender-dashboard,
#     from an image that scripts/release.sh build already produced
#
# Releases to existing services go through scripts/release.sh (no-traffic tag, smoke checks,
# explicit promotion). The load balancer, IAP, WIF and IAM bindings are configured separately.
#
# Usage:
#   scripts/release.sh build      # first, from a clean committed HEAD
#   printf '%s' "$GITHUB_PAT" | ./deploy.sh --token-stdin [--iap-audience AUD] [--runtime-sa EMAIL]
#
# Options:
#   -p, --project ID        GCP project (default: YOUR_PROJECT_ID)
#   -r, --region REGION     Region (default: us-central1)
#   -g, --repo OWNER/REPO   The one repository the services may act on (default: YOUR_ORG/YOUR_REPO)
#   --sha SHA               Image tag to create missing services from (default: git HEAD)
#   --token-stdin           Read the GitHub token for a new GITHUB_TOKEN secret from stdin
#   --iap-audience AUD      IAP audience of the dashboard's load balancer backend
#   --runtime-sa EMAIL      Runtime service account for new services (default: Cloud Run default)
#   --model NAME            Gemini model (default: gemini-3.8-flash)
#   -h, --help
# ==============================================================================
set -euo pipefail

PROJECT_ID="YOUR_PROJECT_ID"
REGION="us-central1"
REPO="YOUR_ORG/YOUR_REPO"
SHA=""
TOKEN_STDIN=false
IAP_AUDIENCE=""
RUNTIME_SA=""
MODEL="gemini-3.8-flash"
FIRESTORE_LOCATION="nam5"

usage() { sed -n '19,45p' "${BASH_SOURCE[0]}"; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--project) PROJECT_ID="$2"; shift 2 ;;
        -r|--region) REGION="$2"; shift 2 ;;
        -g|--repo) REPO="$2"; shift 2 ;;
        --sha) SHA="$2"; shift 2 ;;
        --token-stdin) TOKEN_STDIN=true; shift ;;
        --iap-audience) IAP_AUDIENCE="$2"; shift 2 ;;
        --runtime-sa) RUNTIME_SA="$2"; shift 2 ;;
        --model) MODEL="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "Unknown option: $1" >&2; usage 2 ;;
    esac
done

# This project's gcloud configuration, for this process only (never changes global gcloud state).
export CLOUDSDK_ACTIVE_CONFIG_NAME="${CLOUDSDK_ACTIVE_CONFIG_NAME:-codemender-gitops}"

SHA="${SHA:-$(git rev-parse HEAD)}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/codemender-backend:${SHA}"
BUCKET="${PROJECT_ID}-artifacts"

die() { echo "error: $*" >&2; exit 1; }
gc() { gcloud "$@" --project="$PROJECT_ID" --quiet; }

echo "Project ${PROJECT_ID} | region ${REGION} | repo ${REPO}"
echo "Image   ${IMAGE}"

# 1. APIs
for api in run aiplatform firestore secretmanager bigquery storage artifactregistry cloudbuild \
           cloudscheduler iam iamcredentials; do
    gc services enable "${api}.googleapis.com"
done
echo "APIs enabled."

# 2. Firestore and the artifacts bucket
if gc firestore databases describe --database="(default)" >/dev/null 2>&1; then
    echo "Firestore (default) exists."
else
    gc firestore databases create --location="$FIRESTORE_LOCATION" --type=firestore-native
fi
if gc storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1; then
    echo "Bucket gs://${BUCKET} exists."
else
    gc storage buckets create "gs://${BUCKET}" --location="$REGION" --uniform-bucket-level-access
fi

# 3. Secrets (values never appear in argv or output)
if gc secrets describe GITHUB_TOKEN >/dev/null 2>&1; then
    echo "Secret GITHUB_TOKEN exists (rotate it with: gcloud secrets versions add GITHUB_TOKEN --data-file=-)."
elif [[ "$TOKEN_STDIN" == true ]]; then
    gc secrets create GITHUB_TOKEN --replication-policy=automatic
    gc secrets versions add GITHUB_TOKEN --data-file=- </dev/stdin
    echo "Secret GITHUB_TOKEN created."
else
    die "secret GITHUB_TOKEN is missing; pipe a repository-scoped token in with --token-stdin"
fi
if gc secrets describe GITHUB_WEBHOOK_SECRET >/dev/null 2>&1; then
    echo "Secret GITHUB_WEBHOOK_SECRET exists."
else
    gc secrets create GITHUB_WEBHOOK_SECRET --replication-policy=automatic
    openssl rand -hex 32 | tr -d '\n' | gc secrets versions add GITHUB_WEBHOOK_SECRET --data-file=-
    echo "Secret GITHUB_WEBHOOK_SECRET created."
fi

# 4. Cloud Run services (created only when missing)
gc artifacts docker images describe "$IMAGE" >/dev/null 2>&1 \
    || die "image ${IMAGE} not found; run scripts/release.sh build first"

COMMON_ENV="MOCK_MODE=false,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},CODEMENDER_PROJECT_ID=${PROJECT_ID}"
COMMON_ENV+=",CLOUD_ML_PROJECT_ID=${PROJECT_ID},CLOUD_ML_REGION=${REGION},GEMINI_LOCATION=${REGION}"
COMMON_ENV+=",GOOGLE_CLOUD_LOCATION=global,GOOGLE_GENAI_USE_VERTEXAI=True"
COMMON_ENV+=",GEMINI_MODEL_NAME=${MODEL},VERTEX_MODEL=${MODEL},CODEMENDER_SCAN_MODEL=${MODEL},CODEMENDER_FIX_MODEL=${MODEL}"
COMMON_ENV+=",GITHUB_REPOSITORY=${REPO},ALLOWED_REPOS=${REPO}"
IAP_ENV=""
if [[ -n "$IAP_AUDIENCE" ]]; then
    IAP_ENV=",IAP_AUDIENCE=${IAP_AUDIENCE}"
fi
SA_FLAG=()
if [[ -n "$RUNTIME_SA" ]]; then
    SA_FLAG=(--service-account="$RUNTIME_SA")
fi
# Every service runs background work after it responds, so CPU must stay allocated.
# (${SA_FLAG[@]+...} keeps an empty array safe under set -u in bash 3.2.)
BASE_FLAGS=(--image="$IMAGE" --region="$REGION" --timeout=600 --no-cpu-throttling --cpu-boost
            --no-allow-unauthenticated ${SA_FLAG[@]+"${SA_FLAG[@]}"})

create_service() {
    local name="$1"
    shift
    if gc run services describe "$name" --region="$REGION" >/dev/null 2>&1; then
        echo "Service ${name} exists; release changes with scripts/release.sh."
        return
    fi
    echo "Creating ${name}..."
    gc run deploy "$name" "${BASE_FLAGS[@]}" "$@"
}

create_service codemender-webhook \
    --port=9080 --cpu=2 --memory=4Gi --concurrency=80 --min-instances=1 --max-instances=1 --ingress=all \
    --set-env-vars="${COMMON_ENV},DISABLE_UI=True,WEBHOOK_ONLY=true,WIF_AUTH_ENABLED=true,REQUIRE_INDEPENDENT_APPROVER=false,PARALLEL_SHARDING_THRESHOLD=4" \
    --set-secrets="GITHUB_TOKEN=GITHUB_TOKEN:latest,GITHUB_WEBHOOK_SECRET=GITHUB_WEBHOOK_SECRET:latest"

create_service codemender-backend \
    --port=9080 --cpu=2 --memory=4Gi --concurrency=1 --min-instances=1 --max-instances=1 --ingress=all \
    --set-env-vars="${COMMON_ENV},PARALLEL_SHARDING_THRESHOLD=4${IAP_ENV}" \
    --set-secrets="GITHUB_TOKEN=GITHUB_TOKEN:latest"

create_service codemender-dashboard \
    --port=9080 --cpu=1 --memory=2Gi --concurrency=80 --min-instances=0 --max-instances=10 \
    --ingress=internal-and-cloud-load-balancing \
    --set-env-vars="${COMMON_ENV}${IAP_ENV}" \
    --set-secrets="GITHUB_TOKEN=GITHUB_TOKEN:latest"

if [[ -z "$IAP_AUDIENCE" ]]; then
    echo "Note: no --iap-audience given; the dashboard has no verified identity until IAP_AUDIENCE is set."
fi
echo "Bootstrap complete. Next: scripts/release.sh status"
