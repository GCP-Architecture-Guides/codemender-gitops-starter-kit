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
# 🚀 CodeMender Automated Enterprise Deployment & Infrastructure Provisioner
# ==============================================================================
# This script provisions all GCP infrastructure, security policies, IAM roles,
# Workload Identity Federation (WIF), Firestore, BigQuery, Secret Manager,
# Cloud Storage, and deploys the CodeMender backend to Cloud Run.
#
# Usage:
#   ./deploy.sh [OPTIONS]
#   ./deploy.sh -p YOUR_PROJECT_ID -r us-central1 -g YOUR_ORG/YOUR_REPO -t YOUR_GITHUB_PAT
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

# Default settings
DEFAULT_REGION="us-central1"
DEFAULT_FIRESTORE_LOCATION="nam5"
SERVICE_NAME="codemender-backend"
WIF_POOL_NAME="github-pool"
WIF_PROVIDER_NAME="github-provider"
RUNNER_SA_NAME="codemender-runner"
TRIGGER_SA_NAME="codemender-trigger"

PROJECT_ID=""
REGION=""
REPO=""
GITHUB_TOKEN_INPUT=""
WEBHOOK_SECRET_INPUT=""
SKIP_BUILD=false
ALLOW_UNAUTH=false

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "=================================================================="
    echo "  🛡️  CodeMender Enterprise GitOps Platform: Automated Deployer   "
    echo "=================================================================="
    echo -e "${RESET}"
}

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --project <PROJECT_ID>        GCP Project ID"
    echo "  -r, --region <REGION>             GCP Region (Default: us-central1)"
    echo "  -g, --repo <OWNER/REPO>           Target GitHub Repository (e.g. org/app)"
    echo "  -t, --token <GITHUB_PAT>          GitHub Personal Access Token (PAT)"
    echo "  -s, --secret <WEBHOOK_SECRET>     GitHub Webhook HMAC Secret (Optional, generated if omitted)"
    echo "  --allow-unauth                    Allow unauthenticated ingress on Cloud Run (HMAC validation)"
    echo "  --skip-build                      Skip Cloud Run container deployment"
    echo "  -h, --help                        Show this help menu"
    echo ""
    exit 0
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -p|--project)
            PROJECT_ID="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -g|--repo)
            REPO="$2"
            shift 2
            ;;
        -t|--token)
            GITHUB_TOKEN_INPUT="$2"
            shift 2
            ;;
        -s|--secret)
            WEBHOOK_SECRET_INPUT="$2"
            shift 2
            ;;
        --allow-unauth)
            ALLOW_UNAUTH=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${RESET}"
            usage
            ;;
    esac
done

print_banner

# ------------------------------------------------------------------------------
# 1. Interactive Inputs & Validations
# ------------------------------------------------------------------------------
if [[ -z "$PROJECT_ID" ]]; then
    ACTIVE_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
    if [[ -n "$ACTIVE_PROJECT" ]]; then
        read -p "$(echo -e "${BOLD}Enter GCP Project ID [${CYAN}$ACTIVE_PROJECT${RESET}${BOLD}]: ${RESET}")" input_p
        PROJECT_ID="${input_p:-$ACTIVE_PROJECT}"
    else
        read -p "$(echo -e "${BOLD}Enter GCP Project ID: ${RESET}")" PROJECT_ID
    fi
fi

if [[ -z "$REGION" ]]; then
    read -p "$(echo -e "${BOLD}Enter GCP Region [${CYAN}$DEFAULT_REGION${RESET}${BOLD}]: ${RESET}")" input_r
    REGION="${input_r:-$DEFAULT_REGION}"
fi

if [[ -z "$REPO" ]]; then
    read -p "$(echo -e "${BOLD}Enter Target GitHub Repository (${CYAN}owner/repo${RESET}${BOLD}): ${RESET}")" REPO
fi

if [[ -z "$GITHUB_TOKEN_INPUT" ]]; then
    read -sp "$(echo -e "${BOLD}Enter GitHub Personal Access Token (PAT): ${RESET}")" GITHUB_TOKEN_INPUT
    echo ""
fi

# Basic validation
if [[ -z "$PROJECT_ID" ]]; then
    echo -e "${RED}❌ Error: GCP Project ID is required.${RESET}"
    exit 0
fi

if [[ -z "$REPO" ]] || [[ ! "$REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
    echo -e "${RED}❌ Error: Repository must be in 'owner/repo' format (e.g. acme-corp/sample-app).${RESET}"
    exit 0
fi

if [[ -z "$GITHUB_TOKEN_INPUT" ]]; then
    echo -e "${RED}❌ Error: GitHub Token is required.${RESET}"
    exit 0
fi

if [[ -z "$WEBHOOK_SECRET_INPUT" ]]; then
    # Generate 32-character secure random hex
    WEBHOOK_SECRET_INPUT=$(openssl rand -hex 20 2>/dev/null || head -c 20 /dev/urandom | xxd -p)
    echo -e "${YELLOW}🔑 Generated random GitHub Webhook Secret: ${CYAN}${WEBHOOK_SECRET_INPUT}${RESET}"
fi

ARTIFACT_BUCKET="${PROJECT_ID}-artifacts"
RUNNER_SA_EMAIL="${RUNNER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
TRIGGER_SA_EMAIL="${TRIGGER_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo ""
echo -e "${BLUE}${BOLD}📋 Deployment Summary Configuration:${RESET}"
echo -e "  • Project ID:         ${GREEN}${PROJECT_ID}${RESET}"
echo -e "  • Region:             ${GREEN}${REGION}${RESET}"
echo -e "  • Target Repository:  ${GREEN}${REPO}${RESET}"
echo -e "  • Artifact Bucket:    ${GREEN}gs://${ARTIFACT_BUCKET}${RESET}"
echo -e "  • Cloud Run Service:  ${GREEN}${SERVICE_NAME}${RESET}"
echo -e "  • WIF Pool:           ${GREEN}${WIF_POOL_NAME} / ${WIF_PROVIDER_NAME}${RESET}"
echo ""

# ------------------------------------------------------------------------------
# 2. Authenticate & Verify gcloud
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 1/8: Verifying Google Cloud Authentication...${RESET}"
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    echo -e "${RED}❌ Error: No active gcloud login detected. Please run 'gcloud auth login' and try again.${RESET}"
    exit 0
fi

gcloud config set project "$PROJECT_ID" --quiet >/dev/null
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
echo -e "  ✓ Project verified. Project Number: ${CYAN}${PROJECT_NUMBER}${RESET}"

# ------------------------------------------------------------------------------
# 3. Enable Required Google Cloud APIs
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 2/8: Enabling Required Google Cloud Services & APIs...${RESET}"
APIS=(
    "run.googleapis.com"
    "aiplatform.googleapis.com"
    "firestore.googleapis.com"
    "secretmanager.googleapis.com"
    "bigquery.googleapis.com"
    "storage.googleapis.com"
    "artifactregistry.googleapis.com"
    "cloudbuild.googleapis.com"
    "iam.googleapis.com"
    "iamcredentials.googleapis.com"
)

for API in "${APIS[@]}"; do
    echo -n "  → Enabling ${API}... "
    gcloud services enable "$API" --project="$PROJECT_ID" --quiet
    echo -e "${GREEN}done${RESET}"
done

# ------------------------------------------------------------------------------
# 4. Provision Storage Tier (Firestore & GCS)
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 3/8: Provisioning Cloud Firestore & Cloud Storage...${RESET}"

# Firestore Native database
if gcloud firestore databases list --project="$PROJECT_ID" --format="value(name)" 2>/dev/null | grep -q "default"; then
    echo -e "  ✓ Firestore (default) database already exists."
else
    echo -n "  ➕ Creating Firestore Native database... "
    gcloud firestore databases create \
        --project="$PROJECT_ID" \
        --location="$DEFAULT_FIRESTORE_LOCATION" \
        --type=firestore-native \
        --quiet
    echo -e "${GREEN}created${RESET}"
fi

# GCS Artifacts Bucket
if gcloud storage buckets describe "gs://${ARTIFACT_BUCKET}" --project="$PROJECT_ID" &>/dev/null; then
    echo -e "  ✓ Cloud Storage bucket 'gs://${ARTIFACT_BUCKET}' already exists."
else
    echo -n "  ➕ Creating Cloud Storage bucket 'gs://${ARTIFACT_BUCKET}'... "
    gcloud storage buckets create "gs://${ARTIFACT_BUCKET}" \
        --project="$PROJECT_ID" \
        --location="$REGION" \
        --uniform-bucket-level-access \
        --quiet
    echo -e "${GREEN}created${RESET}"
fi

# ------------------------------------------------------------------------------
# 5. Provision BigQuery Analytics Dataset & Tables
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 4/8: Provisioning BigQuery Telemetry Dataset & Tables...${RESET}"
if bq ls --project_id="$PROJECT_ID" "codemender_analytics" &>/dev/null; then
    echo -e "  ✓ BigQuery dataset 'codemender_analytics' already exists."
else
    echo -n "  ➕ Creating BigQuery dataset 'codemender_analytics'... "
    bq --location=US mk --dataset "${PROJECT_ID}:codemender_analytics" >/dev/null 2>&1 || true
    echo -e "${GREEN}created${RESET}"
fi

# ------------------------------------------------------------------------------
# 6. Configure Secret Manager Secrets
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 5/8: Storing Secrets in Secret Manager...${RESET}"

# Secret: GITHUB_TOKEN
if ! gcloud secrets describe GITHUB_TOKEN --project="$PROJECT_ID" &>/dev/null; then
    gcloud secrets create GITHUB_TOKEN --project="$PROJECT_ID" --replication-policy="automatic" --quiet
fi
echo -n "$GITHUB_TOKEN_INPUT" | gcloud secrets versions add GITHUB_TOKEN --project="$PROJECT_ID" --data-file=- --quiet
echo -e "  ✓ Secret ${CYAN}GITHUB_TOKEN${RESET} updated."

# Secret: GITHUB_WEBHOOK_SECRET
if ! gcloud secrets describe GITHUB_WEBHOOK_SECRET --project="$PROJECT_ID" &>/dev/null; then
    gcloud secrets create GITHUB_WEBHOOK_SECRET --project="$PROJECT_ID" --replication-policy="automatic" --quiet
fi
echo -n "$WEBHOOK_SECRET_INPUT" | gcloud secrets versions add GITHUB_WEBHOOK_SECRET --project="$PROJECT_ID" --data-file=- --quiet
echo -e "  ✓ Secret ${CYAN}GITHUB_WEBHOOK_SECRET${RESET} updated."

# ------------------------------------------------------------------------------
# 7. Provision Service Accounts & Workload Identity Federation (WIF)
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 6/8: Configuring Service Accounts, IAM & Workload Identity...${RESET}"

# A. Runner Service Account (Cloud Run Execution)
if ! gcloud iam service-accounts describe "$RUNNER_SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
    gcloud iam service-accounts create "$RUNNER_SA_NAME" \
        --project="$PROJECT_ID" \
        --display-name="CodeMender Engine Execution Service Account" \
        --quiet
fi

# Assign least-privilege roles to runner
RUNNER_ROLES=(
    "roles/aiplatform.user"
    "roles/datastore.user"
    "roles/secretmanager.secretAccessor"
    "roles/bigquery.dataEditor"
    "roles/bigquery.jobUser"
    "roles/storage.objectAdmin"
)
for ROLE in "${RUNNER_ROLES[@]}"; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${RUNNER_SA_EMAIL}" \
        --role="$ROLE" \
        --condition=None \
        --quiet >/dev/null
done
echo -e "  ✓ Configured IAM roles on ${CYAN}${RUNNER_SA_EMAIL}${RESET}"

# B. Trigger Service Account (WIF GitHub Trigger)
if ! gcloud iam service-accounts describe "$TRIGGER_SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
    gcloud iam service-accounts create "$TRIGGER_SA_NAME" \
        --project="$PROJECT_ID" \
        --display-name="CodeMender GitHub Trigger Service Account" \
        --quiet
fi

# C. Workload Identity Pool
if ! gcloud iam workload-identity-pools describe "$WIF_POOL_NAME" --location="global" --project="$PROJECT_ID" &>/dev/null; then
    gcloud iam workload-identity-pools create "$WIF_POOL_NAME" \
        --project="$PROJECT_ID" \
        --location="global" \
        --display-name="CodeMender GitHub Pool" \
        --quiet
fi

# D. Workload Identity Provider
if ! gcloud iam workload-identity-pools providers describe "$WIF_PROVIDER_NAME" \
    --workload-identity-pool="$WIF_POOL_NAME" \
    --location="global" \
    --project="$PROJECT_ID" &>/dev/null; then
    
    gcloud iam workload-identity-pools providers create-oidc "$WIF_PROVIDER_NAME" \
        --project="$PROJECT_ID" \
        --location="global" \
        --workload-identity-pool="$WIF_POOL_NAME" \
        --display-name="GitHub Actions Provider" \
        --issuer-uri="https://token.actions.githubusercontent.com" \
        --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
        --attribute-condition="assertion.repository == '${REPO}'" \
        --quiet
else
    # Update attribute condition for target repo
    gcloud iam workload-identity-pools providers update-oidc "$WIF_PROVIDER_NAME" \
        --project="$PROJECT_ID" \
        --location="global" \
        --workload-identity-pool="$WIF_POOL_NAME" \
        --attribute-condition="assertion.repository == '${REPO}'" \
        --quiet || true
fi

# E. Authorize GitHub repository to impersonate Trigger Service Account
WIF_PRINCIPAL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_NAME}/attribute.repository/${REPO}"

gcloud iam service-accounts add-iam-policy-binding "$TRIGGER_SA_EMAIL" \
    --project="$PROJECT_ID" \
    --role="roles/iam.workloadIdentityUser" \
    --member="$WIF_PRINCIPAL" \
    --quiet >/dev/null

gcloud iam service-accounts add-iam-policy-binding "$TRIGGER_SA_EMAIL" \
    --project="$PROJECT_ID" \
    --role="roles/iam.serviceAccountOpenIdTokenCreator" \
    --member="$WIF_PRINCIPAL" \
    --quiet >/dev/null

echo -e "  ✓ Configured Workload Identity Federation mapping for ${CYAN}${REPO}${RESET}"

# ------------------------------------------------------------------------------
# 8. Build & Deploy Cloud Run Service
# ------------------------------------------------------------------------------
if [[ "$SKIP_BUILD" == false ]]; then
    echo -e "${BOLD}Step 7/8: Deploying CodeMender Engine to Google Cloud Run...${RESET}"
    
    AUTH_FLAG="--no-allow-unauthenticated"
    if [[ "$ALLOW_UNAUTH" == true ]]; then
        AUTH_FLAG="--allow-unauthenticated"
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"

    gcloud run deploy "$SERVICE_NAME" \
        --source . \
        --project="$PROJECT_ID" \
        --region="$REGION" \
        --memory="4Gi" \
        --cpu="2" \
        --timeout="900" \
        --max-instances="50" \
        --service-account="$RUNNER_SA_EMAIL" \
        --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},GOOGLE_GENAI_USE_VERTEXAI=true,ARTIFACT_BUCKET=${ARTIFACT_BUCKET},GITHUB_REPOSITORY=${REPO},MOCK_MODE=false,PARALLEL_SHARDING_THRESHOLD=4" \
        --set-secrets="GITHUB_TOKEN=GITHUB_TOKEN:latest,GITHUB_WEBHOOK_SECRET=GITHUB_WEBHOOK_SECRET:latest" \
        --no-iap \
        $AUTH_FLAG \
        --quiet
        
    # Grant Cloud Run Invoker permission to Trigger Service Account
    gcloud run services add-iam-policy-binding "$SERVICE_NAME" \
        --project="$PROJECT_ID" \
        --region="$REGION" \
        --member="serviceAccount:${TRIGGER_SA_EMAIL}" \
        --role="roles/run.invoker" \
        --quiet >/dev/null

    echo -e "  ✓ Cloud Run service ${GREEN}${SERVICE_NAME}${RESET} deployed successfully."
else
    echo -e "  ⏩ Skipping Cloud Run build (--skip-build specified)."
fi

# Resolve Service URL
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --project="$PROJECT_ID" --region="$REGION" --format="value(status.url)" 2>/dev/null || echo "https://${SERVICE_NAME}-${PROJECT_NUMBER}.${REGION}.run.app")
WEBHOOK_URL="${SERVICE_URL}/github-webhook"
WIF_PROVIDER_RESOURCE="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_NAME}/providers/${WIF_PROVIDER_NAME}"

# ------------------------------------------------------------------------------
# 9. Generate GitHub Actions Workflow File
# ------------------------------------------------------------------------------
echo -e "${BOLD}Step 8/8: Generating GitHub Workflow & Integration Artifacts...${RESET}"

mkdir -p .github/workflows
cat << WORKFLOW_EOF > .github/workflows/codemender.yml
# CodeMender Autonomous Security Agent Workflow
# Generated automatically by deploy.sh for ${REPO}

name: CodeMender Agent Integration

on:
  pull_request:
    types: [opened, reopened, synchronize, ready_for_review]
  issue_comment:
    types: [created]

permissions:
  id-token: write
  contents: read

jobs:
  codemender-security-gate:
    if: >
      github.event_name == 'pull_request' ||
      (github.event_name == 'issue_comment' && github.event.issue.pull_request &&
       (startsWith(github.event.comment.body, '/verify') ||
        startsWith(github.event.comment.body, '/fix') ||
        startsWith(github.event.comment.body, '/approve') ||
        startsWith(github.event.comment.body, '/dismiss')))
    runs-on: ubuntu-latest
    steps:
      - name: Authenticate to Google Cloud (WIF)
        id: auth
        uses: google-github-actions/auth@v2
        with:
          token_format: 'id_token'
          workload_identity_provider: '${WIF_PROVIDER_RESOURCE}'
          service_account: '${TRIGGER_SA_EMAIL}'
          id_token_audience: '${SERVICE_URL}'
          id_token_include_email: true

      - name: Dispatch Scan / Slash Command to CodeMender
        run: |
          curl -sf -X POST "${WEBHOOK_URL}" \\
            -H "Authorization: Bearer \${{ steps.auth.outputs.id_token }}" \\
            -H "X-CodeMender-Auth: WIF" \\
            -H "Content-Type: application/json" \\
            -H "X-GitHub-Event: \${{ github.event_name }}" \\
            -d @\$GITHUB_EVENT_PATH
WORKFLOW_EOF

cat << ENV_EOF > deployment-config.env
PROJECT_ID=${PROJECT_ID}
REGION=${REGION}
PROJECT_NUMBER=${PROJECT_NUMBER}
REPO=${REPO}
SERVICE_URL=${SERVICE_URL}
WEBHOOK_URL=${WEBHOOK_URL}
WORKLOAD_IDENTITY_PROVIDER=${WIF_PROVIDER_RESOURCE}
TRIGGER_SERVICE_ACCOUNT=${TRIGGER_SA_EMAIL}
RUNNER_SERVICE_ACCOUNT=${RUNNER_SA_EMAIL}
WEBHOOK_SECRET=${WEBHOOK_SECRET_INPUT}
ENV_EOF

# ------------------------------------------------------------------------------
# 10. Success Banner & Instructions
# ------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}==================================================================${RESET}"
echo -e "${GREEN}${BOLD}🎉  CodeMender Platform Successfully Deployed & Provisioned!     ${RESET}"
echo -e "${GREEN}${BOLD}==================================================================${RESET}"
echo ""
echo -e "${BOLD}📍 Deployed Endpoints & Identities:${RESET}"
echo -e "  • Webhook Endpoint:        ${CYAN}${WEBHOOK_URL}${RESET}"
echo -e "  • Dashboard / API URL:     ${CYAN}${SERVICE_URL}${RESET}"
echo -e "  • Workload Identity Prov:  ${CYAN}${WIF_PROVIDER_RESOURCE}${RESET}"
echo -e "  • Trigger Service Account: ${CYAN}${TRIGGER_SA_EMAIL}${RESET}"
echo ""
echo -e "${BOLD}📋 Next Steps to Complete Onboarding for '${REPO}':${RESET}"
echo ""
echo -e "  ${BOLD}1. Commit the generated GitHub Workflow to your target repository:${RESET}"
echo -e "     Copy ${CYAN}.github/workflows/codemender.yml${RESET} into your target repo (${REPO}) and push to main."
echo ""
echo -e "  ${BOLD}2. (Optional) Configure Native Webhook Alternative:${RESET}"
echo -e "     If preferred over GitHub Actions WIF, add a Webhook in GitHub Settings -> Webhooks:"
echo -e "     Payload URL: ${CYAN}${WEBHOOK_URL}${RESET}"
echo -e "     Secret:      ${CYAN}${WEBHOOK_SECRET_INPUT}${RESET}"
echo -e "     Events:      Pull requests, Issue comments"
echo ""
echo -e "  ${BOLD}3. Configure GitHub Protected Branch Merge Gate:${RESET}"
echo -e "     In GitHub -> Settings -> Branches -> Add/Edit Branch Protection Rule ('main'):"
echo -e "     ✓ Enable 'Require status checks to pass before merging'"
echo -e "     ✓ Add status check: ${GREEN}security/codemender-gate${RESET}"
echo -e "     ✓ Check 'Do not allow bypassing the above settings'"
echo ""
echo -e "  ${BOLD}4. Test Vulnerability Remediation:${RESET}"
echo -e "     Copy a file from ${CYAN}samples/vulnerable_app.py${RESET} into a feature branch and open a PR!"
echo ""
