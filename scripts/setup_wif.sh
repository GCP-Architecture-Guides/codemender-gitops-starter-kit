#!/bin/bash
# Copyright 2026 Google LLC
# Idempotent script to set up Workload Identity Federation (WIF) for GitHub Actions on GCP.

set -euo pipefail

# Usage: ./scripts/setup_wif.sh [PROJECT_ID] [REPO] [REGION]
#   APPLY_CONDITION=true ./scripts/setup_wif.sh ...   also tightens an existing provider's condition
#   WIF_CONDITION=repo|strict (default strict): 'repo' admits only this repository; 'strict' also
#   pins main's relay workflow (apply 'strict' only once the pull_request_target relay is on main).
PROJECT_ID="${1:-${GOOGLE_CLOUD_PROJECT:-your-gcp-project-id}}"
REPO="${2:-your-org/your-repo}"
REGION="${3:-us-central1}"
POOL_NAME="github-pool"
PROVIDER_NAME="github-provider"
SA_NAME="codemender-trigger"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# This project's gcloud configuration, for this process only (never changes global gcloud state).
export CLOUDSDK_ACTIVE_CONFIG_NAME="${CLOUDSDK_ACTIVE_CONFIG_NAME:-codemender-gitops}"

# Plan 1.5: only main's copy of the relay workflow in this repository can mint tokens. The relay
# uses pull_request_target and issue_comment, which both run the workflow from refs/heads/main.
# Apply this to an existing provider only after the pull_request_target workflow is on main;
# before that, PR events run from refs/pull/N/merge and would be refused.
WORKFLOW_REF="${REPO}/.github/workflows/codemender-wif.yml@refs/heads/main"
case "${WIF_CONDITION:-strict}" in
    repo) EXPECTED_CONDITION="assertion.repository == '${REPO}'" ;;
    strict) EXPECTED_CONDITION="assertion.repository == '${REPO}' && assertion.job_workflow_ref == '${WORKFLOW_REF}'" ;;
    *) echo "WIF_CONDITION must be 'repo' or 'strict'" >&2; exit 2 ;;
esac

echo "=== CodeMender WIF Automation Setup ==="
echo "Project ID: ${PROJECT_ID}"
echo "Region:     ${REGION}"
echo "Repository: ${REPO}"
echo "======================================="

# 1. Fetch GCP Project Number dynamically
echo "🔍 Fetching project number..."
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format="value(projectNumber)")
echo "Project Number resolved: ${PROJECT_NUMBER}"

# 2. Create Workload Identity Pool if it doesn't exist
echo "🛠️ Configuring Workload Identity Pool..."
if gcloud iam workload-identity-pools describe "${POOL_NAME}" --location="global" --project="${PROJECT_ID}" &>/dev/null; then
    echo "✓ Workload Identity Pool '${POOL_NAME}' already exists."
else
    gcloud iam workload-identity-pools create "${POOL_NAME}" \
        --project="${PROJECT_ID}" \
        --location="global" \
        --display-name="GitHub Actions Pool"
    echo "✓ Successfully created Workload Identity Pool."
fi

# 3. Create OIDC Provider if it doesn't exist
echo "🛠️ Configuring Workload Identity Provider..."
if gcloud iam workload-identity-pools providers describe "${PROVIDER_NAME}" \
    --workload-identity-pool="${POOL_NAME}" \
    --location="global" \
    --project="${PROJECT_ID}" &>/dev/null; then
    echo "✓ Workload Identity Provider '${PROVIDER_NAME}' already exists."
    CURRENT_CONDITION=$(gcloud iam workload-identity-pools providers describe "${PROVIDER_NAME}" \
        --workload-identity-pool="${POOL_NAME}" --location="global" --project="${PROJECT_ID}" \
        --format="value(attributeCondition)")
    if [[ "${CURRENT_CONDITION}" == "${EXPECTED_CONDITION}" ]]; then
        echo "✓ Provider condition is already: ${EXPECTED_CONDITION}"
    elif [[ "${APPLY_CONDITION:-false}" == "true" ]]; then
        gcloud iam workload-identity-pools providers update-oidc "${PROVIDER_NAME}" \
            --project="${PROJECT_ID}" \
            --location="global" \
            --workload-identity-pool="${POOL_NAME}" \
            --attribute-condition="${EXPECTED_CONDITION}"
        echo "✓ Provider condition updated."
    else
        echo "⚠️  Provider condition is broader than expected:"
        echo "    current:  ${CURRENT_CONDITION}"
        echo "    expected: ${EXPECTED_CONDITION}"
        echo "    Re-run with APPLY_CONDITION=true (WIF_CONDITION=strict only once the pull_request_target relay is on main)."
    fi
else
    gcloud iam workload-identity-pools providers create-oidc "${PROVIDER_NAME}" \
        --project="${PROJECT_ID}" \
        --location="global" \
        --workload-identity-pool="${POOL_NAME}" \
        --display-name="GitHub Provider" \
        --issuer-uri="https://token.actions.githubusercontent.com" \
        --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
        --attribute-condition="${EXPECTED_CONDITION}"
    echo "✓ Successfully created Workload Identity Provider."
fi

# 4. Create Service Account if it doesn't exist
echo "🛠️ Configuring Service Account..."
if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" &>/dev/null; then
    echo "✓ Service Account '${SA_EMAIL}' already exists."
else
    gcloud iam service-accounts create "${SA_NAME}" \
        --project="${PROJECT_ID}" \
        --display-name="CodeMender GitHub Trigger Service Account"
    echo "✓ Successfully created Service Account."
fi

# 5. Grant run.invoker permissions on codemender-webhook service
echo "🔐 Granting Cloud Run invoker role to Service Account..."
gcloud run services add-iam-policy-binding codemender-webhook \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/run.invoker" \
    --quiet
echo "✓ Granted run.invoker binding."

# 6. Authorize GitHub repository to impersonate Service Account via Workload Identity Pool
echo "🔐 Granting Workload Identity impersonation bindings..."
gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_NAME}/attribute.repository/${REPO}" \
    --quiet

gcloud iam service-accounts add-iam-policy-binding "${SA_EMAIL}" \
    --project="${PROJECT_ID}" \
    --role="roles/iam.serviceAccountOpenIdTokenCreator" \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_NAME}/attribute.repository/${REPO}" \
    --quiet
echo "✓ Impersonation binding configured successfully."

echo "======================================="
echo "🎉 WIF Configuration Complete!"
echo "Use the following details in your GitHub Workflow:"
echo "  Workload Identity Provider: projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_NAME}/providers/${PROVIDER_NAME}"
echo "  Service Account:             ${SA_EMAIL}"
echo "======================================="
