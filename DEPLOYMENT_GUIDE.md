<!--
Copyright 2023 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This code is for PoC environment only.
This demo code is not built for production workload.
-->

# 📖 CodeMender Enterprise Deployment & Operational Guide

> ⚠️ **Disclaimer: This code is for PoC environment only. This demo code is not built for production workload.**

This document provides a technical reference for deploying, configuring, and maintaining the **CodeMender Enterprise GitOps Platform** on Google Cloud Platform (GCP) and GitHub.

---

## 🏗️ 1. Architecture & Security Model

CodeMender uses a **Zero-Permanent-Key Security Architecture**:
* **No stored cloud keys in GitHub:** Workload Identity Federation (WIF) exchanges short-lived OIDC tokens directly with GCP IAM.
* **Least-Privilege GitHub PAT:** The GitHub Fine-Grained Personal Access Token (PAT) is stored exclusively in **GCP Secret Manager** and accessed only inside ephemeral Cloud Run memory.
* **Stateless Ephemeral Run-Times:** Polyglot build and exploit execution happens inside sandboxed `/tmp/session-{commit_sha}` workspaces with Firestore distributed locking.

---

## 🛠️ 2. Step-by-Step Manual Provisioning

If you prefer to execute the provisioning steps manually instead of using `./deploy.sh`:

### Step 2.1: Enable GCP API Services
```bash
gcloud services enable \
  run.googleapis.com \
  aiplatform.googleapis.com \
  firestore.googleapis.com \
  secretmanager.googleapis.com \
  bigquery.googleapis.com \
  storage.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  --project="YOUR_PROJECT_ID"
```

---

### Step 2.2: Provision Firestore Database
```bash
gcloud firestore databases create \
  --project="YOUR_PROJECT_ID" \
  --location="nam5" \
  --type=firestore-native
```

---

### Step 2.3: Provision Cloud Storage Bucket
```bash
gcloud storage buckets create "gs://YOUR_PROJECT_ID-artifacts" \
  --project="YOUR_PROJECT_ID" \
  --location="us-central1" \
  --uniform-bucket-level-access
```

---

### Step 2.4: Provision BigQuery Dataset & Tables
```bash
bq --location=US mk --dataset "YOUR_PROJECT_ID:codemender_analytics"
```

---

### Step 2.5: Configure Secret Manager
```bash
# Store GitHub PAT
echo -n "YOUR_GITHUB_PAT" | gcloud secrets create GITHUB_TOKEN \
  --project="YOUR_PROJECT_ID" \
  --replication-policy="automatic" \
  --data-file=-

# Store Webhook Secret
echo -n "YOUR_WEBHOOK_SECRET" | gcloud secrets create GITHUB_WEBHOOK_SECRET \
  --project="YOUR_PROJECT_ID" \
  --replication-policy="automatic" \
  --data-file=-
```

---

### Step 2.6: Create Service Accounts & IAM Policies

```bash
# 1. Runner Service Account (Cloud Run Execution)
gcloud iam service-accounts create codemender-runner \
  --project="YOUR_PROJECT_ID" \
  --display-name="CodeMender Engine Runner"

RUNNER_SA="codemender-runner@YOUR_PROJECT_ID.iam.gserviceaccount.com"

# Grant required least-privilege roles
for ROLE in "roles/aiplatform.user" "roles/datastore.user" "roles/secretmanager.secretAccessor" "roles/bigquery.dataEditor" "roles/bigquery.jobUser" "roles/storage.objectAdmin"; do
  gcloud projects add-iam-policy-binding "YOUR_PROJECT_ID" \
    --member="serviceAccount:${RUNNER_SA}" \
    --role="$ROLE"
done

# 2. Trigger Service Account (WIF GitHub Trigger)
gcloud iam service-accounts create codemender-trigger \
  --project="YOUR_PROJECT_ID" \
  --display-name="CodeMender GitHub Trigger"

TRIGGER_SA="codemender-trigger@YOUR_PROJECT_ID.iam.gserviceaccount.com"
```

---

### Step 2.7: Configure Workload Identity Federation (WIF)

```bash
PROJECT_NUMBER=$(gcloud projects describe "YOUR_PROJECT_ID" --format="value(projectNumber)")

# 1. Create Pool
gcloud iam workload-identity-pools create github-pool \
  --project="YOUR_PROJECT_ID" \
  --location="global" \
  --display-name="GitHub Actions Pool"

# 2. Create Provider
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --project="YOUR_PROJECT_ID" \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --display-name="GitHub Provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository == 'YOUR_ORG/YOUR_REPO'"

# 3. Grant Impersonation Permissions
WIF_PRINCIPAL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-pool/attribute.repository/YOUR_ORG/YOUR_REPO"

gcloud iam service-accounts add-iam-policy-binding "${TRIGGER_SA}" \
  --project="YOUR_PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="${WIF_PRINCIPAL}"

gcloud iam service-accounts add-iam-policy-binding "${TRIGGER_SA}" \
  --project="YOUR_PROJECT_ID" \
  --role="roles/iam.serviceAccountOpenIdTokenCreator" \
  --member="${WIF_PRINCIPAL}"
```

---

### Step 2.8: Build & Deploy Container to Cloud Run

```bash
gcloud run deploy codemender-backend \
  --source . \
  --project="YOUR_PROJECT_ID" \
  --region="us-central1" \
  --memory="4Gi" \
  --cpu="2" \
  --timeout="900" \
  --max-instances="50" \
  --service-account="codemender-runner@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID,GOOGLE_CLOUD_LOCATION=us-central1,GOOGLE_GENAI_USE_VERTEXAI=true,ARTIFACT_BUCKET=YOUR_PROJECT_ID-artifacts,GITHUB_REPOSITORY=YOUR_ORG/YOUR_REPO,MOCK_MODE=false,PARALLEL_SHARDING_THRESHOLD=4" \
  --set-secrets="GITHUB_TOKEN=GITHUB_TOKEN:latest,GITHUB_WEBHOOK_SECRET=GITHUB_WEBHOOK_SECRET:latest" \
  --no-allow-unauthenticated

# Grant Invoker role to Trigger Service Account
gcloud run services add-iam-policy-binding codemender-backend \
  --project="YOUR_PROJECT_ID" \
  --region="us-central1" \
  --member="serviceAccount:codemender-trigger@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

---

## 🔍 3. Verification & Troubleshooting

### Check Service Health
```bash
curl -I https://YOUR_SERVICE_URL/healthz
```

### View Live Execution Logs
```bash
gcloud beta run services logs tail codemender-backend --project="YOUR_PROJECT_ID" --region="us-central1"
```

### Verify BigQuery Token Streaming
```bash
bq query --nouse_legacy_sql \
  "SELECT timestamp, task_type, model_name, total_tokens, cost_usd FROM \`YOUR_PROJECT_ID.codemender_analytics.token_usage_log\` ORDER BY timestamp DESC LIMIT 5"
```
