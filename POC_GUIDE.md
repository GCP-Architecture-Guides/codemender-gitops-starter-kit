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

# 🛡️ CodeMender Enterprise Proof-of-Concept (PoC) Guide

> ⚠️ **Disclaimer: This code is for PoC environment only. This demo code is not built for production workload.**

Welcome to the **CodeMender Proof-of-Concept (PoC) Validation Guide**. This document provides an actionable, step-by-step runbook for security leaders, DevSecOps teams, and AppSec engineers evaluating CodeMender’s autonomous vulnerability triage, dynamic exploit validation, and 1-click GitOps remediation capabilities.

---

## 🎯 PoC Goals & Evaluation Matrix

By the end of this PoC, you will validate:

| Capability | Evaluation Criteria | Success Metric |
| :--- | :--- | :--- |
| **1. Cumulative PR Scanning** | Scans entire multi-commit changesets without AST gaps. | 100% detection of critical vulnerabilities in PR diffs. |
| **2. Dynamic Exploit Verification** | Executes synthetic exploit scripts (`exploit.sh`) against mock servers. | Zero false positives; 100% confidence confirmation. |
| **3. Precision AST Remediation** | Generates secure patches directly in PR comments. | Clean syntax; parameterized queries; zero regressions. |
| **4. 1-Click GitOps Merge (`/approve`)** | Commits patch with `[skip ci]` and original author attribution. | PR converted to Ready for Review automatically. |
| **5. Merge Gate Enforcement** | Blocks PR merges on active Critical findings. | `security/codemender-gate` blocks merge until resolved. |
| **6. Multi-User Concurrency** | Handles multiple simultaneous PRs and `/verify all` commands. | Isolated workspaces; zero socket timeouts; zero token drops. |
| **7. Token Analytics & Billing** | Reconciles Vertex AI token usage and ROI in BigQuery. | Full visibility into input/output tokens and cost per PR. |

---

## 📋 Prerequisites & Environment Setup

Before starting the test scenarios, ensure you have:

1. **Google Cloud Project** with billing enabled and active permissions (`roles/owner` or `roles/editor` + `roles/securityAdmin`).
2. **`gcloud` CLI** configured:
   ```bash
   gcloud auth login
   gcloud auth application-default login
   gcloud config set project <YOUR_GCP_PROJECT_ID>
   ```
3. **GitHub Personal Access Token (Fine-Grained PAT)** with:
   - `Repository permissions -> Contents: Read & Write`
   - `Repository permissions -> Pull Requests: Read & Write`
   - `Repository permissions -> Commit Statuses: Read & Write`
   - `Repository permissions -> Issues: Read & Write`
4. **Target GitHub Test Repository** (e.g. `your-org/codemender-poc-test`).

---

## 🚀 Step 1: Deploy the CodeMender Backend

Deploy the complete serverless CodeMender platform to Google Cloud Run in one command:

```bash
cd codemender-starter-kit
./deploy.sh \
  --project "your-gcp-project-id" \
  --region "us-central1" \
  --repo "your-org/your-repo-name" \
  --token "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

The script automatically:
* Enables Vertex AI, Cloud Run, Firestore, BigQuery, Secret Manager, and WIF APIs.
* Provisions Firestore database, GCS artifact bucket, and BigQuery datasets.
* Sets up Workload Identity Federation (WIF) and Secret Manager secrets.
* Builds and deploys `codemender-backend` to Cloud Run.
* Generates `.github/workflows/codemender.yml`.

---

## 🔗 Step 2: Onboard Target Repository

### 1. Commit the GitHub Action Workflow
Copy the generated `.github/workflows/codemender.yml` into your target test repository:

```bash
mkdir -p .github/workflows
cp path/to/starter-kit/.github/workflows/codemender.yml .github/workflows/codemender.yml
git add .github/workflows/codemender.yml
git commit -m "ci: Add CodeMender security workflow"
git push origin main
```

### 2. Configure GitHub Protected Branch Merge Gate
1. On GitHub, navigate to **Settings $\rightarrow$ Branches**.
2. Click **Add branch protection rule** for `main`.
3. Check **Require status checks to pass before merging**.
4. Select **`security/codemender-gate`**.
5. Save Changes.

---

## 🧪 Step 3: PoC Test Scenarios

---

### Scenario 1: Automated AST Triage & PR Comment Generation

**Objective:** Verify that opening a Pull Request with a vulnerable file automatically triggers an AST scan, creates an in-place PR comment, and blocks the merge gate.

#### Execution Steps:
1. Create a feature branch:
   ```bash
   git checkout -b feature/auth-service
   ```
2. Copy the Python test fixture:
   ```bash
   cp samples/vulnerable_app.py app.py
   git add app.py
   git commit -m "feat: Add user authentication service"
   git push origin feature/auth-service
   ```
3. Open a **Draft Pull Request** on GitHub from `feature/auth-service` into `main`.

#### Expected Results:
* GitHub Action triggers the Cloud Run backend via WIF authentication.
* Commit status `security/codemender-gate` changes to `PENDING 🟡`.
* CodeMender posts a single **in-place sticky comment** (`<!-- codemender-security-report -->`):
  * Identifies **SQL Injection (CWE-89)** on `app.py`.
  * Identifies **Hard-Coded Secrets (CWE-798)**.
  * Displays finding table with severity badges and action buttons.
* Commit status changes to `FAILURE 🔴` (`Merge Blocked: 1 CRITICAL vulnerabilities detected`).

---

### Scenario 2: Dynamic Exploit Verification (`/verify`)

**Objective:** Validate that CodeMender dynamically synthesizes and executes a Proof-of-Concept exploit script (`exploit.sh`) inside an isolated sandbox to confirm real exploitability with 100% confidence.

#### Execution Steps:
1. On the PR timeline, reply with:
   ```
   /verify all
   ```
   *(Or `/verify <finding_id>` for a specific finding)*

#### Expected Results:
* The sticky PR comment updates to:
  ```
  ⏳ CodeMender Exploit Verification is in progress... (1m elapsed) — Verifying vulnerability exploitability (cm verify)
  ```
* CodeMender initializes a polyglot mock environment, runs `cm verify`, and synthesizes `exploit.sh`.
* Once completed, the sticky table updates the finding status to:
  👉 **`VERIFIED 🔴 (100% Confidence)`** with detailed reproduction logs.

---

### Scenario 3: 1-Click Remediation (`/fix` and `/approve`)

**Objective:** Verify that CodeMender synthesizes an AST-level remediation patch, stages the diff in the PR comment, and commits the fix directly upon reviewer approval.

#### Execution Steps:
1. On the PR timeline, reply with:
   ```
   /fix all
   ```
2. Inspect the proposed unified Git diff generated in the PR comment (e.g. replacing string formatting with parameterized SQLite queries `cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))`).
3. To approve and apply the remediation patch, reply with:
   ```
   /approve
   ```

#### Expected Results:
* CodeMender commits the remediation patch directly to `feature/auth-service` with `[skip ci]`:
  ```
  CodeMender: Fix vulnerability 7a23420a [skip ci]
  ```
* The commit is authored using the PR author's identity (avoiding CLA failures).
* The PR is automatically converted from **Draft** to **Ready for Review**.
* GitHub commit status `security/codemender-gate` clears to **`SUCCESS 🟢`**.
* The PR can now be merged cleanly!

---

### Scenario 4: Polyglot Vulnerability Coverage

**Objective:** Validate CodeMender's ability to analyze and patch multi-language codebases using the included sample fixtures.

| Language / Tech | Sample File | Vulnerability Target | Command to Test |
| :--- | :--- | :--- | :--- |
| **Python** | [`samples/vulnerable_app.py`](samples/vulnerable_app.py) | SQL Injection & Hardcoded Keys | `cp samples/vulnerable_app.py app.py` |
| **Node.js** | [`samples/vulnerable_node.js`](samples/vulnerable_node.js) | Command Injection (`exec`) & XSS | `cp samples/vulnerable_node.js server.js` |
| **Go** | [`samples/vulnerable_app.go`](samples/vulnerable_app.go) | Path Traversal / Arbitrary File Read | `cp samples/vulnerable_app.go main.go` |
| **Java / Spring** | [`samples/VulnerableController.java`](samples/VulnerableController.java) | SQL Concatenation in Controller | `cp samples/VulnerableController.java Controller.java` |
| **Terraform IaC** | [`samples/main.tf`](samples/main.tf) | Open S3 Bucket / Insecure Security Group | `cp samples/main.tf main.tf` |

---

### Scenario 5: Multi-User Concurrency & Parallel Stress Test

**Objective:** Validate that multiple developers submitting PRs simultaneously are handled safely with zero Git conflicts, isolated sandboxes, and zero token drops.

#### Execution Steps:
1. Open 3 separate feature branches and submit 3 Draft PRs concurrently (e.g. Auth PR, API PR, Admin PR).
2. Observe all 3 webhooks being processed concurrently by Cloud Run.
3. Observe each PR acquiring its own Firestore workspace lock (`workspace-{commit_sha}`) and cloning into isolated `/tmp/session-{sha}` runtimes.
4. Verify that sticky comments update in-place without review timeline spam.

---

### Scenario 6: BigQuery Telemetry & Cost ROI Auditing

**Objective:** Audit token consumption, LLM cache hit rates, and financial reconciliation in BigQuery.

#### Execution Steps:
1. Query BigQuery `token_usage_log`:
   ```sql
   SELECT 
     timestamp,
     session_id,
     task_type,
     model_name,
     input_tokens,
     cached_tokens,
     output_tokens,
     cost_usd,
     duration_sec
   FROM `your-gcp-project-id.codemender_analytics.token_usage_log`
   ORDER BY timestamp DESC
   LIMIT 10;
   ```
2. Query BigQuery `scan_log`:
   ```sql
   SELECT 
     timestamp,
     commit_sha,
     branch_name,
     status,
     findings_count,
     action_taken
   FROM `your-gcp-project-id.codemender_analytics.scan_log`
   ORDER BY timestamp DESC
   LIMIT 10;
   ```

#### Expected Results:
* Exact record of every agent invocation (`qa_agent`, `semantic_agent`, `cm_find`, `cm_verify`, `cm_fix`).
* Breakdown of Vertex AI Compute vs CodeMender Software License costs.
* Measurable ROI from Vertex AI Context Caching ($1.50/M input down to $0.15/M cached input).

---

## 📊 PoC Evaluation Scorecard

Use this scorecard to evaluate CodeMender against traditional SAST tools:

| Evaluation Dimension | Legacy SAST (SonarQube / Snyk) | CodeMender Autonomous GitOps | PoC Validation Status |
| :--- | :--- | :--- | :--- |
| **False Positive Rate** | High (20% – 45% noise) | **0% (Verified via dynamic `exploit.sh`)** | [ ] Pass |
| **Remediation Speed** | Days/weeks (Manual developer fix) | **< 2 minutes (Automated `/fix` & `/approve`)** | [ ] Pass |
| **Developer Friction** | Context switching to external UIs | **100% In-Place GitHub PR Comment UI** | [ ] Pass |
| **Merge Gate Enforcement** | Static pass/fail regex | **Dynamic AST + Proof-of-Exploit Gate** | [ ] Pass |
| **Cost Transparency** | Opaque per-seat licensing | **Granular BigQuery Token & SKU Telemetry** | [ ] Pass |

---

## ❓ Frequently Asked Questions (FAQ) & Troubleshooting

### Q: Why is `security/codemender-gate` stuck in PENDING?
* Check Cloud Run logs: `gcloud beta run services logs read codemender-backend --region us-central1`.
* Ensure your GitHub PAT has `Commit Statuses: Read & Write` permission.

### Q: Does CodeMender commit code without human review?
* **No.** CodeMender only generates patch proposals in PR comments. Code is only committed to the branch when a human reviewer explicitly replies with `/approve`.

### Q: How does CodeMender prevent recursive CI scan loops?
* CodeMender automatically appends `[skip ci]` to all automated commits. The webhook ingress immediately ignores any commits containing `[skip ci]` or pushed by the bot identity.

---

## 🤝 Next Steps & Production Rollout

Once you have completed the PoC scenarios:
1. Review the [Deployment Guide](DEPLOYMENT_GUIDE.md) for custom VPC and Private Service Connect (PSC) configurations.
2. Review the [Architecture & Operational Guide](../codemender_master_architecture_and_operational_guide.md) for enterprise multi-repository onboarding.
