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

Welcome to the **CodeMender Proof-of-Concept (PoC) Validation Guide**. This document provides an actionable, step-by-step runbook for security leaders, DevSecOps teams, and AppSec engineers evaluating CodeMender’s autonomous vulnerability triage, dynamic exploit validation, and 1-click GitOps remediation capabilities via both the **GitHub PR Workflow** and the new **CodeMender Web Dashboard**.

---

## 🎯 PoC Goals & Evaluation Matrix

By the end of this PoC, you will validate:

| Capability | Evaluation Criteria | Success Metric |
| :--- | :--- | :--- |
| **1. Cumulative PR Scanning** | Scans entire multi-commit changesets without AST gaps. | 100% detection of critical vulnerabilities in PR diffs. |
| **2. Dynamic Exploit Verification** | Executes synthetic exploit scripts (`exploit.sh`) against mock servers. | Zero false positives; 100% confidence confirmation via Sandbox. |
| **3. Precision AST Remediation** | Generates secure patches directly in PR comments & UI. | Clean syntax; parameterized queries; zero regressions. |
| **4. 1-Click GitOps Merge** | Commits patch with `[skip ci]` and original author attribution via UI or `/approve`. | PR converted to Ready for Review automatically. |
| **5. Merge Gate Enforcement** | Blocks PR merges on active Critical findings. | `security/codemender-gate` blocks merge until resolved. |
| **6. Interactive Pre-checks** | Pre-commit security scanning in the Browser Editor. | Shift-left security before branches are created. |
| **7. Token Analytics & FinOps** | Reconciles Vertex AI token usage and ROI in BigQuery. | Full UI visibility into tokens, context cache ROI, and cost per PR. |
| **8. Natural Language BI** | Querying telemetry via Gemini Enterprise Analytics Agent. | Accurate SQL translation & CISO executive summaries. |

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
4. **Target GitHub Test Repository** (e.g., `your-org/codemender-poc-test`).

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
* Builds and deploys `codemender-backend` and `codemender-dashboard` to Cloud Run.
* Generates `.github/workflows/codemender.yml`.

---

## 🔗 Step 2: Onboard Target Repository

### 1. Zero-Touch Workflow Push
`./deploy.sh` automatically commits and pushes `.github/workflows/codemender.yml` directly to your target repository's `main` branch. 

### 2. Configure GitHub Protected Branch Merge Gate
1. On GitHub, navigate to **Settings $\rightarrow$ Branches**.
2. Click **Add branch protection rule** for `main`.
3. Check **Require status checks to pass before merging**.
4. Select **`security/codemender-gate`**.
5. Save Changes.

---

## 🧪 Step 3: PoC Test Scenarios

---

### Scenario 1: Automated AST Triage & PR Merge Gate

**Objective:** Verify that opening a Pull Request with a vulnerable file automatically triggers an AST scan, creates an in-place PR comment, populates the CodeMender Dashboard, and blocks the merge gate.

#### Execution Steps:
1. Create a feature branch:
   ```bash
   git checkout -b feature/auth-service
   ```
2. Copy the Python test fixture (or use any language from the Polyglot section below):
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
* CodeMender Dashboard updates with the new PR in the **GitOps Pipeline Dashboard**.
* Commit status changes to `FAILURE 🔴` (`Merge Blocked: CRITICAL vulnerabilities detected`).

---

### Scenario 2: Dynamic Exploit Verification (Dashboard UI & GitHub)

**Objective:** Validate that CodeMender dynamically synthesizes and executes a Proof-of-Concept exploit script inside an isolated sandbox to confirm real exploitability.

#### Execution Steps:
1. Open the CodeMender Dashboard and navigate to the PR findings.
2. Click **Verify Exploit** on the finding (or reply with `/verify all` on the GitHub PR timeline).
3. Observe the sandbox execution logs streaming in real-time.

#### Expected Results:
* CodeMender provisions a polyglot sandbox container, installs dependencies, and runs the mock server.
* Synthesizes `exploit.sh` (e.g., executing a `curl` SQL injection payload).
* Confirms exploitability with the badge 👉 **`✓ Exploit Verified`** on the Dashboard and PR.

---

### Scenario 3: 1-Click Remediation & Human-in-the-Loop Approval

**Objective:** Verify that CodeMender synthesizes an AST-level remediation patch, stages the diff for review, and commits the fix directly upon approval.

#### Execution Steps:
1. In the CodeMender Dashboard, click **Generate Fix** on the verified finding (or reply with `/fix all` on GitHub).
2. CodeMender generates the secure patch and re-runs the PoC exploit to confirm the vulnerability is neutralized.
3. Review the proposed unified Git diff in the PR comment or the Dashboard's **Inspect Diff** viewer.
4. To apply the patch, use the Dashboard UI governance modal and click **Approve** (or reply `/approve` on GitHub).

#### Expected Results:
* CodeMender commits the patch directly to `feature/auth-service` with `[skip ci]`.
* The commit is authored using the PR author's identity.
* `security/codemender-gate` clears to **`SUCCESS 🟢`**.
* The PR can now be merged cleanly!

---

### Scenario 4: Interactive Sandbox Pre-checks (Shift-Left)

**Objective:** Validate the in-browser sandbox for pre-commit vulnerability detection and patching.

#### Execution Steps:
1. Click **Interactive Sandbox** in the top navigation bar of the Dashboard.
2. Paste vulnerable code from `samples/vulnerable_node.js` into the left editor pane.
3. Enter intent: *"Run shell command securely."*
4. Click **Submit for Review**.
5. Once CodeMender proposes a patch, click **Accept & Apply Patch** in the HITL Approval Modal.

#### Expected Results:
* Security & Hygiene report flags Command Injection.
* Code editor updates live with the applied patch.

---

### Scenario 5: Polyglot Vulnerability Coverage

**Objective:** Validate CodeMender's ability to analyze and patch multi-language codebases.

| Language / Tech | Sample File | Vulnerability Target | Command to Test |
| :--- | :--- | :--- | :--- |
| **Python** | [`samples/vulnerable_app.py`](samples/vulnerable_app.py) | SQL Injection & Hardcoded Keys | `cp samples/vulnerable_app.py app.py` |
| **Node.js** | [`samples/vulnerable_node.js`](samples/vulnerable_node.js) | Command Injection (`exec`) & XSS | `cp samples/vulnerable_node.js server.js` |
| **Go** | [`samples/vulnerable_app.go`](samples/vulnerable_app.go) | Path Traversal / Arbitrary File Read | `cp samples/vulnerable_app.go main.go` |
| **Java / Spring** | [`samples/VulnerableController.java`](samples/VulnerableController.java) | SQL Concatenation in Controller | `cp samples/VulnerableController.java Controller.java` |
| **Terraform IaC** | [`samples/main.tf`](samples/main.tf) | Open S3 Bucket / Insecure Security Group | `cp samples/main.tf main.tf` |

---

### Scenario 6: Multi-Commit PR Progression & Duplicate Disambiguation

**Objective:** Demonstrate how CodeMender tracks vulnerability lifecycles across multi-commit PRs, eliminating false "new" finding alerts when lines shift.

#### Execution Steps:
1. Push an initial commit with multiple findings. CodeMender detects SQLi on line 45 and Command Injection on line 78.
2. Fix the SQLi manually, and insert 25 lines of code above the Command Injection endpoint (shifting it to line 103).
3. Commit and push the updates.

#### Expected Results:
* CodeMender marks the SQL Injection as `✅ RESOLVED`.
* Recognizes the Command Injection on line 103 as `⚠️ PERSISTENT` (pointing to `app.py:103 (was :78)`) using its deterministic AST fingerprint without treating it as a new bug.

---

### Scenario 7: BigQuery Telemetry, Cost ROI & GE Analytics Agent

**Objective:** Audit token consumption, LLM cache hit rates, and interact with the natural-language Gemini Enterprise BigQuery Agent.

#### Execution Steps:
1. In the Dashboard, click the **Token Usage & Costs** tab.
2. Review the **4 Executive Scorecards**: Total Cost, Vertex AI Compute, CM License, and Context Cache Savings.
3. Open **Gemini Enterprise** and invoke the **CodeMender BigQuery Analytics Agent**.
4. Ask a natural-language question:
   > *"What is our total AI token spend in USD so far, and what is the total and average cost broken down by task_type (triage scan vs. exploit verification vs. patch generation)?"*

#### Expected Results:
* Exact record of every agent invocation reconciled 1:1 against Google Cloud Billing SKUs.
* Measurable ROI from Vertex AI Context Caching ($1.50/M input down to $0.15/M cached input).
* The GE Analytics agent successfully translates natural language into BigQuery SQL, returning a summary table of operations and costs.

---

## 📊 PoC Evaluation Scorecard

Use this scorecard to evaluate CodeMender against traditional SAST tools:

| Evaluation Dimension | Legacy SAST (SonarQube / Snyk) | CodeMender Autonomous GitOps | PoC Validation Status |
| :--- | :--- | :--- | :--- |
| **False Positive Rate** | High (20% – 45% noise) | **0% (Verified via dynamic `exploit.sh`)** | [ ] Pass |
| **Remediation Speed** | Days/weeks (Manual developer fix) | **< 2 minutes (Automated via UI / `/approve`)** | [ ] Pass |
| **Developer Friction** | Context switching to external UIs | **100% In-Place GitHub PR Comment UI & Unified Dashboard** | [ ] Pass |
| **Merge Gate Enforcement** | Static pass/fail regex | **Dynamic AST + Proof-of-Exploit Gate** | [ ] Pass |
| **Cost Transparency** | Opaque per-seat licensing | **Granular BigQuery Token & SKU Telemetry via UI & AI Agent** | [ ] Pass |

---

## ❓ Frequently Asked Questions (FAQ) & Troubleshooting

### Q: Why is `security/codemender-gate` stuck in PENDING?
* Check Cloud Run logs for the backend service.
* Ensure your GitHub PAT has `Commit Statuses: Read & Write` permission.

### Q: Does CodeMender commit code without human review?
* **No.** CodeMender only generates patch proposals in PR comments and the Dashboard. Code is only committed to the branch when a human reviewer explicitly clicks **Approve** in the UI or replies with `/approve`.

### Q: How does CodeMender prevent recursive CI scan loops?
* CodeMender automatically appends `[skip ci]` to all automated commits. The webhook ingress immediately ignores any commits containing `[skip ci]` or pushed by the bot identity.

---

## 🤝 Next Steps & Production Rollout

Once you have completed the PoC scenarios:
1. Review the **Deployment Guide** for custom VPC and Private Service Connect (PSC) configurations.
2. Review the **Architecture & Operational Guide** for enterprise multi-repository onboarding.
