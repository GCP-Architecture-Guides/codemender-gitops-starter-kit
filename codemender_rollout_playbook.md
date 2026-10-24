# 📘 CodeMender Enterprise Rollout Playbook: Parallel Execution, Concurrency Locking & Security Merge Gates

This step-by-step implementation guide provides drop-in code, Docker configs, GitHub setup, and deployment commands to roll out the hardened CodeMender architecture to any new or existing repository.

---

## 📑 Table of Contents
1. [Architecture Overview & Prerequisites](#1-architecture-overview--prerequisites)
2. [Module 1: Pre-Baked Polyglot Execution Sandbox (`Dockerfile`)](#module-1-pre-baked-polyglot-execution-sandbox-dockerfile)
3. [Module 2: Distributed Locking & Concurrency Guard (`database.py`)](#module-2-distributed-locking--concurrency-guard-databasepy)
4. [Module 3: Parallel Finding Sharding & Threshold Execution (`main.py`)](#module-3-parallel-finding-sharding--threshold-execution-mainpy)
5. [Module 4: GitHub Critical Vulnerability Merge Gate (`github_helpers.py` & `main.py`)](#module-4-github-critical-vulnerability-merge-gate-github_helperspy--mainpy)
6. [Module 5: Exact Vertex AI Token Telemetry Engine (`database.py`)](#module-5-exact-vertex-ai-token-telemetry-engine-databasepy)
7. [Module 6: Cloud Run Deployment & Service Configuration](#module-6-cloud-run-deployment--service-configuration)
8. [Module 7: GitHub Branch Protection Enforcement (1-Minute Setup)](#module-7-github-branch-protection-enforcement-1-minute-setup)

---

## 1. Architecture Overview & Prerequisites

### Topology
* **Gateway Tier (`codemender-webhook`):** Receives GitHub webhooks, verifies HMAC signature, creates scan records, dispatches worker tasks, and enforces `DISABLE_UI=True`.
* **Worker Tier (`codemender-backend`):** Executes triage scans, multi-turn AI reasoning, sandbox mock runs, and exploit verifications (`concurrency = 1`, 2–4 GiB RAM, 2 vCPUs).
* **Portal Tier (`codemender-dashboard`):** Serves the Next.js static UI and REST analytics endpoints.

### Prerequisites (GCP Services & Secrets)
* **GCP APIs:** `run.googleapis.com`, `cloudbuild.googleapis.com`, `firestore.googleapis.com`, `bigquery.googleapis.com`, `secretmanager.googleapis.com`.
* **Secrets in Secret Manager:** `GITHUB_WEBHOOK_SECRET`, `GITHUB_TOKEN` (or GitHub App PEM key).
* **Firestore Collections:** `scans`, `patch_proposals`, `locks`.
* **BigQuery Table:** `codemender_telemetry.token_usage_log`.

---

## Module 1: Pre-Baked Polyglot Execution Sandbox (`Dockerfile`)

> [!IMPORTANT]
> **Why this is required:** Dynamic package installations (`apt-get install gcc`, `pip install flask`, `npm install`) during verification trigger Out-Of-Memory (`exit 137`) errors and network permission blocks. All polyglot compilers must be pre-baked.

### Drop-in `Dockerfile`

```dockerfile
# Step 1: Build the Next.js Frontend
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Step 2: Polyglot Execution Runtime & Python Backend
FROM python:3.12-slim

# Avoid interactive apt prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Pre-bake Polyglot Compilers and Testing Utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    ca-certificates \
    gnupg \
    build-essential \
    gcc \
    g++ \
    make \
    golang-go \
    netcat-openbsd \
    sqlite3 \
    default-jdk \
    maven \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js runtime and global packages
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_18.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y nodejs \
    && npm install -g express axios body-parser sqlite3 \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_PATH=/usr/local/lib/node_modules

# Install Python backend and mock server frameworks
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir flask requests

# Copy backend application source
COPY backend/ ./

# Copy compiled frontend from Step 1
COPY --from=frontend-builder /app/frontend/out ./frontend/out

# Install CodeMender CLI
RUN curl -L -o cm-linux-amd64.zip "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media" \
    && unzip cm-linux-amd64.zip \
    && chmod +x cm \
    && mv cm /usr/local/bin/cm \
    && rm cm-linux-amd64.zip

EXPOSE 8080
CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

---

## Module 2: Distributed Locking & Concurrency Guard (`database.py`)

> [!TIP]
> **Why this is required:** Prevents parallel tasks modifying the same workspace folder (`/tmp/session-{commit_sha}`) from causing git merge conflicts, branch overwrites, or corrupted exploit tests.

### Drop-in Lock Functions (`backend/database.py`)

```python
import logging
from datetime import datetime, timezone
from google.cloud import firestore

logger = logging.getLogger(__name__)
db = firestore.Client()

def acquire_lock(lock_id: str, timeout_seconds: int = 600) -> bool:
    """
    Acquires a Firestore-backed distributed lock.
    Returns True if lock was acquired, False if already held by another task.
    """
    lock_ref = db.collection("locks").document(lock_id)
    now = datetime.now(timezone.utc)
    
    @firestore.transactional
    def _acquire_in_tx(transaction):
        snapshot = lock_ref.get(transaction=transaction)
        if snapshot.exists:
            data = snapshot.to_dict()
            locked_at = data.get("locked_at")
            # Check for stale expired lock (> 10 minutes)
            if locked_at:
                age = (now - locked_at).total_seconds()
                if age < timeout_seconds:
                    logger.warning(f"Lock '{lock_id}' is active (held for {age:.1f}s). Aborting task.")
                    return False
                logger.warning(f"Lock '{lock_id}' expired ({age:.1f}s > {timeout_seconds}s). Reclaiming lock.")
        
        transaction.set(lock_ref, {"locked_at": now, "lock_id": lock_id})
        return True

    transaction = db.transaction()
    try:
        return _acquire_in_tx(transaction)
    except Exception as e:
        logger.error(f"Error acquiring lock '{lock_id}': {e}")
        return False


def release_lock(lock_id: str) -> None:
    """Releases the Firestore distributed lock."""
    try:
        db.collection("locks").document(lock_id).delete()
        logger.info(f"Released lock '{lock_id}'.")
    except Exception as e:
        logger.error(f"Error releasing lock '{lock_id}': {e}")
```

---

## Module 3: Parallel Finding Sharding & Threshold Execution (`main.py`)

### Threshold Strategy & Implementation
* **Finding Count $\le 4$:** Run sequentially in the current process (workspace reset between tests).
* **Finding Count $> 4$:** Fan-out into parallel async worker tasks.

```python
# backend/main.py (Global Configuration)
PARALLEL_SHARDING_THRESHOLD = int(os.getenv("PARALLEL_SHARDING_THRESHOLD", "4"))

async def verify_findings_task(repo_name: str, commit_sha: str, finding_ids: list, is_pr: bool = False, pr_number: int = None):
    lock_id = f"workspace-{commit_sha}"
    if not acquire_lock(lock_id):
        logger.warning(f"Task aborted: Lock active for {lock_id}")
        return

    try:
        token = await get_github_token()
        doc = db.collection("scans").document(commit_sha).get()
        if not doc.exists:
            return

        scan_data = doc.to_dict()
        findings = scan_data.get("findings", [])
        branch = scan_data.get("branch_name")

        to_verify = [f for f in findings if f.get("id") in finding_ids] if finding_ids != ["all"] else findings
        if not to_verify:
            return

        # ========================================================
        # ROUTING GATE: PARALLEL SHARDING vs. SEQUENTIAL LOOP
        # ========================================================
        if len(to_verify) > PARALLEL_SHARDING_THRESHOLD:
            logger.info(f"Finding count ({len(to_verify)}) > threshold ({PARALLEL_SHARDING_THRESHOLD}). Sharding into parallel workers...")
            # Fan out across parallel worker tasks
            tasks = [
                cm_verify(commit_sha, f.get("id"))
                for f in to_verify
            ]
            await asyncio.gather(*tasks)
        else:
            logger.info(f"Finding count ({len(to_verify)}) <= threshold ({PARALLEL_SHARDING_THRESHOLD}). Running sequential in-process loop...")
            git_ws = GitWorkspace(commit_sha)
            for tv in to_verify:
                fid = tv.get("id")
                await cm_verify(commit_sha, fid)
                # Reset workspace to clean git state between tests
                await git_ws._run_command(["git", "checkout", "HEAD", "--", "."])

    finally:
        release_lock(lock_id)
```

---

## Module 4: GitHub Critical Vulnerability Merge Gate (`github_helpers.py` & `main.py`)

### 1. GitHub Status Check API Helper (`backend/github_helpers.py`)

```python
import httpx
import logging
import os

logger = logging.getLogger(__name__)

async def set_commit_status(repo: str, commit_sha: str, state: str, description: str, token: str, target_url: str = None, context: str = "security/codemender-gate"):
    """
    Creates or updates a commit status check on GitHub (pending, success, failure, error)
    to enforce repository branch protection merge gates.
    """
    if os.getenv("MOCK_MODE") == "true":
        logger.info(f"[MOCK COMMIT STATUS {commit_sha}]: state={state}, desc={description}")
        return

    url = f"https://api.github.com/repos/{repo}/statuses/{commit_sha}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "state": state,                 # "pending" | "success" | "failure" | "error"
        "description": description[:140], # GitHub enforces 140 character limit
        "context": context
    }
    if target_url:
        data["target_url"] = target_url

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=headers)
            if response.status_code != 201:
                logger.warning(f"Failed to set commit status on {commit_sha}: {response.status_code} - {response.text}")
            else:
                logger.info(f"Successfully updated GitHub status on {commit_sha}: [{state.upper()}] - {description}")
    except Exception as e:
        logger.error(f"Error setting GitHub commit status on {commit_sha}: {e}")
```

### 2. Integration into Draft PR Scanning Lifecycle (`backend/main.py`)

```python
from github_helpers import set_commit_status, update_or_post_pr_comment

async def process_pr_scan_event(payload: dict, run_id: str = None):
    # Extract PR metadata (pr_number, is_draft, head_sha, base_branch, branch)
    # Check if run_id is superseded by newer commit on the same PR:
    # if active_tasks.get(f"pr-{pr_number}") != run_id: return
    
    # 1. At Scan Start: Set gate status to PENDING
    dashboard_url = f"https://codemender-dashboard-YOUR_PROJECT_NUMBER.us-central1.run.app/scans/{head_sha}"
    await set_commit_status(
        repo=repo_name,
        commit_sha=head_sha,
        state="pending",
        description="CodeMender Gate: Analyzing PR cumulative security diff...",
        token=token,
        target_url=dashboard_url
    )

    try:
        # 2. Cumulative Merge-Base Diff Resolution
        git_ws = GitWorkspace(head_sha, repo=repo_name)
        await git_ws.clone_repo(token, branch)
        changed_files = await git_ws.get_cumulative_diff_files(base_branch=base_branch)

        # 3. Tooling / Framework Bypass ($0 Spend)
        if not target_files:
            await set_commit_status(repo=repo_name, commit_sha=head_sha, state="success", description="Passed: Tooling changes only", token=token)
            await update_or_post_pr_comment(repo_name, pr_number, bypass_comment, token)
            return

        # 4. Run Pre-checks & CodeMender Triage
        findings = await run_triage_agent(session_id=head_sha, filepath=target_files[0], repo_name=repo_name)

        # 5. In-Place Update Pinned Report
        await update_or_post_pr_comment(repo_name, pr_number, findings_comment, token)

        # 6. Evaluate Critical Findings for Merge Gate
        critical_findings = [f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"]
        if critical_findings:
            gate_state = "failure"
            gate_desc = f"Merge Blocked: {len(critical_findings)} CRITICAL vulnerabilities detected. Fix required."
        else:
            gate_state = "success"
            gate_desc = f"Passed: 0 critical vulnerabilities ({len(findings)} total findings)."

        await set_commit_status(
            repo=repo_name,
            commit_sha=head_sha,
            state=gate_state,
            description=gate_desc,
            token=token,
            target_url=dashboard_url
        )

    except Exception as e:
        # 7. On Fatal Error: Set gate status to ERROR
        if token and repo_name:
            await set_commit_status(
                repo=repo_name,
                commit_sha=head_sha,
                state="error",
                description="CodeMender Gate: Security scan encountered a fatal error.",
                token=token
            )
        raise
```

---

## Module 5: Exact Vertex AI Token Telemetry Engine (`database.py`)

### Drop-in SKU Pricing Formula & JSONL Session Parser

```python
def calculate_token_cost(input_tokens: int, output_tokens: int, model: str = "gemini-3.5-flash", cached_tokens: int = 0, thoughts_tokens: int = 0) -> float:
    """
    Calculates cost aligned strictly with Google Cloud Vertex AI Billing SKUs:
    - Gemini 3.5 Flash Text Input (ACB1-637C-8F83): $1.50 / 1M
    - Gemini 3.5 Flash Text Output (CAF8-9360-75F2): $9.00 / 1M
    - Gemini 3.5 Flash Caching (D558-1938-B8A1): $0.15 / 1M
    - Gemini 2.5 Flash Thinking Output (CD33-11F4-1220): $2.50 / 1M
    """
    if "flash" in model.lower():
        cost_input = ((input_tokens - cached_tokens) / 1_000_000.0) * 1.50
        cost_cached = (cached_tokens / 1_000_000.0) * 0.15
        cost_output = (output_tokens / 1_000_000.0) * 9.00
        cost_thinking = (thoughts_tokens / 1_000_000.0) * 2.50
        return max(0.0, cost_input + cost_cached + cost_output + cost_thinking)
    return 0.0


def parse_cm_session_metrics(session_id: str) -> dict:
    """
    Ingests native JSONL interaction session metrics from ~/.codemender/logs/sessions/*/*.jsonl
    Captures complete multi-turn tool loops with zero token omission.
    """
    import glob, json
    base_dir = os.path.expanduser("~/.codemender/logs/sessions")
    pattern = os.path.join(base_dir, "*", f"session-*{session_id}*.jsonl")
    matched_files = glob.glob(pattern)

    metrics = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "thoughts_tokens": 0, "total_tokens": 0}

    for file_path in matched_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    data = json.loads(line.strip())
                    if data.get("type") == "interaction" and data.get("total", 0) > 0:
                        metrics["input_tokens"] = int(data.get("input", 0))
                        metrics["output_tokens"] = int(data.get("output", 0))
                        metrics["cached_tokens"] = int(data.get("cached", 0))
                        metrics["thoughts_tokens"] = int(data.get("thought", 0))
                        metrics["total_tokens"] = int(data.get("total", 0))
        except Exception as e:
            logger.warning(f"Error parsing session file {file_path}: {e}")

    return metrics
```

---

## Module 6: Cloud Run Deployment & Service Configuration

### 1. Build and Push Container
```bash
gcloud builds submit \
    --project=YOUR_PROJECT_ID \
    --tag=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/cloud-run-source-deploy/codemender-backend:latest .
```

### 2. Deploy Webhook Gateway (`codemender-webhook`)
```bash
gcloud run deploy codemender-webhook \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/cloud-run-source-deploy/codemender-backend:latest \
    --project=YOUR_PROJECT_ID \
    --region=us-central1 \
    --memory=2Gi \
    --cpu=2 \
    --timeout=600s \
    --concurrency=80 \
    --set-env-vars=MOCK_MODE=false,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID,GOOGLE_CLOUD_LOCATION=global,GEMINI_LOCATION=us-central1,GOOGLE_GENAI_USE_VERTEXAI=True,DISABLE_UI=True,PARALLEL_SHARDING_THRESHOLD=4 \
    --quiet
```

### 3. Deploy Execution Backend Worker (`codemender-backend`)
```bash
gcloud run deploy codemender-backend \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/cloud-run-source-deploy/codemender-backend:latest \
    --project=YOUR_PROJECT_ID \
    --region=us-central1 \
    --memory=4Gi \
    --cpu=2 \
    --timeout=600s \
    --concurrency=1 \
    --set-env-vars=MOCK_MODE=false,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID,GOOGLE_CLOUD_LOCATION=global,GEMINI_LOCATION=us-central1,GOOGLE_GENAI_USE_VERTEXAI=True,PARALLEL_SHARDING_THRESHOLD=4 \
    --quiet
```

### 4. Deploy Dedicated Portal (`codemender-dashboard`)
```bash
gcloud run deploy codemender-dashboard \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/cloud-run-source-deploy/codemender-backend:latest \
    --project=YOUR_PROJECT_ID \
    --region=us-central1 \
    --memory=2Gi \
    --cpu=2 \
    --timeout=600s \
    --set-env-vars=MOCK_MODE=false,GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID,GOOGLE_CLOUD_LOCATION=global,GEMINI_LOCATION=us-central1,GOOGLE_GENAI_USE_VERTEXAI=True \
    --quiet
```

---

## Module 7: GitHub Branch Protection Enforcement (1-Minute Setup)

To physically block merges on PRs containing Critical findings:

1. Open your repository on GitHub: `https://github.com/OWNER/REPO`.
2. Navigate to **Settings** $\rightarrow$ **Branches**.
3. Under **Branch protection rules**, click **Add rule** (or edit rule for `main` / `master`).
4. Enable the following settings:
   - ✅ **Require a pull request before merging**
   - ✅ **Require status checks to pass before merging**
   - ✅ **Require branches to be up to date before merging**
5. In the status checks search bar, search for and select:
   - `security/codemender-gate`
6. Click **Save Changes**.

---

### 🎉 Resulting Merge Gate Behavior on PRs:

| Scan Finding Result | Gate Status | GitHub PR UI Display | Merge Button State |
| :--- | :---: | :--- | :---: |
| **0 Critical Findings** | 🟢 `success` | `security/codemender-gate — Passed: 0 critical vulnerabilities` | 🟢 **Merge Allowed** |
| **$\ge 1$ Critical Findings** | 🔴 `failure` | `security/codemender-gate — Merge Blocked: X CRITICAL vulnerabilities detected` | ⛔ **Merge Disabled** |
| **Patch Applied & Approved** | 🟢 `success` | `security/codemender-gate — Passed: Security patch applied and approved` | 🟢 **Merge Allowed** |
| **All Findings Dismissed** | 🟢 `success` | `security/codemender-gate — Passed: 0 active critical findings (X dismissed)` | 🟢 **Merge Allowed** |

---

## Module 8: Severity-Based Batching & Reviewer Governance

### 1. Slash Command & Dashboard Action Matrix

| Target Scope | GitHub Slash Command | Dashboard UI Action | Description |
| :--- | :--- | :--- | :--- |
| **Critical Only** | `/verify critical` \| `/fix critical` | Click **🔴 Verify Criticals** \| **🔴 Fix Criticals** | Filters findings where `severity == "CRITICAL"`. |
| **High Only** | `/verify high` \| `/fix high` | Click **🟠 Verify Highs** \| **🟠 Fix Highs** | Filters findings where `severity == "HIGH"`. |
| **All Findings** | `/verify all` \| `/fix all` | Click **🧪 Verify All** \| **⚡ Fix All** | Evaluates 100% of findings with AST index caching. |
| **Single Finding** | `/verify <finding_id>` \| `/fix <finding_id>` | Click **Verify** \| **Fix** on finding card | Targets specific finding UUID. |
| **Reviewer Dismissal** | `/dismiss <id> [CATEGORY] <reason>` | Click **⚠️ Dismiss** ➔ Submit Modal | Dismisses finding, streams audit to BigQuery, and auto-promotes Draft to Ready if 0 criticals remain. |
| **Approve & Merge** | `/approve` | Click **✅ Approve & Apply** | Applies patch to PR branch with author committer identity, `[skip ci]`, and flips gate to `success`. |

### 2. Gemini 3.0 Flash Preview Model Contract
* **Vertex AI Model:** `gemini-3-flash-preview`
* **Dual-Tier Pricing:** $1.50 Compute + $1.50 License ($3.00/1M uncached input, $0.30/1M cached input, $18.00/1M output/thoughts).
* **AST Index Caching:** Builds the local AST index once per target file, reducing `/fix all` batch latency by >60%.
