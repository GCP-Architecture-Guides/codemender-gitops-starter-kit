# 🛡️ CodeMender Development & QA Checklist (GEMINI.md)

This document contains hierarchical rules, anti-patterns, and quality gates for the CodeMender agent (and any AI developer working on the CodeMender backend/CLI). Follow this checklist before committing code, deploying services, or validating vulnerabilities.

---

## 📋 Draft PR-Driven Security Architecture & Ingress
* **Push Event Decommissioning:**
  * **Rule:** Acknowledge raw branch push webhook events with HTTP 200 `{"message": "Push event ignored; PR-triggered scans active"}` and ignore them. Scans trigger exclusively on `pull_request` actions (`opened`, `synchronize`, `reopened`, `ready_for_review`).
  * **Anti-Pattern:** Scanning every intermediate feature branch commit, which generates noisy alerts on incomplete WIP code and wastes 60%–75% of LLM tokens.
* **Cumulative Merge-Base Diff Resolution:**
  * **Rule:** Always resolve modified files using triple-dot merge-base diffing against the base branch (`git diff --name-only origin/{base_branch}...HEAD`).
  * **Anti-Pattern:** Using single-commit diffs (`git show HEAD` or `HEAD~1`), which misses vulnerabilities introduced in earlier commits of a multi-commit PR.
* **Zero-Token Tooling Bypass ($0.00 Spend):**
  * **Rule:** When PR diffs contain only framework, configuration, tooling, or CI files (`backend/`, `frontend/`, `scripts/`, `scratch/`, `configs/`, `.github/`, `.gemini/`), immediately clear the commit status gate (`security/codemender-gate` -> `success`), log `$0.00` spend to BigQuery, and post a bypass badge comment.
  * **Anti-Pattern:** Running heavy AI triage and multi-agent reasoning on frontend UI or build scripts.
* **Single Pinned PR Report:**
  * **Rule:** Search existing PR comments for the unique anchor `<!-- codemender-security-report -->` and `PATCH` the comment in-place.
  * **Anti-Pattern:** Posting a new comment on every commit push, spamming reviewers with redundant reports.
* **In-Flight Task Superseding:**
  * **Rule:** Maintain `active_tasks[f"pr-{pr_number}"] = run_id`. Check before running heavy LLM scans whether the run ID is still current. If superseded by a newer commit, cleanly abort execution.
  * **Anti-Pattern:** Allowing multiple overlapping scan runs to fight over the same PR workspace and overwrite remote comments.

---

## 📋 Concurrency & Workspace Safety
* **Unified Workspace Lock:**
  * **Rule:** Any background task that modifies a repository workspace (e.g. `process_pr_scan_event`, `verify_findings_task`, `fix_findings_task`, manual dashboard fix/verify endpoints) **must** acquire a Firestore-backed lock on the workspace ID (`workspace-{head_sha}`).
  * **Anti-Pattern:** Spawning parallel background threads or API handlers that write to the same `/tmp/session-{commit_sha}` directory without locking, which causes Git conflicts and overwrites remote patch branches.
* **Lock Release Integrity:**
  * **Rule:** Always release the lock (`release_lock(lock_id)`) inside a `finally` block or on all return/failure paths of the worker.

---

## 📋 GitOps & Pull Request Management
* **Dynamic Git Committer Identity:**
  * **Rule:** When committing patches dynamically, fetch the `pusher_name` and `pusher_email` from Firestore for the target commit SHA. Run local git config setup before committing:
    ```bash
    git config user.name "Pusher Name"
    git config user.email "pusher@email.com"
    ```
  * **Anti-Pattern:** Committing patches using a hardcoded bot identity (`agent@codemender.ai`), which causes Google CLA status checks to fail and blocks PR merges.
* **Finding Mapping Guard (Dashboard Fixes):**
  * **Rule:** When the dashboard triggers a fix for a specific `finding_id`, re-scan the workspace and map the ID against the local findings list by matching the **vulnerability type** (`vuln_type` / CWE class).
  * **Anti-Pattern:** Restricting mapping to `local_findings[0]` (the first element in the list), which results in fixing the wrong vulnerability if multiple findings exist in the file.

---

## 📋 Sandbox & Exploit Verification Runtimes
* **Environment Provisioning:**
  * **Rule:** Ensure all runtime dependencies required to spin up mock servers during verification (e.g., Python `flask`, Node.js `express`, `sqlite3`, Java JDK/Maven) are pre-baked into the container image.
  * **Anti-Pattern:** Attempting to run `pip install` or `npm install` dynamically during verification, which is blocked by the container's strict `command_policy.yaml`.
* **Node.js Package Imports:**
  * **Rule:** When installing Node.js packages globally inside the container, configure `ENV NODE_PATH=/usr/local/lib/node_modules` so they can be resolved by global scripts.
* **VCS Headless Config Bypass:**
  * **Rule:** Write a non-interactive config wrapper at `~/.codemender/config.yaml` during workspace initialization to bypass configuration prompts and enable multi-language scans.
* **Exploit Script Port Checks:**
  * **Rule:** When generating exploit scripts (`exploit.sh`), the verification agent must include a loop checking if the target server port (e.g. port 5000) is open and listening before executing the exploit curl/request (e.g. using a short `sleep 2` retry block up to 5 times).
  * **Anti-Pattern:** Running requests immediately after launching mock servers without verifying port readiness, which results in `Connection refused` failures.

---

## 📋 Workspace Cleanliness & Test Hygiene
* **Gitignored Test Samples:**
  * **Rule:** Place all vulnerable sample files used for testing/PoC validations (`vulnerable_app.py`, `vulnerable_node.js`, `main.tf`, `VulnerableController.java`) inside the gitignored [`vulnerable-samples/`](vulnerable-samples/) directory at the repository root.
  * **Anti-Pattern:** Leaving vulnerable samples in the root directory, which triggers automatic webhook scans on unrelated commits and wastes LLM tokens.

---

## 📋 Mock Mode vs. Live Production Config
* **Environment Variable Alignment:**
  * **Rule:** When deploying to production Cloud Run, ensure the environment variable `MOCK_MODE` is strictly configured to `false` across all revision templates (backend, webhook, dashboard).
  * **Anti-Pattern:** Hardcoding mock database responses or mock execution steps when `MOCK_MODE` is set to `false`, which hides real API execution failures.

---

## 📋 Vertex AI Session Expiration & Fallbacks
* **Graceful Session Fallback:**
  * **Rule:** Vertex AI agent sessions expire on the platform after 30-60 minutes. When running `cm session resume <session_id>` fails with a `400: Precondition check failed` error, the backend must catch the failure and transparently fall back to creating a new session instead of hanging or returning raw client exceptions.

---

## 📋 Telemetry & BigQuery Schema Integrity
* **BigQuery Column Mapping:**
  * **Rule:** When writing log rows to `token_usage_log` and `scan_log`, ensure the schema columns (such as `pr_number`, `is_draft`, `event_type`, `cost_usd`, `cached_savings_usd`, `action_taken`, `findings_count`) match exactly with the keys returned by backend analytics parsers and database insertion dicts.
  * **Anti-Pattern:** Attempting to insert rows containing missing, renamed, or un-mapped columns, which causes BigQuery API insertion operations to fail silently or crash the task handler.
* **Google Cloud Billing Daily Boundary Alignment:**
  * **Rule:** All daily aggregation analytics queries in BigQuery must group dates by `EXTRACT(DATE FROM timestamp AT TIME ZONE 'America/Los_Angeles')` to match Google Cloud Billing invoice cutoffs.
  * **Anti-Pattern:** Grouping by raw UTC date (`EXTRACT(DATE FROM timestamp)`), which creates 7-8 hour timezone reconciliation skews against Google Cloud Billing SKUs.

---

## 📋 Enterprise Vulnerability Fingerprinting & Lifecycle Event Sourcing
* **Deterministic Structural Fingerprinting with Scope Anchor:**
  * **Rule:** Always generate vulnerability fingerprints using `repo_name + file_path + enclosing_scope + cwe_id + normalized_sink`. The enclosing AST scope (function/class name) is mandatory to eliminate collision bugs across identical database/sink calls within the same file.
  * **Anti-Pattern:** Using volatile line numbers or un-scoped file-level hashes as primary keys, which breaks across line shifts and causes duplicate-sink collisions.
* **Append-Only Event Sourcing (Zero-DML Lockout):**
  * **Rule:** Never execute DML `UPDATE` or `DELETE` statements on actively streamed BigQuery tables (`vulnerability_findings_inventory`). Instead, append immutable lifecycle events (`DISCOVERED`, `PERSISTED`, `RESOLVED`, `MERGED_RESOLVED`, `DISMISSED`) and resolve the current active state via analytical deduplication views (`v_active_vulnerabilities_org`) using `QUALIFY ROW_NUMBER() OVER (PARTITION BY repo, fingerprint ORDER BY last_seen_at DESC) = 1`.
  * **Anti-Pattern:** Running SQL `UPDATE` on streaming buffers, which throws BigQuery `400: UPDATE over table would affect rows in the streaming buffer` errors.
* **Rebase-Resilient PR Indexing:**
  * **Rule:** Query prior scan findings using the GitHub `pr_number` from Firestore rather than raw Git parent commit SHAs ($N-1$). This ensures rebased or amended commits retain their full triage lineage without parentage disconnects.
* **Dual-ID UX Mapping:**
  * **Rule:** Display a 6-character short prefix (`display_id = fingerprint[:6]`) in PR comments for human ergonomics. Ensure command parsers for `/fix` and `/verify` resolve short display IDs, CLI IDs, and canonical fingerprints interchangeably.

---

## 📋 Deterministic PR Gates & Idempotent Scan Lifecycle
* **Commit-SHA Scan Caching (Idempotency):**
  * **Rule:** When a PR transitions from Draft to Ready for Review (`ready_for_review`), if the target commit SHA has already been scanned (`scans/{head_sha}` in Firestore), reuse the cached findings and status gate directly ($0.00 spend).
  * **Anti-Pattern:** Running duplicate full AI scans on unchanged commits, which causes LLM temperature variance and circular PR triage loops.
* **Canonical CWE Severity Anchoring:**
  * **Rule:** Always normalize parsed vulnerability severities against an immutable enterprise dictionary (`DETERMINISTIC_SEVERITY_POLICY`) keyed by canonical CWE IDs (e.g. SQLi/RCE/Auth Bypass $\rightarrow$ CRITICAL; Mass Assignment/IDOR/XSS $\rightarrow$ HIGH; Secrets $\rightarrow$ MEDIUM).
  * **Anti-Pattern:** Allowing raw LLM temperature variance to fluctuate severity scores between HIGH and CRITICAL on identical code.
* **In-Flight PR Scan Abort on Merge/Close:**
  * **Rule:** Before patching PR comments or updating status checks, background workers must check if the target PR is already merged or closed. If closed/merged, cleanly abort without overwriting the merged PR discussion.
  * **Anti-Pattern:** Late-finishing background workers overwriting the discussions of already-merged PRs with in-progress scan states.

---

## 📋 Release, Status & Task Lifecycle (2026-10-23 hardening)
* **Release only through `scripts/release.sh`:**
  * **Rule:** Build from a committed SHA, deploy with no traffic (image pinned by digest, config via `DEPLOY_FLAGS`), smoke, then promote when no scan/verify/fix is running.
  * **Anti-Pattern:** `gcloud run services update` on a live service, editing env vars or deleting locks by hand, or deploying `:latest`.
* **Scan Result vs. Task Status:**
  * **Rule:** The scan result lives in `findings` + `scan_completed_at`. Verify/fix record the status they found and give it back (`gate_policy.restorable_status`), and a partial scan (`unscanned_files`) is never a pass.
  * **Anti-Pattern:** Marking a scan COMPLETED from repo-level findings, restoring an in-flight status, or letting a dismissal turn a failed or partial scan green.
* **Cancellation & Shutdown:**
  * **Rule:** `TaskCancelled` is a BaseException. Long steps call `TaskSession.raise_if_cancelled()`, the cm runner polls the cancel check, and every worker handles `TaskCancelled` (shutdown → `STALE` + `error` gate).
  * **Anti-Pattern:** Broad `except BaseException`, force-releasing a live lease, or releasing a lease without its owner.
* **Telemetry Attribution:**
  * **Rule:** Worker entry points set `task_context.telemetry_context` (pr_number, event_type, is_draft); `log_token_usage` / `log_scan_summary` fall back to it, and rows are trimmed to the live BigQuery schema.
  * **Anti-Pattern:** Defaulting `event_type` to `pull_request` for comment or dashboard work.
