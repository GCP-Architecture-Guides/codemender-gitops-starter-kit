# 🔄 CodeMender Parallel Execution & Concurrency Architecture

This visual guide details how CodeMender handles parallel actions, distributed locks, and resource isolation across different operational scenarios.

---

## 📑 Scenarios Covered
1. [Scenario 1: Actions on the SAME Commit (Verify All, Verify + Fix Race Prevention)](#-scenario-1-actions-on-the-same-commit)
2. [Scenario 2: Actions on SEPARATE Commits (Parallel Scans & PR Verifications)](#-scenario-2-actions-on-separate-commits)
3. [Scenario 3: Enterprise Map-Reduce Finding Sharding](#-scenario-3-enterprise-map-reduce-finding-sharding)
4. [Summary Comparison Matrix](#-summary-comparison-matrix)

---

## 🟢 Scenario 1: Actions on the SAME Commit

> [!IMPORTANT]
> **Core Principle:** Any task modifying a workspace at `/tmp/session-{commit_sha}` MUST acquire a distributed Firestore lock on `workspace-{commit_sha}`.

### 1.1 Race Prevention (Verify + Fix at the Same Time)

If a developer clicks "Verify" and immediately clicks "Fix", or if two PR comments arrive simultaneously for the same commit:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / GitHub
    participant GW as Webhook / API Gateway
    participant FS as Firestore Distributed Lock
    participant W1 as Worker Task 1 (Verify)
    participant W2 as Worker Task 2 (Fix)
    participant Disk as Local Workspace /tmp

    Dev->>GW: 1. Trigger /verify finding-1
    GW->>W1: Spawn async task
    W1->>FS: acquire_lock(workspace-commit_sha)
    FS-->>W1: Lock Granted (timestamp)
    
    Dev->>GW: 2. Trigger /fix finding-2 (Simultaneous)
    GW->>W2: Spawn async task
    W2->>FS: acquire_lock(workspace-commit_sha)
    FS-->>W2: Lock Active (Rejected / Aborted)
    Note over W2: W2 logs warning and safely aborts to prevent git tree corruption

    W1->>Disk: Executes exploit test on original code
    W1->>FS: Updates finding status -> VERIFIED
    W1->>FS: release_lock(workspace-commit_sha)
    Note over FS: Lock released in finally block
```

---

### 1.2 How `/verify all` Runs (Sequential Finding Loop)

When verifying multiple findings on the same commit, the single task holds the lock and iterates sequentially with clean git workspace resets:

```mermaid
flowchart TD
    Start(["User runs /verify all"]) --> Lock["Acquire Lock: workspace-commit_sha"]
    Lock --> WInit["ensure_workspace: Checkout target commit"]
    
    subgraph Loop ["Iterate Through All Findings"]
        F1["Select Finding 1"] --> V1["Run: cm verify finding-1"]
        V1 --> Art1["Upload PoC Artifacts to GCS"]
        Art1 --> R1["Git Reset: git checkout HEAD -- ."]
        
        R1 --> F2["Select Finding 2"]
        F2 --> V2["Run: cm verify finding-2"]
        V2 --> Art2["Upload PoC Artifacts to GCS"]
        Art2 --> R2["Git Reset: git checkout HEAD -- ."]
        
        R2 --> FN["Select Next Finding..."]
    end
    
    WInit --> Loop
    Loop --> Rep["Build Consolidated Markdown Report"]
    Rep --> Comment["Post Unified Table to GitHub PR"]
    Comment --> Unlock["Release Lock: workspace-commit_sha"]
    Unlock --> EndNode(["Done"])
```

---

## 🔵 Scenario 2: Actions on SEPARATE Commits

> [!TIP]
> **Core Principle:** Tasks on different commits use different lock IDs (`workspace-c3b3...` vs `workspace-60ab...`) and completely isolated `/tmp` workspace folders. They execute 100% concurrently without blocking.

```mermaid
flowchart LR
    subgraph PR25 ["PR #25 - Go Application"]
        direction TB
        E1["Push / Comment on PR #25<br/>Commit: c3b3a8b3..."]
        --> L1["Lock: workspace-c3b3a8b3<br/>Status: GRANTED"]
        --> D1["Workspace: /tmp/session-c3b3a8b3<br/>Uses Pre-baked Go Toolchain"]
        --> BQ1["Log Go Tokens to BigQuery<br/>Task: cm_verify"]
        --> GH1["Post PoC Report to PR #25"]
        --> U1["Release Lock: workspace-c3b3a8b3"]
    end

    subgraph PR26 ["PR #26 - Python Flask XSS"]
        direction TB
        E2["Push / Comment on PR #26<br/>Commit: 60abdc86..."]
        --> L2["Lock: workspace-60abdc86<br/>Status: GRANTED"]
        --> D2["Workspace: /tmp/session-60abdc86<br/>Runs Flask on isolated socket"]
        --> BQ2["Log Python Tokens to BigQuery<br/>Task: cm_verify"]
        --> GH2["Post PoC Report to PR #26"]
        --> U2["Release Lock: workspace-60abdc86"]
    end

    PR25 -.->|Fully Parallel & Isolated| PR26
```

---

## ⚡ Scenario 3: Enterprise Map-Reduce Finding Sharding

For massive repositories with 10+ findings, the gateway shards findings across parallel Cloud Run worker instances:

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer / PR Comment
    participant GW as API Gateway (Cloud Run)
    participant Q as Cloud Tasks Queue
    participant W1 as Worker 1 (Finding #1)
    participant W2 as Worker 2 (Finding #2)
    participant W3 as Worker 3 (Finding #3)
    participant BQ as BigQuery Analytics
    participant PR as GitHub PR

    Dev->>GW: Trigger /verify all (10 Findings)
    GW->>Q: Enqueue Task 1 for Finding #1
    GW->>Q: Enqueue Task 2 for Finding #2
    GW->>Q: Enqueue Task 3 for Finding #3
    GW-->>Dev: 202 Accepted (Verification started in parallel)

    par Parallel Worker Execution (Concurrency = 1 per container)
        Q->>W1: Verify Finding #1 in isolated container
        Q->>W2: Verify Finding #2 in isolated container
        Q->>W3: Verify Finding #3 in isolated container
    end

    W1->>BQ: Stream Token Usage (Task: cm_verify)
    W2->>BQ: Stream Token Usage (Task: cm_verify)
    W3->>BQ: Stream Token Usage (Task: cm_verify)

    W1->>PR: Update finding status table
    W2->>PR: Update finding status table
    W3->>PR: Update finding status table
    Note over Dev,PR: Entire PR verified in ~3 minutes total wall-clock time
```

---

## ⚡ Scenario 4: Draft PR Iterative Commit Superseding & In-Place Reporting

When a developer rapidly pushes multiple commits to an active Draft PR (e.g. Commit B pushed while Commit A is still being analyzed):

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant GW as Webhook Gateway
    participant St as Active Tasks Registry
    participant W1 as Worker 1 (Commit A)
    participant W2 as Worker 2 (Commit B)
    participant GH as GitHub PR

    Dev->>GW: 1. Push Commit A to PR #45
    GW->>St: Set active_tasks["pr-45"] = "run-A"
    GW->>W1: Launch process_pr_scan_event(Commit A, run_id="run-A")
    W1->>W1: Cloning branch & running pre-checks...

    Dev->>GW: 2. Push Commit B to PR #45 (Newer Commit)
    GW->>St: Overwrite active_tasks["pr-45"] = "run-B"
    GW->>W2: Launch process_pr_scan_event(Commit B, run_id="run-B")

    Note over W1: W1 checks active_tasks["pr-45"] == "run-A" (Evaluates to False)
    W1-->>W1: Cleanly aborts before heavy LLM scan (Saves tokens!)

    W2->>W2: Cumulative diff: origin/main...HEAD (Includes Commits A + B)
    W2->>W2: Run cm find on complete delta
    W2->>GH: PATCH comment with anchor <!-- codemender-security-report -->
    Note over GH: Single pinned comment updated in-place without duplicate bot comments!
```

---

## 📊 Summary Comparison Matrix

| Concurrency Scenario | Lock ID Used | Workspace Path | Execution Mode | Behavior / Protection |
| :--- | :--- | :--- | :---: | :--- |
| **Verify + Fix on same PR** | `workspace-{head_sha}` | `/tmp/session-{head_sha}` | **Sequential / Mutex** | First task acquires lock; second task aborts to prevent git tree corruption. |
| **`/verify all` on same PR** | `workspace-{head_sha}` | `/tmp/session-{head_sha}` | **Sequential Loop** | 1 task holds lock, iterates findings, resets workspace between each test. |
| **Simultaneous PR #25 & PR #26** | `workspace-{sha1}`<br>`workspace-{sha2}` | `/tmp/session-{sha1}`<br>`/tmp/session-{sha2}` | **100% Parallel** | Independent locks & directories. Upgraded 4GB RAM handles both without OOM. |
| **Sharded Finding Verification** | `workspace-{sha}-{finding_id}` | Isolated container `/tmp` | **Map-Reduce Parallel** | $N$ parallel containers verify $N$ findings simultaneously in $\approx 3$ minutes flat. |
| **Iterative PR Commits** | `workspace-{head_sha}` | `/tmp/session-{head_sha}` | **Superseding Cancel** | Active task registry cancels older in-flight scan; updates pinned comment in-place. |
