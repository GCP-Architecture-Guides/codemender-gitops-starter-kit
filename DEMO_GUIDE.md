# 🚀 CodeMender in Action: Pull Request Demo Guide

This guide runs a complete CodeMender demo from the **GitHub web UI**: commit a vulnerable sample,
open a pull request, read the security report, verify a finding, generate a fix and approve it.

Before you start, finish the [Quickstart](README.md#quickstart) so the relay workflow and the merge
gate are set up on the repository you protect.

> This release has no web dashboard. Every step happens on the pull request.

---

## 🎯 Storyline

1. **Find:** opening a pull request triggers a scan of the files it changes. One pinned comment
   lists the findings, and the `security/codemender-gate` check blocks the merge while a CRITICAL
   finding is open.
2. **Verify:** `/verify` runs a real exploit in a sandbox, so a finding is proven rather than argued.
3. **Remediate:** `/fix` generates a minimal patch and validates it.
4. **Approve:** `/approve` commits the patch to the PR branch, re-scans, and the gate turns green
   once no CRITICAL finding is left.

---

## 📦 Vulnerable samples

Pick a sample from the [`samples/`](samples/) folder. They are intentionally vulnerable; never deploy
them.

| Sample | Stack | Vulnerabilities included |
|---|---|---|
| [`vulnerable_app.py`](samples/vulnerable_app.py) | Python (Flask + SQLite) | SQL injection, command injection, IDOR, XSS, hardcoded secrets |
| [`vulnerable_app.go`](samples/vulnerable_app.go) | Go (`net/http` + SQLite) | SQL injection, IDOR, command injection, hardcoded secrets |
| [`vulnerable_node.js`](samples/vulnerable_node.js) | Node.js (Express) | Command injection, authentication bypass, hardcoded secrets |
| [`VulnerableController.java`](samples/VulnerableController.java) | Java (Spring) | SQL injection, path traversal, insecure deserialization |
| [`main.tf`](samples/main.tf) | Terraform (Google Cloud) | Public bucket, open Cloud SQL, hardcoded secrets |

`vulnerable_app.py` gives the most complete demo: it usually yields two CRITICAL findings (SQL
injection and OS command injection) plus several HIGH ones.

---

## 🎬 Step 1: Commit a sample and open a draft PR (`Find`)

1. In the protected repository, click **Add file → Create new file**.
2. Name it `vulnerable_app.py` and paste the contents of
   [`samples/vulnerable_app.py`](samples/vulnerable_app.py).
3. Choose **Create a new branch for this commit and start a pull request**, then
   **Propose changes**.
4. Click the arrow next to **Create pull request**, choose **Create draft pull request**, and
   create it.

**What happens (about 2–3 minutes):**

- The **CodeMender Security Gate (WIF)** workflow relays the event; its run finishes in seconds.
- `security/codemender-gate` shows **pending** ("Analyzing Draft PR … security…") and a progress
  comment appears.
- When the scan finishes, the progress comment is removed and the pinned
  **🔍 CodeMender PR Security Analysis** comment lists every finding with its ID, severity, CWE,
  file and line.
- The gate turns **failure** ("Merge blocked: N unresolved CRITICAL finding(s)") and the merge
  button stays blocked.

## 🧪 Step 2: Verify exploitability (`Verify`)

Reply on the PR with one finding ID from the report, for example:

```text
/verify a1b2c3d4
```

CodeMender starts the sample app in a sandbox, runs an exploit against it and posts the verdict
with its evidence. Verification takes several minutes; a progress comment shows that it is running.
Use `/verify critical` to verify every CRITICAL finding.

## 🛠️ Step 3: Generate the patch (`Remediate`)

```text
/fix critical
```

CodeMender generates a patch for the selected findings, validates it, and posts the proposed diff on
the PR. Nothing is committed yet.

## ✅ Step 4: Approve the patch and unblock the merge (`Approve`)

```text
/approve
```

CodeMender applies the proposal, commits it to the PR branch (authored as the PR's pusher), and the
new commit triggers a re-scan. The pinned report marks the fixed findings **RESOLVED**, and the gate
turns **success** once no CRITICAL finding is open.

### Alternative: accept the risk

Maintainers can dismiss a finding with a governance category and a justification:

```text
/dismiss e5f6a7b8 [COMPENSATING_CONTROL] Internal-only route behind an allowlisting proxy
```

or accept every open finding on the commit:

```text
/override-gate [BUSINESS_ACCEPTED_RISK] Emergency hotfix approved by the security lead
```

Dismissals are recorded in BigQuery and are shown as **DISMISSED** in the report.

---

## 🔧 Tips

- **Stop a running task:** reply `/cancel`.
- **Re-run a scan:** push a new commit, or close and reopen the PR.
- **Command rules:** only the first line of a comment counts, commands are case-insensitive, and
  they run only for collaborators with write or admin permission.
