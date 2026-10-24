---
trigger: always_on
---

# Project scope: CM-GitOps-goDemos (local rule, overrides global setup)

This workspace has its own identity, cloud project and source of truth. If a global rule, skill, plugin, gcloud default or ADC setting conflicts with this file, **this file wins**.

## 0. Confirmed scope (user-confirmed 2026-10-23)
- **Folder:** `/Users/manishkgaur/Desktop/Workspace/CM-GitOps-goDemos`, including `.worktrees/`.
- **GCP:** `YOUR_PROJECT_ID` (number `YOUR_PROJECT_NUMBER`), region `us-central1`, through the gcloud configuration `codemender-gitops`.
- **Repo for the PR-driven workflow:** `YOUR_ORG/YOUR_REPO`.
- **Global settings are out of scope.** Ignore the global gcloud config, global ADC, and global rules or skills (except the skills in §4). Don't use them, audit them or report on them, and never write this project's rules or config globally.
- **Reviews are read-only.** No fixes, deploys, traffic shifts or GitHub writes until the user approves them.
- **`CM-GitOps-Argolis` is out of scope entirely** (see §1). It's a separate project, maintained elsewhere.

## 1. Folder (source of truth)
- **The only source of truth** is `/Users/manishkgaur/Desktop/Workspace/CM-GitOps-goDemos`, including its git worktrees under `.worktrees/`.
- **`CM-GitOps-Argolis` (and `CM-GitOps-Argolisv1(old)`) doesn't belong here.** It's a separate project, maintained elsewhere.
  - Never read, list, write, copy from, fetch from, push to, build from, deploy from or reference it. No read-only comparisons either.
  - Nothing in this project (code, config, docs, git remotes or branches) may point to it.
- **Don't use other sibling folders.** Never read from, copy from, build from or deploy from `CM-GitOps-goDemosv1(old)`, `CM-terminal`, `codemender-poc` or `*.zip` archives, unless the user explicitly asks for a read-only comparison.
- **`vulnerable-samples/` means this folder's `vulnerable-samples/`.** The root GEMINI.md link to `codemender-poc` is stale. It's fixed on `fix/e2e-phase1` (`36aaa34`).
- **Branch state (updated 2026-10-23 18:47 CDT):**
  - `feat/gemini-3-8-flash-rollout` (`e9c6485`) is the last complete baseline.
  - `fix/e2e-phase1` (`.worktrees/fix-e2e-phase1`) is that baseline plus the Oct 22 fix commits, plus the local sanitization commit `36aaa34`. The user has files open there; leave it as is.
  - **`fix/e2e-hardening` (`.worktrees/e2e-hardening`, from `36aaa34`) is where the implementation plan is executed.** One commit per plan task, each gated by `scripts/check.sh`. It has its own `.venv`. Local only: not pushed, not deployed.
    - Head `19000a7` (15:53 CDT): all local code for Release 1 is committed (390 tests).
    - Priority (user, 15:48 CDT): quality and user experience over cost.
    - The queue and pending approvals are in plan v2: `~/.gemini/jetski/brain/2802dfc6-0b87-4ff8-91fa-386e579f9669/implementation_plan.md`.
  - **Release 1 is live (promoted 18:45 CDT):** image `codemender-backend:19000a7…` (digest `sha256:15264984f678…`) on `codemender-webhook-00060-civ` and `codemender-dashboard-00067-hoh`.
    - Rollback targets: webhook `00049-x7k`, dashboard `00063-zow`.
    - `codemender-backend` stays on `00075-jen` (`0dd25b3`), pending deletion (D-11).
  - Traffic is pinned on all three services (no `latestRevision`), since 15:56 CDT. Config changes go through `release.sh deploy` + `promote`.
  - `fix/e2e-phase1` and the other local fix branches aren't on GitHub (verified 2026-10-23).
  - `feat/scan-and-telemetry-fix` is missing `git_manager.py`, `shared_state.py`, `fleet/` and `maintenance.py`, so never build or deploy it as-is. The main folder is checked out on it.
- **Before any build or deploy:**
  - Confirm `python3 -m compileall backend` passes and every local import resolves (`scripts/check.sh` on `fix/e2e-hardening` does both, plus the scope lint and pytest).
  - Build from committed code only (see the global `cicd-integrity` rule). Tag images with the git SHA, never `:latest`.
  - Deploy with `--no-traffic --tag`, smoke-test, then shift traffic. On `fix/e2e-hardening` this is `scripts/release.sh build|deploy|smoke|promote`; every step except `status` (including `build`, a Cloud Build in our project) needs the user's approval.
    - `release.sh` deploys images by digest, takes config changes as `DEPLOY_FLAGS` / `DEPLOY_FLAGS_<SERVICE>`, and `promote` refuses while tasks run.
    - `scripts/setup_runner_sa.sh` and `scripts/setup_alerts.sh` are dry runs unless `APPLY=true`; applying either needs approval.

## 2. Google Cloud (project and identity)
- **Project:** `YOUR_PROJECT_ID` (number `YOUR_PROJECT_NUMBER`), region `us-central1`. Gemini 3.x calls use `GOOGLE_CLOUD_LOCATION=global`.
- **Identity:** `user@example.com`, through the gcloud configuration `codemender-gitops`.
- **Every gcloud, bq and gsutil command:**
  - Prefix it with `CLOUDSDK_ACTIVE_CONFIG_NAME=codemender-gitops`, plus the `CLOUDSDK_METRICS_ENVIRONMENT` attribution prefix.
  - Pass `--project=YOUR_PROJECT_ID`.
- **Never use the global defaults:** account `admin@manishkgaur.altostrat.com`, project `elevate26-test`, ADC quota project `agent-factory-ctrl`.
- **Never use `codemender-prd` or `codemender-poc`.** Where code defaults name them, override with `CODEMENDER_PROJECT_ID=YOUR_PROJECT_ID` and `GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID`.
- **Never change global state:**
  - No `gcloud config set` without `--configuration=codemender-gitops`.
  - Run `gcloud auth login` only with `--no-activate`.
  - Never run `gcloud auth application-default login` against the default config.
- **If a tool needs ADC** (cm CLI, google-auth scripts), use a project-local ADC file:
  - Create it once: `CLOUDSDK_CONFIG=~/.config/gcloud-codemender-gitops gcloud auth application-default login`
  - Then run the tool with `GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud-codemender-gitops/application_default_credentials.json`.

## 3. GitHub
- **Repo:** `YOUR_ORG/YOUR_REPO`.
- **Token:** use only `GITHUB_TOKEN` from Secret Manager in `YOUR_PROJECT_ID`.
  - Fetch it at the moment of use and pass it via stdin or env.
  - Never print it, write it to disk, put it in a URL or git remote, or log it.
- **Off-limits tokens:**
  - the ones in `codemender-prd` and `codemender-poc` (they only cover `mgaur10/*` repos)
  - any token embedded in another folder's git remote
- **Commit identity:** `YOUR_BOT_NAME <bot@example.com>`.
- **Approval:** GitHub writes (comments, statuses, PRs, webhooks, pushes) and Cloud Run deploys need explicit user approval.

## 4. Skills
- **Use:**
  - `google-cloud-auth-verification` and `enforcing-resource-attribution`, with the §2 identity
  - `vertex-ai-global-endpoint-adk` for the Gemini 3.x global endpoint
  - `gemini-token-telemetry-calculator` for CodeMender costs and BigQuery telemetry
  - `managing-python-dependencies` (virtual envs only)
  - `accidental-data-loss-prevention`
- **Ignore unless the user asks**, because they target other projects or identities:
  - `kora-*`, `immigration-*`, fiduciary-ai skills, `firebase-*`
  - `agw-*`, `sgp-*`, `agent-gateway-*`, `a2a-*`, `gateway-agent-sdk`
  - BigQuery, Dataform, Dataflow and Spark pipeline skills
  - the global `vertex-ai-agent-runtime-gotchas` rule (this project runs on Cloud Run)
  - any skill that hard-codes another project, account or region

## 5. User preferences
- Show all times in US Central (CDT until Nov 1, then CST).
- Keep answers concise. Discuss findings and get approval before fixing, deploying or writing to GitHub.

## 6. Promotion flow (one-way)
- **Flow:** fix in this folder → test in `YOUR_PROJECT_ID` with `YOUR_ORG/YOUR_REPO` → publish a sanitized starter kit, only with the user's explicit approval.
- **The publish target is whatever the user names at that time. It's never `CM-GitOps-Argolis`.**
- **Sanitize before publishing:** remove our project ID and number, identities, repo name, service URLs and secrets.
- **Never flow back:** sanitized content (placeholders, `.example` workflows, WIF bypasses, neutralized secrets) must never land in this folder's branches.
- **Local sanitization done (2026-10-23 11:16 CDT, user-approved):**
  - Removed the `starter-kit` git remote and all of its refs.
  - Commit `36aaa34` on `fix/e2e-phase1` removed the starter-kit tooling, docs and samples and the foreign-target scripts, and repointed the tooling defaults. It's local only: not pushed, not deployed.
- **Still to sanitize (per the implementation plan, after the user's review):**
  - foreign fallbacks in runtime code (`backend/`, `frontend/src`)
  - the fleet/Titan feature
  - the foreign-based local branches (`feat/scan-and-telemetry-fix`, `dev/codemender-test-vuln`, `qa/*`, `master`)
  - cross-repo Firestore data and fleet tokens

## 7. PR-driven workflow (verified 2026-10-23)
- **Trigger:** `.github/workflows/codemender-wif.yml` ("CodeMender Security Gate (WIF)") on GitHub's default branch `main`. It runs on `pull_request` (opened, synchronize, reopened, ready_for_review) and on PR comments that start with `/` (`issue_comment`). A local copy is in `fix/e2e-phase1`.
  - `codemender.yml` was disabled by hand on GitHub on 2026-08-18 and is not the trigger. Its committed copies on `feat/scan-and-telemetry-fix` and `dev/codemender-test-vuln` point to `codemender-prd` (161943671234), so never re-enable or push them.
  - The local clone doesn't track `origin/main` (only `origin/master` from July). Don't fetch without approval.
- **Auth:** WIF provider `projects/YOUR_PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider`, as `codemender-trigger@YOUR_PROJECT_ID.iam.gserviceaccount.com`.
- **Entry point:** `https://codemender-webhook-YOUR_PROJECT_NUMBER.us-central1.run.app/github-webhook`.
- **Services (us-central1):** `codemender-webhook`, `codemender-backend` and `codemender-dashboard`, all built from `us-central1-docker.pkg.dev/YOUR_PROJECT_ID/cloud-run-source-deploy/codemender-backend`, with `ALLOWED_REPOS=YOUR_ORG/YOUR_REPO`.
