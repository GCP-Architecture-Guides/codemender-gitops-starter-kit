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
# CodeMender release procedure for the existing Cloud Run services (plan 1.3 / 6.1)
# ==============================================================================
#   scripts/release.sh build                     check.sh, then Cloud Build of HEAD -> :<sha>
#   scripts/release.sh deploy                    one revision per service: no traffic, tag sha-<short>
#   scripts/release.sh smoke                     health/auth checks against the tag URLs
#   scripts/release.sh promote                   pin 100% of traffic to the tagged revisions
#   scripts/release.sh rollback SERVICE REVISION pin 100% of SERVICE back to REVISION
#   scripts/release.sh prune-tags [--yes]        remove tags other than this release's
#   scripts/release.sh status                    traffic and tags of every service
#
# Rules this script enforces:
#   - Images are built from a committed, clean HEAD (git archive) and tagged with the full SHA.
#     Never :latest. deploy pins the image by digest, so a re-pushed tag can't change what runs
#     (plan 1.10).
#   - deploy replaces the image (plus --no-cpu-throttling, which background work needs) and adds
#     DEPLOY_FLAGS and DEPLOY_FLAGS_<SERVICE> (e.g. DEPLOY_FLAGS_DASHBOARD="--port=9080").
#     Everything else on the service stays as it is. With pinned traffic, config changes take
#     effect only through deploy + promote (conflict review B2). Flag values can't contain spaces.
#   - deploy never moves traffic. promote pins traffic to explicit revisions, so later env-only
#     updates can't silently move it (review B2/F4).
#   - smoke first checks that each new revision runs an image pinned by digest with
#     MOCK_MODE=false, and prints its service account.
#   - promote refuses while scan/verify/fix tasks are running (scripts/inflight_scans.py):
#     promotion stops the old revision's instances (conflict review C2). FORCE=1 overrides.
# Every command except build/status changes Cloud Run state: run each one deliberately.
#
# Environment overrides: PROJECT_ID, REGION, SERVICES (space separated), SHA, IMAGE (deploy an
# existing image, e.g. a config-only revision), TAG, DEPLOY_FLAGS, DEPLOY_FLAGS_WEBHOOK,
# DEPLOY_FLAGS_BACKEND, DEPLOY_FLAGS_DASHBOARD, FORCE.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROJECT_ID="${PROJECT_ID:-YOUR_PROJECT_ID}"
REGION="${REGION:-us-central1}"
IMAGE_REPO="${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/codemender-backend"
read -r -a SERVICES <<< "${SERVICES:-codemender-webhook codemender-backend codemender-dashboard}"
# Services whose tag URLs are reachable from outside (the dashboard is behind the load balancer).
SMOKE_SERVICES=(codemender-webhook codemender-backend)

# This project's gcloud configuration, for this process only (never changes global gcloud state).
export CLOUDSDK_ACTIVE_CONFIG_NAME="${CLOUDSDK_ACTIVE_CONFIG_NAME:-codemender-gitops}"

SHA="${SHA:-$(git rev-parse HEAD)}"
SHORT="${SHA:0:7}"
TAG="${TAG:-sha-${SHORT}}"
IMAGE_FROM_ENV="${IMAGE:-}"
IMAGE="${IMAGE:-${IMAGE_REPO}:${SHA}}"

die() { echo "error: $*" >&2; exit 1; }
gc() { gcloud "$@" --project="$PROJECT_ID" --quiet; }
run_gc() { gc run "$@" --region="$REGION"; }

describe_json() { run_gc services describe "$1" --format=json; }

# traffic_field SERVICE TAG FIELD -> FIELD (url | revisionName) of the traffic entry tagged TAG.
traffic_field() {
    describe_json "$1" | python3 -c '
import json, sys
tag, field = sys.argv[1], sys.argv[2]
entries = json.load(sys.stdin).get("status", {}).get("traffic", [])
match = [e for e in entries if e.get("tag") == tag]
if not match:
    sys.exit(f"no traffic entry tagged {tag}")
print(match[0][field])' "$2" "$3"
}

# serving_revisions SERVICE -> "rev=percent,..." of the revisions that currently get traffic.
serving_revisions() {
    describe_json "$1" | python3 -c '
import json, sys
entries = json.load(sys.stdin).get("status", {}).get("traffic", [])
print(",".join("%s=%s" % (e["revisionName"], e["percent"]) for e in entries if e.get("percent")))'
}

# image_digest -> sha256:... of $IMAGE, or nothing when it doesn't exist.
image_digest() { gc artifacts docker images describe "$IMAGE" --format="value(image_summary.digest)" 2>/dev/null || true; }
image_exists() { [[ -n "$(image_digest)" ]]; }

# pinned_image -> $IMAGE referenced by digest (REPO@sha256:...), plan 1.10.
pinned_image() {
    if [[ "$IMAGE" == *@sha256:* ]]; then
        echo "$IMAGE"
        return
    fi
    local digest
    digest="$(image_digest)"
    [[ "$digest" == sha256:* ]] || die "image $IMAGE not found; run: scripts/release.sh build"
    echo "${IMAGE%:*}@${digest}"
}

# service_flags SERVICE -> DEPLOY_FLAGS plus DEPLOY_FLAGS_<SERVICE> (codemender-webhook -> WEBHOOK).
service_flags() {
    local suffix var
    suffix="$(echo "${1#codemender-}" | tr '[:lower:]-' '[:upper:]_')"
    var="DEPLOY_FLAGS_${suffix}"
    echo "${DEPLOY_FLAGS:-} ${!var:-}"
}

require_clean_head() {
    [[ -z "$(git status --porcelain)" ]] || die "the working tree has uncommitted changes; commit first"
    [[ "$(git rev-parse HEAD)" == "$SHA" ]] || die "SHA $SHA is not HEAD; check out that commit to build it"
}

cmd_build() {
    [[ -z "$IMAGE_FROM_ENV" ]] || die "IMAGE is set; build always builds and tags the committed SHA"
    require_clean_head
    if image_exists; then
        echo "Image already built: $IMAGE"
        return
    fi
    "$ROOT/scripts/check.sh"
    BUILD_SRC="$(mktemp -d)"
    trap 'rm -rf "$BUILD_SRC"' EXIT
    git archive "$SHA" | tar -x -C "$BUILD_SRC"
    gc builds submit "$BUILD_SRC" --tag="$IMAGE"
    echo "Built $IMAGE ($(image_digest))"
}

cmd_deploy() {
    local pinned
    pinned="$(pinned_image)"
    for svc in "${SERVICES[@]}"; do
        local extra=()
        read -r -a extra <<< "$(service_flags "$svc")"
        echo "== $svc: deploying ${pinned##*@} with no traffic (tag $TAG)${extra[*]+; flags: ${extra[*]}}"
        run_gc deploy "$svc" --image="$pinned" --no-traffic --tag="$TAG" --no-cpu-throttling ${extra[@]+"${extra[@]}"}
    done
    cmd_status
}

# check NAME EXPECTED_CODE CURL_ARGS... (the identity token is passed on stdin, never in argv)
check() {
    local name="$1" expected="$2"
    shift 2
    local code
    code="$(printf 'Authorization: Bearer %s\n' "$ID_TOKEN" | curl -sS -o /dev/null -w '%{http_code}' -H @- "$@" || true)"
    if [[ "$code" == "$expected" ]]; then
        echo "  ok   $name -> $code"
    else
        echo "  FAIL $name -> $code (expected $expected)"
        SMOKE_FAILED=1
    fi
}

# revision_check SERVICE: the tagged revision runs an image pinned by digest, with MOCK_MODE=false.
revision_check() {
    local rev
    rev="$(traffic_field "$1" "$TAG" revisionName)"
    echo "== $1: revision $rev"
    run_gc revisions describe "$rev" --format=json | python3 -c '
import json, sys
spec = json.load(sys.stdin).get("spec", {})
container = (spec.get("containers") or [{}])[0]
env = {e.get("name"): e.get("value") for e in container.get("env", []) if "value" in e}
image = container.get("image", "")
problems = []
if "@sha256:" not in image:
    problems.append("image is not pinned by digest: %s" % image)
if str(env.get("MOCK_MODE", "false")).strip().lower() != "false":
    problems.append("MOCK_MODE=%s" % env.get("MOCK_MODE"))
print("  sa=%s digest=%s" % (spec.get("serviceAccountName"), image.rsplit("@", 1)[-1][:19]))
for problem in problems:
    print("  FAIL " + problem)
sys.exit(1 if problems else 0)'
}

cmd_smoke() {
    SMOKE_FAILED=0
    for svc in "${SERVICES[@]}"; do
        revision_check "$svc" || SMOKE_FAILED=1
    done
    ID_TOKEN="$(gcloud auth print-identity-token)"
    for svc in "${SERVICES[@]}"; do
        [[ " ${SMOKE_SERVICES[*]} " == *" $svc "* ]] || continue  # only services in this release with external tag URLs
        local url
        url="$(traffic_field "$svc" "$TAG" url)"
        echo "== $svc ($url)"
        check "GET /health" 200 "$url/health"
        if [[ "$svc" == "codemender-webhook" ]]; then
            check "GET /api/scans is not served (WEBHOOK_ONLY)" 404 "$url/api/scans"
            check "POST /github-webhook without WIF or signature" 401 -X POST -H "X-GitHub-Event: ping" -d '{}' "$url/github-webhook"
        else
            check "POST cancel without an IAP identity" 401 -X POST "$url/api/scans/smoke/cancel"
        fi
    done
    unset ID_TOKEN
    echo "codemender-dashboard: ingress is internal-and-cloud-load-balancing; check it through the load balancer."
    [[ "$SMOKE_FAILED" == 0 ]] || die "smoke checks failed"
}

# preflight_no_running_tasks: promotion stops the old revision's instances, which interrupts running
# scan/verify/fix tasks (conflict review C2), so promote waits until none is running.
preflight_no_running_tasks() {
    local rc=0
    echo "== checking for running CodeMender tasks"
    local py=python3
    [[ -x "$ROOT/.venv/bin/python" ]] && py="$ROOT/.venv/bin/python"
    gcloud auth print-access-token 2>/dev/null | "$py" "$ROOT/scripts/inflight_scans.py" "$PROJECT_ID" || rc=$?
    if [[ "$rc" == 0 ]]; then
        return 0
    fi
    if [[ "${FORCE:-}" == 1 ]]; then
        echo "FORCE=1: promoting anyway (the shutdown hook closes out interrupted tasks)."
        return 0
    fi
    if [[ "$rc" == 3 ]]; then
        die "tasks are running; promoting now would interrupt them (wait, or set FORCE=1)"
    fi
    die "could not check for running tasks (set FORCE=1 to promote anyway)"
}

cmd_promote() {
    preflight_no_running_tasks
    for svc in "${SERVICES[@]}"; do
        local rev previous
        rev="$(traffic_field "$svc" "$TAG" revisionName)"
        previous="$(serving_revisions "$svc")"
        echo "== $svc: ${previous:-none} -> $rev=100"
        echo "   rollback: scripts/release.sh rollback $svc ${previous%%=*}"
        run_gc services update-traffic "$svc" --to-revisions="$rev=100"
    done
}

cmd_rollback() {
    local svc="${1:-}" rev="${2:-}"
    [[ -n "$svc" && -n "$rev" ]] || die "usage: scripts/release.sh rollback SERVICE REVISION"
    run_gc services update-traffic "$svc" --to-revisions="$rev=100"
}

cmd_prune_tags() {
    local confirm="${1:-}"
    for svc in "${SERVICES[@]}"; do
        local stale
        stale="$(describe_json "$svc" | python3 -c '
import json, sys
keep = sys.argv[1]
entries = json.load(sys.stdin).get("status", {}).get("traffic", [])
print(",".join(e["tag"] for e in entries if e.get("tag") and e["tag"] != keep and not e.get("percent")))' "$TAG")"
        if [[ -z "$stale" ]]; then
            echo "== $svc: no stale tags"
            continue
        fi
        echo "== $svc: removing tags $stale (revisions are kept)"
        if [[ "$confirm" == "--yes" ]]; then
            run_gc services update-traffic "$svc" --remove-tags="$stale"
        fi
    done
    [[ "$confirm" == "--yes" ]] || echo "Dry run. Re-run with --yes to remove the tags."
}

cmd_status() {
    for svc in "${SERVICES[@]}"; do
        echo "== $svc"
        describe_json "$svc" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for e in d.get("status", {}).get("traffic", []):
    target = ("LATEST -> %s" % e.get("revisionName")) if e.get("latestRevision") else e.get("revisionName")
    print("  %3s%%  %s  %s" % (e.get("percent", 0), target, e.get("tag", "")))'
    done
}

case "${1:-}" in
    build) cmd_build ;;
    deploy) cmd_deploy ;;
    smoke) cmd_smoke ;;
    promote) cmd_promote ;;
    rollback) shift; cmd_rollback "$@" ;;
    prune-tags) shift; cmd_prune_tags "$@" ;;
    status) cmd_status ;;
    *) awk 'NR >= 19 && /^#/ { print; next } NR >= 19 { exit }' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
