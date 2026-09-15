# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# you may obtain a copy of the License at
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

import logging
from google.cloud import firestore

logger = logging.getLogger(__name__)

# Initialize Firestore Client (connects to standard default DB under active project)
db = firestore.Client()

def save_patch_proposal(commit_sha: str, branch_name: str, filename: str, git_diff: str, patched_code: str, pr_number: int = None, patch_commit_sha: str = None):
    """Saves the proposed patch diff and metadata to Firestore keyed by base commit SHA."""
    import time
    try:
        doc_ref = db.collection("patches").document(commit_sha)
        data = {
            "commit_sha": commit_sha,
            "branch_name": branch_name,
            "filename": filename,
            "git_diff": git_diff,
            "patched_code": patched_code,
            "is_applied": False,
            "created_at": time.time()
        }
        if pr_number is not None:
            data["pr_number"] = pr_number
        if patch_commit_sha is not None:
            data["patch_commit_sha"] = patch_commit_sha
        doc_ref.set(data, merge=True)
        logger.info(f"Saved patch proposal to Firestore for commit {commit_sha} (PR: {pr_number}, Patch SHA: {patch_commit_sha})")
    except Exception as e:
        logger.error(f"Failed to write patch proposal to Firestore: {e}")
        raise

def list_patch_proposals() -> list[dict]:
    """Retrieves all patch proposals from Firestore, sorted by created_at descending in memory."""
    try:
        patches_ref = db.collection("patches")
        docs = patches_ref.stream()
        results = []
        for doc in docs:
            results.append(doc.to_dict())
        results.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return results
    except Exception as e:
        logger.error(f"Failed to list patch proposals: {e}")
        return []


def get_patch_proposal(commit_sha: str) -> dict:
    """Retrieves the patch metadata from Firestore using the commit SHA."""
    try:
        doc_ref = db.collection("patches").document(commit_sha)
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        logger.warning(f"No patch proposal found in Firestore for commit {commit_sha}")
        return {}
    except Exception as e:
        logger.error(f"Failed to read patch proposal from Firestore: {e}")
        raise

def get_patch_proposal_by_pr(pr_number: int, unapplied_only: bool = True) -> dict:
    """Retrieves the latest patch metadata from Firestore for a given PR number."""
    try:
        patches_ref = db.collection("patches")
        docs = patches_ref.where("pr_number", "==", pr_number).stream()
        proposals = [d.to_dict() for d in docs]
        # Sort descending by created_at
        proposals.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        if unapplied_only:
            unapplied = [p for p in proposals if not p.get("is_applied")]
            if unapplied:
                return unapplied[0]
        if proposals:
            return proposals[0]
        logger.warning(f"No patch proposal found in Firestore for PR #{pr_number}")
        return {}
    except Exception as e:
        logger.error(f"Failed to query patch proposal from Firestore: {e}")
        raise

def mark_patch_as_applied(pr_number: int, commit_sha: str = None):
    """Marks a patch proposal as applied in Firestore."""
    try:
        if commit_sha:
            db.collection("patches").document(commit_sha).update({
                "is_applied": True
            })
            logger.info(f"Marked patch proposal {commit_sha} as applied in Firestore")
            return
            
        patches_ref = db.collection("patches")
        docs = patches_ref.where("pr_number", "==", pr_number).stream()
        proposals = [(d.id, d.to_dict()) for d in docs]
        proposals.sort(key=lambda x: x[1].get("created_at", 0), reverse=True)
        for doc_id, p in proposals:
            if not p.get("is_applied"):
                db.collection("patches").document(doc_id).update({
                    "is_applied": True
                })
                logger.info(f"Marked patch for PR #{pr_number} (doc: {doc_id}) as applied in Firestore")
                return
    except Exception as e:
        logger.error(f"Failed to update patch status in Firestore: {e}")
        raise

def acquire_lock(lock_id: str, ttl_seconds: int = 240) -> bool:
    """Attempts to atomically acquire a lock for a given lock_id in Firestore using a transaction."""
    import time
    try:
        transaction = db.transaction()
        doc_ref = db.collection("locks").document(lock_id)
        
        @firestore.transactional
        def _tx(tx):
            snapshot = doc_ref.get(transaction=tx)
            now = time.time()
            if snapshot.exists:
                data = snapshot.to_dict()
                locked_at = data.get("locked_at", 0)
                if now - locked_at < ttl_seconds:
                    return False
            tx.set(doc_ref, {
                "lock_id": lock_id,
                "locked_at": now
            })
            return True
            
        return _tx(transaction)
    except Exception as e:
        logger.error(f"Failed to acquire lock for {lock_id}: {e}")
        return False

def release_lock(lock_id: str):
    """Releases a lock by deleting the lock document from Firestore."""
    try:
        db.collection("locks").document(lock_id).delete()
        logger.info(f"Released lock for {lock_id}")
    except Exception as e:
        logger.error(f"Failed to release lock for {lock_id}: {e}")

def update_scan_status(commit_sha: str, branch_name: str = None, status: str = None, message: str = None, findings: list = None, logs: dict = None, pr_number: int = None, repo_name: str = None, pusher_name: str = None, pusher_email: str = None, target_file: str = None, is_draft: bool = None, pr_title: str = None, pr_url: str = None, base_branch: str = None, is_superseded: bool = None):
    """Updates the scan status, progress message, findings, logs, repo_name, pr_number, pusher details, draft state, and target_file for a given commit SHA in Firestore."""
    import time
    try:
        doc_ref = db.collection("scans").document(commit_sha)
        data = {}
        if branch_name:
            data["branch_name"] = branch_name
        if status:
            data["status"] = status
        if message:
            data["message"] = message
        if findings is not None:
            data["findings"] = findings
        if logs is not None:
            data["logs"] = logs
        if pr_number is not None:
            data["pr_number"] = pr_number
        if repo_name:
            data["repo_name"] = repo_name
        if pusher_name:
            data["pusher_name"] = pusher_name
        if pusher_email:
            data["pusher_email"] = pusher_email
        if target_file:
            data["target_file"] = target_file
        if is_draft is not None:
            data["is_draft"] = is_draft
        if pr_title:
            data["pr_title"] = pr_title
        if pr_url:
            data["pr_url"] = pr_url
        if base_branch:
            data["base_branch"] = base_branch
        if is_superseded is not None:
            data["is_superseded"] = is_superseded
        data["updated_at"] = time.time()
        
        doc_ref.set(data, merge=True)
        logger.info(f"Updated scan status for commit {commit_sha}: {status} - {message} (findings: {len(findings) if findings else 0}, PR: #{pr_number})")
    except Exception as e:
        logger.error(f"Failed to update scan status in Firestore: {e}")


def append_scan_step(commit_sha: str, step_type: str, message: str):
    """Atomically appends a progress step to the steps list of a scan document in Firestore."""
    import time
    try:
        doc_ref = db.collection("scans").document(commit_sha)
        doc_ref.set({
            "steps": firestore.ArrayUnion([{
                "timestamp": time.time(),
                "type": step_type,
                "message": message
            }])
        }, merge=True)
        logger.info(f"Appended scan step for commit {commit_sha} ({step_type}): {message}")
    except Exception as e:
        logger.error(f"Failed to append scan step in Firestore: {e}")


def list_scans() -> list[dict]:
    """Retrieves all scan statuses from Firestore, sorted by updated_at descending."""
    try:
        scans_ref = db.collection("scans")
        docs = scans_ref.stream()
        results = []
        for doc in docs:
            d = doc.to_dict()
            if not d:
                continue
            # Filter out SKIPPED scans from cluttering the active dashboard feed
            if d.get("status") == "SKIPPED":
                continue
            d["commit_sha"] = doc.id
            results.append(d)
        results.sort(key=lambda x: x.get("updated_at", 0), reverse=True)
        return results
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        return []

def get_scan_repo_name(commit_sha: str) -> str:
    """Retrieves the repository name for a given commit SHA from Firestore."""
    try:
        doc = db.collection("scans").document(commit_sha).get()
        if doc.exists:
            return doc.to_dict().get("repo_name", "codemender-workspace")
    except Exception as e:
        logger.error(f"Failed to get scan repo name for {commit_sha}: {e}")
    return "codemender-workspace"

# BigQuery Analytics Layer Support
try:
    from google.cloud import bigquery
    bq_client = bigquery.Client()
except Exception as bq_init_err:
    logger.warning(f"BigQuery client could not be initialized: {bq_init_err}")
    bq_client = None

def ensure_bigquery_table():
    """Checks if the analytics dataset and table exist in BigQuery, and creates them if they do not exist."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping table verification.")
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.applied_security_patches"
    
    # 1. Create dataset if not exists
    try:
        bq_client.get_dataset(dataset_id)
        logger.info(f"BigQuery dataset {dataset_id} already exists.")
    except Exception:
        logger.info(f"BigQuery dataset {dataset_id} not found. Creating...")
        dataset = bigquery.Dataset(dataset_id)
        dataset.location = "US"
        bq_client.create_dataset(dataset, timeout=30)
        logger.info(f"Created BigQuery dataset {dataset_id}.")
        
    # 2. Create table if not exists
    try:
        bq_client.get_table(table_id)
        logger.info(f"BigQuery table {table_id} already exists.")
    except Exception:
        logger.info(f"BigQuery table {table_id} not found. Creating...")
        schema = [
            bigquery.SchemaField("merge_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("pr_number", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("branch", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("commit_sha", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("merged_at", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("merged_by", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("time_to_remediate_sec", "INTEGER", mode="REQUIRED"),
            
            # Discovery Metrics
            bigquery.SchemaField("total_findings", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("critical_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("high_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("medium_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("low_count", "INTEGER", mode="REQUIRED"),
            
            # Verification Metrics
            bigquery.SchemaField("verified_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("verified_finding_ids", "STRING", mode="NULLABLE"),
            
            # Patch Metrics
            bigquery.SchemaField("patched_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("patched_finding_ids", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("unpatched_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("unpatched_finding_ids", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("remediation_rate_pct", "FLOAT", mode="REQUIRED"),
            
            # Full Structured Payload
            bigquery.SchemaField("findings_full_json", "STRING", mode="REQUIRED"),
        ]
        table = bigquery.Table(table_id, schema=schema)
        bq_client.create_table(table, timeout=30)
        logger.info(f"Created BigQuery table {table_id}.")

def insert_analytics_patch_merged(row: dict):
    """Asynchronously streams a row representing a merged patch into the applied_security_patches table in BigQuery."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping analytics streaming.")
        return
    ensure_bigquery_table()
    dataset_id = "codemender_analytics"
    table_id = "applied_security_patches"
    table_ref = bq_client.dataset(dataset_id).table(table_id)
    
    # We use insert_rows_json to perform a streaming insert
    errors = bq_client.insert_rows_json(table_ref, [row])
    if errors:
        logger.error(f"Failed to stream row to BigQuery applied_security_patches table. Errors: {errors}")
        raise RuntimeError(f"BigQuery insert failed: {errors}")
    else:
        logger.info(f"Successfully streamed merged PR analytics row to BigQuery: {row.get('pr_number')}")

def ensure_dismissed_audit_table():
    """Checks if the dismissed_vulnerabilities_audit table exists in BigQuery, and creates it if not."""
    if not bq_client:
        return
    from google.api_core.exceptions import NotFound, Conflict
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.dismissed_vulnerabilities_audit"
    
    try:
        bq_client.get_dataset(dataset_id)
    except Exception:
        try:
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = "US"
            bq_client.create_dataset(dataset, timeout=30)
        except Exception:
            pass
            
    try:
        bq_client.get_table(table_id)
    except NotFound:
        try:
            schema = [
                bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
                bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("pr_number", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("commit_sha", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("finding_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("vuln_type", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("severity", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("dismissed_by", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("category", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("reason", "STRING", mode="REQUIRED"),
            ]
            table = bigquery.Table(table_id, schema=schema)
            bq_client.create_table(table, timeout=30)
            logger.info(f"Created BigQuery table {table_id}.")
        except Conflict:
            pass
    except Exception as e:
        logger.debug(f"Table check note: {e}")

def insert_analytics_finding_dismissed(row: dict):
    """Streams a risk acceptance/dismissal record to the dismissed_vulnerabilities_audit BigQuery table."""
    if not bq_client:
        return
    ensure_dismissed_audit_table()
    dataset_id = "codemender_analytics"
    table_id = "dismissed_vulnerabilities_audit"
    table_ref = bq_client.dataset(dataset_id).table(table_id)
    
    errors = bq_client.insert_rows_json(table_ref, [row])
    if errors:
        logger.error(f"Failed to stream row to BigQuery dismissed_vulnerabilities_audit table: {errors}")
    else:
        logger.info(f"Successfully streamed dismissal audit row to BigQuery: finding {row.get('finding_id')}")

def ensure_token_usage_table():
    """Checks if the analytics dataset and token_usage_log table exist in BigQuery, and creates them if they do not exist."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping token usage table verification.")
        return
    from google.api_core.exceptions import NotFound, Conflict
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.token_usage_log"
    
    # 1. Create dataset if not exists
    try:
        bq_client.get_dataset(dataset_id)
    except NotFound:
        try:
            logger.info(f"BigQuery dataset {dataset_id} not found. Creating...")
            dataset = bigquery.Dataset(dataset_id)
            dataset.location = "US"
            bq_client.create_dataset(dataset, timeout=30)
            logger.info(f"Created BigQuery dataset {dataset_id}.")
        except Conflict:
            pass
    except Exception as e:
        logger.debug(f"Note on dataset check: {e}")
        
    # 2. Create table if not exists or migrate missing columns
    schema = [
        bigquery.SchemaField("log_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
        bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("session_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("task_type", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("model_name", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("input_tokens", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("output_tokens", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("cached_tokens", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("thoughts_tokens", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("total_tokens", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("cost_usd", "FLOAT", mode="REQUIRED"),
        bigquery.SchemaField("compute_cost_usd", "FLOAT", mode="NULLABLE"),
        bigquery.SchemaField("license_cost_usd", "FLOAT", mode="NULLABLE"),
        bigquery.SchemaField("cached_savings_usd", "FLOAT", mode="NULLABLE"),
        bigquery.SchemaField("pricing_tier", "STRING", mode="NULLABLE"),
        bigquery.SchemaField("duration_sec", "FLOAT", mode="NULLABLE"),
    ]
    try:
        table = bq_client.get_table(table_id)
        existing_names = [f.name for f in table.schema]
        missing_fields = [f for f in schema if f.name not in existing_names]
        if missing_fields:
            table.schema = list(table.schema) + missing_fields
            bq_client.update_table(table, ["schema"])
            logger.info(f"Updated schema for BigQuery table {table_id} with new fields: {[f.name for f in missing_fields]}")
        else:
            logger.info(f"BigQuery table {table_id} already exists with full schema.")
    except NotFound:
        try:
            logger.info(f"BigQuery table {table_id} not found. Creating...")
            table = bigquery.Table(table_id, schema=schema)
            bq_client.create_table(table, timeout=30)
            logger.info(f"Created BigQuery table {table_id}.")
        except Conflict:
            pass
    except Exception as e:
        logger.debug(f"Note on table check: {e}")

def calculate_token_cost(model_name: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0, thoughts_tokens: int = 0, is_codemender_task: bool = True) -> dict:
    """Calculates Gemini API cost in USD broken down by Compute (Layer 1) and CodeMender Software License (Layer 2) matching Google Cloud Billing SKUs."""
    model_str = (model_name or "gemini-3-flash-preview").lower()
    
    if "3.5" in model_str or "3.5-flash" in model_str:
        # Layer 1: Vertex AI Gemini 3.5 Flash Compute SKU
        compute_input_rate = 1.50 / 1_000_000.0
        compute_cached_rate = 0.15 / 1_000_000.0
        compute_output_rate = 9.00 / 1_000_000.0
        compute_thoughts_rate = 9.00 / 1_000_000.0
        
        # Layer 2: CodeMender Gemini 3.5 Flash Software License SKU
        license_input_rate = 1.50 / 1_000_000.0 if is_codemender_task else 0.0
        license_cached_rate = 0.15 / 1_000_000.0 if is_codemender_task else 0.0
        license_output_rate = 9.00 / 1_000_000.0 if is_codemender_task else 0.0
        license_thoughts_rate = 9.00 / 1_000_000.0 if is_codemender_task else 0.0
        pricing_tier = "DUAL_TIER_CODEMENDER" if is_codemender_task else "SINGLE_TIER_COMPUTE"
        
    elif "3.1-pro" in model_str or "pro" in model_str:
        # Layer 1: Vertex AI Gemini 3.1 Pro Compute SKU ($2.00 / $0.20 / $12.00)
        compute_input_rate = 2.00 / 1_000_000.0
        compute_cached_rate = 0.20 / 1_000_000.0
        compute_output_rate = 12.00 / 1_000_000.0
        compute_thoughts_rate = 12.00 / 1_000_000.0
        
        # Layer 2: CodeMender Gemini 3.1 Pro Software License SKU ($2.00 / $0.20 / $12.00)
        license_input_rate = 2.00 / 1_000_000.0 if is_codemender_task else 0.0
        license_cached_rate = 0.20 / 1_000_000.0 if is_codemender_task else 0.0
        license_output_rate = 12.00 / 1_000_000.0 if is_codemender_task else 0.0
        license_thoughts_rate = 12.00 / 1_000_000.0 if is_codemender_task else 0.0
        pricing_tier = "DUAL_TIER_CODEMENDER" if is_codemender_task else "SINGLE_TIER_COMPUTE"

    elif "gemini-3-flash" in model_str or "3-flash" in model_str:
        # Layer 1: Vertex AI Gemini 3 Flash Compute SKU ($0.50 / $0.05 / $3.00)
        compute_input_rate = 0.50 / 1_000_000.0
        compute_cached_rate = 0.05 / 1_000_000.0
        compute_output_rate = 3.00 / 1_000_000.0
        compute_thoughts_rate = 3.00 / 1_000_000.0
        
        # Layer 2: CodeMender Gemini 3 Flash Software License SKU ($0.50 / $0.05 / $3.00)
        license_input_rate = 0.50 / 1_000_000.0 if is_codemender_task else 0.0
        license_cached_rate = 0.05 / 1_000_000.0 if is_codemender_task else 0.0
        license_output_rate = 3.00 / 1_000_000.0 if is_codemender_task else 0.0
        license_thoughts_rate = 3.00 / 1_000_000.0 if is_codemender_task else 0.0
        pricing_tier = "DUAL_TIER_CODEMENDER" if is_codemender_task else "SINGLE_TIER_COMPUTE"
        
    else:  # Gemini 2.5 Flash / Helper Sub-agents tier
        compute_input_rate = 0.15 / 1_000_000.0
        compute_cached_rate = 0.0375 / 1_000_000.0
        compute_output_rate = 0.60 / 1_000_000.0
        compute_thoughts_rate = 2.50 / 1_000_000.0
        
        license_input_rate = 0.0
        license_cached_rate = 0.0
        license_output_rate = 0.0
        license_thoughts_rate = 0.0
        pricing_tier = "SINGLE_TIER_COMPUTE"

    non_cached_input = max(0, input_tokens - cached_tokens)
    
    compute_cost = (non_cached_input * compute_input_rate) + (cached_tokens * compute_cached_rate) + (output_tokens * compute_output_rate) + (thoughts_tokens * compute_thoughts_rate)
    license_cost = (non_cached_input * license_input_rate) + (cached_tokens * license_cached_rate) + (output_tokens * license_output_rate) + (thoughts_tokens * license_thoughts_rate)
    total_cost = compute_cost + license_cost
    
    # Calculate dollar savings from Context Caching (uncached price minus cached price across both tiers)
    cached_savings = cached_tokens * ((compute_input_rate - compute_cached_rate) + (license_input_rate - license_cached_rate))
    
    return {
        "compute_cost_usd": float(compute_cost),
        "license_cost_usd": float(license_cost),
        "total_cost_usd": float(total_cost),
        "cached_savings_usd": float(cached_savings),
        "pricing_tier": pricing_tier
    }

def parse_cm_session_metrics(output_text: str = "", log_file_path: str = None) -> dict:
    """Extracts exact token metrics from CodeMender structured JSONL session interaction logs or fallback text logs."""
    import re
    import glob
    import os
    import json
    import time

    metrics = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cached_tokens": 0,
        "thoughts_tokens": 0,
        "total_tokens": 0,
        "source": "none"
    }

    # 1. Discover session ID or log path
    cm_sess_id = None
    if output_text:
        sess_match = re.search(r"Session:\s*([a-zA-Z0-9_-]+)", output_text, re.IGNORECASE)
        if sess_match:
            cm_sess_id = sess_match.group(1).strip()
        if not log_file_path:
            log_path_match = re.search(r"Session log:\s*([^\s\n]+)", output_text)
            if log_path_match:
                log_file_path = log_path_match.group(1).strip()

    # 2. Check for native JSONL session file (~/.codemender/logs/sessions/*/*.jsonl)
    jsonl_files = []
    sessions_base_dir = os.path.expanduser("~/.codemender/logs/sessions")
    if os.path.exists(sessions_base_dir):
        candidate_jsonls = glob.glob(os.path.join(sessions_base_dir, "*", "*.jsonl"))
        if candidate_jsonls:
            if cm_sess_id:
                jsonl_files = [f for f in candidate_jsonls if cm_sess_id[:8] in os.path.basename(f)]
            if not jsonl_files:
                candidate_jsonls.sort(key=os.path.getmtime, reverse=True)
                if time.time() - os.path.getmtime(candidate_jsonls[0]) < 300.0:
                    jsonl_files = [candidate_jsonls[0]]

    # Parse JSONL interaction events if found
    for jf in jsonl_files:
        try:
            with open(jf, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("type") == "interaction":
                            # Exact integer tokens from CLI multi-turn interaction
                            inp = int(record.get("input", 0))
                            out = int(record.get("output", 0))
                            cached = int(record.get("cached", 0))
                            thought = int(record.get("thought", 0))
                            tot = int(record.get("total", 0))
                            
                            metrics["input_tokens"] += inp
                            metrics["output_tokens"] += out
                            metrics["cached_tokens"] += cached
                            metrics["thoughts_tokens"] += thought
                            metrics["total_tokens"] += tot
                            metrics["source"] = "jsonl"
                    except json.JSONDecodeError:
                        continue
            if metrics["total_tokens"] > 0 or metrics["input_tokens"] > 0:
                logger.info(f"Successfully extracted exact JSONL session metrics from {jf}: {metrics}")
                return metrics
        except Exception as err:
            logger.warning(f"Failed reading JSONL session file {jf}: {err}")

    # 3. Fallback: Parse stdout or text log via regex
    log_content = ""
    if log_file_path and os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as lf:
                log_content = lf.read()
        except Exception:
            pass
    elif not log_content:
        logs_dir = os.path.expanduser("~/.codemender/logs")
        if os.path.exists(logs_dir):
            txt_logs = glob.glob(os.path.join(logs_dir, "*.log"))
            non_pending = [lf for lf in txt_logs if not lf.endswith("_pending.log")]
            non_pending.sort(key=os.path.getmtime, reverse=True)
            if non_pending and time.time() - os.path.getmtime(non_pending[0]) < 300.0:
                try:
                    with open(non_pending[0], "r", encoding="utf-8") as lf:
                        log_content = lf.read()
                except Exception:
                    pass

    content_to_scan = log_content if log_content else output_text
    if content_to_scan:
        def to_num(s):
            s = s.strip().lower()
            if s.endswith("k"):
                return int(float(s[:-1]) * 1000)
            return int(float(s))

        pattern = r"(?:Completed\s+(\d+)\s+tool steps.*?\|\s*)?Tokens:\s*([0-9.]+[k]?)\s*in\s*/\s*([0-9.]+[k]?)\s*out(?:\s*/\s*([0-9.]+[k]?)\s*total)?"
        matches = re.findall(pattern, content_to_scan, re.IGNORECASE)
        for steps_str, inp_str, out_str, tot_str in matches:
            num_steps = int(steps_str) if steps_str else 1
            inp = to_num(inp_str)
            out = to_num(out_str)
            tot = to_num(tot_str) if tot_str else (inp + out)
            cum_input = int(inp * (num_steps + 1) / 2) if num_steps > 1 else inp
            thoughts = max(0, tot - (inp + out))

            metrics["input_tokens"] += cum_input
            metrics["output_tokens"] += out
            metrics["thoughts_tokens"] += thoughts
            metrics["total_tokens"] += (cum_input + out + thoughts)
            metrics["source"] = "regex"

    return metrics

def parse_and_log_cm_session(session_id: str, repo_name: str, task_type: str, model_name: str, output_text: str, duration_sec: float = None, log_file_path: str = None):
    """Parses CodeMender CLI session metrics and logs cumulative token usage to BigQuery."""
    try:
        metrics = parse_cm_session_metrics(output_text=output_text, log_file_path=log_file_path)
        if metrics["input_tokens"] > 0 or metrics["output_tokens"] > 0 or metrics["total_tokens"] > 0:
            logger.info(
                f"Logging CodeMender CLI token usage for task '{task_type}' (Model: {model_name}) -> "
                f"Input: {metrics['input_tokens']}, Output: {metrics['output_tokens']}, Cached: {metrics['cached_tokens']}, "
                f"Thoughts: {metrics['thoughts_tokens']}, Source: {metrics['source']}, Duration: {duration_sec:.2f}s"
            )
            log_token_usage(
                session_id=session_id,
                repo_name=repo_name,
                task_type=task_type,
                model_name=model_name,
                input_tokens=metrics["input_tokens"],
                output_tokens=metrics["output_tokens"],
                cached_tokens=metrics["cached_tokens"],
                thoughts_tokens=metrics["thoughts_tokens"],
                duration_sec=duration_sec
            )
    except Exception as e:
        logger.warning(f"Failed to parse and log CodeMender session tokens: {e}")

def log_token_usage(session_id: str, repo_name: str, task_type: str, model_name: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0, thoughts_tokens: int = 0, duration_sec: float = None):
    """Streams a token usage log entry to BigQuery for cost and audit analytics."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping token usage logging.")
        return
    import uuid
    import time
    from datetime import datetime, UTC
    
    try:
        ensure_token_usage_table()
        
        is_cm_task = task_type in ["cm_find", "cm_verify", "cm_fix", "scan", "verify", "patch"]
        cost_breakdown = calculate_token_cost(
            model_name=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_tokens=cached_tokens,
            thoughts_tokens=thoughts_tokens,
            is_codemender_task=is_cm_task
        )
        
        total_tokens = input_tokens + output_tokens + thoughts_tokens
        
        row = {
            "log_id": str(uuid.uuid4()),
            "timestamp": datetime.fromtimestamp(time.time(), UTC).isoformat(),
            "repo_name": repo_name,
            "session_id": session_id,
            "task_type": task_type,
            "model_name": model_name,
            "input_tokens": int(input_tokens),
            "output_tokens": int(output_tokens),
            "cached_tokens": int(cached_tokens),
            "thoughts_tokens": int(thoughts_tokens),
            "total_tokens": int(total_tokens),
            "cost_usd": float(cost_breakdown["total_cost_usd"]),
            "compute_cost_usd": float(cost_breakdown["compute_cost_usd"]),
            "license_cost_usd": float(cost_breakdown["license_cost_usd"]),
            "cached_savings_usd": float(cost_breakdown["cached_savings_usd"]),
            "pricing_tier": str(cost_breakdown["pricing_tier"]),
            "duration_sec": float(duration_sec) if duration_sec is not None else None
        }
        
        dataset_id = "codemender_analytics"
        table_id = "token_usage_log"
        table_ref = bq_client.dataset(dataset_id).table(table_id)
        
        errors = bq_client.insert_rows_json(table_ref, [row])
        if errors:
            logger.error(f"Failed to stream row to BigQuery token_usage_log table: {errors}")
        else:
            logger.info(f"Successfully logged token usage to BigQuery: {total_tokens} tokens (${cost_breakdown['total_cost_usd']:.6f}) for task '{task_type}'")
    except Exception as e:
        logger.error(f"Error logging token usage to BigQuery: {e}")

def get_token_analytics(range_days: int = 7, start_date: str = None, end_date: str = None) -> dict:
    """Queries BigQuery to retrieve aggregated token usage and cost metrics.
    Supports either rolling `range_days` or explicit `start_date` and `end_date` (YYYY-MM-DD).
    """
    if not bq_client:
        logger.warning("BigQuery client not active. Returning empty analytics payload.")
        return {}
        
    try:
        ensure_token_usage_table()
    except Exception as table_err:
        logger.warning(f"Note on ensure_token_usage_table in analytics: {table_err}")

    project = bq_client.project
    table_path = f"{project}.codemender_analytics.token_usage_log"
    
    # Build dynamic WHERE filter and parameters (Aligned with Google Cloud Billing PST/PDT America/Los_Angeles timezone)
    if start_date and end_date:
        where_clause = "WHERE timestamp >= TIMESTAMP(@start_date, 'America/Los_Angeles') AND timestamp < TIMESTAMP_ADD(TIMESTAMP(@end_date, 'America/Los_Angeles'), INTERVAL 1 DAY)"
        query_params = [
            bigquery.ScalarQueryParameter("start_date", "STRING", start_date),
            bigquery.ScalarQueryParameter("end_date", "STRING", end_date)
        ]
    else:
        where_clause = "WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL @range_days DAY)"
        query_params = [
            bigquery.ScalarQueryParameter("range_days", "INT64", range_days or 7)
        ]
    
    # 1. Total summary stats (Row-level COALESCE ensures historical rows without bifurcated columns are properly split)
    q_summary = f"""
        SELECT 
          COALESCE(SUM(cost_usd), 0.0) as total_cost,
          COALESCE(SUM(COALESCE(compute_cost_usd, cost_usd / 2.0)), 0.0) as compute_cost,
          COALESCE(SUM(COALESCE(license_cost_usd, cost_usd / 2.0)), 0.0) as license_cost,
          COALESCE(SUM(COALESCE(cached_savings_usd, 
            CASE 
              WHEN cached_tokens > 0 THEN cached_tokens * ((1.50 - 0.15) + (1.50 - 0.15)) / 1000000.0 
              ELSE 0.0 
            END
          )), 0.0) as cached_savings,
          COALESCE(SUM(total_tokens), 0) as total_tokens,
          COALESCE(SUM(input_tokens), 0) as input_tokens,
          COALESCE(SUM(output_tokens), 0) as output_tokens,
          COALESCE(SUM(cached_tokens), 0) as cached_tokens,
          COALESCE(SUM(thoughts_tokens), 0) as thoughts_tokens,
          COUNT(DISTINCT session_id) as total_sessions,
          COUNTIF(task_type IN ('cm_find', 'scan')) as total_scans,
          COUNTIF(task_type IN ('cm_verify', 'verify')) as total_verifications,
          COUNTIF(task_type IN ('cm_fix', 'patch', 'fix')) as total_patches
        FROM `{table_path}`
        {where_clause}
    """

    # 1.5. SKU Line-Item Reconciliation stats
    q_sku = f"""
        SELECT
          -- CM Find
          COALESCE(SUM(CASE WHEN task_type IN ('cm_find', 'scan') THEN input_tokens ELSE 0 END), 0) as cm_find_input,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_find', 'scan') THEN output_tokens ELSE 0 END), 0) as cm_find_output,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_find', 'scan') THEN cached_tokens ELSE 0 END), 0) as cm_find_cached,
          
          -- CM Verify
          COALESCE(SUM(CASE WHEN task_type IN ('cm_verify', 'verify') THEN input_tokens ELSE 0 END), 0) as cm_verify_input,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_verify', 'verify') THEN output_tokens ELSE 0 END), 0) as cm_verify_output,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_verify', 'verify') THEN cached_tokens ELSE 0 END), 0) as cm_verify_cached,
          
          -- CM Fix / Patch
          COALESCE(SUM(CASE WHEN task_type IN ('cm_fix', 'patch', 'fix') THEN input_tokens ELSE 0 END), 0) as cm_fix_input,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_fix', 'patch', 'fix') THEN output_tokens ELSE 0 END), 0) as cm_fix_output,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_fix', 'patch', 'fix') THEN cached_tokens ELSE 0 END), 0) as cm_fix_cached,
          
          -- Total CM Engine (Gemini 3.5 Flash / Gemini 3 Flash)
          COALESCE(SUM(CASE WHEN task_type IN ('cm_find', 'cm_verify', 'cm_fix', 'cm_init', 'scan', 'verify', 'patch', 'fix') THEN input_tokens ELSE 0 END), 0) as total_cm_input,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_find', 'cm_verify', 'cm_fix', 'cm_init', 'scan', 'verify', 'patch', 'fix') THEN output_tokens ELSE 0 END), 0) as total_cm_output,
          COALESCE(SUM(CASE WHEN task_type IN ('cm_find', 'cm_verify', 'cm_fix', 'cm_init', 'scan', 'verify', 'patch', 'fix') THEN cached_tokens ELSE 0 END), 0) as total_cm_cached,
          
          -- Helper Agents (Gemini 2.5 Flash)
          COALESCE(SUM(CASE WHEN task_type IN ('triage_scan', 'qa_agent', 'semantic_agent', 'map_finding_ids', 'exploit_report_formatter', 'exploit_verify') THEN input_tokens ELSE 0 END), 0) as helper_input,
          COALESCE(SUM(CASE WHEN task_type IN ('triage_scan', 'qa_agent', 'semantic_agent', 'map_finding_ids', 'exploit_report_formatter', 'exploit_verify') THEN output_tokens ELSE 0 END), 0) as helper_output,
          COALESCE(SUM(CASE WHEN task_type IN ('triage_scan', 'qa_agent', 'semantic_agent', 'map_finding_ids', 'exploit_report_formatter', 'exploit_verify') THEN thoughts_tokens ELSE 0 END), 0) as helper_thoughts
        FROM `{table_path}`
        {where_clause}
    """
    
    # 2. Timeline group by date (in America/Los_Angeles Google Cloud Billing timezone)
    q_date = f"""
        SELECT 
          FORMAT_DATE('%Y-%m-%d', EXTRACT(DATE FROM timestamp AT TIME ZONE 'America/Los_Angeles')) as date,
          SUM(total_tokens) as total_tokens,
          SUM(cost_usd) as cost_usd
        FROM `{table_path}`
        {where_clause}
        GROUP BY date
        ORDER BY date ASC
    """
    
    # 3. Usage by repo
    q_repo = f"""
        SELECT 
          repo_name,
          SUM(total_tokens) as total_tokens,
          SUM(cost_usd) as cost_usd
        FROM `{table_path}`
        {where_clause}
        GROUP BY repo_name
        ORDER BY cost_usd DESC
    """
    
    # 4. Usage by task type and model name
    q_task = f"""
        SELECT 
          task_type,
          model_name,
          SUM(total_tokens) as total_tokens,
          SUM(cost_usd) as cost_usd,
          COALESCE(AVG(duration_sec), 0.0) as avg_duration_sec
        FROM `{table_path}`
        {where_clause}
        GROUP BY task_type, model_name
        ORDER BY cost_usd DESC
    """
    
    try:
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        
        # Summary
        query_job = bq_client.query(q_summary, job_config=job_config)
        rows_summary = list(query_job.result())
        summary_dict = {}
        if rows_summary:
            r = rows_summary[0]
            total_cost = float(r.total_cost)
            total_scans = int(r.total_scans)
            total_verifications = int(r.total_verifications)
            total_patches = int(r.total_patches)
            
            summary_dict = {
                "total_cost": total_cost,
                "compute_cost": float(r.compute_cost),
                "license_cost": float(r.license_cost),
                "cached_savings": float(r.cached_savings),
                "total_tokens": int(r.total_tokens),
                "input_tokens": int(r.input_tokens),
                "output_tokens": int(r.output_tokens),
                "cached_tokens": int(r.cached_tokens),
                "thoughts_tokens": int(r.thoughts_tokens),
                "total_sessions": int(r.total_sessions),
                "total_scans": total_scans,
                "total_verifications": total_verifications,
                "total_patches": total_patches,
                "avg_cost_per_scan": (total_cost / total_scans) if total_scans > 0 else 0.0,
                "avg_cost_per_verified": (total_cost / total_verifications) if total_verifications > 0 else 0.0,
                "avg_cost_per_patch": (total_cost / total_patches) if total_patches > 0 else 0.0
            }

        # SKU Line-Item Breakdown
        sku_dict = {}
        try:
            query_sku_job = bq_client.query(q_sku, job_config=job_config)
            rows_sku = list(query_sku_job.result())
            if rows_sku:
                sr = rows_sku[0]
                sku_dict = {
                    "cm_find_input": int(sr.cm_find_input),
                    "cm_find_output": int(sr.cm_find_output),
                    "cm_find_cached": int(sr.cm_find_cached),
                    "cm_verify_input": int(sr.cm_verify_input),
                    "cm_verify_output": int(sr.cm_verify_output),
                    "cm_verify_cached": int(sr.cm_verify_cached),
                    "cm_fix_input": int(sr.cm_fix_input),
                    "cm_fix_output": int(sr.cm_fix_output),
                    "cm_fix_cached": int(sr.cm_fix_cached),
                    "total_cm_input": int(sr.total_cm_input),
                    "total_cm_output": int(sr.total_cm_output),
                    "total_cm_cached": int(sr.total_cm_cached),
                    "helper_input": int(sr.helper_input),
                    "helper_output": int(sr.helper_output),
                    "helper_thoughts": int(sr.helper_thoughts)
                }
        except Exception as sku_err:
            logger.warning(f"Note querying SKU line-items: {sku_err}")
            
        # By Date
        query_job = bq_client.query(q_date, job_config=job_config)
        rows_date = [{"date": r.date, "total_tokens": int(r.total_tokens), "cost_usd": float(r.cost_usd)} for r in query_job.result()]
        
        # By Repo
        query_job = bq_client.query(q_repo, job_config=job_config)
        rows_repo = [{"repo_name": r.repo_name, "total_tokens": int(r.total_tokens), "cost_usd": float(r.cost_usd)} for r in query_job.result()]
        
        # By Task
        query_job = bq_client.query(q_task, job_config=job_config)
        rows_task = [{"task_type": r.task_type, "model_name": r.model_name, "total_tokens": int(r.total_tokens), "cost_usd": float(r.cost_usd), "avg_duration_sec": float(r.avg_duration_sec)} for r in query_job.result()]
        
        return {
            "status": "success",
            "range_days": range_days if not (start_date and end_date) else None,
            "start_date": start_date,
            "end_date": end_date,
            "summary": summary_dict,
            "sku_reconciliation": sku_dict,
            "by_date": rows_date,
            "by_repo": rows_repo,
            "by_task": rows_task
        }
    except Exception as e:
        logger.error(f"Failed to query token usage metrics from BigQuery: {e}")
        return {
            "status": "error",
            "message": str(e)
        }

def ensure_scan_log_table():
    """Checks if the analytics dataset and scan_log table exist in BigQuery, and creates them if they do not exist."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping scan log table verification.")
        return
    dataset_id = f"{bq_client.project}.codemender_analytics"
    table_id = f"{dataset_id}.scan_log"
    
    try:
        bq_client.get_dataset(dataset_id)
    except Exception:
        logger.info(f"BigQuery dataset {dataset_id} not found. Creating...")
        dataset = bigquery.Dataset(dataset_id)
        dataset.location = "US"
        bq_client.create_dataset(dataset, timeout=30)
        logger.info(f"Created BigQuery dataset {dataset_id}.")
        
    try:
        bq_client.get_table(table_id)
        logger.info(f"BigQuery table {table_id} already exists.")
    except Exception:
        logger.info(f"BigQuery table {table_id} not found. Creating...")
        schema = [
            bigquery.SchemaField("scan_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("commit_sha", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("repo_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("branch_name", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("event_type", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("status", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("target_file", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("findings_count", "INTEGER", mode="REQUIRED"),
            bigquery.SchemaField("findings_list", "STRING", mode="NULLABLE"),
            bigquery.SchemaField("action_taken", "STRING", mode="NULLABLE"),
        ]
        table = bigquery.Table(table_id, schema=schema)
        bq_client.create_table(table, timeout=30)
        logger.info(f"Created BigQuery table {table_id}.")

def log_scan_summary(commit_sha: str, repo_name: str, branch_name: str, event_type: str, status: str, target_file: str, findings_count: int, findings: list[dict], action_taken: str, pr_number: int = None, is_draft: bool = False, **kwargs):
    """Streams a scan process summary log entry to BigQuery for project-wide analytics."""
    if not bq_client:
        logger.warning("BigQuery client not active. Skipping scan summary logging.")
        return
    import uuid
    import time
    import json
    from datetime import datetime, UTC
    
    try:
        ensure_scan_log_table()
        
        findings_json = json.dumps(findings) if findings else None
        
        row = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.fromtimestamp(time.time(), UTC).isoformat(),
            "commit_sha": commit_sha,
            "repo_name": repo_name,
            "branch_name": branch_name,
            "event_type": event_type,
            "status": status,
            "target_file": target_file,
            "findings_count": int(findings_count),
            "findings_list": findings_json,
            "action_taken": action_taken
        }
        
        dataset_id = "codemender_analytics"
        table_id = "scan_log"
        table_ref = bq_client.dataset(dataset_id).table(table_id)
        
        errors = bq_client.insert_rows_json(table_ref, [row])
        if errors:
            logger.error(f"Failed to stream row to BigQuery scan_log table: {errors}")
        else:
            logger.info(f"Successfully logged scan summary to BigQuery: {findings_count} findings for SHA {commit_sha} action '{action_taken}'")
    except Exception as e:
        logger.error(f"Error logging scan summary to BigQuery: {e}")




