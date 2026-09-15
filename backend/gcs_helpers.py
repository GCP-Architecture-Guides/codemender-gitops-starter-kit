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

import os
import logging
from pathlib import Path
from google.cloud import storage

logger = logging.getLogger(__name__)

def upload_session_artifacts(commit_sha: str, cm_session_id: str):
    """Finds all local files under ~/.codemender/artifacts/{cm_session_id}/ and uploads them to GCS."""
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
    bucket_name = os.environ.get("ARTIFACT_BUCKET", f"{project_id}-artifacts")
    artifacts_dir = os.path.expanduser(f"~/.codemender/artifacts/{cm_session_id}")
    # Create directory if it doesn't exist
    os.makedirs(artifacts_dir, exist_ok=True)
        
    try:
        from database import db
        doc_ref = db.collection("scans").document(commit_sha)
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            report_content = f"# CodeMender Session Security Report\n\n"
            report_content += f"**Commit SHA**: `{commit_sha}`\n"
            report_content += f"**Session ID**: `{cm_session_id}`\n"
            report_content += f"**Branch Name**: `{data.get('branch_name')}`\n\n"
            
            report_content += "## Identified Vulnerabilities\n"
            findings = data.get("findings", [])
            for f in findings:
                report_content += f"- **ID**: `{f.get('id')}`\n"
                report_content += f"  - **Type**: {f.get('vuln_type')}\n"
                report_content += f"  - **File**: `{f.get('filepath')}`\n"
                report_content += f"  - **Status**: `{f.get('status')}`\n"
                report_content += f"  - **Description**: {f.get('description')}\n\n"
                
            report_content += "## Raw Execution Logs\n\n"
            logs = data.get("logs", {})
            if logs.get("find_output"):
                report_content += "### Triage Find Log\n"
                report_content += f"```\n{logs.get('find_output')}\n```\n\n"
            if logs.get("verify_output"):
                report_content += "### Exploit Verification Log\n"
                report_content += f"```\n{logs.get('verify_output')}\n```\n\n"
            if logs.get("fix_output"):
                report_content += "### Secure Patch Log\n"
                report_content += f"```\n{logs.get('fix_output')}\n```\n\n"
                
            report_path = os.path.join(artifacts_dir, "REPORT.md")
            with open(report_path, "w") as rf:
                rf.write(report_content)
    except Exception as doc_err:
        logger.warning(f"Failed to pre-compile REPORT.md for session upload: {doc_err}")

    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        uploaded_artifacts = []
        path_list = Path(artifacts_dir).glob("**/*")
        for path in path_list:
            if path.is_file():
                relative_path = path.relative_to(artifacts_dir)
                gcs_blob_path = f"{commit_sha}/{cm_session_id}/{relative_path}"
                blob = bucket.blob(gcs_blob_path)
                blob.upload_from_filename(str(path))
                
                # Link format for GCP storage console viewer
                url = f"https://storage.cloud.google.com/{bucket_name}/{gcs_blob_path}"
                uploaded_artifacts.append({
                    "name": str(relative_path),
                    "url": url
                })
                
        if uploaded_artifacts:
            from database import db
            doc_ref = db.collection("scans").document(commit_sha)
            doc = doc_ref.get()
            existing = []
            if doc.exists:
                existing = doc.to_dict().get("artifacts", [])
            # Deduplicate items by name
            merged_dict = {a["name"]: a for a in (existing + uploaded_artifacts)}
            doc_ref.set({"artifacts": list(merged_dict.values())}, merge=True)
            
            from database import append_scan_step
            append_scan_step(commit_sha, "info", f"Uploaded {len(uploaded_artifacts)} research artifacts to Cloud Storage.")
            logger.info(f"Successfully uploaded {len(uploaded_artifacts)} artifacts for session {cm_session_id} to GCS.")
    except Exception as e:
        logger.error(f"Failed to upload artifacts to GCS: {e}")


def download_state_database(commit_sha: str) -> bool:
    """Downloads the SQLite state database for the given commit SHA from GCS to local ~/.codemender/state.db."""
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
    bucket_name = os.environ.get("ARTIFACT_BUCKET", f"{project_id}-artifacts")
    db_path = os.path.expanduser("~/.codemender/state.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        gcs_blob_path = f"sessions/{commit_sha}/state.db"
        blob = bucket.blob(gcs_blob_path)
        
        if not blob.exists():
            logger.info(f"No state.db found in GCS for commit {commit_sha}")
            return False
            
        blob.download_to_filename(db_path)
        logger.info(f"Successfully downloaded state.db for commit {commit_sha} from GCS to {db_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to download state.db from GCS: {e}")
        return False


def upload_state_database(commit_sha: str) -> bool:
    """Uploads the local SQLite state database to GCS for the given commit SHA."""
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))
    bucket_name = os.environ.get("ARTIFACT_BUCKET", f"{project_id}-artifacts")
    db_path = os.path.expanduser("~/.codemender/state.db")
    
    if not os.path.exists(db_path):
        logger.warning(f"Local state.db not found at {db_path}; skipping upload.")
        return False
        
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        gcs_blob_path = f"sessions/{commit_sha}/state.db"
        blob = bucket.blob(gcs_blob_path)
        blob.upload_from_filename(db_path)
        logger.info(f"Successfully uploaded state.db to GCS at {gcs_blob_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload state.db to GCS: {e}")
        return False
