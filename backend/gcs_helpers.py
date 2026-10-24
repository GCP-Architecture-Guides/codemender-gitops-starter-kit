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
import shutil
import logging
from pathlib import Path
from google.cloud import storage

logger = logging.getLogger(__name__)

# Workspace file written by `cm init`/`cm find` that links a checkout to its project in state.db.
_CM_PROJECT_FILE = ".cm_project"


def _artifacts_bucket_name() -> str:
    """GCS bucket holding session artifacts and CodeMender state bundles."""
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or "YOUR_PROJECT_ID"
    return f"{project_id}-artifacts"


def _state_db_path() -> str:
    return os.path.expanduser("~/.codemender/state.db")


def _state_blob_path(commit_sha: str, name: str = "state.db") -> str:
    return f"sessions/{commit_sha}/{name}"


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except Exception as rm_err:
        logger.warning(f"Could not remove temporary file {path}: {rm_err}")


def _snapshot_sqlite(db_path: str) -> str:
    """Returns a temp-file copy of a WAL-mode SQLite db, including un-checkpointed WAL pages."""
    import sqlite3
    import tempfile
    fd, snapshot_path = tempfile.mkstemp(prefix="cm-state-", suffix=".db")
    os.close(fd)
    try:
        src = sqlite3.connect(db_path, timeout=30)
        try:
            dst = sqlite3.connect(snapshot_path)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
    except Exception:
        _remove_quietly(snapshot_path)
        raise
    return snapshot_path


def upload_session_artifacts(commit_sha: str, cm_session_id: str):
    """Finds all local files under ~/.codemender/artifacts/{cm_session_id}/ and uploads them to GCS."""
    bucket_name = _artifacts_bucket_name()
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
    bucket_name = _artifacts_bucket_name()
    db_path = _state_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    tmp_path = f"{db_path}.download"
    
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        gcs_blob_path = _state_blob_path(commit_sha)
        blob = bucket.blob(gcs_blob_path)
        
        if not blob.exists():
            logger.info(f"No state.db found in GCS for commit {commit_sha}")
            return False
            
        # Download beside the target and swap atomically so a failed download never leaves a
        # truncated state.db behind.
        blob.download_to_filename(tmp_path)
        os.replace(tmp_path, db_path)
        # WAL/SHM side files belong to the database that was just replaced.
        for suffix in ("-wal", "-shm"):
            _remove_quietly(db_path + suffix)
        logger.info(f"Successfully downloaded state.db for commit {commit_sha} from GCS to {db_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to download state.db from GCS: {e}")
        return False
    finally:
        if os.path.exists(tmp_path):
            _remove_quietly(tmp_path)


def download_codemender_state_bundle(commit_sha: str, workspace_path: str = None) -> bool:
    """Hydrates the CodeMender state bundle (state.db + workspace .cm_project) from Cloud Storage.

    Returns True only when everything the fast path needs was restored: state.db and, when
    ``workspace_path`` is given, the workspace's .cm_project file.
    """
    if not download_state_database(commit_sha):
        return False
    if not workspace_path:
        return True

    workspace = Path(workspace_path)
    if not workspace.is_dir():
        logger.warning(f"Workspace {workspace_path} does not exist; cannot restore {_CM_PROJECT_FILE}.")
        return False
    target = workspace / _CM_PROJECT_FILE
    tmp_target = workspace / f"{_CM_PROJECT_FILE}.download"
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(_artifacts_bucket_name())
        blob = bucket.blob(_state_blob_path(commit_sha, _CM_PROJECT_FILE))
        if not blob.exists():
            logger.info(f"No {_CM_PROJECT_FILE} found in GCS for commit {commit_sha}; state bundle not hydrated.")
            return False
        blob.download_to_filename(str(tmp_target))
        # Older code created .cm_project as a directory; the CLI expects a JSON file.
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        os.replace(tmp_target, target)
        logger.info(f"Restored {_CM_PROJECT_FILE} for commit {commit_sha} into {workspace_path}")
        return True
    except Exception as e:
        logger.warning(f"Could not restore {_CM_PROJECT_FILE} into workspace: {e}")
        return False
    finally:
        if tmp_target.exists():
            _remove_quietly(str(tmp_target))


def upload_state_database(commit_sha: str) -> bool:
    """Uploads the local SQLite state database to GCS for the given commit SHA."""
    bucket_name = _artifacts_bucket_name()
    db_path = _state_db_path()
    
    if not os.path.exists(db_path):
        logger.warning(f"Local state.db not found at {db_path}; skipping upload.")
        return False
        
    snapshot_path = None
    try:
        upload_path = db_path
        if os.path.exists(db_path + "-wal"):
            # Un-checkpointed WAL pages (e.g. after a killed CLI run) are not in state.db yet.
            try:
                snapshot_path = _snapshot_sqlite(db_path)
                upload_path = snapshot_path
            except Exception as snap_err:
                logger.warning(f"Could not snapshot state.db; uploading the raw file instead: {snap_err}")
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        gcs_blob_path = _state_blob_path(commit_sha)
        blob = bucket.blob(gcs_blob_path)
        blob.upload_from_filename(upload_path)
        logger.info(f"Successfully uploaded state.db to GCS at {gcs_blob_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload state.db to GCS: {e}")
        return False
    finally:
        if snapshot_path:
            _remove_quietly(snapshot_path)


def upload_codemender_state_bundle(commit_sha: str, workspace_path: str | None = None) -> bool:
    """Uploads the CodeMender state bundle for ``commit_sha``.

    The bundle is ~/.codemender/state.db (stored where download_state_database reads it) plus the
    workspace's .cm_project file when present. Returns True when every present part was uploaded.
    """
    if not upload_state_database(commit_sha):
        return False
    if not workspace_path:
        return True

    cm_project = Path(workspace_path) / _CM_PROJECT_FILE
    if not cm_project.is_file():
        logger.info(f"No {_CM_PROJECT_FILE} file in {workspace_path}; uploaded state.db only.")
        return True
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(_artifacts_bucket_name())
        gcs_blob_path = _state_blob_path(commit_sha, _CM_PROJECT_FILE)
        bucket.blob(gcs_blob_path).upload_from_filename(str(cm_project))
        logger.info(f"Successfully uploaded {_CM_PROJECT_FILE} to GCS at {gcs_blob_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload {_CM_PROJECT_FILE} to GCS: {e}")
        return False
