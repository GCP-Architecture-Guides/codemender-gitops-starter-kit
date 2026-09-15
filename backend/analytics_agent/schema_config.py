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

DOMAIN = "CodeMender Developer Security Automation & Telemetry"

PII_COLUMNS = {"email", "phone", "ssn", "credit_card", "password", "dob", "date_of_birth"}

TABLE_CATALOGUE = {
    "applied_security_patches": {
        "bq_ref": "applied_security_patches",
        "description": "Remediation telemetry for successfully patched and merged security vulnerabilities.",
        "key_columns": [
            "merge_id", "pr_number", "repo_name", "branch", "commit_sha", "merged_at",
            "merged_by", "time_to_remediate_sec", "total_findings", "critical_count",
            "high_count", "patched_count", "unpatched_count", "remediation_rate_pct"
        ],
        "typical_questions": [
            "What is our average time to remediate vulnerabilities?",
            "What is our overall security patching success/remediation rate?",
            "Who has merged the most security patches?"
        ]
    },
    "scan_log": {
        "bq_ref": "scan_log",
        "description": "Execution log of all security code scan runs triggered by branch pushes.",
        "key_columns": [
            "scan_id", "timestamp", "commit_sha", "repo_name", "branch_name", 
            "status", "target_file", "findings_count", "action_taken"
        ],
        "typical_questions": [
            "How many scans were run this week?",
            "Which repository branch triggers the most findings?",
            "Are there any failed or stuck scan jobs?"
        ]
    },
    "token_usage_log": {
        "bq_ref": "token_usage_log",
        "description": "Model token cost telemetry for all AI agent verification and fix operations.",
        "key_columns": [
            "log_id", "timestamp", "repo_name", "session_id", "task_type", 
            "model_name", "input_tokens", "output_tokens", "total_tokens", "cost_usd"
        ],
        "typical_questions": [
            "What is the total AI token spend/cost so far?",
            "What is the average cost of fixing a vulnerability vs verifying one?",
            "Which AI models are used the most?"
        ]
    }
}
