# schema_config.py
# Schema catalogue, PII list, and domain configuration for the BigQuery Analytics Agent.

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
    },
    "vulnerability_lifecycle_events": {
        "bq_ref": "vulnerability_lifecycle_events",
        "description": "Immutable ledger of all vulnerability state transitions (DISCOVERED, PERSISTED, RESOLVED, DISMISSED) with structural fingerprints.",
        "key_columns": [
            "event_id", "event_timestamp", "event_type", "finding_fingerprint", "display_id",
            "repo_name", "target_file", "line_number", "cwe", "vuln_type", "severity", "lifecycle_status"
        ],
        "typical_questions": [
            "What is the complete lifecycle history of a vulnerability?",
            "How many new vulnerabilities were introduced this sprint?",
            "Which files have the highest rate of persistent vulnerabilities?"
        ]
    },
    "v_active_vulnerabilities_org": {
        "bq_ref": "v_active_vulnerabilities_org",
        "description": "Real-time deduplicated view of all currently open (NEW or PERSISTENT) vulnerabilities across all monitored repositories.",
        "key_columns": [
            "org_name", "repo_name", "target_file", "line_number", "cwe", "vuln_type", "severity", "display_id", "last_updated_at"
        ],
        "typical_questions": [
            "Show me all active Critical and High vulnerabilities across all repositories.",
            "Which repositories have open SQL injections right now?",
            "What is our total count of unresolved security findings?"
        ]
    },
    "v_remediation_velocity_metrics": {
        "bq_ref": "v_remediation_velocity_metrics",
        "description": "Aggregated Mean Time to Remediate (MTTR in minutes) and resolution rate percentages grouped by repository and severity.",
        "key_columns": [
            "repo_name", "severity", "total_discovered", "total_resolved", "resolution_rate_pct", "mean_time_to_remediate_minutes"
        ],
        "typical_questions": [
            "Which repository has the fastest Mean Time to Remediate (MTTR)?",
            "What is our overall fix resolution rate across repositories?",
            "How fast are Critical vulnerabilities resolved compared to Highs?"
        ]
    }
}
