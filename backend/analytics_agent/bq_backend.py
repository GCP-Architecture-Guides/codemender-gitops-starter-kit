# bq_backend.py
# Backend queries, validation, formatting, and safety checks for BigQuery Analytics Agent.

import re
import logging
import os
from google.cloud import bigquery
bq_client = None

def _get_bq_client():
    global bq_client
    if bq_client is None:
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        if not project:
            raise RuntimeError("GOOGLE_CLOUD_PROJECT is not set; the analytics agent needs an explicit project.")
        # Application Default Credentials only; never mint tokens for a personal gcloud account.
        bq_client = bigquery.Client(project=project)
    return bq_client

from analytics_agent.schema_config import PII_COLUMNS

logger = logging.getLogger(__name__)

# Forbidden keywords pattern (case-insensitive)
FORBIDDEN_KEYWORDS = re.compile(
    r'\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|MERGE|TRUNCATE|GRANT|REVOKE|EXEC|CALL|REPLACE)\b',
    re.IGNORECASE
)

def validate_sql_query(sql: str) -> tuple[bool, str]:
    """Returns (is_safe, error_message). Enforces read-only SELECT guardrails."""
    sql_clean = sql.strip()
    if not sql_clean:
        return False, "Query is empty."
        
    # Check forbidden write statements
    if FORBIDDEN_KEYWORDS.search(sql_clean):
        match = FORBIDDEN_KEYWORDS.search(sql_clean)
        return False, f"Query blocked: '{match.group()}' statements are not permitted. This agent is read-only."
        
    # Check multiple statements (semicolon injection check)
    # Allow a trailing semicolon, but block multiple queries separated by semicolons
    statements = [s.strip() for s in sql_clean.split(";") if s.strip()]
    if len(statements) > 1:
        return False, "Query blocked: Multiple SQL statements detected."
        
    # Ensure it's a SELECT statement
    if not re.match(r'^\s*SELECT\b', sql_clean, re.IGNORECASE):
        return False, "Query blocked: Only SELECT statements are permitted."
        
    return True, ""

def execute_safe_query(sql: str) -> str:
    """Validates, limits, and executes SQL query against BigQuery. Returns formatted markdown table."""
    client = _get_bq_client()
    if not client:
        return "Error: BigQuery client is not initialized."
        
    sql_clean = sql.strip()
    is_safe, error_msg = validate_sql_query(sql_clean)
    if not is_safe:
        return error_msg
        
    # Append LIMIT 100 if not present
    if not re.search(r'\bLIMIT\s+\d+', sql_clean, re.IGNORECASE):
        # Handle cases with trailing semicolon
        if sql_clean.endswith(";"):
            sql_clean = sql_clean[:-1] + " LIMIT 100;"
        else:
            sql_clean = sql_clean + " LIMIT 100"
            
    # Dry-run check for cost control (10GB limit)
    try:
        job_config = bigquery.QueryJobConfig(dry_run=True, use_query_cache=False)
        dry_run_job = client.query(sql_clean, job_config=job_config)
        bytes_scanned = dry_run_job.total_bytes_processed
        if bytes_scanned > 10 * 1024**3: # 10 GB
            scanned_gb = bytes_scanned / (1024**3)
            return f"Query Blocked: This query would process {scanned_gb:.2f} GB of data. Please apply filters to limit scans below 10.00 GB."
    except Exception as dry_err:
        logger.warning(f"Dry run failed: {dry_err}")
        # Proceed to run directly if dry run fails to evaluate (e.g. syntax error in query)
        
    # Run the actual query
    try:
        query_job = client.query(sql_clean)
        results = query_job.result()
        
        # Check if empty
        if results.total_rows == 0:
            return "No data found matching your query."
            
        # Get columns and format header
        schema_fields = results.schema
        headers = [field.name for field in schema_fields]
        
        markdown = "| " + " | ".join(headers) + " |\n"
        markdown += "| " + " | ".join(["---"] * len(headers)) + " |\n"
        
        # Format rows and apply PII redaction
        row_count = 0
        for row in results:
            row_vals = []
            for field in schema_fields:
                val = row[field.name]
                if val is None:
                    row_vals.append("NULL")
                else:
                    val_str = str(val)
                    if field.name.lower() in PII_COLUMNS:
                        val_str = "***REDACTED***"
                    # Escape vertical bars to keep markdown valid
                    val_str = val_str.replace("|", "\\|")
                    row_vals.append(val_str)
            markdown += "| " + " | ".join(row_vals) + " |\n"
            row_count += 1
            if row_count >= 100:
                break
                
        # Enforce strict character size gate with nudge to prevent context overflow
        if len(markdown) > 50000:
            markdown = (
                markdown[:50000] + 
                "\n\n... [TRUNCATED: The query output exceeded 50,000 characters. Only the first part is shown. "
                "Please refine your SELECT query columns, apply stricter WHERE filters, or use LIMIT clauses to query smaller slices of data.]"
            )
                
        return markdown
    except Exception as e:
        logger.error(f"BigQuery execution failed: {e}")
        return f"BigQuery Execution Error: {str(e)}\nPlease check your table references or query syntax."
