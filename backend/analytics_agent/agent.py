# agent.py
# Antigravity Agent definition and tool bindings for BigQuery Analytics.

import os
import re
import time
import logging
from google.cloud import bigquery
from google import genai
from google.genai import types
bq_client = None
from analytics_agent.schema_config import TABLE_CATALOGUE, DOMAIN
from analytics_agent.bq_backend import execute_safe_query, validate_sql_query, _get_bq_client

logger = logging.getLogger(__name__)

# Core tools implementation

def list_available_tables() -> str:
    """Lists all available telemetry tables with their descriptions and typical questions.
    
    Returns:
        A formatted string describing all available tables.
    """
    output = "Here are the available tables you can query:\n\n"
    for table_key, info in TABLE_CATALOGUE.items():
        output += f"- **Table Name**: `{table_key}`\n"
        output += f"  *Description*: {info['description']}\n"
        output += f"  *Key Columns*: {', '.join(info['key_columns'])}\n"
        output += f"  *Example Questions*:\n"
        for q in info['typical_questions']:
            output += f"    - \"{q}\"\n"
        output += "\n"
    return output

def get_table_schema(table_name: str) -> str:
    """Gets the schema and column details for a specific table.
    
    Args:
        table_name: The business name of the table (e.g., 'token_usage_log').
    """
    if table_name not in TABLE_CATALOGUE:
        return f"Error: Table '{table_name}' is not in the catalogue. Call list_available_tables first."
        
    if not _get_bq_client():
        return "Error: BigQuery client is not active."
        
    dataset_id = "codemender_analytics"
    table_ref = f"{_get_bq_client().project}.{dataset_id}.{table_name}"
    
    try:
        table = _get_bq_client().get_table(table_ref)
        schema_info = f"Schema for table `{table_name}`:\n\n"
        schema_info += "| Column Name | Data Type | Mode | Description |\n"
        schema_info += "| --- | --- | --- | --- |\n"
        for field in table.schema:
            desc = field.description or "No description available"
            schema_info += f"| {field.name} | {field.field_type} | {field.mode} | {desc} |\n"
        return schema_info
    except Exception as e:
        logger.error(f"Failed to fetch schema for {table_name}: {e}")
        return f"Failed to fetch schema: {str(e)}"

def get_sample_data(table_name: str, limit: int = 5) -> str:
    """Returns a small preview (sample rows) of the table. PII is automatically redacted.
    
    Args:
        table_name: The business name of the table (e.g., 'scan_log').
        limit: Max number of rows to retrieve (default: 5, max: 10).
    """
    if table_name not in TABLE_CATALOGUE:
        return f"Error: Table '{table_name}' is not in the catalogue."
        
    capped_limit = min(max(1, limit), 10)
    sql = f"SELECT * FROM `{_get_bq_client().project}.codemender_analytics.{table_name}` LIMIT {capped_limit}"
    return execute_safe_query(sql)

def execute_insight_query(sql: str) -> str:
    """Executes a custom read-only SELECT SQL query on BigQuery.
    
    Args:
        sql: The valid GoogleSQL SELECT query. Ensure it targets '<project>.codemender_analytics.<table>'.
    """
    project_id = _get_bq_client().project
    # Strip any placeholders or malformed qualifiers like `<project>.` or double dataset prefixes
    sql = re.sub(r'<project>\.?', '', sql, flags=re.IGNORECASE)
    sql = re.sub(rf'`?([a-zA-Z0-9_\-]+:)?([a-zA-Z0-9_\-]+\.)?codemender_analytics\.`?', '', sql)
    sql = re.sub(r'codemender_analytics\.', '', sql)

    # Replace bare table references with fully qualified `project.codemender_analytics.table`
    for table_key in TABLE_CATALOGUE.keys():
        sql = re.sub(rf'`{table_key}`', table_key, sql)
        sql = re.sub(rf'\b{table_key}\b', f"`{project_id}.codemender_analytics.{table_key}`", sql)
        
    return execute_safe_query(sql)

def run_aggregation(table_name: str, metric: str, dimension: str, filters: str = "") -> str:
    """Performs counts, sums, or averages grouped by a dimension.
    
    Args:
        table_name: Business table name.
        metric: Aggregation expression (e.g., "count", "sum(cost_usd)", "average(time_to_remediate_sec)").
        dimension: Column name to group by.
        filters: Optional raw SQL WHERE clause filter expression (e.g. "repo_name = 'YOUR_ORG/YOUR_REPO'").
    """
    if table_name not in TABLE_CATALOGUE:
        return f"Error: Table '{table_name}' is not in the catalogue."
        
    # Translate metric
    metric_sql = ""
    metric_clean = metric.lower().strip()
    
    if metric_clean == "count":
        metric_sql = "COUNT(*) as count"
    elif metric_clean.startswith("sum(") and metric_clean.endswith(")"):
        col = metric_clean[4:-1].strip()
        metric_sql = f"SUM({col}) as total_{col}"
    elif metric_clean.startswith("average(") and metric_clean.endswith(")"):
        col = metric_clean[8:-1].strip()
        metric_sql = f"AVG({col}) as avg_{col}"
    elif metric_clean.startswith("min(") and metric_clean.endswith(")"):
        col = metric_clean[4:-1].strip()
        metric_sql = f"MIN({col}) as min_{col}"
    elif metric_clean.startswith("max(") and metric_clean.endswith(")"):
        col = metric_clean[4:-1].strip()
        metric_sql = f"MAX({col}) as max_{col}"
    else:
        return f"Error: Unsupported metric format '{metric}'. Use 'count', 'sum(column)', 'average(column)'."
        
    sql = f"SELECT {dimension}, {metric_sql} FROM `{_get_bq_client().project}.codemender_analytics.{table_name}`"
    if filters:
        sql += f" WHERE {filters}"
    sql += f" GROUP BY {dimension} ORDER BY {dimension} ASC"
    
    return execute_safe_query(sql)

def find_trends(table_name: str, metric: str, date_column: str, period: str = "monthly") -> str:
    """Analyzes metrics over time (daily, weekly, monthly, quarterly).
    
    Args:
        table_name: Business table name.
        metric: Aggregation expression (e.g., "count", "sum(cost_usd)").
        date_column: The timestamp/date column to use (e.g., 'timestamp' or 'merged_at').
        period: Time-series truncation ('daily', 'weekly', 'monthly', 'quarterly', 'yearly').
    """
    if table_name not in TABLE_CATALOGUE:
        return f"Error: Table '{table_name}' is not in the catalogue."
        
    period_map = {
        "daily": "DAY",
        "weekly": "WEEK",
        "monthly": "MONTH",
        "quarterly": "QUARTER",
        "yearly": "YEAR"
    }
    
    trunc_unit = period_map.get(period.lower().strip(), "MONTH")
    
    # Translate metric
    metric_sql = ""
    metric_clean = metric.lower().strip()
    if metric_clean == "count":
        metric_sql = "COUNT(*) as count"
    elif metric_clean.startswith("sum(") and metric_clean.endswith(")"):
        col = metric_clean[4:-1].strip()
        metric_sql = f"SUM({col}) as total_{col}"
    elif metric_clean.startswith("average(") and metric_clean.endswith(")"):
        col = metric_clean[8:-1].strip()
        metric_sql = f"AVG({col}) as avg_{col}"
    else:
        return f"Error: Unsupported metric format '{metric}'."
        
    sql = (
        f"SELECT DATE_TRUNC({date_column}, {trunc_unit}) as time_period, {metric_sql} "
        f"FROM `{_get_bq_client().project}.codemender_analytics.{table_name}` "
        f"GROUP BY time_period ORDER BY time_period ASC"
    )
    
    return execute_safe_query(sql)

def compare_segments(table_name: str, metric: str, segment_column: str, segment_a: str, segment_b: str) -> str:
    """Compares metrics between two segments of a dimension.
    
    Args:
        table_name: Business table name.
        metric: Aggregation metric (e.g., "count", "sum(cost_usd)").
        segment_column: Column name defining the segments (e.g., 'repo_name', 'merged_by').
        segment_a: The first segment value (e.g., 'repo_alpha').
        segment_b: The second segment value (e.g., 'repo_beta').
    """
    if table_name not in TABLE_CATALOGUE:
        return f"Error: Table '{table_name}' is not in the catalogue."
        
    # Translate metric
    metric_sql = ""
    metric_clean = metric.lower().strip()
    if metric_clean == "count":
        metric_sql = "COUNT(*) as val"
    elif metric_clean.startswith("sum(") and metric_clean.endswith(")"):
        col = metric_clean[4:-1].strip()
        metric_sql = f"SUM({col}) as val"
    elif metric_clean.startswith("average(") and metric_clean.endswith(")"):
        col = metric_clean[8:-1].strip()
        metric_sql = f"AVG({col}) as val"
    else:
        return f"Error: Unsupported metric format."
        
    sql = (
        f"SELECT {segment_column}, {metric_sql} "
        f"FROM `{_get_bq_client().project}.codemender_analytics.{table_name}` "
        f"WHERE {segment_column} IN ('{segment_a}', '{segment_b}') "
        f"GROUP BY {segment_column}"
    )
    
    return execute_safe_query(sql)

def summarize_findings(data: str, question: str) -> str:
    """Generates an executive, business-friendly summary of the query data.
    
    Args:
        data: The formatted markdown table or data string.
        question: The user's original business question.
    """
    # This tool calls the model directly to summarize the formatted table data
    from google import genai
    prompt = (
        f"Question asked: \"{question}\"\n\n"
        f"Query Results Data:\n{data}\n\n"
        "Generate a 3-5 sentence executive summary of these findings. "
        "Write in simple, clear business language. Focus on trends, outliers, or key figures."
    )
    try:
        model_tier = os.getenv("VERTEX_MODEL", "gemini-3.8-flash")
        loc = "global" if ("3." in model_tier or "gemini-3" in model_tier) else os.getenv("GEMINI_LOCATION", "us-central1")
        client = genai.Client(vertexai=True, project=_get_bq_client().project, location=loc)
        response = client.models.generate_content(
            model=model_tier,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                system_instruction="You are an expert business intelligence analyst. Summarize data clearly for leadership."
            )
        )
        try:
            from database import log_token_usage
            usage = response.usage_metadata
            log_token_usage(
                session_id="analytics-summary",
                repo_name="codemender-analytics",
                task_type="analytics_agent",
                model_name=model_tier,
                input_tokens=usage.prompt_token_count,
                output_tokens=usage.candidates_token_count,
                cached_tokens=usage.cached_content_token_count or 0,
                thoughts_tokens=getattr(usage, "thoughts_token_count", 0) or 0
            )
        except Exception as log_err:
            logger.warning(f"Failed to log analytics agent tokens: {log_err}")
        return response.text
    except Exception as e:
        logger.error(f"Failed to generate summary: {e}")
        return f"Failed to generate summary: {str(e)}"

# Setup Agent Configuration

def build_agent_instruction() -> str:
    schema_context = ""
    for table_key, info in TABLE_CATALOGUE.items():
        schema_context += f"Table: {table_key}\n  Description: {info['description']}\n  Columns: {', '.join(info['key_columns'])}\n\n"
        
    instruction = f"""You are an expert business intelligence and security analyst for {DOMAIN}.
You help developers, security engineers, and business leaders track security remediation progress, costs, and scan history.
DATASETS YOU CAN QUERY:
{schema_context}
CAPABILITIES:
- List available tables and details
- Fetch schemas and previews
- Run aggregations, time-series trends, and segment comparisons
- Execute custom SELECT queries for deep analysis
- Generate business summaries for executives

WORKFLOW:
1. Translate the user's natural language request into table lookups and metrics.
2. Select and call the most specific tool (e.g. list_available_tables first if they ask about tables).
3. If they ask a custom query, construct a valid SELECT statement and run it using execute_insight_query.
4. Output the results clearly as markdown, and ALWAYS explain what the numbers mean in plain English.
5. Suggest related follow-up questions.
"""
    return instruction

def get_file_vulnerability_history(file_path: str, repo_name: str = None) -> str:
    """Retrieves the complete historical timeline of vulnerabilities detected and resolved in a specific file.
    
    Args:
        file_path: The relative file path to inspect (e.g. 'routes/search.ts' or 'app.py').
        repo_name: Optional repository name filter (e.g. 'YOUR_ORG/YOUR_REPO').
    """
    clean_file = file_path.strip().replace("'", "\\'")
    where_clauses = [f"target_file LIKE '%{clean_file}%'"]
    if repo_name:
        where_clauses.append(f"repo_name = '{repo_name.strip()}'")
    where_str = " AND ".join(where_clauses)
    
    sql = f"""
    SELECT 
      event_timestamp,
      event_type,
      display_id,
      repo_name,
      target_file,
      line_number,
      cwe,
      vuln_type,
      severity,
      lifecycle_status,
      commit_sha,
      pr_number,
      pusher_name
    FROM `{_get_bq_client().project}.codemender_analytics.vulnerability_lifecycle_events`
    WHERE {where_str}
    ORDER BY event_timestamp DESC
    LIMIT 25
    """
    return execute_safe_query(sql)

def query_org_active_vulnerabilities(severity: str = None, repo_name: str = None) -> str:
    """Queries all currently active (unresolved) vulnerabilities across all monitored repositories.
    
    Args:
        severity: Optional severity filter (e.g. 'CRITICAL', 'HIGH').
        repo_name: Optional repository filter (e.g. 'YOUR_ORG/YOUR_REPO').
    """
    where_clauses = []
    if severity:
        where_clauses.append(f"severity = '{severity.strip().upper()}'")
    if repo_name:
        where_clauses.append(f"repo_name = '{repo_name.strip()}'")
    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    
    sql = f"""
    SELECT 
      org_name,
      repo_name,
      target_file,
      line_number,
      cwe,
      vuln_type,
      severity,
      display_id,
      last_updated_at,
      pr_number
    FROM `{_get_bq_client().project}.codemender_analytics.v_active_vulnerabilities_org`
    {where_str}
    ORDER BY last_updated_at DESC
    LIMIT 50
    """
    return execute_safe_query(sql)

def get_remediation_velocity_leaderboard() -> str:
    """Retrieves the remediation velocity metrics (MTTR and resolution rate %) across repositories."""
    sql = f"""
    SELECT 
      repo_name,
      severity,
      total_discovered,
      total_resolved,
      ROUND(resolution_rate_pct, 1) as resolution_rate_pct,
      ROUND(mean_time_to_remediate_minutes, 1) as mean_time_to_remediate_minutes
    FROM `{_get_bq_client().project}.codemender_analytics.v_remediation_velocity_metrics`
    ORDER BY resolution_rate_pct DESC, mean_time_to_remediate_minutes ASC
    LIMIT 20
    """
    return execute_safe_query(sql)

def get_vulnerability_lifecycle_audit(finding_id_or_fingerprint: str) -> str:
    """Retrieves the complete audit trail and state transitions for a specific finding ID or fingerprint.
    
    Args:
        finding_id_or_fingerprint: 6-char display ID or full 16-char canonical fingerprint.
    """
    target = finding_id_or_fingerprint.strip()
    sql = f"""
    SELECT 
      event_timestamp,
      event_type,
      display_id,
      finding_fingerprint,
      repo_name,
      target_file,
      line_number,
      cwe,
      vuln_type,
      severity,
      lifecycle_status,
      commit_sha,
      pr_number,
      pusher_name,
      exploit_verified
    FROM `{_get_bq_client().project}.codemender_analytics.vulnerability_lifecycle_events`
    WHERE display_id = '{target}' OR finding_fingerprint = '{target}'
    ORDER BY event_timestamp ASC
    """
    return execute_safe_query(sql)

async def chat_with_analytics_agent(message: str) -> str:
    model_tier = os.getenv("VERTEX_MODEL", "gemini-3.8-flash")
    proj = os.getenv("GOOGLE_CLOUD_PROJECT")
    loc = "global" if ("3." in model_tier or "gemini-3" in model_tier) else os.getenv("GEMINI_LOCATION", "us-central1")
    client = genai.Client(
        vertexai=True,
        project=proj,
        location=loc
    )
    
    tools_list = [
        list_available_tables,
        get_table_schema,
        get_sample_data,
        execute_insight_query,
        run_aggregation,
        find_trends,
        compare_segments,
        summarize_findings,
        get_file_vulnerability_history,
        query_org_active_vulnerabilities,
        get_remediation_velocity_leaderboard,
        get_vulnerability_lifecycle_audit
    ]
    
    chat = client.chats.create(
        model=model_tier,
        config=types.GenerateContentConfig(
            system_instruction=build_agent_instruction(),
            tools=tools_list,
        )
    )
    
    import asyncio
    start_time = time.time()
    response = await asyncio.to_thread(chat.send_message, message)
    duration = time.time() - start_time
    
    try:
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            meta = response.usage_metadata
            input_tokens = getattr(meta, "prompt_token_count", 0) or 0
            output_tokens = getattr(meta, "candidates_token_count", 0) or 0
            cached_tokens = getattr(meta, "cached_content_token_count", 0) or 0
            thoughts_tokens = getattr(meta, "thoughts_token_count", 0) or 0
            
            from database import log_token_usage
            log_token_usage(
                session_id="analytics-chat",
                repo_name="analytics_agent",
                task_type="analytics_agent",
                model_name=model_tier,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_tokens=cached_tokens,
                thoughts_tokens=thoughts_tokens,
                duration_sec=duration
            )
            logger.info(f"Logged Analytics Agent tokens -> In: {input_tokens}, Out: {output_tokens}, Cached: {cached_tokens}, Thoughts: {thoughts_tokens}")
    except Exception as token_err:
        logger.warning(f"Failed to log token usage for analytics agent: {token_err}")

    return response.text or ""

