# vertex_agent.py
# Compliant ADK Agent definition for Vertex AI Reasoning Engine.

import os

# Set container process environment variables for google-adk execution.
# GOOGLE_CLOUD_PROJECT must come from the deployment; there is deliberately no default project.
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
os.environ["GOOGLE_CLOUD_LOCATION"] = os.getenv("GOOGLE_CLOUD_LOCATION", "global")

from google.adk import Agent
from google.adk.models.google_llm import Gemini
from google import genai

from analytics_agent.agent import (
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
    get_vulnerability_lifecycle_audit,
    build_agent_instruction
)

# Active project
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "")

# Tools list
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

class GlobalGemini(Gemini):
    """
    Forces Vertex AI global endpoint for gemini-3.x models.
    Belt-and-suspenders guard — env vars are primary, this is fallback.
    """
    @property
    def api_client(self):
        return genai.Client(
            vertexai=True,
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location="global",   # never use regional for 3.x
        )

# Create the underlying ADK Agent object
adk_agent = Agent(
    name="BigQueryAnalyticsAgentCore",
    description="Core ADK Agent for querying the BigQuery Analytics database.",
    model=GlobalGemini(model=os.getenv("VERTEX_MODEL", "gemini-3.8-flash")),
    instruction=build_agent_instruction(),
    tools=tools_list
)

# Export the native google.adk.Agent instance directly
agent_instance = adk_agent
