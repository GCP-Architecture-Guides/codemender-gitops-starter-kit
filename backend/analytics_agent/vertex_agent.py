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

import os

# Set container process environment variables for google-adk execution
if "GOOGLE_GENAI_USE_VERTEXAI" not in os.environ:
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
if "GOOGLE_CLOUD_PROJECT" not in os.environ:
    os.environ["GOOGLE_CLOUD_PROJECT"] = os.getenv("PROJECT_ID", "YOUR_PROJECT_ID")
if "GOOGLE_CLOUD_LOCATION" not in os.environ:
    os.environ["GOOGLE_CLOUD_LOCATION"] = os.getenv("LOCATION", "global")

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
    build_agent_instruction
)

# Active project
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID"))

# Tools list
tools_list = [
    list_available_tables,
    get_table_schema,
    get_sample_data,
    execute_insight_query,
    run_aggregation,
    find_trends,
    compare_segments,
    summarize_findings
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
            project=os.environ.get("GOOGLE_CLOUD_PROJECT", os.getenv("PROJECT_ID", "YOUR_PROJECT_ID")),
            location="global",   # never use regional for 3.x
        )

# Create the underlying ADK Agent object
adk_agent = Agent(
    name="BigQueryAnalyticsAgentCore",
    description="Core ADK Agent for querying the BigQuery Analytics database.",
    model=GlobalGemini(model="gemini-3-flash"),
    instruction=build_agent_instruction(),
    tools=tools_list
)

# Export the native google.adk.Agent instance directly
agent_instance = adk_agent
