# deploy_reasoning_engine.py
# Deployment script to register/update the BigQuery Analytics Agent in Vertex AI Agent Engine as a native ADK Agent.

import os
import sys

# Default project configs
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "YOUR_PROJECT_ID")
LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
STAGING_BUCKET = os.getenv("STAGING_BUCKET_NAME", f"gs://{PROJECT_ID}-artifacts")

# Stable resource ID for the analytics agent to prevent duplicate resources (set to empty to deploy a new instance)
STABLE_ENGINE_ID = os.getenv("REASONING_ENGINE_RESOURCE_ID", "projects/YOUR_PROJECT_NUMBER/locations/us-central1/reasoningEngines/394814284569247744")

# Make sure backend folder is in path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

from google.cloud import aiplatform
from vertexai import agent_engines

def deploy():
    print(f"Initializing Vertex AI SDK for project {PROJECT_ID} in {LOCATION}...")
    aiplatform.init(
        project=PROJECT_ID,
        location=LOCATION,
        staging_bucket=STAGING_BUCKET
    )
    
    # Change working directory to backend so extra_packages packages analytics_agent from the local context
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

    # Load the agent instance from vertex_agent
    from analytics_agent.vertex_agent import agent_instance

    reasoning_engine = None

    # Try updating the existing stable agent first
    print(f"Checking for existing Agent Engine: {STABLE_ENGINE_ID}...")
    try:
        print("Existing Agent Engine found. Updating with latest source code and dependencies...")
        reasoning_engine = agent_engines.update(
            resource_name=STABLE_ENGINE_ID,
            agent_engine=agent_instance,
            requirements=[
                "google-adk==1.31.1",
                "google-cloud-aiplatform[adk,agent_engines]==1.149.0",
                "google-cloud-bigquery",
                "requests>=2.31.0",
            ],
            extra_packages=[
                "analytics_agent"
            ]
        )
        print("\n=======================================================")
        print("🎉 Successfully UPDATED Native ADK Agent in Vertex AI Agent Engine!")
        print(f"Resource Name: {reasoning_engine.resource_name}")
        print("=======================================================\n")
    except Exception as update_err:
        print(f"Could not update existing agent (will attempt to recreate): {update_err}")
        
        # Fall back to creating a new one if update fails
        print("Creating a new Agent Engine resource...")
        try:
            reasoning_engine = agent_engines.create(
                agent_engine=agent_instance,
                requirements=[
                    "google-adk==1.31.1",
                    "google-cloud-aiplatform[adk,agent_engines]==1.149.0",
                    "google-cloud-bigquery",
                    "requests>=2.31.0",
                ],
                extra_packages=[
                    "analytics_agent"
                ],
                display_name="codemender-bq-analytics-agent"
            )
            print("\n=======================================================")
            print("🎉 Successfully DEPLOYED NEW Native ADK Agent to Vertex AI Agent Engine!")
            print(f"Resource Name: {reasoning_engine.resource_name}")
            print(f"ID: {reasoning_engine.gca_resource.name}")
            print("=======================================================\n")
        except Exception as create_err:
            print(f"\n❌ Deployment failed: {create_err}")
            sys.exit(1)

if __name__ == "__main__":
    deploy()
