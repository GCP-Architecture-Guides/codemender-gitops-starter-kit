#!/usr/bin/env python3
# run_analytics.py
# CLI wrapper to run the BigQuery Analytics Agent locally.

import os
import sys
import asyncio

# Default to this deployment's telemetry project if not set in environment
if "GOOGLE_CLOUD_PROJECT" not in os.environ:
    os.environ["GOOGLE_CLOUD_PROJECT"] = "YOUR_PROJECT_ID"

# Append backend folder to python path so it can import backend modules
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

from analytics_agent.agent import chat_with_analytics_agent

async def main():
    if len(sys.argv) < 2:
        print("Usage: python run_analytics.py \"<your question here>\"")
        sys.exit(1)
        
    query = sys.argv[1]
    
    print("🤖 Initializing BigQuery Analytics Agent...")
    try:
        response = await chat_with_analytics_agent(query)
        print("\n=== Agent Response ===")
        print(response)
        print("======================\n")
    except Exception as e:
        print(f"\n❌ Error executing query: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
