"""
Data access and helpers for:
- AgentExecutionTrace (Auditing & Step-by-Step Inspector)
- PatchProposal (Patch generation, AST validation, and Approval tracking)
- HumanIntervention (HITL Approval queue)
"""

import os
import sys
import logging
import time
from typing import Dict, List, Any, Optional

logger = logging.getLogger("codemender.agent_models")

def get_firestore_client():
    try:
        from google.cloud import firestore
        return firestore.Client()
    except Exception as e:
        logger.warning(f"Firestore client init skipped: {e}")
        return None

def log_agent_trace(
    execution_id: str,
    agent_name: str,
    step_type: str,
    input_payload: Optional[Dict[str, Any]] = None,
    output_payload: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
    duration_ms: int = 0,
    tokens_prompt: int = 0,
    tokens_completion: int = 0,
    cost_usd: float = 0.0
) -> str:
    """Logs a single step trace to Firestore."""
    db = get_firestore_client()
    trace_id = f"trace_{int(time.time()*1000)}"
    if db:
        try:
            db.collection("agent_traces").document(trace_id).set({
                "id": trace_id,
                "execution_id": execution_id,
                "agent_name": agent_name,
                "step_type": step_type,
                "input_payload": input_payload,
                "output_payload": output_payload,
                "error_message": error_message,
                "duration_ms": duration_ms,
                "tokens_prompt": tokens_prompt,
                "tokens_completion": tokens_completion,
                "cost_usd": cost_usd,
                "created_at": time.time()
            })
        except Exception as e:
            logger.error(f"Failed to write agent trace {trace_id}: {e}")
    return trace_id

def get_agent_traces(execution_id: str) -> List[Dict[str, Any]]:
    """Retrieves all agent traces for a specific execution run."""
    db = get_firestore_client()
    if not db:
        return []
    try:
        docs = db.collection("agent_traces").where("execution_id", "==", execution_id).stream()
        traces = [doc.to_dict() for doc in docs]
        traces.sort(key=lambda x: x.get("created_at", 0))
        return traces
    except Exception as e:
        logger.error(f"Failed to fetch traces for execution {execution_id}: {e}")
        return []

def list_human_interventions(status: Optional[str] = "PENDING") -> List[Dict[str, Any]]:
    """Lists human interventions from Firestore."""
    db = get_firestore_client()
    if not db:
        return []
    try:
        query = db.collection("human_interventions")
        if status:
            query = query.where("status", "==", status)
        docs = query.stream()
        items = [doc.to_dict() for doc in docs]
        items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return items
    except Exception as e:
        logger.error(f"Failed to list human interventions: {e}")
        return []

def resolve_human_intervention(intervention_id: str, action: str, reviewer: str, notes: Optional[str] = None) -> bool:
    """Updates an intervention status in Firestore."""
    db = get_firestore_client()
    if not db:
        return False
    try:
        db.collection("human_interventions").document(intervention_id).update({
            "status": "APPROVED" if action.upper() == "APPROVE" else "REJECTED",
            "reviewer_user": reviewer,
            "reviewer_notes": notes,
            "resolved_at": time.time()
        })
        return True
    except Exception as e:
        logger.error(f"Failed to resolve human intervention {intervention_id}: {e}")
        return False
