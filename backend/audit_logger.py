"""
audit_logger.py — Mandatory Audit Logging
Logs every LLM interaction, tool call, analyst action, and state transition
to Elasticsearch audit_logs index for regulatory compliance.
RBI AI Governance Principles — Traceable & Explainable AI Decisions.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from elasticsearch import Elasticsearch


AUDIT_INDEX = "audit_logs"


def get_es_client() -> Elasticsearch:
    return Elasticsearch("http://localhost:9200", verify_certs=False, ssl_show_warn=False)


def _write_audit(record: Dict[str, Any]) -> bool:
    """Write a single audit record to Elasticsearch."""
    try:
        es = get_es_client()
        es.index(index=AUDIT_INDEX, id=str(uuid4()), document=record)
        return True
    except Exception as e:
        # Fallback: write to local file so audit is never lost
        with open("/tmp/audit_fallback.jsonl", "a") as f:
            f.write(json.dumps(record) + "\n")
        return False


# ─── Public Audit Functions ───────────────────────────────────────────────────

def log_llm_interaction(
    user_id: str,
    incident_id: str,
    prompt_sent: str,
    model_response: str,
    model_name: str = "llama3",
) -> None:
    """Log prompt sent to LLM and the response received. MANDATORY for compliance."""
    _write_audit({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "LLM_INTERACTION",
        "user_id": user_id,
        "incident_id": incident_id,
        "prompt_sent": prompt_sent,
        "model_response": model_response,
        "model_name": model_name,
        "tools_called": [],
        "analyst_action": None,
    })


def log_tool_call(
    user_id: str,
    incident_id: str,
    tool_name: str,
    tool_input: Dict[str, Any],
    tool_output: Any,
) -> None:
    """Log every tool invocation — query_siem, check_threat_intel, etc."""
    _write_audit({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "TOOL_CALL",
        "user_id": user_id,
        "incident_id": incident_id,
        "prompt_sent": None,
        "model_response": None,
        "tools_called": [tool_name],
        "tool_input": json.dumps(tool_input),
        "tool_output": json.dumps(tool_output) if not isinstance(tool_output, str) else tool_output,
        "analyst_action": None,
    })


def log_analyst_action(
    user_id: str,
    incident_id: str,
    action: str,  # "APPROVE" | "REJECT" | "ESCALATE" | "EXECUTE_REMEDIATION"
    details: str = "",
) -> None:
    """Log analyst decisions for human-in-the-loop audit trail."""
    _write_audit({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "ANALYST_ACTION",
        "user_id": user_id,
        "incident_id": incident_id,
        "prompt_sent": None,
        "model_response": None,
        "tools_called": [],
        "analyst_action": action,
        "details": details,
    })


def log_state_transition(
    incident_id: str,
    from_state: str,
    to_state: str,
    reason: str = "",
    user_id: str = "system",
) -> None:
    """Log every state machine transition in the LangGraph agent."""
    _write_audit({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "STATE_TRANSITION",
        "user_id": user_id,
        "incident_id": incident_id,
        "from_state": from_state,
        "to_state": to_state,
        "reason": reason,
        "prompt_sent": None,
        "model_response": None,
        "tools_called": [],
        "analyst_action": None,
    })


def log_alert_generated(
    incident_id: str,
    fidelity_score: float,
    severity: str,
    mitre_technique: str,
) -> None:
    """Log when a new alert is generated and its fidelity score."""
    _write_audit({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "ALERT_GENERATED",
        "user_id": "system",
        "incident_id": incident_id,
        "fidelity_score": fidelity_score,
        "severity": severity,
        "mitre_technique": mitre_technique,
        "prompt_sent": None,
        "model_response": None,
        "tools_called": [],
        "analyst_action": None,
    })


def get_audit_trail(incident_id: str) -> List[Dict[str, Any]]:
    """Retrieve the full audit trail for a specific incident."""
    try:
        es = get_es_client()
        result = es.search(
            index=AUDIT_INDEX,
            body={
                "query": {"term": {"incident_id": incident_id}},
                "sort": [{"timestamp": {"order": "asc"}}],
                "size": 500,
            }
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]
    except Exception as e:
        return [{"error": str(e)}]
