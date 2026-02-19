"""
agent_graph.py — LangGraph Agent Orchestration
State machine: Triage → Dedup → Investigator → Response
LLM: Ollama (local only) — llama3
All outputs are strictly validated Pydantic JSON.
No free-text LLM output allowed.
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Annotated, TypedDict

from pydantic import BaseModel, Field, validator
from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.output_parsers import PydanticOutputParser

import audit_logger
import dedup
from tools_server import query_siem, check_threat_intel, get_compliance_sop, get_mitre_details
from mitre_mapper import map_event_to_mitre


# ─── Ollama LLM (Local Only) ──────────────────────────────────────────────────
def get_llm(model: str = "llama3") -> Ollama:
    """Return a local Ollama LLM. No cloud API keys needed."""
    return Ollama(
        model=model,
        base_url="http://localhost:11434",
        temperature=0.1,  # Low temp for consistent, structured output
        timeout=120,
    )


# ─── Strict Output Schema (Pydantic) ─────────────────────────────────────────

class PlaybookStep(BaseModel):
    step_number: int
    action: str
    responsible_team: str
    deadline: str
    compliance_ref: Optional[str] = None


class IncidentResponse(BaseModel):
    """
    Strictly validated incident response output.
    No free text allowed — every field is typed and validated.
    """
    incident_id: str
    summary: str = Field(..., min_length=20, max_length=1000)
    mitre_technique: str
    mitre_tactic: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    explanation: List[str] = Field(..., min_items=1)
    playbook_steps: List[PlaybookStep] = Field(..., min_items=1)
    recommended_actions: List[str] = Field(..., min_items=1)
    requires_human_approval: bool = True
    severity: str = Field(..., regex="^(Critical|High|Medium|Low)$")
    affected_users: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    regulatory_obligations: List[str] = Field(default_factory=list)


# ─── Agent State ──────────────────────────────────────────────────────────────

class AgentState(TypedDict):
    incident_id: str
    raw_alert: Dict[str, Any]
    analysis_result: Dict[str, Any]
    is_duplicate: bool
    investigation_data: Dict[str, Any]
    siem_results: Dict[str, Any]
    threat_intel: Dict[str, Any]
    mitre_details: Dict[str, Any]
    sop: Dict[str, Any]
    final_response: Optional[Dict[str, Any]]
    error: Optional[str]
    state_history: List[str]
    user_id: str


# ─── Node Functions ───────────────────────────────────────────────────────────

def triage_node(state: AgentState) -> AgentState:
    """
    Triage Node: Check fidelity score.
    If fidelity < 0.75 → skip to END (do not waste LLM resources).
    """
    incident_id = state["incident_id"]
    analysis = state["analysis_result"]

    audit_logger.log_state_transition(incident_id, "START", "TRIAGE", user_id=state["user_id"])
    state["state_history"].append("TRIAGE")

    fidelity = analysis.get("fidelity", {}).get("fidelity_score", 0.0)
    if fidelity < 0.75:
        audit_logger.log_state_transition(
            incident_id, "TRIAGE", "END",
            reason=f"Fidelity {fidelity:.3f} below threshold 0.75",
            user_id=state["user_id"]
        )
        state["final_response"] = {
            "incident_id": incident_id,
            "skipped": True,
            "reason": f"Fidelity score {fidelity:.3f} below activation threshold 0.75",
            "severity": analysis.get("fidelity", {}).get("severity", "Low"),
        }

    return state


def dedup_node(state: AgentState) -> AgentState:
    """
    Dedup Node: Check if this alert is a duplicate.
    If duplicate → skip to END, log suppression.
    """
    if state.get("final_response"):
        return state  # Already terminated in triage

    incident_id = state["incident_id"]
    raw_alert = state["raw_alert"]

    audit_logger.log_state_transition(incident_id, "TRIAGE", "DEDUP", user_id=state["user_id"])
    state["state_history"].append("DEDUP")

    is_dup = dedup.is_duplicate(raw_alert)
    state["is_duplicate"] = is_dup

    if is_dup:
        audit_logger.log_state_transition(
            incident_id, "DEDUP", "END",
            reason="Duplicate alert suppressed",
            user_id=state["user_id"]
        )
        state["final_response"] = {
            "incident_id": incident_id,
            "skipped": True,
            "reason": "Duplicate alert — suppressed by deduplication engine",
        }

    return state


def investigator_node(state: AgentState) -> AgentState:
    """
    Investigator Node: Run SIEM queries, threat intel, MITRE lookup.
    Gathers all evidence needed for response generation.
    """
    if state.get("final_response"):
        return state

    incident_id = state["incident_id"]
    alert = state["raw_alert"]
    user_id = state["user_id"]

    audit_logger.log_state_transition(incident_id, "DEDUP", "INVESTIGATOR", user_id=user_id)
    state["state_history"].append("INVESTIGATOR")

    source_ip = alert.get("source_ip", "")
    user_id_target = alert.get("user_id", "")
    event_type = alert.get("event_type", "")

    # Tool 1: Query SIEM for correlated events
    siem_query = f"{user_id_target} {source_ip} authentication"
    siem_results = query_siem(siem_query, incident_id=incident_id, user_id=user_id)
    state["siem_results"] = siem_results

    # Tool 2: Threat intelligence check
    threat_intel = check_threat_intel(source_ip, incident_id=incident_id, user_id=user_id)
    state["threat_intel"] = threat_intel

    # Tool 3: MITRE technique details
    mitre_technique = alert.get("mitre_technique", "")
    if not mitre_technique:
        mitre_map = map_event_to_mitre(event_type, alert.get("event_id", ""))
        mitre_technique = mitre_map.get("technique_id", "UNKNOWN")

    mitre_details = get_mitre_details(mitre_technique, incident_id=incident_id, user_id=user_id)
    state["mitre_details"] = mitre_details

    # Tool 4: Get compliance SOP
    threat_type = mitre_details.get("name", event_type) or event_type
    sop = get_compliance_sop(threat_type, incident_id=incident_id, user_id=user_id)
    state["sop"] = sop

    state["investigation_data"] = {
        "siem_hit_count": siem_results.get("total_hits", 0),
        "source_ip_malicious": threat_intel.get("is_malicious", False),
        "threat_score": threat_intel.get("threat_score", 0.0),
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_details.get("tactic", ""),
        "mitre_severity": mitre_details.get("severity_weight", 0.5),
    }

    return state


def response_node(state: AgentState) -> AgentState:
    """
    Response Node: Generate structured incident response using local LLM.
    Output is strictly validated via Pydantic schema — no free text allowed.
    """
    if state.get("final_response"):
        return state

    incident_id = state["incident_id"]
    alert = state["raw_alert"]
    analysis = state["analysis_result"]
    investigation = state["investigation_data"]
    sop = state.get("sop", {})
    mitre = state.get("mitre_details", {})
    threat_intel = state.get("threat_intel", {})
    user_id = state["user_id"]

    audit_logger.log_state_transition(incident_id, "INVESTIGATOR", "RESPONSE", user_id=user_id)
    state["state_history"].append("RESPONSE")

    # ── Build structured context for LLM prompt ──
    top_features = analysis.get("top_contributing_features", [])
    feature_text = "\n".join([
        f"  - {f['feature']}: value={f['actual_value']:.3f}, importance={f['importance']:.3f}"
        for f in top_features
    ])

    sop_steps_text = "\n".join(sop.get("steps", ["Follow general IR procedure."]))

    prompt = f"""You are a banking cybersecurity AI. Analyze this incident and return ONLY valid JSON.

INCIDENT CONTEXT:
- Incident ID: {incident_id}
- Source IP: {alert.get('source_ip', '')} (Malicious: {threat_intel.get('is_malicious', False)}, Threat Score: {threat_intel.get('threat_score', 0.0)})
- Target User: {alert.get('user_id', '')}
- Event Type: {alert.get('event_type', '')}
- MITRE Technique: {investigation.get('mitre_technique', '')} ({mitre.get('name', '')})
- MITRE Tactic: {investigation.get('mitre_tactic', '')}
- Anomaly Score: {analysis.get('anomaly_score', 0.0):.3f}
- Fidelity Score: {analysis.get('fidelity', {}).get('fidelity_score', 0.0):.3f}
- Severity: {analysis.get('fidelity', {}).get('severity', 'High')}
- SIEM Correlated Events: {investigation.get('siem_hit_count', 0)}
- Banking Risk: {mitre.get('banking_risk', 'HIGH')}

TOP ANOMALY FEATURES:
{feature_text}

COMPLIANCE SOP STEPS:
{sop_steps_text}

Return ONLY this exact JSON structure (no markdown, no explanation):
{{
  "incident_id": "{incident_id}",
  "summary": "<2-3 sentence factual summary of what happened and risk>",
  "mitre_technique": "{investigation.get('mitre_technique', '')}",
  "mitre_tactic": "{investigation.get('mitre_tactic', '')}",
  "confidence_score": {min(analysis.get('fidelity', {}).get('fidelity_score', 0.8), 1.0):.2f},
  "severity": "{analysis.get('fidelity', {}).get('severity', 'High')}",
  "explanation": [
    "<key finding 1>",
    "<key finding 2>",
    "<key finding 3>"
  ],
  "playbook_steps": [
    {{
      "step_number": 1,
      "action": "<specific action>",
      "responsible_team": "<SOC|NOC|Identity|Compliance>",
      "deadline": "<immediate|1h|6h|24h>",
      "compliance_ref": "<RBI/CERT-In reference if applicable>"
    }}
  ],
  "recommended_actions": [
    "<action 1>",
    "<action 2>",
    "<action 3>"
  ],
  "requires_human_approval": true,
  "affected_users": ["{alert.get('user_id', '')}"],
  "source_ips": ["{alert.get('source_ip', '')}"],
  "regulatory_obligations": [
    "<specific regulatory deadline or obligation>"
  ]
}}"""

    try:
        llm = get_llm()
        audit_logger.log_llm_interaction(user_id, incident_id, prompt, "PENDING")

        raw_output = llm.invoke(prompt)

        # Audit the actual LLM response
        audit_logger.log_llm_interaction(user_id, incident_id, prompt, raw_output)

        # ── Strict JSON parsing + Pydantic validation ──
        # Strip markdown code fences if present
        clean_output = raw_output.strip()
        if clean_output.startswith("```"):
            lines = clean_output.split("\n")
            clean_output = "\n".join(lines[1:-1])

        parsed_json = json.loads(clean_output)
        validated = IncidentResponse(**parsed_json)
        state["final_response"] = validated.dict()

    except json.JSONDecodeError as e:
        # LLM returned non-JSON — build structured fallback (no free text leaks)
        state["final_response"] = _build_fallback_response(
            incident_id, alert, analysis, investigation, sop, mitre, threat_intel
        )
        audit_logger.log_tool_call(user_id, incident_id, "LLM_JSON_PARSE_ERROR", {"error": str(e)}, {})

    except Exception as e:
        # LLM unavailable — graceful fallback
        state["final_response"] = _build_fallback_response(
            incident_id, alert, analysis, investigation, sop, mitre, threat_intel
        )
        audit_logger.log_tool_call(user_id, incident_id, "LLM_ERROR", {"error": str(e)}, {})

    audit_logger.log_state_transition(incident_id, "RESPONSE", "END", user_id=user_id)
    state["state_history"].append("END")

    return state


def _build_fallback_response(
    incident_id, alert, analysis, investigation, sop, mitre, threat_intel
) -> Dict[str, Any]:
    """
    Rule-based fallback response when LLM is unavailable or returns invalid output.
    Ensures the platform remains operational offline without LLM.
    """
    sop_steps = sop.get("steps", ["Follow general IR procedure."])
    playbook_steps = [
        {
            "step_number": i + 1,
            "action": step,
            "responsible_team": "SOC",
            "deadline": "immediate" if i == 0 else "1h",
            "compliance_ref": sop.get("compliance_ref", ""),
        }
        for i, step in enumerate(sop_steps[:5])
    ]

    return {
        "incident_id": incident_id,
        "summary": (
            f"Security incident detected: {alert.get('event_type', 'Authentication anomaly')} "
            f"from {alert.get('source_ip', 'unknown IP')} targeting {alert.get('user_id', 'unknown user')}. "
            f"MITRE technique {investigation.get('mitre_technique', '')} identified. "
            f"{'Source IP confirmed malicious in threat intel. ' if threat_intel.get('is_malicious') else ''}"
            f"Fidelity score: {analysis.get('fidelity', {}).get('fidelity_score', 0.0):.3f}."
        ),
        "mitre_technique": investigation.get("mitre_technique", ""),
        "mitre_tactic": investigation.get("mitre_tactic", ""),
        "confidence_score": analysis.get("fidelity", {}).get("fidelity_score", 0.75),
        "severity": analysis.get("fidelity", {}).get("severity", "High"),
        "explanation": [
            f"Anomaly score: {analysis.get('anomaly_score', 0.0):.3f} — indicates unusual behavior pattern",
            f"Source IP {alert.get('source_ip', '')} threat score: {threat_intel.get('threat_score', 0.0):.2f}",
            f"SIEM correlated {investigation.get('siem_hit_count', 0)} related events",
        ],
        "playbook_steps": playbook_steps,
        "recommended_actions": [
            f"Block source IP {alert.get('source_ip', '')} at perimeter firewall",
            f"Lock account {alert.get('user_id', '')} pending investigation",
            "Notify CISO and escalate to Security Operations",
            "File CERT-In report within mandatory timeline",
        ],
        "requires_human_approval": True,
        "affected_users": [alert.get("user_id", "")],
        "source_ips": [alert.get("source_ip", "")],
        "generated_at": datetime.utcnow().isoformat(),
        "regulatory_obligations": [
            f"CERT-In notification: {sop.get('regulatory_deadlines', {}).get('cert_in_notification', '6 hours')}",
            f"RBI notification: {sop.get('regulatory_deadlines', {}).get('rbi_notification', '6 hours')}",
        ],
        "generated_by": "rule_based_fallback",
    }


# ─── Graph Orchestration ──────────────────────────────────────────────────────

def run_agent(
    raw_alert: Dict[str, Any],
    analysis_result: Dict[str, Any],
    user_id: str = "system",
) -> Dict[str, Any]:
    """
    Execute the full LangGraph agent pipeline:
    START → Triage → Dedup → Investigator → Response → END
    """
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

    # Initialize state
    state: AgentState = {
        "incident_id": incident_id,
        "raw_alert": raw_alert,
        "analysis_result": analysis_result,
        "is_duplicate": False,
        "investigation_data": {},
        "siem_results": {},
        "threat_intel": {},
        "mitre_details": {},
        "sop": {},
        "final_response": None,
        "error": None,
        "state_history": ["START"],
        "user_id": user_id,
    }

    audit_logger.log_state_transition(incident_id, "INIT", "START", user_id=user_id)

    # Run pipeline sequentially (LangGraph-style state passing)
    try:
        state = triage_node(state)
        state = dedup_node(state)
        state = investigator_node(state)
        state = response_node(state)
    except Exception as e:
        state["error"] = str(e)
        state["final_response"] = {
            "incident_id": incident_id,
            "error": str(e),
            "requires_human_approval": True,
        }
        audit_logger.log_tool_call(user_id, incident_id, "AGENT_ERROR", {"error": str(e)}, {})

    return {
        "incident_id": incident_id,
        "state_history": state["state_history"],
        "response": state["final_response"],
        "investigation": state.get("investigation_data", {}),
        "is_duplicate": state.get("is_duplicate", False),
    }
