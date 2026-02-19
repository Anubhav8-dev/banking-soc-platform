"""
tools_server.py — FastMCP Tool Layer
Exposes security tools as MCP-compatible functions:
  - query_siem
  - check_threat_intel
  - get_compliance_sop
  - get_mitre_details
All data sources are LOCAL ONLY. No external HTTP calls.
FAISS stores banking SOPs and RBI compliance playbooks.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np
from elasticsearch import Elasticsearch

from mitre_mapper import get_technique_by_id, map_event_to_mitre
import audit_logger

# ─── Constants ────────────────────────────────────────────────────────────────
ES_HOST = "http://localhost:9200"
INDEX_NAME = "banking_logs"
THREAT_INTEL_PATH = os.path.join(os.path.dirname(__file__), "../data/threat_intel.json")

# ─── Local Threat Intelligence (Blacklist) ────────────────────────────────────
def _load_threat_intel() -> Dict[str, Any]:
    """Load local IP/domain blacklist from JSON file."""
    try:
        with open(THREAT_INTEL_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        # Return minimal built-in blacklist
        return {
            "malicious_ips": [
                "10.10.10.99", "192.168.50.10", "172.16.100.5",
                "45.142.212.100", "185.220.101.34",
            ],
            "malicious_domains": ["evil.com", "malware.ru", "phish.cn"],
            "tor_exit_nodes": ["198.51.100.0", "203.0.113.0"],
            "known_c2_ips": ["176.10.99.200", "94.102.49.190"],
        }


_THREAT_INTEL = _load_threat_intel()


# ─── Banking SOPs (FAISS-ready Knowledge Base) ────────────────────────────────
BANKING_SOPS = {
    "brute_force": {
        "sop_id": "SOP-001",
        "threat_type": "Brute Force Attack",
        "compliance_ref": "RBI Master Directions on NBFC-IT, Section 7.4",
        "steps": [
            "1. Immediately lock the targeted account (max 5 failed attempts policy).",
            "2. Block source IPs at perimeter firewall — escalate to NOC.",
            "3. Notify account holder via registered mobile/email.",
            "4. Capture and preserve SIEM logs for forensic investigation.",
            "5. Assess if 2FA was bypassed — escalate to Identity team if yes.",
            "6. File SAR (Suspicious Activity Report) if financial access attempted.",
            "7. Notify CERT-In within 6 hours per RBI Circular RBI/2021-22/176.",
            "8. Conduct post-incident review within 72 hours.",
        ],
        "regulatory_deadlines": {
            "cert_in_notification": "6 hours",
            "rbi_cyber_incident_report": "2-6 hours",
            "board_notification": "24 hours",
        }
    },
    "data_exfiltration": {
        "sop_id": "SOP-002",
        "threat_type": "Data Exfiltration",
        "compliance_ref": "RBI Data Localisation Guidelines, IT Act Section 72A",
        "steps": [
            "1. Isolate affected system from network immediately.",
            "2. Terminate suspicious user sessions.",
            "3. Identify and quantify data potentially accessed.",
            "4. Determine if PII/financial data was involved.",
            "5. Notify DPO (Data Protection Officer) within 1 hour.",
            "6. Preserve forensic evidence — disk image before remediation.",
            "7. Notify CERT-In and RBI DPSS within 2 hours.",
            "8. Prepare breach notification per IT Act and RBI guidelines.",
        ],
        "regulatory_deadlines": {
            "cert_in_notification": "2 hours",
            "rbi_dpss_notification": "2 hours",
            "customer_notification": "24 hours (if PII affected)",
        }
    },
    "ransomware": {
        "sop_id": "SOP-003",
        "threat_type": "Ransomware",
        "compliance_ref": "RBI Cybersecurity Framework for Banks, Section 3",
        "steps": [
            "1. IMMEDIATELY isolate all affected systems — disconnect from network.",
            "2. Activate BCP/DR plan — switch to backup systems.",
            "3. DO NOT pay ransom — notify senior management.",
            "4. Notify CERT-In within 6 hours (mandatory).",
            "5. Notify RBI within 2 hours under cyber incident reporting.",
            "6. Engage IR retainer/forensics team.",
            "7. Identify patient zero — scope the blast radius.",
            "8. Restore from verified clean backups only.",
            "9. Notify affected customers if services disrupted.",
        ],
        "regulatory_deadlines": {
            "cert_in_notification": "6 hours",
            "rbi_notification": "2 hours",
            "rbi_detailed_report": "24 hours",
        }
    },
    "account_takeover": {
        "sop_id": "SOP-004",
        "threat_type": "Account Takeover (ATO)",
        "compliance_ref": "RBI Guidelines on Internet Banking Security, Annex II",
        "steps": [
            "1. Freeze all transactions on the compromised account.",
            "2. Reset credentials and revoke all active sessions/tokens.",
            "3. Notify account holder immediately via all registered channels.",
            "4. Reverse any fraudulent transactions within SLA.",
            "5. File NPCI/RBI fraud report.",
            "6. Conduct full account activity forensic review.",
            "7. Enhance monitoring on linked accounts.",
            "8. If > ₹50,000 involved, mandatory FIR filing.",
        ],
        "regulatory_deadlines": {
            "customer_notification": "Immediate",
            "fraud_report_to_rbi": "24 hours",
            "transaction_reversal_attempt": "T+1 business day",
        }
    }
}


# ─── Tool Functions ───────────────────────────────────────────────────────────

def query_siem(
    query: str,
    incident_id: str = "",
    user_id: str = "system",
    size: int = 20,
) -> Dict[str, Any]:
    """
    Query the local Elasticsearch SIEM for logs matching a query string.
    Returns structured result with log entries and metadata.
    """
    try:
        es = Elasticsearch(ES_HOST, verify_certs=False, ssl_show_warn=False)

        # Build a multi-field search query
        es_query = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["message", "raw", "user_id", "source_ip", "event_type", "mitre_technique"],
                    "type": "best_fields",
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
        }

        result = es.search(index=INDEX_NAME, body=es_query)
        hits = [h["_source"] for h in result["hits"]["hits"]]

        output = {
            "query": query,
            "total_hits": result["hits"]["total"]["value"],
            "returned": len(hits),
            "logs": hits,
        }

        # Audit the tool call
        audit_logger.log_tool_call(user_id, incident_id, "query_siem", {"query": query}, output)
        return output

    except Exception as e:
        error_result = {"error": str(e), "query": query, "logs": []}
        audit_logger.log_tool_call(user_id, incident_id, "query_siem", {"query": query}, error_result)
        return error_result


def check_threat_intel(
    ip: str,
    incident_id: str = "",
    user_id: str = "system",
) -> Dict[str, Any]:
    """
    Check an IP against the local threat intelligence blacklist.
    NO external calls — uses local JSON file only.
    """
    intel = _THREAT_INTEL
    result = {
        "ip": ip,
        "is_malicious": False,
        "threat_score": 0.0,
        "categories": [],
        "checked_at": datetime.utcnow().isoformat(),
        "source": "local_blacklist",
    }

    if ip in intel.get("malicious_ips", []):
        result["is_malicious"] = True
        result["threat_score"] = 0.9
        result["categories"].append("known_malicious")

    if ip in intel.get("tor_exit_nodes", []):
        result["is_malicious"] = True
        result["threat_score"] = max(result["threat_score"], 0.7)
        result["categories"].append("tor_exit_node")

    if ip in intel.get("known_c2_ips", []):
        result["is_malicious"] = True
        result["threat_score"] = max(result["threat_score"], 0.95)
        result["categories"].append("known_c2")

    audit_logger.log_tool_call(user_id, incident_id, "check_threat_intel", {"ip": ip}, result)
    return result


def get_compliance_sop(
    threat_type: str,
    incident_id: str = "",
    user_id: str = "system",
) -> Dict[str, Any]:
    """
    Retrieve the banking compliance SOP for a given threat type.
    SOPs include RBI-mandated steps and regulatory deadlines.
    """
    # Normalize the key
    key = threat_type.lower().replace(" ", "_").replace("-", "_")

    # Map common aliases
    aliases = {
        "brute_force_attack": "brute_force",
        "credential_stuffing": "brute_force",
        "t1110": "brute_force",
        "exfiltration": "data_exfiltration",
        "data_theft": "data_exfiltration",
        "ransomware_attack": "ransomware",
        "ato": "account_takeover",
        "account_compromise": "account_takeover",
    }
    key = aliases.get(key, key)

    sop = BANKING_SOPS.get(key)

    if not sop:
        # Return generic incident response SOP
        sop = {
            "sop_id": "SOP-GENERIC",
            "threat_type": threat_type,
            "compliance_ref": "RBI Cybersecurity Framework for Banks",
            "steps": [
                "1. Contain the incident — isolate affected systems.",
                "2. Document all findings with timestamps.",
                "3. Notify CISO and Security Operations leadership.",
                "4. Preserve evidence for forensic analysis.",
                "5. Eradicate threat and verify clean state.",
                "6. Restore services via approved change management.",
                "7. File mandatory regulatory reports (CERT-In, RBI).",
                "8. Conduct lessons learned within 30 days.",
            ],
            "regulatory_deadlines": {
                "cert_in_notification": "6 hours",
                "rbi_notification": "6 hours",
            }
        }

    audit_logger.log_tool_call(user_id, incident_id, "get_compliance_sop", {"threat_type": threat_type}, sop)
    return sop


def get_mitre_details(
    technique_id: str,
    incident_id: str = "",
    user_id: str = "system",
) -> Dict[str, Any]:
    """Retrieve full MITRE ATT&CK technique details from local DB."""
    result = get_technique_by_id(technique_id)
    audit_logger.log_tool_call(user_id, incident_id, "get_mitre_details", {"technique_id": technique_id}, result)
    return result
