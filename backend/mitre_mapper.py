"""
mitre_mapper.py — MITRE ATT&CK Local Mapping Engine
Stores a compact local MITRE JSON and maps event patterns to technique IDs.
Fully offline — no external calls.
"""

import json
import re
from typing import Dict, List, Optional, Any

# ─── Compact Local MITRE Knowledge Base ──────────────────────────────────────
# Subset focused on banking-relevant techniques
MITRE_DB: Dict[str, Dict] = {
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "severity_weight": 0.85,
        "description": "Adversaries use brute force techniques to gain access to accounts when passwords are unknown.",
        "subtechniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        "indicators": ["multiple failed logins", "event_id 4625", "rapid authentication attempts"],
        "banking_risk": "HIGH — credential theft leads to fraudulent transactions",
        "mitigations": ["M1036", "M1032"],
        "detection": "Monitor authentication logs for high failure rates",
    },
    "T1059": {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "severity_weight": 0.80,
        "description": "Adversaries abuse command interpreters to execute commands.",
        "subtechniques": ["T1059.001", "T1059.003"],
        "indicators": ["powershell.exe", "cmd.exe", "wscript.exe", "bash", "python.exe"],
        "banking_risk": "HIGH — used for lateral movement and data exfiltration",
        "mitigations": ["M1038", "M1042"],
        "detection": "Monitor for unusual script execution via process creation logs",
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "severity_weight": 0.90,
        "description": "Adversaries obtain and abuse credentials of existing accounts.",
        "subtechniques": ["T1078.001", "T1078.002", "T1078.003"],
        "indicators": ["after-hours login", "unusual geo location", "privileged account misuse"],
        "banking_risk": "CRITICAL — compromised accounts enable insider-threat-level access",
        "mitigations": ["M1027", "M1026"],
        "detection": "Correlate login times, geolocations, and privilege usage",
    },
    "T1566": {
        "technique_id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "severity_weight": 0.70,
        "description": "Adversaries send phishing messages to gain access.",
        "subtechniques": ["T1566.001", "T1566.002"],
        "indicators": ["suspicious email attachment", "macro-enabled document", "external email link"],
        "banking_risk": "HIGH — common initial access vector in banking attacks",
        "mitigations": ["M1049", "M1031"],
        "detection": "Email gateway alerts, sandbox detonation results",
    },
    "T1005": {
        "technique_id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "severity_weight": 0.75,
        "description": "Adversaries search local system for files of interest.",
        "subtechniques": [],
        "indicators": ["bulk file access", "database dump", "mass read operations"],
        "banking_risk": "CRITICAL — customer PII and financial data exfiltration risk",
        "mitigations": ["M1057"],
        "detection": "Monitor unusual file system access patterns and database queries",
    },
    "T1190": {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "severity_weight": 0.88,
        "description": "Adversaries exploit internet-facing applications.",
        "subtechniques": [],
        "indicators": ["SQL injection", "XSS payload", "abnormal HTTP response codes", "WAF alerts"],
        "banking_risk": "CRITICAL — direct access to banking application backend",
        "mitigations": ["M1048", "M1051"],
        "detection": "Web application firewall logs, application error rates",
    },
    "T1071": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "severity_weight": 0.72,
        "description": "Adversaries communicate using application layer protocols.",
        "subtechniques": ["T1071.001", "T1071.004"],
        "indicators": ["unusual DNS queries", "HTTP beacon pattern", "periodic outbound connections"],
        "banking_risk": "HIGH — C2 communications indicate active compromise",
        "mitigations": ["M1031", "M1037"],
        "detection": "Network traffic analysis, DNS monitoring",
    },
    "T1486": {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "severity_weight": 0.98,
        "description": "Adversaries encrypt data to render systems unusable (ransomware).",
        "subtechniques": [],
        "indicators": ["rapid file encryption", "ransom note creation", "vssadmin delete shadows"],
        "banking_risk": "CRITICAL — operational disruption, regulatory penalties, reputational damage",
        "mitigations": ["M1053", "M1040"],
        "detection": "File system monitoring for mass encryption activity",
    },
}

# ─── Pattern → Technique Mapping Rules ───────────────────────────────────────
PATTERN_RULES = [
    {
        "pattern": r"4625|failed.?login|authentication.?fail|invalid.?password|wrong.?password",
        "technique_id": "T1110",
        "confidence": 0.9,
    },
    {
        "pattern": r"powershell|cmd\.exe|wscript|cscript|bash\.exe",
        "technique_id": "T1059",
        "confidence": 0.8,
    },
    {
        "pattern": r"unusual.?login|off.?hours|geo.?anomaly|vpn.?bypass",
        "technique_id": "T1078",
        "confidence": 0.75,
    },
    {
        "pattern": r"phish|malicious.?attachment|macro|spear.?phish",
        "technique_id": "T1566",
        "confidence": 0.7,
    },
    {
        "pattern": r"sql.?inject|xss|directory.?traversal|rce|exploit",
        "technique_id": "T1190",
        "confidence": 0.88,
    },
    {
        "pattern": r"dns.?tunnel|beacon|c2|command.?control|covert.?channel",
        "technique_id": "T1071",
        "confidence": 0.72,
    },
    {
        "pattern": r"encrypt|ransomware|ransom|locked.?file|shadow.?copy.?delete",
        "technique_id": "T1486",
        "confidence": 0.95,
    },
    {
        "pattern": r"bulk.?read|database.?dump|exfil|mass.?download",
        "technique_id": "T1005",
        "confidence": 0.75,
    },
]


def map_event_to_mitre(event_text: str, event_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Auto-map an event (text description or log entry) to a MITRE technique.
    Returns technique details with confidence score.
    """
    text = (event_text + " " + (event_id or "")).lower()
    best_match = None
    best_confidence = 0.0

    for rule in PATTERN_RULES:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            if rule["confidence"] > best_confidence:
                best_confidence = rule["confidence"]
                best_match = rule["technique_id"]

    if best_match and best_match in MITRE_DB:
        technique = MITRE_DB[best_match].copy()
        technique["match_confidence"] = best_confidence
        return technique

    # Default — unclassified
    return {
        "technique_id": "UNKNOWN",
        "name": "Unclassified",
        "tactic": "Unknown",
        "severity_weight": 0.3,
        "match_confidence": 0.0,
        "banking_risk": "UNKNOWN",
    }


def get_technique_by_id(technique_id: str) -> Dict[str, Any]:
    """Look up a specific MITRE technique by ID."""
    if technique_id in MITRE_DB:
        return MITRE_DB[technique_id]
    return {
        "error": f"Technique {technique_id} not found in local MITRE DB",
        "available": list(MITRE_DB.keys()),
    }


def list_all_techniques() -> List[Dict[str, Any]]:
    """Return all techniques in the local MITRE knowledge base."""
    return [
        {
            "technique_id": t["technique_id"],
            "name": t["name"],
            "tactic": t["tactic"],
            "severity_weight": t["severity_weight"],
        }
        for t in MITRE_DB.values()
    ]
