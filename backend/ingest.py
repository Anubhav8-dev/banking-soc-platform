"""
ingest.py — Banking-Grade Log Ingestion Module
Handles Elasticsearch connection, index creation, bulk CSV ingestion,
and dummy brute-force attack data generation.
MITRE ATT&CK Technique: T1110 (Brute Force)
"""

import csv
import json
import uuid
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

from elasticsearch import Elasticsearch, helpers

# ─── Elasticsearch Client ─────────────────────────────────────────────────────
ES_HOST = "http://localhost:9200"
INDEX_NAME = "banking_logs"
AUDIT_INDEX = "audit_logs"


def get_es_client() -> Elasticsearch:
    """Return a local-only Elasticsearch client. No cloud, no telemetry."""
    return Elasticsearch(
        ES_HOST,
        verify_certs=False,
        ssl_show_warn=False,
        # Disable any Elasticsearch telemetry
        request_timeout=30,
    )


# ─── Index Mapping ────────────────────────────────────────────────────────────
BANKING_LOGS_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":     {"type": "date"},
            "source_ip":     {"type": "keyword"},
            "event_id":      {"type": "keyword"},
            "user_id":       {"type": "keyword"},
            "process_name":  {"type": "keyword"},
            "host_name":     {"type": "keyword"},
            "status":        {"type": "keyword"},
            # Extended fields
            "event_type":    {"type": "keyword"},
            "mitre_technique": {"type": "keyword"},
            "mitre_tactic":  {"type": "keyword"},
            "destination_ip": {"type": "keyword"},
            "port":          {"type": "integer"},
            "bytes_sent":    {"type": "long"},
            "log_level":     {"type": "keyword"},
            "message":       {"type": "text"},
            "session_id":    {"type": "keyword"},
            "country":       {"type": "keyword"},
            "raw":           {"type": "text"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    }
}

AUDIT_LOGS_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":     {"type": "date"},
            "action":        {"type": "keyword"},
            "user_id":       {"type": "keyword"},
            "incident_id":   {"type": "keyword"},
            "prompt_sent":   {"type": "text"},
            "model_response":{"type": "text"},
            "tools_called":  {"type": "keyword"},
            "analyst_action":{"type": "keyword"},
            "details":       {"type": "text"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    }
}


def create_indices(es: Elasticsearch) -> None:
    """Create banking_logs and audit_logs indices if they don't exist."""
    for index, mapping in [(INDEX_NAME, BANKING_LOGS_MAPPING), (AUDIT_INDEX, AUDIT_LOGS_MAPPING)]:
        if not es.indices.exists(index=index):
            es.indices.create(index=index, body=mapping)
            print(f"[INGEST] Created index: {index}")
        else:
            print(f"[INGEST] Index already exists: {index}")


def bulk_ingest_csv(es: Elasticsearch, csv_path: str) -> Dict[str, Any]:
    """
    Bulk ingest log records from a CSV file into banking_logs.
    Expected CSV columns: timestamp,source_ip,event_id,user_id,process_name,host_name,status
    """
    docs = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            doc = {
                "_index": INDEX_NAME,
                "_id": str(uuid.uuid4()),
                "_source": {
                    "timestamp": row.get("timestamp", datetime.utcnow().isoformat()),
                    "source_ip": row.get("source_ip", ""),
                    "event_id":  row.get("event_id", ""),
                    "user_id":   row.get("user_id", ""),
                    "process_name": row.get("process_name", ""),
                    "host_name": row.get("host_name", ""),
                    "status":    row.get("status", ""),
                    "raw":       json.dumps(row),
                }
            }
            docs.append(doc)

    success, errors = helpers.bulk(es, docs, raise_on_error=False)
    return {"success": success, "errors": errors, "total": len(docs)}


def generate_brute_force_logs(
    es: Elasticsearch,
    count: int = 200,
    target_user: str = "admin",
    attacker_ip: str = "10.10.10.99"
) -> Dict[str, Any]:
    """
    Generate synthetic brute-force attack logs tagged with MITRE T1110.
    Simulates rapid failed logins followed by one success.
    """
    docs = []
    base_time = datetime.utcnow() - timedelta(minutes=30)

    # Attacker IPs — slight variation to simulate distributed attack
    attacker_ips = [attacker_ip] + [
        f"10.10.10.{random.randint(100, 150)}" for _ in range(3)
    ]

    for i in range(count):
        ts = base_time + timedelta(seconds=i * 8)
        is_success = (i == count - 1)  # Last event is the successful login
        current_ip = random.choice(attacker_ips)

        doc = {
            "_index": INDEX_NAME,
            "_id": str(uuid.uuid4()),
            "_source": {
                "timestamp":       ts.isoformat(),
                "source_ip":       current_ip,
                "event_id":        "4625" if not is_success else "4624",
                "user_id":         target_user,
                "process_name":    "lsass.exe",
                "host_name":       "CORP-DC-01",
                "status":          "FAILURE" if not is_success else "SUCCESS",
                "event_type":      "Authentication",
                "mitre_technique": "T1110",
                "mitre_tactic":    "Credential Access",
                "destination_ip":  "192.168.1.10",
                "port":            445,
                "bytes_sent":      random.randint(200, 600),
                "log_level":       "WARNING" if not is_success else "CRITICAL",
                "message":         (
                    f"Failed login attempt for {target_user} from {current_ip}"
                    if not is_success else
                    f"SUCCESSFUL login for {target_user} from {current_ip} after {count-1} failures"
                ),
                "session_id":      f"sess_{uuid.uuid4().hex[:8]}",
                "country":         random.choice(["CN", "RU", "KP", "IR", "US"]),
                "raw":             f"EventID={4625 if not is_success else 4624} User={target_user} IP={current_ip}",
            }
        }
        docs.append(doc)

    success, errors = helpers.bulk(es, docs, raise_on_error=False)
    return {
        "success": success,
        "errors": errors,
        "total": count,
        "mitre_technique": "T1110",
        "description": "Brute Force Attack simulation ingested"
    }
