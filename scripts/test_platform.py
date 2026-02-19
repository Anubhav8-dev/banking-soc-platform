
import sys
import os

# Ensure backend directory is in Python path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

#!/usr/bin/env python3
"""
test_platform.py — Integration Test Script
Tests the core backend components without requiring a running server.
Run this after installing requirements to verify the setup.
"""

import sys
import json

def test_ingest():
    print("\n[1/5] Testing ingest module...")
    try:
        from ingest import get_es_client, create_indices
        es = get_es_client()
        es.ping()
        print("  ✓ Elasticsearch connection OK")
        create_indices(es)
        print("  ✓ Indices created/verified")
    except Exception as e:
        print(f"  ✗ Elasticsearch unavailable: {e}")
        print("  → Start ES: docker run -p 9200:9200 -e discovery.type=single-node elasticsearch:8.11.0")

def test_analytics():
    print("\n[2/5] Testing analytics module...")
    try:
        from analytics import extract_features, compute_fidelity_score
        import pandas as pd
        from datetime import datetime, timedelta

        # Simulate brute-force log data
        logs = []
        base = datetime.utcnow()
        for i in range(50):
            logs.append({
                "timestamp": (base + timedelta(seconds=i*5)).isoformat(),
                "source_ip": "10.10.10.99",
                "user_id": "admin",
                "status": "FAILURE" if i < 49 else "SUCCESS",
                "event_id": "4625" if i < 49 else "4624",
            })

        features = extract_features(logs)
        print(f"  ✓ Feature extraction: {len(features)} windows, columns: {list(features.columns)}")

        fidelity = compute_fidelity_score(0.92, 0.9, 0.8, 0.85, 0.7)
        print(f"  ✓ Fidelity: {fidelity['fidelity_score']} → {fidelity['severity']}")
    except Exception as e:
        print(f"  ✗ Analytics error: {e}")

def test_mitre():
    print("\n[3/5] Testing MITRE mapper...")
    try:
        from mitre_mapper import map_event_to_mitre, get_technique_by_id, list_all_techniques

        result = map_event_to_mitre("failed login event_id 4625 multiple attempts", "4625")
        print(f"  ✓ Mapped '4625 failed login' → {result['technique_id']} ({result['name']})")
        print(f"    Confidence: {result.get('match_confidence', 0)}")

        t1110 = get_technique_by_id("T1110")
        print(f"  ✓ T1110 lookup: {t1110['name']} | Severity: {t1110['severity_weight']}")

        techniques = list_all_techniques()
        print(f"  ✓ Total techniques in local DB: {len(techniques)}")
    except Exception as e:
        print(f"  ✗ MITRE error: {e}")

def test_dedup():
    print("\n[4/5] Testing deduplication engine...")
    try:
        from dedup import is_duplicate, get_dedup_stats
        from datetime import datetime

        alert = {
            "user_id": "admin",
            "source_ip": "10.10.10.99",
            "event_id": "4625",
            "timestamp": datetime.utcnow().isoformat()
        }

        r1 = is_duplicate(alert)
        r2 = is_duplicate(alert)  # Should be duplicate
        print(f"  ✓ First alert: {'duplicate' if r1 else 'new'}")
        print(f"  ✓ Same alert 30s later: {'duplicate (suppressed)' if r2 else 'new'}")

        stats = get_dedup_stats()
        print(f"  ✓ Dedup stats: {stats}")
    except Exception as e:
        print(f"  ✗ Dedup error: {e}")

def test_tools():
    print("\n[5/5] Testing tool server...")
    try:
        from tools_server import check_threat_intel, get_compliance_sop, get_mitre_details

        ti = check_threat_intel("10.10.10.99")
        print(f"  ✓ Threat intel for 10.10.10.99: malicious={ti['is_malicious']}, score={ti['threat_score']}")

        sop = get_compliance_sop("brute_force")
        print(f"  ✓ SOP for brute_force: {sop['sop_id']} with {len(sop['steps'])} steps")

        mitre = get_mitre_details("T1110")
        print(f"  ✓ MITRE T1110: {mitre['name']} | Tactic: {mitre['tactic']}")
    except Exception as e:
        print(f"  ✗ Tools error: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("BankShield SOC Platform — Component Tests")
    print("=" * 60)

    test_ingest()
    test_analytics()
    test_mitre()
    test_dedup()
    test_tools()

    print("\n" + "=" * 60)
    print("Tests complete. Check output above for any failures.")
    print("\nTo start the platform:")
    print("  Backend:  cd backend && uvicorn main:app --reload --port 8000")
    print("  Frontend: cd frontend && npm install && npm run dev")
    print("=" * 60)
