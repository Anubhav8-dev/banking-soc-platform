"""
dedup.py — Alert Deduplication Engine
Uses hash fingerprinting to cluster and deduplicate similar alerts
within a 5-minute time window. Prevents duplicate LLM execution.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict

# In-memory dedup store (for production, persist in Redis/ES)
_dedup_store: Dict[str, Dict] = {}
WINDOW_MINUTES = 5


def _build_fingerprint(user_id: str, source_ip: str, event_id: str, window_bucket: str) -> str:
    """
    Create a deterministic fingerprint hash from incident identifiers + time bucket.
    Time bucket quantizes timestamps to 5-minute windows.
    """
    raw = f"{user_id}|{source_ip}|{event_id}|{window_bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_time_bucket(ts: datetime) -> str:
    """Quantize a timestamp to the nearest 5-minute bucket."""
    bucket_minute = (ts.minute // WINDOW_MINUTES) * WINDOW_MINUTES
    return ts.strftime(f"%Y-%m-%dT%H:{bucket_minute:02d}")


def is_duplicate(alert: Dict[str, Any]) -> bool:
    """
    Check if an alert is a duplicate of one already processed in the same time window.
    Returns True if duplicate (should skip LLM processing).
    """
    # Parse timestamp
    try:
        ts = datetime.fromisoformat(alert.get("timestamp", datetime.utcnow().isoformat()))
    except Exception:
        ts = datetime.utcnow()

    bucket = _get_time_bucket(ts)
    fingerprint = _build_fingerprint(
        user_id=alert.get("user_id", ""),
        source_ip=alert.get("source_ip", ""),
        event_id=alert.get("event_id", ""),
        window_bucket=bucket,
    )

    if fingerprint in _dedup_store:
        # Update hit count
        _dedup_store[fingerprint]["hit_count"] += 1
        _dedup_store[fingerprint]["last_seen"] = datetime.utcnow().isoformat()
        return True

    # New unique alert — register it
    _dedup_store[fingerprint] = {
        "fingerprint": fingerprint,
        "first_seen": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "hit_count": 1,
        "alert_snapshot": {
            "user_id": alert.get("user_id"),
            "source_ip": alert.get("source_ip"),
            "event_id": alert.get("event_id"),
            "time_bucket": bucket,
        }
    }
    return False


def get_dedup_stats() -> Dict[str, Any]:
    """Return current deduplication statistics."""
    total = len(_dedup_store)
    suppressed = sum(max(0, v["hit_count"] - 1) for v in _dedup_store.values())
    return {
        "unique_fingerprints": total,
        "total_suppressed_duplicates": suppressed,
        "window_minutes": WINDOW_MINUTES,
    }


def cluster_similar_alerts(alerts: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """
    Group alerts into clusters based on shared (source_ip, event_id) pairs.
    Returns a list of clusters (each cluster is a list of related alerts).
    """
    clusters: Dict[str, List[Dict]] = defaultdict(list)

    for alert in alerts:
        cluster_key = f"{alert.get('source_ip', '')}|{alert.get('event_id', '')}"
        clusters[cluster_key].append(alert)

    return list(clusters.values())


def purge_expired_fingerprints() -> int:
    """
    Remove fingerprints older than the dedup window.
    Call periodically (e.g., every 10 minutes) to prevent memory growth.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=WINDOW_MINUTES * 2)
    expired_keys = []

    for key, entry in _dedup_store.items():
        try:
            last_seen = datetime.fromisoformat(entry["last_seen"])
            if last_seen < cutoff:
                expired_keys.append(key)
        except Exception:
            expired_keys.append(key)

    for key in expired_keys:
        del _dedup_store[key]

    return len(expired_keys)
