"""
analytics.py — UEBA Analytics Engine
Feature extraction with tsfresh, anomaly detection with PyOD (IForest + COPOD),
and explainability via SHAP.
All computation is fully local — no external calls.
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List, Optional

# PyOD detectors
from pyod.models.iforest import IForest
from pyod.models.copod import COPOD

# SHAP for explainability
import shap

# Sklearn utilities
from sklearn.preprocessing import StandardScaler


# ─── Feature Extraction ───────────────────────────────────────────────────────

def extract_features(logs: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Extract behavioral features from raw log records.
    tsfresh-inspired manual extraction (avoids heavy tsfresh overhead
    on small streaming windows; full tsfresh used for batch).
    Features:
      - failed_login_count_per_min
      - login_entropy (Shannon entropy of user attempts)
      - ip_repetition_frequency
      - time_delta_variance
      - unique_ips
      - unique_users
      - success_failure_ratio
    """
    if not logs:
        return pd.DataFrame()

    df = pd.DataFrame(logs)

    # Parse timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.sort_values("timestamp")

    records = []

    # Sliding 5-minute windows
    window_size = pd.Timedelta("5min")
    if len(df) < 2:
        return pd.DataFrame()

    start = df["timestamp"].iloc[0]
    end = df["timestamp"].iloc[-1]
    current = start

    while current < end:
        window_end = current + window_size
        mask = (df["timestamp"] >= current) & (df["timestamp"] < window_end)
        w = df[mask]

        if len(w) == 0:
            current = window_end
            continue

        # Failed login count
        failed_count = len(w[w.get("status", pd.Series()) == "FAILURE"]) if "status" in w else 0

        # Login entropy — Shannon entropy over user_id distribution
        if "user_id" in w and len(w) > 0:
            user_counts = w["user_id"].value_counts(normalize=True)
            entropy = float(-np.sum(user_counts * np.log2(user_counts + 1e-9)))
        else:
            entropy = 0.0

        # IP repetition frequency
        if "source_ip" in w and len(w) > 0:
            ip_counts = w["source_ip"].value_counts()
            ip_repeat_freq = float(ip_counts.max() / len(w)) if len(w) > 0 else 0.0
            unique_ips = int(ip_counts.shape[0])
        else:
            ip_repeat_freq = 0.0
            unique_ips = 0

        # Time delta variance
        if len(w) > 1:
            deltas = w["timestamp"].diff().dt.total_seconds().dropna()
            time_delta_var = float(deltas.var()) if len(deltas) > 0 else 0.0
        else:
            time_delta_var = 0.0

        # Success/failure ratio
        success_count = len(w[w.get("status", pd.Series()) == "SUCCESS"]) if "status" in w else 0
        total = len(w)
        sf_ratio = success_count / total if total > 0 else 0.0

        records.append({
            "window_start": current.isoformat(),
            "event_count": total,
            "failed_login_count_per_min": failed_count / 5.0,
            "login_entropy": entropy,
            "ip_repetition_frequency": ip_repeat_freq,
            "time_delta_variance": time_delta_var,
            "unique_ips": unique_ips,
            "unique_users": int(w["user_id"].nunique()) if "user_id" in w else 0,
            "success_failure_ratio": sf_ratio,
        })

        current = window_end

    return pd.DataFrame(records)


# ─── Anomaly Detection ────────────────────────────────────────────────────────

FEATURE_COLS = [
    "failed_login_count_per_min",
    "login_entropy",
    "ip_repetition_frequency",
    "time_delta_variance",
    "unique_ips",
    "unique_users",
    "success_failure_ratio",
]


def detect_anomalies(feature_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Run Isolation Forest + COPOD ensemble on feature vectors.
    Returns per-window anomaly scores and SHAP explanations.
    """
    if feature_df.empty or len(feature_df) < 2:
        return {"error": "Insufficient data for anomaly detection", "windows": []}

    X = feature_df[FEATURE_COLS].fillna(0).values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Isolation Forest ──
    iforest = IForest(contamination=0.15, random_state=42, n_estimators=100)
    iforest.fit(X_scaled)
    iforest_scores = iforest.decision_function(X_scaled)  # Higher = more normal
    iforest_labels = iforest.predict(X_scaled)

    # ── COPOD ──
    copod = COPOD(contamination=0.15)
    copod.fit(X_scaled)
    copod_scores = copod.decision_function(X_scaled)
    copod_labels = copod.predict(X_scaled)

    # ── Ensemble score (normalized average) ──
    def normalize(arr):
        mn, mx = arr.min(), arr.max()
        if mx == mn:
            return np.zeros_like(arr)
        return (arr - mn) / (mx - mn)

    iforest_norm = normalize(iforest_scores)
    copod_norm = normalize(copod_scores)

    # Invert iforest (higher score = more normal, we want higher = more anomalous)
    ensemble_score = 0.5 * (1 - iforest_norm) + 0.5 * copod_norm

    # ── SHAP Explainability (IForest) ──
    explainer = shap.TreeExplainer(iforest.detector_)
    shap_values = explainer.shap_values(X_scaled)

    windows = []
    for i, row in feature_df.iterrows():
        idx = list(feature_df.index).index(i)

        # Top contributing features for this window
        abs_shap = np.abs(shap_values[idx])
        top_k = min(3, len(FEATURE_COLS))
        top_indices = np.argsort(abs_shap)[::-1][:top_k]
        top_features = [
            {
                "feature": FEATURE_COLS[j],
                "shap_value": float(shap_values[idx][j]),
                "importance": float(abs_shap[j]),
                "actual_value": float(X[idx][j]),
            }
            for j in top_indices
        ]

        anomaly_score = float(ensemble_score[idx])
        is_anomaly = bool(iforest_labels[idx] == 1 or copod_labels[idx] == 1)

        windows.append({
            "window_start": row.get("window_start", ""),
            "event_count": int(row.get("event_count", 0)),
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "iforest_label": int(iforest_labels[idx]),
            "copod_label": int(copod_labels[idx]),
            "top_contributing_features": top_features,
            "features": {col: float(row.get(col, 0)) for col in FEATURE_COLS},
        })

    return {
        "total_windows": len(windows),
        "anomaly_count": sum(1 for w in windows if w["is_anomaly"]),
        "windows": windows,
    }


# ─── Fidelity Ranking ─────────────────────────────────────────────────────────

def compute_fidelity_score(
    anomaly_score: float,
    threat_intel_score: float = 0.0,
    correlation_strength: float = 0.5,
    mitre_severity: float = 0.5,
    historical_similarity: float = 0.3,
) -> Dict[str, Any]:
    """
    Weighted fidelity ranking:
    Fidelity = 0.4*anomaly + 0.2*threat_intel + 0.2*correlation + 0.1*mitre + 0.1*historical
    """
    fidelity = (
        0.4 * anomaly_score
        + 0.2 * threat_intel_score
        + 0.2 * correlation_strength
        + 0.1 * mitre_severity
        + 0.1 * historical_similarity
    )
    fidelity = round(min(max(fidelity, 0.0), 1.0), 4)

    if fidelity >= 0.90:
        severity = "Critical"
    elif fidelity >= 0.75:
        severity = "High"
    elif fidelity >= 0.50:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "fidelity_score": fidelity,
        "severity": severity,
        "triggers_agent": fidelity >= 0.75,
        "components": {
            "anomaly_score": anomaly_score,
            "threat_intel_score": threat_intel_score,
            "correlation_strength": correlation_strength,
            "mitre_severity": mitre_severity,
            "historical_similarity": historical_similarity,
        }
    }


def run_full_analysis(logs: List[Dict[str, Any]], threat_intel_score: float = 0.0) -> Dict[str, Any]:
    """
    End-to-end pipeline: feature extraction → anomaly detection → fidelity ranking.
    Returns structured result ready for agent consumption.
    """
    feature_df = extract_features(logs)
    if feature_df.empty:
        return {"error": "Feature extraction failed — insufficient logs"}

    anomaly_result = detect_anomalies(feature_df)
    if "error" in anomaly_result:
        return anomaly_result

    # Use the max anomaly score across windows as the representative score
    windows = anomaly_result.get("windows", [])
    if not windows:
        return {"error": "No anomaly windows produced"}

    max_window = max(windows, key=lambda w: w["anomaly_score"])
    anomaly_score = max_window["anomaly_score"]

    fidelity = compute_fidelity_score(
        anomaly_score=anomaly_score,
        threat_intel_score=threat_intel_score,
        correlation_strength=min(1.0, len(logs) / 100),  # More correlated events = higher
        mitre_severity=0.7,  # Default for T1110
        historical_similarity=0.3,
    )

    return {
        "anomaly_score": anomaly_score,
        "top_contributing_features": max_window["top_contributing_features"],
        "fidelity": fidelity,
        "windows_analyzed": anomaly_result["total_windows"],
        "anomalous_windows": anomaly_result["anomaly_count"],
        "peak_window": max_window,
        "all_windows": windows,
    }
