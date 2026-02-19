"""
main.py — Banking SOC Platform — FastAPI Application
Fully offline, JWT-secured, RBAC-enforced.
Endpoints: /login, /ingest, /analyze, /alerts, /incident/{id},
           /approve/{id}, /reject/{id}, /audit/{id}
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

import ingest as ingest_module
import analytics
import agent_graph
import audit_logger
from dedup import get_dedup_stats
from mitre_mapper import list_all_techniques

# ─── App Config ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Banking SOC Platform",
    description="Offline Banking-Grade Autonomous Cyber Incident Response",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    # Disable external schema fetching — offline mode
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── JWT / Auth Config ────────────────────────────────────────────────────────
SECRET_KEY = "CHANGE_THIS_IN_PRODUCTION_USE_STRONG_KEY_32BYTES"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8-hour shift

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# ── In-memory user store (replace with encrypted DB in production) ──
USERS_DB = {
    "analyst1": {
        "username": "analyst1",
        "hashed_password": pwd_context.hash("analyst123"),
        "role": "analyst",
        "full_name": "Security Analyst",
    },
    "supervisor1": {
        "username": "supervisor1",
        "hashed_password": pwd_context.hash("supervisor123"),
        "role": "supervisor",
        "full_name": "SOC Supervisor",
    },
    "auditor1": {
        "username": "auditor1",
        "hashed_password": pwd_context.hash("auditor123"),
        "role": "auditor",
        "full_name": "Compliance Auditor",
    },
}

# ── In-memory incident store (replace with ES in production) ──
INCIDENTS_DB: Dict[str, Dict] = {}


# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in USERS_DB:
            raise credentials_exception
        return USERS_DB[username]
    except JWTError:
        raise credentials_exception


def require_role(*roles):
    """Role-based access control decorator factory."""
    def checker(user: Dict = Depends(get_current_user)):
        if user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires role: {', '.join(roles)}"
            )
        return user
    return checker


# ─── Request/Response Models ──────────────────────────────────────────────────

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str


class IngestRequest(BaseModel):
    generate_dummy: bool = True
    count: int = 200
    csv_path: Optional[str] = None


class AnalyzeRequest(BaseModel):
    time_range_minutes: int = 60
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    auto_trigger_agent: bool = True


class ApproveRejectRequest(BaseModel):
    comment: str = ""
    execute_immediately: bool = False


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/login", response_model=LoginResponse, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return JWT token."""
    user = USERS_DB.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "username": user["username"],
    }


@app.post("/ingest", tags=["Data"])
async def ingest_logs(
    req: IngestRequest,
    user: Dict = Depends(require_role("analyst", "supervisor")),
):
    """
    Ingest logs into Elasticsearch.
    Can generate synthetic brute-force data or bulk ingest from CSV.
    """
    try:
        es = ingest_module.get_es_client()
        ingest_module.create_indices(es)

        if req.generate_dummy:
            result = ingest_module.generate_brute_force_logs(es, count=req.count)
        elif req.csv_path:
            result = ingest_module.bulk_ingest_csv(es, req.csv_path)
        else:
            raise HTTPException(status_code=400, detail="Provide generate_dummy=true or csv_path")

        audit_logger.log_analyst_action(user["username"], "SYSTEM", "INGEST", json.dumps(result))
        return {"status": "success", "result": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@app.post("/analyze", tags=["Analysis"])
async def analyze_logs(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    user: Dict = Depends(require_role("analyst", "supervisor")),
):
    """
    Run UEBA analysis on recent logs and optionally trigger the LangGraph agent.
    Returns anomaly scores, fidelity ranking, and agent-generated incident response.
    """
    try:
        es = ingest_module.get_es_client()

        # Fetch recent logs from Elasticsearch
        time_filter = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {
                            "timestamp": {
                                "gte": f"now-{req.time_range_minutes}m",
                                "lte": "now"
                            }
                        }}
                    ],
                    "filter": []
                }
            },
            "size": 1000,
            "sort": [{"timestamp": {"order": "asc"}}]
        }

        # Optional filters
        if req.source_ip:
            time_filter["query"]["bool"]["filter"].append(
                {"term": {"source_ip": req.source_ip}}
            )
        if req.user_id:
            time_filter["query"]["bool"]["filter"].append(
                {"term": {"user_id": req.user_id}}
            )

        result = es.search(index=ingest_module.INDEX_NAME, body=time_filter)
        logs = [hit["_source"] for hit in result["hits"]["hits"]]

        if not logs:
            return {"status": "no_data", "message": "No logs found in specified time range"}

        # Run analytics pipeline
        from tools_server import check_threat_intel
        # Get dominant source IP for threat intel enrichment
        from collections import Counter
        ip_counts = Counter(log.get("source_ip", "") for log in logs)
        top_ip = ip_counts.most_common(1)[0][0] if ip_counts else ""
        threat_score = 0.0
        if top_ip:
            ti = check_threat_intel(top_ip)
            threat_score = ti.get("threat_score", 0.0)

        analysis_result = analytics.run_full_analysis(logs, threat_intel_score=threat_score)

        if "error" in analysis_result:
            return {"status": "analysis_error", "error": analysis_result["error"]}

        # Determine if agent should trigger
        fidelity = analysis_result.get("fidelity", {}).get("fidelity_score", 0.0)
        agent_result = None

        if req.auto_trigger_agent and fidelity >= 0.75:
            # Build representative alert from logs
            representative_alert = logs[-1] if logs else {}
            agent_result = agent_graph.run_agent(
                raw_alert=representative_alert,
                analysis_result=analysis_result,
                user_id=user["username"],
            )

            # Store incident
            incident_id = agent_result["incident_id"]
            INCIDENTS_DB[incident_id] = {
                "incident_id": incident_id,
                "status": "pending_approval",
                "created_at": datetime.utcnow().isoformat(),
                "created_by": user["username"],
                "fidelity_score": fidelity,
                "severity": analysis_result.get("fidelity", {}).get("severity", "High"),
                "analysis": analysis_result,
                "agent_response": agent_result.get("response"),
                "logs_analyzed": len(logs),
                "approved_by": None,
                "rejected_by": None,
                "action_timestamp": None,
            }

            audit_logger.log_alert_generated(
                incident_id,
                fidelity,
                analysis_result.get("fidelity", {}).get("severity", "High"),
                analysis_result.get("peak_window", {}).get("features", {}).get("mitre_technique", "T1110"),
            )

        return {
            "status": "success",
            "logs_analyzed": len(logs),
            "analysis": analysis_result,
            "fidelity_score": fidelity,
            "agent_triggered": agent_result is not None,
            "agent_result": agent_result,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/alerts", tags=["Alerts"])
async def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    user: Dict = Depends(get_current_user),
):
    """Get all active incidents sorted by fidelity score (highest first)."""
    incidents = list(INCIDENTS_DB.values())

    # Filter by severity if specified
    if severity:
        incidents = [i for i in incidents if i.get("severity", "").lower() == severity.lower()]
    if status:
        incidents = [i for i in incidents if i.get("status", "") == status]

    # Sort by fidelity score descending
    incidents.sort(key=lambda x: x.get("fidelity_score", 0), reverse=True)

    return {
        "total": len(incidents),
        "incidents": incidents,
        "dedup_stats": get_dedup_stats(),
    }


@app.get("/incident/{incident_id}", tags=["Incidents"])
async def get_incident(
    incident_id: str,
    user: Dict = Depends(get_current_user),
):
    """Get full details for a specific incident including audit trail."""
    incident = INCIDENTS_DB.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch audit trail
    audit_trail = audit_logger.get_audit_trail(incident_id)

    return {
        "incident": incident,
        "audit_trail": audit_trail,
    }


@app.post("/approve/{incident_id}", tags=["Actions"])
async def approve_incident(
    incident_id: str,
    req: ApproveRejectRequest,
    user: Dict = Depends(require_role("supervisor")),  # Only supervisors can approve
):
    """
    Approve AI-generated playbook and optionally execute remediation.
    REQUIRES SUPERVISOR ROLE — human authority preserved.
    """
    incident = INCIDENTS_DB.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident["status"] != "pending_approval":
        raise HTTPException(
            status_code=400,
            detail=f"Incident is {incident['status']} — cannot approve"
        )

    incident["status"] = "approved"
    incident["approved_by"] = user["username"]
    incident["action_timestamp"] = datetime.utcnow().isoformat()
    incident["approval_comment"] = req.comment

    if req.execute_immediately:
        incident["status"] = "remediation_in_progress"
        # In production: trigger remediation scripts here

    audit_logger.log_analyst_action(
        user["username"], incident_id, "APPROVE",
        f"Comment: {req.comment} | Execute: {req.execute_immediately}"
    )

    return {"status": "approved", "incident_id": incident_id, "approved_by": user["username"]}


@app.post("/reject/{incident_id}", tags=["Actions"])
async def reject_incident(
    incident_id: str,
    req: ApproveRejectRequest,
    user: Dict = Depends(require_role("analyst", "supervisor")),
):
    """Reject AI-generated playbook. Analyst or Supervisor can reject."""
    incident = INCIDENTS_DB.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident["status"] not in ["pending_approval", "approved"]:
        raise HTTPException(status_code=400, detail=f"Cannot reject incident in status: {incident['status']}")

    incident["status"] = "rejected"
    incident["rejected_by"] = user["username"]
    incident["action_timestamp"] = datetime.utcnow().isoformat()
    incident["rejection_comment"] = req.comment

    audit_logger.log_analyst_action(
        user["username"], incident_id, "REJECT",
        f"Reason: {req.comment}"
    )

    return {"status": "rejected", "incident_id": incident_id, "rejected_by": user["username"]}


@app.get("/audit/{incident_id}", tags=["Audit"])
async def get_audit_trail(
    incident_id: str,
    user: Dict = Depends(require_role("auditor", "supervisor")),  # Auditors and supervisors only
):
    """Get full audit trail for compliance review. Auditor role required."""
    trail = audit_logger.get_audit_trail(incident_id)
    return {"incident_id": incident_id, "audit_trail": trail, "total_events": len(trail)}


@app.get("/mitre/techniques", tags=["Intelligence"])
async def get_mitre_techniques(user: Dict = Depends(get_current_user)):
    """List all MITRE techniques in the local knowledge base."""
    return {"techniques": list_all_techniques()}


@app.get("/health", tags=["System"])
async def health_check():
    """Health check — verifies offline components."""
    checks = {}

    # Check Elasticsearch
    try:
        es = ingest_module.get_es_client()
        es.ping()
        checks["elasticsearch"] = "ok"
    except Exception:
        checks["elasticsearch"] = "unavailable"

    # Check Ollama
    try:
        import httpx
        # Ollama runs locally on port 11434
        r = httpx.get("http://localhost:11434/api/tags", timeout=3)
        checks["ollama"] = "ok" if r.status_code == 200 else "unavailable"
    except Exception:
        checks["ollama"] = "unavailable"

    checks["internet_access"] = "disabled"  # Offline by design
    checks["telemetry"] = "disabled"

    return {
        "status": "operational",
        "checks": checks,
        "timestamp": datetime.utcnow().isoformat(),
        "mode": "offline_only",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
