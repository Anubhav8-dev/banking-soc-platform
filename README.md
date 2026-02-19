# 🏦 BankShield SOC — Banking-Grade Autonomous Cyber Incident Response Platform

A **fully offline**, **banking-grade** AI Security Operations Center that:
- Reduces false positives via UEBA + fidelity scoring
- Automates investigation with LangGraph agents
- Generates RBI-compliant incident response playbooks
- Preserves human authority (supervisor approval required)
- Passes regulatory audit review (complete audit trail)

---

## 📁 Project Structure

```
banking-soc-platform/
├── backend/
│   ├── main.py              # FastAPI app — all endpoints
│   ├── ingest.py            # Elasticsearch log ingestion
│   ├── analytics.py         # UEBA: tsfresh + PyOD + SHAP
│   ├── agent_graph.py       # LangGraph orchestration (Triage→Dedup→Investigate→Respond)
│   ├── tools_server.py      # FastMCP tools (SIEM, ThreatIntel, SOP, MITRE)
│   ├── mitre_mapper.py      # Local MITRE ATT&CK mapping engine
│   ├── dedup.py             # Alert deduplication (hash fingerprint)
│   ├── audit_logger.py      # Mandatory audit trail → Elasticsearch
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx           # Router + Auth context
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx           # JWT authentication
│   │   │   ├── DashboardLayout.tsx     # Sidebar + header
│   │   │   ├── AlertsPage.tsx          # Incident list + controls
│   │   │   ├── IncidentDetailPage.tsx  # Split-screen detail + SHAP chart
│   │   │   ├── AuditPage.tsx           # Audit trail viewer
│   │   │   └── SettingsPage.tsx        # System status + RBAC
│   │   └── utils/api.ts
│   ├── package.json
│   └── vite.config.ts
├── data/
│   ├── threat_intel.json    # Local IP blacklist
│   └── sample_logs.csv      # Test log data
└── scripts/
    └── test_platform.py     # Component test script
```

---

## 🚀 Setup Instructions

### Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.10+ | Backend |
| Node.js | 18+ | Frontend |
| Elasticsearch | 8.x | Log storage + audit |
| Ollama | Latest | Local LLM (llama3) |
| Docker (optional) | Any | Easy ES setup |

---

### Step 1: Start Elasticsearch (Local, No Cloud)

**Option A — Docker:**
```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e discovery.type=single-node \
  -e xpack.security.enabled=false \
  -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
  elasticsearch:8.11.0
```

**Option B — Download directly:**
```bash
# Download from elastic.co (no account required for local use)
# Extract and run: ./bin/elasticsearch
```

Verify: `curl http://localhost:9200`

---

### Step 2: Install and Start Ollama

```bash
# Install Ollama (Linux/Mac)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull and run llama3 locally
ollama pull llama3
ollama run llama3

# Verify
curl http://localhost:11434/api/tags
```

> **Note:** The platform works without Ollama — falls back to rule-based responses automatically.

---

### Step 3: Backend Setup

```bash
cd banking-soc-platform/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run component tests
cd ../scripts
python test_platform.py

# Start the API server
cd ../backend
uvicorn main:app --reload --port 8000 --host 0.0.0.0
```

API docs: `http://localhost:8000/api/docs`

---

### Step 4: Frontend Setup

```bash
cd banking-soc-platform/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

App: `http://localhost:5173`

---

### Step 5: First Run — Generate Data

1. **Login** at `http://localhost:5173/login`
   - `analyst1` / `analyst123` → Analyst role
   - `supervisor1` / `supervisor123` → Supervisor role
   - `auditor1` / `auditor123` → Auditor role

2. **Generate test logs** — Click "Generate Test Logs" (creates 200 brute-force events tagged T1110)

3. **Run analysis** — Click "Run UEBA Analysis" (triggers full pipeline)

4. **Review incident** — Click on any generated incident to see the split-screen detail

5. **Approve playbook** — Login as `supervisor1` and approve the AI-generated playbook

---

## 🔒 Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OFFLINE PERIMETER                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │  React   │──▶│ FastAPI  │──▶│ LangGraph│──▶│  Ollama  │ │
│  │  (Vite)  │   │  (JWT)   │   │  Agent   │   │ (llama3) │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘ │
│       │              │               │                       │
│       │         ┌────▼────┐   ┌──────▼──────┐              │
│       │         │  PyOD   │   │Elasticsearch│              │
│       │         │  SHAP   │   │  (Logs +    │              │
│       │         │ tsfresh │   │  Audit)     │              │
│       └─────────└─────────┘   └─────────────┘              │
│                                                             │
│  ✗ No internet  ✗ No telemetry  ✗ No cloud APIs            │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Fidelity Scoring Formula

```
Fidelity = 0.4 × anomaly_score
          + 0.2 × threat_intel_score
          + 0.2 × correlation_strength
          + 0.1 × mitre_severity
          + 0.1 × historical_similarity

Fidelity ≥ 0.75  →  Agent triggered
Fidelity ≥ 0.90  →  Critical severity
Fidelity ≥ 0.75  →  High severity
Fidelity ≥ 0.50  →  Medium severity
Fidelity < 0.50  →  Low severity
```

---

## 🔐 RBAC Permissions

| Endpoint | Analyst | Supervisor | Auditor |
|----------|---------|------------|---------|
| POST /login | ✓ | ✓ | ✓ |
| GET /alerts | ✓ | ✓ | ✓ |
| POST /ingest | ✓ | ✓ | ✗ |
| POST /analyze | ✓ | ✓ | ✗ |
| GET /incident/:id | ✓ | ✓ | ✓ |
| POST /approve/:id | ✗ | ✓ | ✗ |
| POST /reject/:id | ✓ | ✓ | ✗ |
| GET /audit/:id | ✗ | ✓ | ✓ |

---

## 🏛️ Regulatory Compliance

- **RBI Cybersecurity Framework for Banks** (2016)
- **RBI Master Directions on NBFC-IT** (2017)
- **CERT-In Notification Requirements** (6-hour breach reporting)
- **IT Act Section 72A** (data breach notification)
- **MITRE ATT&CK Framework** (technique classification)
- **RBI AI Governance Principles** (explainable, auditable AI)

---

## 🧪 Testing

```bash
# Run all component tests
cd scripts && python test_platform.py

# Test specific endpoints (with server running)
curl -X POST http://localhost:8000/login \
  -d "username=analyst1&password=analyst123"

# Health check
curl http://localhost:8000/health
```

---

## ⚠️ Production Hardening Checklist

- [ ] Replace `SECRET_KEY` in `main.py` with 32-byte random key
- [ ] Replace in-memory `USERS_DB` with encrypted database
- [ ] Enable Elasticsearch TLS (`xpack.security.enabled=true`)
- [ ] Set up data-at-rest encryption for ES indices
- [ ] Configure network firewall rules (block outbound by default)
- [ ] Set up log rotation for Elasticsearch
- [ ] Configure Ollama model access controls
- [ ] Add rate limiting to API endpoints
- [ ] Set up certificate-based auth for ES client
- [ ] Enable audit log archival to WORM storage

---

## 📞 Support

This is a fully offline system. All components run locally.
No data leaves the environment. No external support calls are made.
