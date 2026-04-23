# 🛡️ CTI Platform — AI-Powered Cyber Threat Intelligence

**Production-grade SOC-level threat intelligence platform.**  
Collects, classifies, scores, and alerts on real-world cyber threats using AI/NLP.

---

## Architecture

```
Data Sources (NVD, OTX, Exploit-DB, TAXII/STIX, RSS)
        ↓
Collector Engine (rate limiting · retry · scheduler)
        ↓
Processing Pipeline (clean · normalize · IOC extraction)
        ↓ ─────────────────────────────── ↓
NLP Classifier                    Correlation Engine
(TF-IDF + LR · MITRE ATT&CK)     (threat actors · similarity)
        ↓ ─────────────────────────────── ↓
Risk Scoring Engine
(CVSS · exploit · velocity · IOC count · recency)
        ↓
PostgreSQL Database
(threats · IOCs · actors · alerts · audit log)
        ↓ ─────────────── ↓ ─────────────── ↓
FastAPI REST API     SOC Dashboard       Alert System
(JWT auth · STIX)    (Streamlit)         (Email · Slack)
        ↓
External Integrations
(SentinelScan · Malware Detection · SIEM)
```

---

## Features

| Feature | Status | Notes |
|---|---|---|
| NVD/CVE data collection | ✅ | With API key support & rate limiting |
| AlienVault OTX pulses | ✅ | Requires free OTX API key |
| TAXII/STIX feed support | ✅ | Via `stix2` + `taxii2-client` |
| IOC extraction | ✅ | IPs, domains, hashes, CVEs, emails, URLs |
| NLP threat classification | ✅ | TF-IDF + Logistic Regression, 10 categories |
| MITRE ATT&CK mapping | ✅ | Auto-mapped per category + keyword refinement |
| Composite risk scoring | ✅ | CVSS + exploit + velocity + IOCs + actor count |
| Threat velocity scoring | ✅ | How fast a threat is spreading |
| Threat actor profiling | ✅ | STIX-compatible actor model |
| PostgreSQL storage | ✅ | Full ORM, migrations via Alembic |
| REST API | ✅ | FastAPI + JWT auth |
| STIX 2.1 export | ✅ | Per-threat export endpoint |
| SOC Dashboard | ✅ | Streamlit with auth, charts, IOC lookup |
| Email alerts | ✅ | SMTP with HTML templates |
| Slack alerts | ✅ | Webhook with rich formatting |
| Threshold rules | ✅ | CVSS, exploit, in-the-wild, zero-day |
| Background scheduler | ✅ | APScheduler, configurable intervals |
| Docker Compose | ✅ | Full stack: DB + API + Dashboard + Scheduler |
| Structured logging | ✅ | JSON (prod) / human-readable (dev) |
| Test suite | ✅ | Pytest covering all modules |
| SentinelScan integration | ✅ | CVE enrichment bridge |
| Malware Detection integration | ✅ | Hash IOC correlation |
| Report export | ✅ | Markdown + CSV from dashboard |

---

## Quick Start

### Option A — Docker (recommended)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your API keys (NVD, OTX, Slack, email)

# 2. Start the full stack
cd docker
docker-compose up -d

# 3. Access
# Dashboard:  http://localhost:8501
# API docs:   http://localhost:8000/docs
# Default credentials: admin / admin (change in .env!)
```

### Option B — Local development

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env

# 3. Initialize database
python -c "from src.database.db import init_db; init_db()"

# 4. Run pipeline (fetch + classify + score threats)
python src/pipeline.py --days 7

# 5. Start dashboard
streamlit run dashboard/app.py

# 6. Start API (separate terminal)
uvicorn api.app:app --reload --port 8000

# 7. Start scheduler (separate terminal)
python src/scheduler.py
```

---

## Configuration

All configuration is via `.env`. Key settings:

| Variable | Description | Default |
|---|---|---|
| `NVD_API_KEY` | NIST NVD API key (free) | — |
| `OTX_API_KEY` | AlienVault OTX key (free) | — |
| `DATABASE_URL` | PostgreSQL or SQLite URL | SQLite |
| `COLLECTION_INTERVAL_MINUTES` | Pipeline run frequency | 60 |
| `CRITICAL_CVSS_THRESHOLD` | Alert threshold | 9.0 |
| `SLACK_WEBHOOK_URL` | Slack alerts webhook | — |
| `SMTP_*` | Email alert settings | — |
| `DASHBOARD_USERNAME` | Dashboard login | admin |
| `DASHBOARD_PASSWORD` | Dashboard password | admin |

---

## API Reference

### Auth
```bash
POST /auth/token?username=admin&password=admin
→ { "access_token": "...", "token_type": "bearer" }
```

### Threats
```bash
GET /threats?severity=Critical&exploit_only=true
GET /threats/{id}
GET /cve/CVE-2024-12345
```

### IOC Lookup
```bash
GET /iocs/search?value=203.0.113.42
GET /iocs/search?value=malicious.example.com
```

### Statistics
```bash
GET /stats
```

### STIX Export
```bash
GET /export/stix/{threat_id}
→ STIX 2.1 bundle JSON
```

### Alerts
```bash
GET /alerts?status=new
PATCH /alerts/{id}/acknowledge
```

---

## NLP Model

The classifier uses **TF-IDF + Logistic Regression** on threat descriptions.

**Categories:**
- Malware, Ransomware, Phishing, DDoS
- Remote Code Execution, SQL Injection, XSS
- Privilege Escalation, Supply Chain, Zero Day

Each classification automatically maps to a **MITRE ATT&CK** tactic + technique.

**To retrain with custom data:**
```python
from src.nlp.classifier import get_classifier
clf = get_classifier()
clf.retrain([
    ("custom threat description", "Malware"),
    ("another example", "Ransomware"),
])
```

---

## Risk Scoring

The composite risk score (0–10) combines:

| Factor | Weight |
|---|---|
| CVSS score | 50% |
| Active exploitation in the wild | +2.0 pts |
| Public exploit available | +1.5 pts |
| Recency (< 24h) | +0.5 pts |
| IOC count enrichment | up to +1.0 pts |
| Threat actor linked | up to +0.75 pts |
| No patch available | +0.5 pts |
| Category multiplier | ×0.9 – ×1.25 |

---

## Project Structure

```
cti-platform/
├── api/app.py               FastAPI REST API
├── config/settings.py       Env config loader
├── dashboard/app.py         Streamlit SOC dashboard
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── src/
│   ├── alerts/              Alert manager (email + Slack)
│   ├── collectors/          NVD, OTX, RSS, TAXII collectors
│   ├── database/            SQLAlchemy models + session
│   ├── integrations/        SentinelScan + Malware Det.
│   ├── nlp/                 TF-IDF classifier + MITRE mapping
│   ├── processing/          IOC extractor + data cleaner
│   ├── scoring/             Composite risk scoring engine
│   ├── utils/               Structured logger
│   ├── pipeline.py          Main orchestrator
│   └── scheduler.py         APScheduler background runner
├── tests/test_platform.py   Full pytest test suite
├── requirements.txt
└── .env.example
```

---

## Tests

```bash
pytest tests/ -v
```

Covers: IOC extraction, NLP classification, risk scoring,
alert rules, and integration bridges.

---

## Integrations

### SentinelScan
```python
from src.integrations.integration_bridge import get_sentinel_bridge
bridge = get_sentinel_bridge()

# Enrich scan results with CTI data
cti_data = bridge.enrich_scan_with_cti(["CVE-2024-1234", "CVE-2023-9999"])
```

### Malware Detection
```python
from src.integrations.integration_bridge import get_malware_bridge
bridge = get_malware_bridge()

# Check if a hash is a known malicious IOC
result = bridge.check_hash_against_cti("abc123...sha256hash")
```

---

## Erasmus / Academic Report Structure

1. **Introduction** — Why CTI matters in modern SOC operations
2. **Problem Statement** — Volume, velocity, unstructured data
3. **Architecture** — Layered pipeline with diagram
4. **Data Sources** — NVD, OTX, TAXII/STIX, Exploit-DB
5. **NLP Model** — TF-IDF + LR, training data, MITRE mapping
6. **Risk Scoring** — Multi-factor composite methodology
7. **IOC Tracking** — Extraction, storage, lookup
8. **Dashboard** — SOC interface design and features
9. **Integrations** — SentinelScan bridge, Malware Detection bridge
10. **Results** — Threats classified, IOCs extracted, alerts triggered
11. **Use Cases** — Patch prioritization, incident response, threat hunting
12. **Future Work** — Transformer model, threat graph, ML re-training loop
