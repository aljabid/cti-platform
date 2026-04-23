"""
api/app.py
FastAPI REST API for the CTI Platform.
Includes JWT authentication, threat queries, IOC lookup, STIX export.
Gap filled: auth, STIX export, IOC search, report endpoints.
"""
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
import json
import jwt
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../"))

from src.database.db import get_db_session, init_db
from src.database.models import Threat, IOC, Alert, ThreatActor, SeverityLevel, AlertStatus
from src.utils.logger import get_logger

logger = get_logger("cti.api")

SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "admin")

app = FastAPI(
    title="CTI Platform API",
    description="Cyber Threat Intelligence Platform — REST API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# ─── Auth ─────────────────────────────────────────────────────────────────────

def create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": username, "exp": expire},
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/auth/token")
def login(username: str, password: str):
    """Get JWT token."""
    if username != API_USERNAME or password != API_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(username)
    return {"access_token": token, "token_type": "bearer", "expires_hours": TOKEN_EXPIRE_HOURS}


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ─── Threats ──────────────────────────────────────────────────────────────────

@app.get("/threats", tags=["Threats"])
def list_threats(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by category"),
    min_risk: Optional[float] = Query(None, description="Minimum risk score"),
    exploit_only: bool = Query(False, description="Only threats with public exploits"),
    in_wild_only: bool = Query(False, description="Only actively exploited"),
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    """List threats with filtering."""
    q = db.query(Threat)

    if severity:
        try:
            q = q.filter(Threat.severity == SeverityLevel(severity))
        except ValueError:
            raise HTTPException(400, f"Invalid severity: {severity}")

    if category:
        q = q.filter(Threat.category.ilike(f"%{category}%"))

    if min_risk is not None:
        q = q.filter(Threat.risk_score >= min_risk)

    if exploit_only:
        q = q.filter(Threat.exploit_available == True)

    if in_wild_only:
        q = q.filter(Threat.in_the_wild == True)

    total = q.count()
    threats = q.order_by(Threat.risk_score.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "threats": [t.to_dict() for t in threats],
    }


@app.get("/threats/{threat_id}", tags=["Threats"])
def get_threat(
    threat_id: str,
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    """Get a single threat with full details."""
    threat = db.query(Threat).filter_by(id=threat_id).first()
    if not threat:
        raise HTTPException(404, "Threat not found")

    result = threat.to_dict()
    result["iocs"] = [
        {"type": ioc.ioc_type.value, "value": ioc.value, "is_malicious": ioc.is_malicious}
        for ioc in threat.iocs
    ]
    return result


@app.get("/cve/{cve_id}", tags=["Threats"])
def get_by_cve(
    cve_id: str,
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    """Look up a threat by CVE ID."""
    threat = db.query(Threat).filter_by(cve_id=cve_id.upper()).first()
    if not threat:
        raise HTTPException(404, f"CVE {cve_id} not found")
    return threat.to_dict()


# ─── IOC Lookup (NEW - gap filled) ────────────────────────────────────────────

@app.get("/iocs/search", tags=["IOC"])
def search_ioc(
    value: str = Query(..., description="IP, domain, hash, or CVE to look up"),
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    """Search IOCs across all threats."""
    results = db.query(IOC).filter(IOC.value.ilike(f"%{value}%")).limit(100).all()
    return {
        "query": value,
        "count": len(results),
        "iocs": [
            {
                "type": ioc.ioc_type.value,
                "value": ioc.value,
                "is_malicious": ioc.is_malicious,
                "threat_id": ioc.threat_id,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "hit_count": ioc.hit_count,
            }
            for ioc in results
        ],
    }


# ─── Statistics ───────────────────────────────────────────────────────────────

@app.get("/stats", tags=["Statistics"])
def get_stats(
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    """Dashboard summary statistics."""
    total = db.query(Threat).count()
    critical = db.query(Threat).filter_by(severity=SeverityLevel.CRITICAL).count()
    high = db.query(Threat).filter_by(severity=SeverityLevel.HIGH).count()
    exploit_count = db.query(Threat).filter_by(exploit_available=True).count()
    wild_count = db.query(Threat).filter_by(in_the_wild=True).count()
    ioc_count = db.query(IOC).count()
    open_alerts = db.query(Alert).filter_by(status=AlertStatus.NEW).count()

    # Category distribution
    from sqlalchemy import func
    cat_dist = db.query(Threat.category, func.count(Threat.id))\
        .group_by(Threat.category).all()

    return {
        "total_threats": total,
        "critical": critical,
        "high": high,
        "with_exploits": exploit_count,
        "in_the_wild": wild_count,
        "total_iocs": ioc_count,
        "open_alerts": open_alerts,
        "category_distribution": {str(c): n for c, n in cat_dist if c},
    }


# ─── STIX 2.1 Export (NEW - gap filled) ───────────────────────────────────────

@app.get("/export/stix/{threat_id}", tags=["Export"], response_class=PlainTextResponse)
def export_stix(
    threat_id: str,
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    """Export a threat as STIX 2.1 JSON bundle."""
    threat = db.query(Threat).filter_by(id=threat_id).first()
    if not threat:
        raise HTTPException(404, "Threat not found")

    bundle = _threat_to_stix(threat)
    return PlainTextResponse(
        content=json.dumps(bundle, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={threat_id}.stix.json"},
    )


def _threat_to_stix(threat: Threat) -> Dict:
    """Convert a Threat to a minimal STIX 2.1 bundle."""
    now = datetime.now(timezone.utc).isoformat()
    vuln_id = f"vulnerability--{threat.id}"

    objects = [
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "name": threat.cve_id or threat.title[:100],
            "description": (threat.description or "")[:2000],
            "created": now,
            "modified": now,
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": threat.cve_id,
                    "url": threat.source_url or "",
                }
            ] if threat.cve_id else [],
            "labels": [threat.category.value if threat.category else "unknown"],
            "x_risk_score": threat.risk_score,
            "x_cvss_score": threat.cvss_score,
        }
    ]

    if threat.mitre_technique:
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{threat.id}",
            "name": threat.mitre_technique_name or threat.mitre_technique,
            "created": now,
            "modified": now,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": threat.mitre_technique,
                    "url": f"https://attack.mitre.org/techniques/{threat.mitre_technique}/",
                }
            ],
        })

    # IOC indicators
    for ioc in threat.iocs[:20]:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ioc.id}",
            "created": now,
            "modified": now,
            "pattern": f"[{ioc.ioc_type.value}:value = '{ioc.value}']",
            "pattern_type": "stix",
            "valid_from": now,
        })

    return {
        "type": "bundle",
        "id": f"bundle--{threat.id}",
        "objects": objects,
    }


# ─── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/alerts", tags=["Alerts"])
def list_alerts(
    status: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db_session),
    _: str = Depends(verify_token),
):
    q = db.query(Alert)
    if status:
        try:
            q = q.filter(Alert.status == AlertStatus(status))
        except ValueError:
            raise HTTPException(400, f"Invalid status: {status}")

    alerts = q.order_by(Alert.created_at.desc()).limit(limit).all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity.value if a.severity else None,
            "status": a.status.value if a.status else None,
            "triggered_by": a.triggered_by,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]


@app.patch("/alerts/{alert_id}/acknowledge", tags=["Alerts"])
def acknowledge_alert(
    alert_id: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(verify_token),
):
    alert = db.query(Alert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True, "acknowledged_by": user}


# ─── Startup ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    logger.info("CTI Platform API started")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
