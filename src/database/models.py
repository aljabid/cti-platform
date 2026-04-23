"""
src/database/models.py
SQLAlchemy ORM models for the entire CTI platform.
Includes: threats, IOCs, threat actors, MITRE mappings, alerts, audit log.
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Text,
    Integer, ForeignKey, Enum, JSON, Index
)
from sqlalchemy.orm import (DeclarativeBase, relationship)
import enum
import uuid


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ─── Enums ────────────────────────────────────────────────────────────────────

class ThreatCategory(str, enum.Enum):
    MALWARE = "Malware"
    PHISHING = "Phishing"
    RANSOMWARE = "Ransomware"
    DDOS = "DDoS"
    EXPLOIT = "Exploit"
    RCE = "Remote Code Execution"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    SUPPLY_CHAIN = "Supply Chain"
    ZERO_DAY = "Zero Day"
    UNKNOWN = "Unknown"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    YARA_RULE = "yara"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ─── Core Threat Model ────────────────────────────────────────────────────────

class Threat(Base):
    __tablename__ = "threats"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cve_id = Column(String(20), unique=True, nullable=True, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)

    # Classification
    category = Column(Enum(ThreatCategory), default=ThreatCategory.UNKNOWN)
    category_confidence = Column(Float, default=0.0)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.MEDIUM)

    # Scores
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    risk_score = Column(Float, default=0.0)  # Our composite score
    threat_velocity = Column(Float, default=0.0)  # How fast it's spreading

    # Exploit info
    exploit_available = Column(Boolean, default=False)
    exploit_url = Column(String(512), nullable=True)
    in_the_wild = Column(Boolean, default=False)

    # MITRE ATT&CK (NEW)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(50), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)

    # Source
    source = Column(String(100), nullable=True)
    source_url = Column(String(512), nullable=True)
    raw_data = Column(JSON, nullable=True)

    # Timestamps
    published_at = Column(DateTime(timezone=True), nullable=True)
    collected_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    iocs = relationship("IOC", back_populates="threat", cascade="all, delete-orphan")
    actor_associations = relationship("ThreatActorAssociation", back_populates="threat")
    alerts = relationship("Alert", back_populates="threat")

    __table_args__ = (
        Index("ix_threats_severity", "severity"),
        Index("ix_threats_risk_score", "risk_score"),
        Index("ix_threats_collected_at", "collected_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value if self.category else None,
            "category_confidence": round(self.category_confidence, 3),
            "severity": self.severity.value if self.severity else None,
            "cvss_score": self.cvss_score,
            "risk_score": round(self.risk_score, 2),
            "threat_velocity": round(self.threat_velocity, 2),
            "exploit_available": self.exploit_available,
            "in_the_wild": self.in_the_wild,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "source": self.source,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
        }


# ─── IOC Model (NEW - Gap filled) ─────────────────────────────────────────────

class IOC(Base):
    """Indicators of Compromise extracted from threat data."""
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_id = Column(String(36), ForeignKey("threats.id"), nullable=True, index=True)

    ioc_type = Column(Enum(IOCType), nullable=False)
    value = Column(String(512), nullable=False, index=True)
    context = Column(Text, nullable=True)

    # Enrichment (VirusTotal, Shodan, etc.)
    vt_positives = Column(Integer, nullable=True)
    vt_total = Column(Integer, nullable=True)
    is_malicious = Column(Boolean, default=False)
    confidence = Column(Float, default=0.5)

    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)
    hit_count = Column(Integer, default=1)

    threat = relationship("Threat", back_populates="iocs")

    __table_args__ = (
        Index("ix_iocs_type_value", "ioc_type", "value"),
    )


# ─── Threat Actor Model (NEW) ─────────────────────────────────────────────────

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False, unique=True)
    aliases = Column(JSON, default=list)  # List of known aliases
    description = Column(Text, nullable=True)
    origin_country = Column(String(100), nullable=True)
    motivation = Column(String(200), nullable=True)  # Financial, espionage, hacktivism
    sophistication = Column(String(50), nullable=True)  # APT level
    stix_id = Column(String(100), nullable=True)  # STIX 2.1 threat-actor ID
    mitre_groups = Column(JSON, default=list)  # e.g. ["G0034", "G0016"]

    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    threat_associations = relationship("ThreatActorAssociation", back_populates="actor")


class ThreatActorAssociation(Base):
    __tablename__ = "threat_actor_associations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_id = Column(String(36), ForeignKey("threats.id"), nullable=False)
    actor_id = Column(String(36), ForeignKey("threat_actors.id"), nullable=False)
    confidence = Column(Float, default=0.5)
    attribution_method = Column(String(100), nullable=True)

    threat = relationship("Threat", back_populates="actor_associations")
    actor = relationship("ThreatActor", back_populates="threat_associations")


# ─── Alert Model ──────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_id = Column(String(36), ForeignKey("threats.id"), nullable=True, index=True)

    title = Column(String(512), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW)

    triggered_by = Column(String(100), nullable=True)  # "cvss_threshold" | "exploit_available" | etc.
    notified_via = Column(JSON, default=list)  # ["email", "slack"]

    created_at = Column(DateTime(timezone=True), default=utcnow)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    threat = relationship("Threat", back_populates="alerts")


# ─── Audit Log (NEW) ──────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String(100), nullable=False, index=True)
    actor = Column(String(100), nullable=True)  # "system" | "api_user" | "scheduler"
    description = Column(Text, nullable=True)
    metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


# ─── Feed Cache ───────────────────────────────────────────────────────────────

class FeedCache(Base):
    """Track last successful fetch per feed to avoid redundant requests."""
    __tablename__ = "feed_cache"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    feed_name = Column(String(100), nullable=False, unique=True)
    last_fetched_at = Column(DateTime(timezone=True), nullable=True)
    last_item_id = Column(String(200), nullable=True)  # For pagination/delta
    items_fetched = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    status = Column(String(50), default="idle")  # idle | running | error
