"""
src/pipeline.py
Main CTI pipeline orchestrator.
Runs: collect → process → classify → score → store → alert.
Called by the scheduler or manually.
"""
from datetime import datetime, timezone
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../"))

from src.utils.logger import get_logger
from src.database.db import get_db, init_db
from src.database.models import Threat, IOC, Alert, AuditLog, SeverityLevel, ThreatCategory, IOCType
from src.collectors.cve_collector import CVECollector
from src.collectors.otx_collector import OTXCollector
from src.processing.ioc_extractor import extract_iocs
from src.nlp.classifier import get_classifier
from src.scoring.risk_engine import score_from_raw
from src.alerts.alert_manager import AlertManager

logger = get_logger("cti.pipeline")

SEVERITY_MAP = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "UNKNOWN": SeverityLevel.MEDIUM,
}

CATEGORY_MAP = {c.value: c for c in ThreatCategory}

IOC_TYPE_MAP = {
    "ip": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5": IOCType.FILE_HASH_MD5,
    "sha1": IOCType.FILE_HASH_SHA1,
    "sha256": IOCType.FILE_HASH_SHA256,
    "email": IOCType.EMAIL,
    "cve": IOCType.CVE,
}


class CTIPipeline:
    def __init__(self, settings=None):
        self.settings = settings
        self.classifier = get_classifier()
        self._setup_alert_manager()

    def _setup_alert_manager(self):
        s = self.settings
        if s:
            self.alert_manager = AlertManager(
                smtp_host=s.smtp_host,
                smtp_port=s.smtp_port,
                smtp_username=s.smtp_username or "",
                smtp_password=s.smtp_password or "",
                from_email=s.alert_from_email,
                to_emails=s.alert_to_emails,
                slack_webhook=s.slack_webhook_url or "",
                critical_threshold=s.critical_cvss_threshold,
                alert_on_exploit=s.alert_on_exploit_available,
            )
        else:
            self.alert_manager = AlertManager()

    def run(self, days_back: int = 1, fetch_critical: bool = True) -> Dict:
        """Full pipeline run. Returns summary stats."""
        logger.info(f"=== CTI Pipeline starting (days_back={days_back}) ===")
        start = datetime.now(timezone.utc)
        stats = {
            "collected": 0, "processed": 0, "classified": 0,
            "stored": 0, "alerts_triggered": 0, "errors": 0,
            "iocs_extracted": 0,
        }

        # 1. Collect
        raw_threats = self._collect(days_back, fetch_critical)
        stats["collected"] = len(raw_threats)
        logger.info(f"Collected {len(raw_threats)} raw threats")

        if not raw_threats:
            logger.info("No new threats to process")
            return stats

        # 2. Classify + Score + Store
        for raw in raw_threats:
            try:
                result = self._process_threat(raw)
                if result:
                    stats["processed"] += 1
                    stats["stored"] += 1
                    stats["iocs_extracted"] += result.get("ioc_count", 0)
                    if result.get("alert_triggered"):
                        stats["alerts_triggered"] += 1
            except Exception as e:
                logger.error(f"Pipeline error for threat: {e}")
                stats["errors"] += 1

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        stats["elapsed_seconds"] = round(elapsed, 2)

        # 3. Audit log
        self._log_audit("pipeline_run", stats)
        logger.info(f"=== Pipeline complete: {stats} ===")
        return stats

    def _collect(self, days_back: int, fetch_critical: bool) -> List[Dict]:
        """Run all collectors."""
        threats = []
        api_key = self.settings.nvd_api_key if self.settings else None

        # NVD CVEs
        try:
            cve_collector = CVECollector(api_key=api_key)
            recent = cve_collector.fetch_recent(days_back=days_back)
            threats.extend(recent)
            if fetch_critical:
                critical = cve_collector.fetch_critical()
                # Avoid duplicates
                existing_ids = {t.get("cve_id") for t in threats}
                for c in critical:
                    if c.get("cve_id") not in existing_ids:
                        threats.append(c)
            cve_collector.update_feed_cache("nvd", len(threats))
        except Exception as e:
            logger.error(f"NVD collection failed: {e}")

        # OTX
        try:
            otx_key = self.settings.otx_api_key if self.settings else None
            otx = OTXCollector(api_key=otx_key)
            pulses = otx.fetch_subscribed_pulses(days_back=days_back)
            threats.extend(pulses)
        except Exception as e:
            logger.error(f"OTX collection failed: {e}")

        return threats

    def _process_threat(self, raw: Dict) -> Optional[Dict]:
        """Classify, score, store one threat."""
        description = raw.get("description", "") or raw.get("title", "")
        if not description:
            return None

        # Skip if already in DB
        cve_id = raw.get("cve_id")
        with get_db() as db:
            if cve_id:
                existing = db.query(Threat).filter_by(cve_id=cve_id).first()
                if existing:
                    return None

            # Classify
            classification = self.classifier.classify(description)
            category_str = classification.get("category", "Unknown")
            category = CATEGORY_MAP.get(category_str, ThreatCategory.UNKNOWN)

            # Extract IOCs
            iocs = extract_iocs(description)
            ioc_count = len(iocs)

            # Score
            published = raw.get("published_at")
            severity_label = raw.get("severity_label", "UNKNOWN")
            scoring = score_from_raw(
                cvss_score=raw.get("cvss_score"),
                severity_label=severity_label,
                exploit_available=raw.get("exploit_available", False),
                in_the_wild=raw.get("in_the_wild", False),
                published_at=published,
                ioc_count=ioc_count,
                category=category_str,
            )

            # Store threat
            severity_enum = SEVERITY_MAP.get(
                scoring.severity.upper(), SeverityLevel.MEDIUM
            )

            threat = Threat(
                cve_id=cve_id,
                title=raw.get("title", description[:200]),
                description=description[:5000],
                category=category,
                category_confidence=classification.get("confidence", 0.0),
                severity=severity_enum,
                cvss_score=raw.get("cvss_score"),
                cvss_vector=raw.get("cvss_vector"),
                risk_score=scoring.risk_score,
                threat_velocity=scoring.threat_velocity,
                exploit_available=raw.get("exploit_available", False),
                in_the_wild=raw.get("in_the_wild", False),
                mitre_tactic=classification.get("mitre_tactic"),
                mitre_technique=classification.get("mitre_technique"),
                mitre_technique_name=classification.get("mitre_technique_name"),
                source=raw.get("source"),
                source_url=raw.get("source_url"),
                raw_data=raw.get("raw_data"),
                published_at=published,
            )
            db.add(threat)
            db.flush()  # Get the ID

            # Store IOCs
            for ioc_data in iocs[:100]:  # Limit per threat
                ioc_type_str = ioc_data["type"]
                ioc_type = IOC_TYPE_MAP.get(ioc_type_str)
                if ioc_type:
                    ioc = IOC(
                        threat_id=threat.id,
                        ioc_type=ioc_type,
                        value=ioc_data["value"],
                    )
                    db.add(ioc)

            # Check alerts
            threat_dict = threat.to_dict()
            alert = self.alert_manager.evaluate_threat(threat_dict)
            alert_triggered = False
            if alert:
                channels = self.alert_manager.send_alert(alert)
                alert.notified_via = channels
                db.add(alert)
                alert_triggered = True

            return {
                "threat_id": threat.id,
                "cve_id": cve_id,
                "category": category_str,
                "risk_score": scoring.risk_score,
                "ioc_count": ioc_count,
                "alert_triggered": alert_triggered,
            }

    def _log_audit(self, event_type: str, metadata: Dict):
        try:
            with get_db() as db:
                entry = AuditLog(
                    event_type=event_type,
                    actor="system:pipeline",
                    description=f"Pipeline run completed",
                    metadata=metadata,
                )
                db.add(entry)
        except Exception as e:
            logger.error(f"Audit log failed: {e}")


def run_pipeline(days_back: int = 1):
    """Entry point for scheduler and CLI."""
    try:
        from config.settings import settings
    except Exception:
        settings = None

    init_db()
    pipeline = CTIPipeline(settings=settings)
    return pipeline.run(days_back=days_back)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CTI Pipeline Runner")
    parser.add_argument("--days", type=int, default=1, help="Days of data to fetch")
    args = parser.parse_args()
    result = run_pipeline(days_back=args.days)
    print(f"\nPipeline result: {result}")
