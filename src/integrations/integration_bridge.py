"""
src/integrations/integration_bridge.py
Connects CTI Platform with SentinelScan and Malware Detection.
Enables: CVE matching from scan results, IOC-based malware correlation.
Gap filled: actual integration implementation.
"""
import requests
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from src.utils.logger import get_logger
from src.database.db import get_db
from src.database.models import Threat, IOC

logger = get_logger("cti.integrations")


class SentinelScanBridge:
    """
    Integrates with SentinelScan:
    - Send CVE IDs to SentinelScan to check if target is vulnerable
    - Receive scan results and enrich with CTI data
    """
    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})

    def get_vulnerable_cves_for_target(self, target_ip: str) -> List[str]:
        """Ask SentinelScan which CVEs affect a given IP/host."""
        try:
            resp = self.session.get(
                f"{self.api_url}/scan/results",
                params={"target": target_ip, "format": "cve_list"},
                timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("cves", [])
        except Exception as e:
            logger.error(f"SentinelScan query failed for {target_ip}: {e}")
            return []

    def enrich_scan_with_cti(self, cve_ids: List[str]) -> List[Dict]:
        """
        Given CVE IDs from a scan, return CTI enrichment from local DB.
        This is the core integration value: scan finds services → CVEs →
        CTI gives context (severity, exploits, MITRE, IOCs).
        """
        if not cve_ids:
            return []

        results = []
        with get_db() as db:
            for cve_id in cve_ids:
                threat = db.query(Threat).filter_by(cve_id=cve_id.upper()).first()
                if threat:
                    results.append({
                        "cve_id": cve_id,
                        "found_in_cti": True,
                        "category": threat.category.value if threat.category else "Unknown",
                        "severity": threat.severity.value if threat.severity else "Unknown",
                        "risk_score": threat.risk_score,
                        "exploit_available": threat.exploit_available,
                        "in_the_wild": threat.in_the_wild,
                        "mitre_tactic": threat.mitre_tactic,
                        "mitre_technique": threat.mitre_technique,
                        "recommended_action": (
                            "URGENT: Patch immediately — exploit available"
                            if threat.exploit_available
                            else "Schedule patch per severity level"
                        ),
                    })
                else:
                    results.append({
                        "cve_id": cve_id,
                        "found_in_cti": False,
                        "note": "Not in CTI DB — may need manual research",
                    })

        return results

    def trigger_scan_for_threat(self, cve_id: str, targets: List[str]) -> Optional[str]:
        """Tell SentinelScan to scan targets for a specific CVE."""
        try:
            resp = self.session.post(
                f"{self.api_url}/scan/trigger",
                json={"cve_id": cve_id, "targets": targets},
                timeout=15
            )
            resp.raise_for_status()
            return resp.json().get("scan_id")
        except Exception as e:
            logger.error(f"SentinelScan trigger failed: {e}")
            return None


class MalwareDetectionBridge:
    """
    Integrates with Malware Detection module:
    - Check if file hash matches known CTI IOCs
    - Submit hashes for enrichment
    """
    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})

    def check_hash_against_cti(self, file_hash: str) -> Dict:
        """
        Look up a file hash against all CTI IOCs.
        Returns match info if found.
        """
        with get_db() as db:
            ioc = db.query(IOC).filter(
                IOC.value == file_hash.lower()
            ).first()

            if ioc and ioc.threat_id:
                threat = db.query(Threat).filter_by(id=ioc.threat_id).first()
                if threat:
                    return {
                        "matched": True,
                        "hash": file_hash,
                        "ioc_type": ioc.ioc_type.value,
                        "threat": {
                            "cve_id": threat.cve_id,
                            "category": threat.category.value if threat.category else "Unknown",
                            "severity": threat.severity.value if threat.severity else "Unknown",
                            "risk_score": threat.risk_score,
                        },
                        "recommendation": "BLOCK — hash matches known threat IOC",
                    }

        return {"matched": False, "hash": file_hash, "recommendation": "Not found in CTI database"}

    def submit_detection_to_cti(self, detection: Dict) -> bool:
        """
        When malware detection finds something new,
        add its IOCs to the CTI database for future correlation.
        """
        file_hash = detection.get("hash")
        threat_id = detection.get("threat_id")

        if not file_hash:
            return False

        try:
            from src.database.models import IOCType
            with get_db() as db:
                # Determine hash type by length
                hash_type = {32: IOCType.FILE_HASH_MD5,
                             40: IOCType.FILE_HASH_SHA1,
                             64: IOCType.FILE_HASH_SHA256}.get(len(file_hash))
                if not hash_type:
                    return False

                ioc = IOC(
                    threat_id=threat_id,
                    ioc_type=hash_type,
                    value=file_hash.lower(),
                    context=f"Detected by Malware Detection module: {detection.get('family', 'unknown')}",
                    is_malicious=True,
                    confidence=detection.get("confidence", 0.8),
                )
                db.add(ioc)
            logger.info(f"Malware IOC added to CTI: {file_hash}")
            return True
        except Exception as e:
            logger.error(f"Failed to add malware IOC to CTI: {e}")
            return False


def get_sentinel_bridge() -> Optional[SentinelScanBridge]:
    """Get SentinelScan bridge if configured."""
    url = os.getenv("SENTINELSCAN_API_URL")
    key = os.getenv("SENTINELSCAN_API_KEY", "")
    if url:
        return SentinelScanBridge(url, key)
    return None


def get_malware_bridge() -> Optional[MalwareDetectionBridge]:
    """Get Malware Detection bridge if configured."""
    url = os.getenv("MALWARE_DETECTION_API_URL")
    key = os.getenv("MALWARE_DETECTION_API_KEY", "")
    if url:
        return MalwareDetectionBridge(url, key)
    return None
