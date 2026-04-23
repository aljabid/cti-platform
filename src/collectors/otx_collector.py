"""
src/collectors/otx_collector.py
AlienVault OTX (Open Threat Exchange) feed collector.
Fetches pulses, IOCs, and threat intelligence.
"""
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))
from src.utils.logger import get_logger

logger = get_logger("cti.collector.otx")

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


class OTXCollector:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"X-OTX-API-KEY": api_key})
        self.session.headers.update({"User-Agent": "CTI-Platform/1.0"})

    def fetch_subscribed_pulses(self, days_back: int = 1) -> List[Dict]:
        """Fetch latest threat pulses from OTX."""
        if not self.api_key:
            logger.warning("No OTX API key configured — skipping OTX collection")
            return []

        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
        results = []
        page = 1

        while True:
            try:
                resp = self.session.get(
                    f"{OTX_BASE_URL}/pulses/subscribed",
                    params={"modified_since": since, "page": page, "limit": 50},
                    timeout=30
                )
                resp.raise_for_status()
                data = resp.json()
                pulses = data.get("results", [])
                if not pulses:
                    break

                for pulse in pulses:
                    parsed = self._parse_pulse(pulse)
                    if parsed:
                        results.append(parsed)

                page += 1
                if not data.get("next"):
                    break

            except requests.RequestException as e:
                logger.error(f"OTX fetch error: {e}")
                break

        logger.info(f"OTX: collected {len(results)} threat pulses")
        return results

    def fetch_iocs_for_cve(self, cve_id: str) -> List[Dict]:
        """Get IOCs related to a specific CVE."""
        if not self.api_key:
            return []
        try:
            resp = self.session.get(
                f"{OTX_BASE_URL}/indicator/CVE/{cve_id}/general",
                timeout=20
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("pulse_info", {}).get("pulses", [])
        except Exception as e:
            logger.error(f"OTX CVE lookup failed for {cve_id}: {e}")
            return []

    def _parse_pulse(self, pulse: Dict) -> Optional[Dict]:
        """Parse OTX pulse into normalized threat format."""
        try:
            iocs = []
            for indicator in pulse.get("indicators", [])[:50]:
                iocs.append({
                    "type": indicator.get("type", ""),
                    "value": indicator.get("indicator", ""),
                    "description": indicator.get("description", ""),
                })

            tags = pulse.get("tags", [])
            tlp = pulse.get("tlp", "white").lower()

            return {
                "title": pulse.get("name", "Unknown Threat"),
                "description": pulse.get("description", ""),
                "source": "AlienVault OTX",
                "source_url": f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                "published_at": self._parse_dt(pulse.get("created")),
                "tags": tags,
                "tlp": tlp,
                "iocs": iocs,
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
                "cves": pulse.get("references", []),
                "raw_data": {
                    "pulse_id": pulse.get("id"),
                    "author": pulse.get("author", {}).get("username"),
                    "indicator_count": pulse.get("indicator_count", 0),
                },
            }
        except Exception as e:
            logger.warning(f"OTX pulse parse error: {e}")
            return None

    def _parse_dt(self, dt_str: Optional[str]) -> Optional[datetime]:
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except ValueError:
            return None
