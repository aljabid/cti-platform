"""
src/collectors/cve_collector.py
Fetches CVE data from NIST NVD API v2.
Handles rate limiting, pagination, and delta fetching via FeedCache.
"""
import time
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from src.utils.logger import get_logger
from src.database.db import get_db
from src.database.models import FeedCache

logger = get_logger("cti.collector.nvd")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 100

# NVD rate limits: 5 req/30s without key, 50 req/30s with key
RATE_LIMIT_DELAY_NO_KEY = 6.5  # seconds
RATE_LIMIT_DELAY_WITH_KEY = 0.6  # seconds


class CVECollector:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.delay = RATE_LIMIT_DELAY_WITH_KEY if api_key else RATE_LIMIT_DELAY_NO_KEY
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        self.session.headers.update({"User-Agent": "CTI-Platform/1.0"})

    def _fetch_page(self, params: Dict) -> Optional[Dict]:
        """Fetch a single page with retry logic."""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = self.session.get(NVD_BASE_URL, params=params, timeout=30)
                resp.raise_for_status()
                time.sleep(self.delay)
                return resp.json()
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    wait = 30 * (attempt + 1)
                    logger.warning(f"NVD rate limit hit. Waiting {wait}s (attempt {attempt+1}/{max_retries})")
                    time.sleep(wait)
                else:
                    logger.error(f"NVD HTTP error: {e}")
                    return None
            except requests.exceptions.RequestException as e:
                logger.error(f"NVD request failed (attempt {attempt+1}): {e}")
                time.sleep(5 * (attempt + 1))
        return None

    def fetch_recent(self, days_back: int = 1) -> List[Dict]:
        """Fetch CVEs published in the last N days."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days_back)

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        }

        return self._collect_all_pages(params, label=f"recent ({days_back}d)")

    def fetch_critical(self, min_cvss: float = 9.0) -> List[Dict]:
        """Fetch CVEs with CVSS score >= threshold."""
        params = {
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": 0,
        }
        return self._collect_all_pages(params, label=f"critical (CVSS>={min_cvss})")

    def fetch_by_cve_id(self, cve_id: str) -> Optional[Dict]:
        """Fetch a specific CVE by ID."""
        data = self._fetch_page({"cveId": cve_id})
        if data and data.get("vulnerabilities"):
            return self._parse_cve(data["vulnerabilities"][0]["cve"])
        return None

    def _collect_all_pages(self, params: Dict, label: str = "") -> List[Dict]:
        """Paginate through all results."""
        results = []
        start_index = 0

        logger.info(f"Starting NVD collection: {label}")

        while True:
            params["startIndex"] = start_index
            data = self._fetch_page(params)

            if not data:
                logger.error("Failed to fetch NVD page, stopping.")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            for vuln in vulnerabilities:
                parsed = self._parse_cve(vuln.get("cve", {}))
                if parsed:
                    results.append(parsed)

            logger.info(f"NVD: fetched {len(results)}/{total} CVEs")

            start_index += len(vulnerabilities)
            if start_index >= total or not vulnerabilities:
                break

        logger.info(f"NVD collection complete: {len(results)} CVEs")
        return results

    def _parse_cve(self, cve: Dict) -> Optional[Dict]:
        """Parse raw NVD CVE object into normalized dict."""
        try:
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            # Extract CVSS v3 score
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_vector = None
            severity = "UNKNOWN"

            for key in ["cvssMetricV31", "cvssMetricV30"]:
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    break

            # CWE info
            weaknesses = cve.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for d in w.get("description", []):
                    if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                        cwe_ids.append(d["value"])

            # Published date
            published = cve.get("published")
            published_dt = None
            if published:
                try:
                    published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except ValueError:
                    pass

            # References
            refs = cve.get("references", [])
            ref_urls = [r.get("url", "") for r in refs[:5]]

            return {
                "cve_id": cve_id,
                "title": f"{cve_id}: {desc_en[:100]}..." if len(desc_en) > 100 else f"{cve_id}: {desc_en}",
                "description": desc_en,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity_label": severity,
                "cwe_ids": cwe_ids,
                "references": ref_urls,
                "published_at": published_dt,
                "source": "NVD",
                "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "raw_data": {
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "cwe_ids": cwe_ids,
                },
            }
        except Exception as e:
            logger.warning(f"Failed to parse CVE: {e}")
            return None

    def update_feed_cache(self, feed_name: str, items_count: int, error: Optional[str] = None):
        """Update the feed cache after a run."""
        with get_db() as db:
            cache = db.query(FeedCache).filter_by(feed_name=feed_name).first()
            if not cache:
                cache = FeedCache(feed_name=feed_name)
                db.add(cache)
            cache.last_fetched_at = datetime.now(timezone.utc)
            cache.items_fetched = items_count
            cache.last_error = error
            cache.status = "error" if error else "idle"
