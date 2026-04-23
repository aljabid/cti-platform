"""
src/processing/ioc_extractor.py
Extracts Indicators of Compromise (IOCs) from threat text.
Identifies: IPs, domains, URLs, file hashes, CVE IDs, email addresses.
This fills the major gap in the original blueprint.
"""
import re
from typing import List, Dict, Tuple
from src.utils.logger import get_logger

logger = get_logger("cti.ioc_extractor")

# ─── Regex Patterns ───────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|gov|edu|io|co|uk|de|ru|cn|br|info|biz|xyz|top|online|site)\b",
        re.IGNORECASE,
    ),
    "url": re.compile(
        r"https?://[^\s<>\"{}|\\^`\[\]]{8,}",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "cve": re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b",
        re.IGNORECASE,
    ),
}

# Private IP ranges to exclude (RFC 1918, loopback, etc.)
PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "255.",
)

# Common false-positive domains to exclude
EXCLUDED_DOMAINS = {
    "example.com", "test.com", "localhost.com",
    "nvd.nist.gov", "cve.mitre.org",
}


def extract_iocs(text: str) -> List[Dict]:
    """
    Extract all IOCs from a block of text.
    Returns list of dicts with keys: type, value.
    """
    if not text:
        return []

    found = []
    seen = set()

    def add(ioc_type: str, value: str):
        key = f"{ioc_type}:{value.lower()}"
        if key not in seen:
            seen.add(key)
            found.append({"type": ioc_type, "value": value})

    # IPv4 (excluding private ranges)
    for match in PATTERNS["ipv4"].finditer(text):
        ip = match.group()
        if not any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES):
            add("ip", ip)

    # IPv6
    for match in PATTERNS["ipv6"].finditer(text):
        add("ip", match.group())

    # URLs (before domains, to avoid double-counting)
    url_positions = set()
    for match in PATTERNS["url"].finditer(text):
        add("url", match.group())
        url_positions.add(match.start())

    # Domains (skip if already captured in a URL)
    for match in PATTERNS["domain"].finditer(text):
        domain = match.group().lower()
        if domain not in EXCLUDED_DOMAINS and not _is_in_url(match.start(), url_positions, text):
            add("domain", domain)

    # File hashes — order matters (sha256 > sha1 > md5 to avoid prefix collision)
    sha256_spans = set()
    for match in PATTERNS["sha256"].finditer(text):
        add("sha256", match.group().lower())
        sha256_spans.add((match.start(), match.end()))

    sha1_spans = set()
    for match in PATTERNS["sha1"].finditer(text):
        if not _overlaps(match.start(), match.end(), sha256_spans):
            add("sha1", match.group().lower())
            sha1_spans.add((match.start(), match.end()))

    all_hash_spans = sha256_spans | sha1_spans
    for match in PATTERNS["md5"].finditer(text):
        if not _overlaps(match.start(), match.end(), all_hash_spans):
            add("md5", match.group().lower())

    # Email addresses
    for match in PATTERNS["email"].finditer(text):
        email = match.group().lower()
        if not email.endswith((".png", ".jpg", ".gif", ".svg")):
            add("email", email)

    # CVE IDs
    for match in PATTERNS["cve"].finditer(text):
        add("cve", match.group().upper())

    return found


def _is_in_url(pos: int, url_positions: set, text: str) -> bool:
    """Check if a position is inside a URL match."""
    for url_start in url_positions:
        if pos >= url_start:
            return True
    return False


def _overlaps(start: int, end: int, spans: set) -> bool:
    """Check if a span overlaps with any existing spans."""
    for s, e in spans:
        if start < e and end > s:
            return True
    return False


def count_ioc_types(iocs: List[Dict]) -> Dict[str, int]:
    """Summarize IOC counts by type."""
    counts = {}
    for ioc in iocs:
        t = ioc["type"]
        counts[t] = counts.get(t, 0) + 1
    return counts
