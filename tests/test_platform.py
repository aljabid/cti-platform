"""
tests/test_platform.py
Pytest test suite for the CTI Platform.
Covers: IOC extraction, classifier, risk scoring, pipeline, API.
"""
import pytest
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../"))

# ─── IOC Extractor Tests ──────────────────────────────────────────────────────

from src.processing.ioc_extractor import extract_iocs, count_ioc_types


class TestIOCExtractor:

    def test_extract_ipv4(self):
        text = "The attacker connected from 203.0.113.42 to port 443."
        iocs = extract_iocs(text)
        ips = [i for i in iocs if i["type"] == "ip"]
        assert any(i["value"] == "203.0.113.42" for i in ips)

    def test_excludes_private_ip(self):
        text = "Internal server 192.168.1.1 was not affected."
        iocs = extract_iocs(text)
        ips = [i for i in iocs if i["type"] == "ip"]
        assert not any(i["value"] == "192.168.1.1" for i in ips)

    def test_extract_domain(self):
        text = "Payload contacted malicious-c2.example.com for instructions."
        iocs = extract_iocs(text)
        domains = [i for i in iocs if i["type"] == "domain"]
        assert len(domains) >= 1

    def test_extract_sha256(self):
        sha = "a" * 64
        text = f"Malware hash: {sha}"
        iocs = extract_iocs(text)
        hashes = [i for i in iocs if i["type"] == "sha256"]
        assert any(i["value"] == sha for i in hashes)

    def test_extract_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        text = f"File hash MD5: {md5}"
        iocs = extract_iocs(text)
        hashes = [i for i in iocs if i["type"] == "md5"]
        assert any(i["value"] == md5 for i in hashes)

    def test_extract_cve(self):
        text = "This is related to CVE-2024-12345 and CVE-2023-99999."
        iocs = extract_iocs(text)
        cves = [i for i in iocs if i["type"] == "cve"]
        assert len(cves) == 2

    def test_extract_url(self):
        text = "Download from https://malicious.ru/payload.exe"
        iocs = extract_iocs(text)
        urls = [i for i in iocs if i["type"] == "url"]
        assert len(urls) >= 1

    def test_no_duplicates(self):
        text = "IP 203.0.113.1 contacted 203.0.113.1 twice."
        iocs = extract_iocs(text)
        values = [i["value"] for i in iocs if i["type"] == "ip"]
        assert len(values) == len(set(values))

    def test_empty_text(self):
        assert extract_iocs("") == []
        assert extract_iocs(None) == []

    def test_count_ioc_types(self):
        iocs = [
            {"type": "ip", "value": "1.2.3.4"},
            {"type": "ip", "value": "5.6.7.8"},
            {"type": "domain", "value": "evil.com"},
        ]
        counts = count_ioc_types(iocs)
        assert counts["ip"] == 2
        assert counts["domain"] == 1


# ─── Classifier Tests ─────────────────────────────────────────────────────────

from src.nlp.classifier import ThreatClassifier


class TestClassifier:

    @pytest.fixture(scope="class")
    def clf(self):
        return ThreatClassifier()

    def test_classifies_ransomware(self, clf):
        text = "ransomware encrypts all user files and demands bitcoin payment"
        result = clf.classify(text)
        assert result["category"] == "Ransomware"
        assert result["confidence"] > 0.5

    def test_classifies_rce(self, clf):
        text = "buffer overflow allows remote code execution on unpatched systems"
        result = clf.classify(text)
        assert result["category"] == "Remote Code Execution"

    def test_classifies_phishing(self, clf):
        text = "spear phishing email harvests credentials via fake login page"
        result = clf.classify(text)
        assert result["category"] == "Phishing"

    def test_classifies_ddos(self, clf):
        text = "UDP flood amplification DDoS attack disrupts service availability"
        result = clf.classify(text)
        assert result["category"] == "DDoS"

    def test_mitre_mapping_present(self, clf):
        text = "ransomware encryption files locked ransom demand"
        result = clf.classify(text)
        assert result["mitre_tactic"] != ""
        assert result["mitre_technique"] != ""

    def test_returns_confidence(self, clf):
        text = "some threat description text"
        result = clf.classify(text)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_empty_text(self, clf):
        result = clf.classify("")
        assert result["category"] == "Unknown"

    def test_all_scores_present(self, clf):
        result = clf.classify("malware backdoor trojan")
        assert isinstance(result["all_scores"], dict)
        assert len(result["all_scores"]) > 0


# ─── Risk Scoring Tests ───────────────────────────────────────────────────────

from src.scoring.risk_engine import calculate_risk, ScoringInput


class TestRiskScoring:

    def test_critical_rce_in_wild(self):
        inp = ScoringInput(
            cvss_score=9.8,
            exploit_available=True,
            in_the_wild=True,
            category="Remote Code Execution",
            published_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        result = calculate_risk(inp)
        assert result.severity == "Critical"
        assert result.risk_score >= 9.0

    def test_low_risk_old_no_exploit(self):
        inp = ScoringInput(
            cvss_score=3.0,
            exploit_available=False,
            in_the_wild=False,
            category="Cross-Site Scripting",
            published_at=datetime.now(timezone.utc) - timedelta(days=60),
        )
        result = calculate_risk(inp)
        assert result.severity in ("Low", "Medium")
        assert result.risk_score < 6.0

    def test_exploit_bonus(self):
        base = ScoringInput(cvss_score=7.0, category="Malware")
        with_exploit = ScoringInput(cvss_score=7.0, exploit_available=True, category="Malware")
        r_base = calculate_risk(base)
        r_exploit = calculate_risk(with_exploit)
        assert r_exploit.risk_score > r_base.risk_score

    def test_ransomware_multiplier(self):
        base = ScoringInput(cvss_score=7.0, category="Unknown")
        ransomware = ScoringInput(cvss_score=7.0, category="Ransomware")
        r_base = calculate_risk(base)
        r_ransom = calculate_risk(ransomware)
        assert r_ransom.risk_score > r_base.risk_score

    def test_risk_score_clamped(self):
        inp = ScoringInput(
            cvss_score=10.0,
            exploit_available=True,
            in_the_wild=True,
            ioc_count=100,
            actor_count=5,
            category="Zero Day",
            published_at=datetime.now(timezone.utc),
            patch_available=False,
        )
        result = calculate_risk(inp)
        assert result.risk_score <= 10.0

    def test_velocity_high_when_in_wild(self):
        inp = ScoringInput(
            cvss_score=8.0,
            in_the_wild=True,
            exploit_available=True,
            published_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        result = calculate_risk(inp)
        assert result.threat_velocity >= 6.0

    def test_risk_factors_populated(self):
        inp = ScoringInput(cvss_score=8.5, exploit_available=True, category="Malware")
        result = calculate_risk(inp)
        assert len(result.risk_factors) > 0

    def test_recommended_action_present(self):
        inp = ScoringInput(cvss_score=9.5, in_the_wild=True)
        result = calculate_risk(inp)
        assert "IMMEDIATE" in result.recommended_action

    def test_no_cvss_fallback(self):
        inp = ScoringInput(cvss_score=None, severity_label="HIGH")
        result = calculate_risk(inp)
        assert result.risk_score > 0


# ─── Alert Manager Tests ──────────────────────────────────────────────────────

from src.alerts.alert_manager import AlertManager, CVSSThresholdRule, ExploitAvailableRule


class TestAlertManager:

    def test_cvss_rule_triggers(self):
        rule = CVSSThresholdRule(9.0)
        assert rule.evaluate({"risk_score": 9.5}) is True
        assert rule.evaluate({"risk_score": 7.0}) is False

    def test_exploit_rule_triggers(self):
        rule = ExploitAvailableRule()
        assert rule.evaluate({"exploit_available": True}) is True
        assert rule.evaluate({"exploit_available": False}) is False

    def test_alert_created_on_trigger(self):
        mgr = AlertManager(critical_threshold=9.0)
        threat = {
            "id": "test-id",
            "cve_id": "CVE-2024-9999",
            "category": "Remote Code Execution",
            "risk_score": 9.8,
            "cvss_score": 9.8,
            "exploit_available": True,
            "in_the_wild": False,
            "mitre_tactic": "Execution",
            "mitre_technique": "T1203",
            "mitre_technique_name": "Exploitation",
            "description": "Critical RCE vulnerability",
        }
        alert = mgr.evaluate_threat(threat)
        assert alert is not None
        assert "CVE-2024-9999" in alert.title

    def test_no_alert_below_threshold(self):
        mgr = AlertManager(critical_threshold=9.0, alert_on_exploit=False)
        threat = {
            "id": "test-id",
            "risk_score": 5.0,
            "cvss_score": 5.0,
            "exploit_available": False,
            "in_the_wild": False,
        }
        alert = mgr.evaluate_threat(threat)
        assert alert is None


# ─── Integration Bridge Tests (mock) ──────────────────────────────────────────

from unittest.mock import patch, MagicMock
from src.integrations.integration_bridge import MalwareDetectionBridge


class TestIntegrationBridge:

    def test_hash_type_detection_md5(self):
        bridge = MalwareDetectionBridge("http://localhost:9999")
        # MD5 = 32 chars
        result = bridge.check_hash_against_cti("d" * 32)
        assert "matched" in result

    def test_hash_type_detection_sha256(self):
        bridge = MalwareDetectionBridge("http://localhost:9999")
        result = bridge.check_hash_against_cti("a" * 64)
        assert "matched" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
