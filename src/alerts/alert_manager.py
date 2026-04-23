"""
src/alerts/alert_manager.py
Alert system: evaluates threats against threshold rules,
sends notifications via email and Slack webhook.
Gap filled: threshold-based rules, Slack integration.
"""
import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from typing import List, Optional
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from src.utils.logger import get_logger
try:
    from src.database.db import get_db
    from src.database.models import Alert, AlertStatus, SeverityLevel
except ImportError:
    from dataclasses import dataclass, field
    from enum import Enum
    class AlertStatus(str, Enum):
        NEW = "new"; ACKNOWLEDGED = "acknowledged"
        RESOLVED = "resolved"; FALSE_POSITIVE = "false_positive"
    class SeverityLevel(str, Enum):
        CRITICAL = "Critical"; HIGH = "High"; MEDIUM = "Medium"; LOW = "Low"
    @dataclass
    class Alert:
        threat_id: object = None; title: str = ""; message: str = ""
        severity: object = None; status: object = None
        triggered_by: object = None; notified_via: list = field(default_factory=list)
        created_at: object = None

logger = get_logger("cti.alerts")


class AlertRule:
    """Defines a condition that triggers an alert."""
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def evaluate(self, threat_dict: dict) -> bool:
        raise NotImplementedError


class CVSSThresholdRule(AlertRule):
    def __init__(self, threshold: float):
        super().__init__("cvss_threshold", f"CVSS score >= {threshold}")
        self.threshold = threshold

    def evaluate(self, threat: dict) -> bool:
        score = threat.get("cvss_score") or threat.get("risk_score", 0)
        return score is not None and score >= self.threshold


class ExploitAvailableRule(AlertRule):
    def __init__(self):
        super().__init__("exploit_available", "Public exploit exists")

    def evaluate(self, threat: dict) -> bool:
        return threat.get("exploit_available", False)


class InTheWildRule(AlertRule):
    def __init__(self):
        super().__init__("in_the_wild", "Actively exploited in the wild")

    def evaluate(self, threat: dict) -> bool:
        return threat.get("in_the_wild", False)


class ZeroDayRule(AlertRule):
    def __init__(self):
        super().__init__("zero_day", "Zero-day vulnerability detected")

    def evaluate(self, threat: dict) -> bool:
        return threat.get("category") == "Zero Day"


class AlertManager:
    def __init__(
        self,
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_username: str = "",
        smtp_password: str = "",
        from_email: str = "cti@localhost",
        to_emails: List[str] = None,
        slack_webhook: str = "",
        critical_threshold: float = 9.0,
        high_threshold: float = 7.0,
        alert_on_exploit: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.from_email = from_email
        self.to_emails = to_emails or []
        self.slack_webhook = slack_webhook

        # Build default rules
        self.rules: List[AlertRule] = [
            CVSSThresholdRule(critical_threshold),
            InTheWildRule(),
            ZeroDayRule(),
        ]
        if alert_on_exploit:
            self.rules.append(ExploitAvailableRule())

    def evaluate_threat(self, threat: dict) -> Optional[Alert]:
        """Check all rules. If any fire, create an alert."""
        triggered = [rule for rule in self.rules if rule.evaluate(threat)]
        if not triggered:
            return None

        severity = self._determine_severity(threat)
        cve = threat.get("cve_id", "N/A")
        category = threat.get("category", "Unknown")
        risk = threat.get("risk_score", 0.0)

        title = f"[{severity.upper()}] {cve} — {category}"
        message = (
            f"Threat Intelligence Alert\n"
            f"{'=' * 50}\n"
            f"CVE: {cve}\n"
            f"Category: {category}\n"
            f"Severity: {severity}\n"
            f"Risk Score: {risk:.1f}/10\n"
            f"CVSS: {threat.get('cvss_score', 'N/A')}\n"
            f"Exploit Available: {threat.get('exploit_available', False)}\n"
            f"In The Wild: {threat.get('in_the_wild', False)}\n"
            f"MITRE Tactic: {threat.get('mitre_tactic', 'N/A')}\n"
            f"MITRE Technique: {threat.get('mitre_technique', 'N/A')} "
            f"— {threat.get('mitre_technique_name', '')}\n"
            f"\nTriggered by: {', '.join(r.name for r in triggered)}\n"
            f"\nDescription:\n{(threat.get('description') or '')[:500]}\n"
        )

        alert = Alert(
            threat_id=threat.get("id"),
            title=title,
            message=message,
            severity=SeverityLevel(severity),
            triggered_by=",".join(r.name for r in triggered),
        )

        return alert

    def send_alert(self, alert: Alert) -> List[str]:
        """Send alert via configured channels. Returns list of channels used."""
        channels = []

        if self.to_emails and self.smtp_host:
            if self._send_email(alert):
                channels.append("email")

        if self.slack_webhook:
            if self._send_slack(alert):
                channels.append("slack")

        if not channels:
            # Fallback: console log
            logger.warning(f"ALERT (no channels configured): {alert.title}")
            channels.append("console")

        return channels

    def _send_email(self, alert: Alert) -> bool:
        """Send email alert via SMTP."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = alert.title
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)

            # Plain text
            text_part = MIMEText(alert.message, "plain")

            # HTML part
            color = {"Critical": "#dc2626", "High": "#ea580c",
                     "Medium": "#ca8a04", "Low": "#16a34a"}.get(
                alert.severity.value, "#6b7280"
            )
            html = f"""
<html><body style="font-family: monospace; background: #0f172a; color: #e2e8f0; padding: 24px;">
<div style="background: #1e293b; border: 1px solid {color}; border-radius: 8px; padding: 20px; max-width: 600px;">
  <h2 style="color: {color}; margin: 0 0 16px;">{alert.title}</h2>
  <pre style="white-space: pre-wrap; font-size: 13px; color: #cbd5e1;">{alert.message}</pre>
  <p style="font-size: 11px; color: #64748b;">Sent by CTI Platform · {datetime.now(timezone.utc).isoformat()}</p>
</div>
</body></html>
"""
            msg.attach(text_part)
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                if self.smtp_username:
                    server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.from_email, self.to_emails, msg.as_string())

            logger.info(f"Email alert sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False

    def _send_slack(self, alert: Alert) -> bool:
        """Send Slack webhook alert with rich formatting."""
        color = {"Critical": "#dc2626", "High": "#ea580c",
                 "Medium": "#ca8a04", "Low": "#16a34a"}.get(
            alert.severity.value, "#6b7280"
        )
        emoji = {"Critical": "🚨", "High": "⚠️",
                 "Medium": "⚡", "Low": "ℹ️"}.get(alert.severity.value, "🔔")

        payload = {
            "text": f"{emoji} *CTI Alert: {alert.title}*",
            "attachments": [
                {
                    "color": color,
                    "text": f"```{alert.message[:1500]}```",
                    "footer": "CTI Platform",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ],
        }
        try:
            resp = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=10
            )
            resp.raise_for_status()
            logger.info(f"Slack alert sent: {alert.title}")
            return True
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False

    def _determine_severity(self, threat: dict) -> str:
        risk = threat.get("risk_score", 0)
        if risk >= 9.0 or threat.get("in_the_wild"):
            return "Critical"
        elif risk >= 7.0 or threat.get("exploit_available"):
            return "High"
        elif risk >= 4.0:
            return "Medium"
        return "Low"
