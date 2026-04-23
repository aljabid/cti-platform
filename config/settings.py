"""
config/settings.py
Loads and validates all environment configuration.
"""
import os
from dataclasses import dataclass, field
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    # App
    app_env: str = os.getenv("APP_ENV", "development")
    secret_key: str = os.getenv("APP_SECRET_KEY", "dev-secret-key")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    # Database
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/cti.db")

    # API Keys
    nvd_api_key: Optional[str] = os.getenv("NVD_API_KEY")
    otx_api_key: Optional[str] = os.getenv("OTX_API_KEY")
    shodan_api_key: Optional[str] = os.getenv("SHODAN_API_KEY")
    vt_api_key: Optional[str] = os.getenv("VT_API_KEY")

    # TAXII
    taxii_server_url: str = os.getenv("TAXII_SERVER_URL", "https://cti-taxii.mitre.org/taxii/")
    taxii_username: Optional[str] = os.getenv("TAXII_USERNAME")
    taxii_password: Optional[str] = os.getenv("TAXII_PASSWORD")

    # Scheduler
    collection_interval_minutes: int = int(os.getenv("COLLECTION_INTERVAL_MINUTES", "60"))
    alert_check_interval_minutes: int = int(os.getenv("ALERT_CHECK_INTERVAL_MINUTES", "5"))

    # Alerts - Email
    smtp_host: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: Optional[str] = os.getenv("SMTP_USERNAME")
    smtp_password: Optional[str] = os.getenv("SMTP_PASSWORD")
    alert_from_email: str = os.getenv("ALERT_FROM_EMAIL", "cti@localhost")
    alert_to_emails: List[str] = field(default_factory=lambda: [
        e.strip() for e in os.getenv("ALERT_TO_EMAILS", "").split(",") if e.strip()
    ])

    # Alerts - Slack
    slack_webhook_url: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")

    # Alert thresholds
    critical_cvss_threshold: float = float(os.getenv("CRITICAL_CVSS_THRESHOLD", "9.0"))
    high_cvss_threshold: float = float(os.getenv("HIGH_CVSS_THRESHOLD", "7.0"))
    alert_on_exploit_available: bool = os.getenv("ALERT_ON_EXPLOIT_AVAILABLE", "true").lower() == "true"

    # Dashboard
    dashboard_username: str = os.getenv("DASHBOARD_USERNAME", "admin")
    dashboard_password: str = os.getenv("DASHBOARD_PASSWORD", "admin")

    # Integrations
    sentinelscan_api_url: Optional[str] = os.getenv("SENTINELSCAN_API_URL")
    sentinelscan_api_key: Optional[str] = os.getenv("SENTINELSCAN_API_KEY")
    malware_detection_api_url: Optional[str] = os.getenv("MALWARE_DETECTION_API_URL")
    malware_detection_api_key: Optional[str] = os.getenv("MALWARE_DETECTION_API_KEY")


settings = Settings()
