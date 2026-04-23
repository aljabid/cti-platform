"""
src/scoring/risk_engine.py
Composite risk scoring engine.
Combines: CVSS, exploit availability, IOC count,
          recency, in-the-wild status, threat velocity.
Industry-grade scoring fills the basic CVSS-only gap.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from src.utils.logger import get_logger

logger = get_logger("cti.scoring")


@dataclass
class ScoringInput:
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    in_the_wild: bool = False
    published_at: Optional[datetime] = None
    ioc_count: int = 0
    category: str = "Unknown"
    description: str = ""
    severity_label: str = "UNKNOWN"  # From source (NVD, etc.)
    actor_count: int = 0  # Number of known threat actors using this
    patch_available: bool = False


@dataclass
class ScoringResult:
    risk_score: float          # 0.0 – 10.0
    threat_velocity: float     # 0.0 – 10.0 (how fast spreading)
    severity: str              # Critical / High / Medium / Low
    risk_factors: List[str]    # Human-readable reasons
    recommended_action: str


# Category risk multipliers (some threat types are inherently riskier at same CVSS)
CATEGORY_MULTIPLIERS = {
    "Remote Code Execution": 1.15,
    "Ransomware": 1.20,
    "Zero Day": 1.25,
    "Supply Chain": 1.20,
    "Privilege Escalation": 1.10,
    "Malware": 1.05,
    "Phishing": 1.0,
    "DDoS": 0.95,
    "SQL Injection": 1.05,
    "Cross-Site Scripting": 0.90,
    "Unknown": 1.0,
}

RECOMMENDED_ACTIONS = {
    "Critical": (
        "⚠️ IMMEDIATE ACTION REQUIRED: Patch within 24 hours. "
        "Isolate affected systems. Trigger incident response if actively exploited."
    ),
    "High": (
        "Patch within 72 hours. Monitor for exploitation indicators. "
        "Enable enhanced logging on affected systems."
    ),
    "Medium": (
        "Schedule patch within 30 days. Review exposure. "
        "Add to next patching cycle."
    ),
    "Low": (
        "Monitor. Include in next scheduled maintenance window. "
        "Low exploitation probability."
    ),
}


def calculate_risk(inp: ScoringInput) -> ScoringResult:
    """
    Calculate composite risk score (0–10) and threat velocity.
    
    Score components:
      - Base CVSS (0–10):          50% weight
      - Exploit available:         +1.5 points
      - In-the-wild exploitation:  +2.0 points
      - Recency (< 7 days):        +0.5 points
      - IOC count enrichment:      up to +1.0 points
      - Threat actor linked:       +0.5 points
      - No patch available:        +0.5 points
    
    Then apply category multiplier, clamp to 10.
    """
    factors = []
    score = 0.0

    # 1. Base CVSS
    if inp.cvss_score is not None:
        cvss_contribution = inp.cvss_score * 0.50
        score += cvss_contribution
        factors.append(f"CVSS {inp.cvss_score:.1f} (base)")
    else:
        # Estimate from severity label if CVSS missing
        severity_fallback = {
            "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5,
            "LOW": 3.0, "UNKNOWN": 5.0
        }
        fallback = severity_fallback.get(inp.severity_label.upper(), 5.0)
        score += fallback * 0.50
        factors.append(f"Estimated from severity label: {inp.severity_label}")

    # 2. Exploit availability
    if inp.exploit_available:
        score += 1.5
        factors.append("Public exploit available (+1.5)")

    # 3. Active exploitation
    if inp.in_the_wild:
        score += 2.0
        factors.append("Actively exploited in the wild (+2.0)")

    # 4. Recency (newer = higher urgency)
    if inp.published_at:
        now = datetime.now(timezone.utc)
        age_days = (now - inp.published_at.replace(tzinfo=timezone.utc)
                    if inp.published_at.tzinfo is None
                    else now - inp.published_at).days
        if age_days <= 1:
            score += 0.5
            factors.append("Published within 24 hours (+0.5)")
        elif age_days <= 7:
            score += 0.3
            factors.append(f"Published {age_days} days ago (+0.3)")

    # 5. IOC enrichment (presence of IOCs indicates real-world activity)
    if inp.ioc_count > 0:
        ioc_bonus = min(inp.ioc_count / 20.0, 1.0)
        score += ioc_bonus
        factors.append(f"{inp.ioc_count} IOCs extracted (+{ioc_bonus:.2f})")

    # 6. Threat actor association
    if inp.actor_count > 0:
        score += min(inp.actor_count * 0.25, 0.75)
        factors.append(f"Linked to {inp.actor_count} threat actor(s)")

    # 7. No patch available
    if not inp.patch_available and inp.cvss_score and inp.cvss_score >= 7.0:
        score += 0.5
        factors.append("No patch available (+0.5)")

    # 8. Category multiplier
    multiplier = CATEGORY_MULTIPLIERS.get(inp.category, 1.0)
    if multiplier != 1.0:
        score *= multiplier
        factors.append(f"Category multiplier: {inp.category} (×{multiplier})")

    # Clamp
    risk_score = round(min(score, 10.0), 2)

    # Severity label
    severity = _score_to_severity(risk_score)

    # Threat velocity (how fast spreading: based on recency + in_wild + exploits)
    velocity = _calculate_velocity(inp)

    return ScoringResult(
        risk_score=risk_score,
        threat_velocity=velocity,
        severity=severity,
        risk_factors=factors,
        recommended_action=RECOMMENDED_ACTIONS[severity],
    )


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def _calculate_velocity(inp: ScoringInput) -> float:
    """
    Threat velocity = how fast is this spreading / being picked up.
    High velocity = needs faster response time.
    """
    vel = 0.0

    if inp.in_the_wild:
        vel += 4.0
    if inp.exploit_available:
        vel += 2.5

    if inp.published_at:
        now = datetime.now(timezone.utc)
        pub = inp.published_at
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        age_hours = (now - pub).total_seconds() / 3600

        # Exponential decay: newer = higher velocity
        if age_hours < 6:
            vel += 3.0
        elif age_hours < 24:
            vel += 2.0
        elif age_hours < 72:
            vel += 1.0

    if inp.ioc_count > 10:
        vel += 1.0
    elif inp.ioc_count > 3:
        vel += 0.5

    return round(min(vel, 10.0), 2)


def score_from_raw(
    cvss_score: Optional[float],
    severity_label: str,
    exploit_available: bool,
    in_the_wild: bool,
    published_at: Optional[datetime],
    ioc_count: int,
    category: str,
    actor_count: int = 0,
    patch_available: bool = True,
) -> ScoringResult:
    """Convenience function for one-line scoring from raw values."""
    return calculate_risk(ScoringInput(
        cvss_score=cvss_score,
        severity_label=severity_label,
        exploit_available=exploit_available,
        in_the_wild=in_the_wild,
        published_at=published_at,
        ioc_count=ioc_count,
        category=category,
        actor_count=actor_count,
        patch_available=patch_available,
    ))
