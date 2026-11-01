"""Risk scoring: turn rule severity plus enrichment context into a 0-100 score.

Deliberately simple and explainable -- every point added comes with a reason
the analyst can read in `risk_factors`.
"""

from app.detection import Alert

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
BASE_SCORE = {"low": 20, "medium": 45, "high": 70, "critical": 90}
THREAT_INTEL_BONUS = 15
EXTERNAL_SOURCE_BONUS = 5
ROOT_ACCOUNT_BONUS = 10


def score(alert: Alert) -> Alert:
    points = BASE_SCORE[alert.severity]
    factors = [f"severity {alert.severity} (+{points})"]

    if alert.threat.listed:
        points += THREAT_INTEL_BONUS
        factors.append(f"source IP on threat intel: {', '.join(alert.threat.feeds)} (+{THREAT_INTEL_BONUS})")
    if alert.source.internal is False:
        points += EXTERNAL_SOURCE_BONUS
        where = f" ({alert.source.geo.country})" if alert.source.geo and alert.source.geo.country else ""
        factors.append(f"external source{where} (+{EXTERNAL_SOURCE_BONUS})")
    if alert.user.name == "root":
        points += ROOT_ACCOUNT_BONUS
        factors.append(f"root account involved (+{ROOT_ACCOUNT_BONUS})")

    alert.risk_score = min(points, 100)
    alert.risk_factors = factors
    return alert


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
