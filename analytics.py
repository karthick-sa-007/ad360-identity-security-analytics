"""
analytics.py — Analytics engine for AD360 Identity Security Analytics.

Provides functions to calculate security scores, identify high-risk users,
summarise compliance posture, generate trend data, and produce a consolidated
identity summary.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

import config


# ---------------------------------------------------------------------------
# Security Score
# ---------------------------------------------------------------------------

def calculate_security_score(client: Any) -> dict:
    """Calculate a weighted security score (0–100) from AD360 data.

    Returns a dict with keys:
      score (float), grade (str), breakdown (dict)
    """
    failed_logins = client.get_failed_logins()
    lockouts = client.get_user_lockouts()
    inactive_users = client.get_inactive_users()
    privilege_changes = client.get_privilege_changes()

    thresholds = config.ALERT_THRESHOLDS
    weights = config.RISK_WEIGHTS

    # Component scores — 100 is perfect (no events), decreasing with volume
    def _penalise(count: int, critical: int, high: int) -> float:
        """Map count to a 0-100 component score."""
        if count == 0:
            return 100.0
        if count >= critical:
            return max(0.0, 100.0 - (count / critical) * 60)
        if count >= high:
            return max(10.0, 100.0 - (count / high) * 40)
        return max(20.0, 100.0 - (count / high) * 20)

    fl_score = _penalise(
        len(failed_logins),
        thresholds["failed_logins_critical"],
        thresholds["failed_logins_high"],
    )
    lo_score = _penalise(
        len(lockouts),
        thresholds["lockouts_critical"],
        thresholds["lockouts_high"],
    )
    iu_score = max(
        0.0,
        100.0 - (len(inactive_users) / max(thresholds["inactive_users_warning"], 1)) * 30,
    )
    pc_score = max(
        0.0,
        100.0 - (len(privilege_changes) / max(thresholds["privilege_changes_warning"], 1)) * 30,
    )

    breakdown = {
        "failed_logins": round(fl_score, 1),
        "lockouts": round(lo_score, 1),
        "inactive_users": round(iu_score, 1),
        "privilege_changes": round(pc_score, 1),
    }

    score = (
        fl_score * weights["failed_logins"]
        + lo_score * weights["lockouts"]
        + iu_score * weights["inactive_users"]
        + pc_score * weights["privilege_changes"]
    )
    score = round(score, 1)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "breakdown": breakdown}


# ---------------------------------------------------------------------------
# High Risk Users
# ---------------------------------------------------------------------------

def get_high_risk_users(client: Any) -> list:
    """Correlate events and return the top-10 highest-risk users.

    Each entry has: username, risk_score, risk_factors, last_activity.
    """
    failed_logins = client.get_failed_logins()
    lockouts = client.get_user_lockouts()
    privilege_changes = client.get_privilege_changes()

    risk: dict[str, dict] = {}

    def _ensure(username: str) -> None:
        if username not in risk:
            risk[username] = {
                "username": username,
                "risk_score": 0,
                "risk_factors": [],
                "last_activity": None,
            }

    for event in failed_logins:
        u = event.get("username", "unknown")
        _ensure(u)
        risk[u]["risk_score"] += 5
        if "Bad password" in event.get("reason", ""):
            risk[u]["risk_factors"].append("Failed login (bad password)")
        else:
            risk[u]["risk_factors"].append(f"Failed login ({event.get('reason', 'unknown')})")
        ts = event.get("timestamp")
        if ts and (risk[u]["last_activity"] is None or ts > risk[u]["last_activity"]):
            risk[u]["last_activity"] = ts

    for event in lockouts:
        u = event.get("username", "unknown")
        _ensure(u)
        risk[u]["risk_score"] += 20
        risk[u]["risk_factors"].append("Account locked out")
        ts = event.get("locked_at")
        if ts and (risk[u]["last_activity"] is None or ts > risk[u]["last_activity"]):
            risk[u]["last_activity"] = ts

    for event in privilege_changes:
        u = event.get("username", "unknown")
        _ensure(u)
        risk[u]["risk_score"] += 15
        risk[u]["risk_factors"].append(
            f"Privilege change: {event.get('old_role')} → {event.get('new_role')}"
        )
        ts = event.get("timestamp")
        if ts and (risk[u]["last_activity"] is None or ts > risk[u]["last_activity"]):
            risk[u]["last_activity"] = ts

    # De-duplicate risk factors
    for entry in risk.values():
        entry["risk_factors"] = list(dict.fromkeys(entry["risk_factors"]))
        entry["risk_factors"] = entry["risk_factors"][:5]  # cap to 5 items
        entry["risk_score"] = min(entry["risk_score"], 100)

    sorted_users = sorted(risk.values(), key=lambda x: x["risk_score"], reverse=True)
    return sorted_users[:10]


# ---------------------------------------------------------------------------
# Compliance Summary
# ---------------------------------------------------------------------------

def get_compliance_summary(client: Any) -> dict:
    """Return GDPR, HIPAA, and PCI-DSS compliance readiness percentages."""
    compliance_data = client.get_compliance_data()
    summary: dict[str, int] = {}
    for framework, details in compliance_data.items():
        summary[framework] = details.get("score", 0)
    return summary


# ---------------------------------------------------------------------------
# Security Trends (mock 30-day data)
# ---------------------------------------------------------------------------

def get_security_trends() -> dict:
    """Return mock 30-day trend data suitable for time-series charts.

    Returns a dict with keys:
      dates (list[str]), failed_logins (list[int]), lockouts (list[int])
    """
    random.seed(0)  # reproducible trends
    today = datetime.utcnow().date()
    dates: list[str] = []
    fl_trend: list[int] = []
    lo_trend: list[int] = []

    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        dates.append(day.isoformat())
        fl_trend.append(random.randint(0, 8))
        lo_trend.append(random.randint(0, 3))

    return {"dates": dates, "failed_logins": fl_trend, "lockouts": lo_trend}


# ---------------------------------------------------------------------------
# Identity Summary
# ---------------------------------------------------------------------------

def get_identity_summary(client: Any) -> dict:
    """Return a consolidated identity summary for display in the dashboard."""
    from alerts import AlertsEngine  # local import to avoid circular deps

    score_data = calculate_security_score(client)
    high_risk = get_high_risk_users(client)
    compliance = get_compliance_summary(client)
    alerts = AlertsEngine().evaluate_all(client)

    return {
        "score": score_data["score"],
        "grade": score_data["grade"],
        "breakdown": score_data["breakdown"],
        "high_risk_users": high_risk,
        "compliance": compliance,
        "active_alerts_count": len(alerts),
        "alerts": alerts,
    }
