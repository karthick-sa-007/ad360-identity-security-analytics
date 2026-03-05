"""
analytics.py — Analytics engine for AD360 Identity Security Analytics.

Provides functions to calculate security scores, identify high-risk users,
summarise compliance posture, generate trend data, and produce a consolidated
identity summary including advanced ITDR analytics.
"""

from __future__ import annotations

import random
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import config


# ---------------------------------------------------------------------------
# Security Score (original)
# ---------------------------------------------------------------------------

def calculate_security_score(client: Any) -> dict:
    """Calculate a weighted security score (0–100) from AD360 data."""
    failed_logins = client.get_failed_logins()
    lockouts = client.get_user_lockouts()
    inactive_users = client.get_inactive_users()
    privilege_changes = client.get_privilege_changes()

    thresholds = config.ALERT_THRESHOLDS
    weights = config.RISK_WEIGHTS

    def _penalise(count: int, critical: int, high: int) -> float:
        if count == 0:
            return 100.0
        if count >= critical:
            return max(0.0, 100.0 - (count / critical) * 60)
        if count >= high:
            return max(10.0, 100.0 - (count / high) * 40)
        return max(20.0, 100.0 - (count / high) * 20)

    fl_score = _penalise(len(failed_logins), thresholds["failed_logins_critical"], thresholds["failed_logins_high"])
    lo_score = _penalise(len(lockouts), thresholds["lockouts_critical"], thresholds["lockouts_high"])
    iu_score = max(0.0, 100.0 - (len(inactive_users) / max(thresholds["inactive_users_warning"], 1)) * 30)
    pc_score = max(0.0, 100.0 - (len(privilege_changes) / max(thresholds["privilege_changes_warning"], 1)) * 30)

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

    grade = "A" if score >= 90 else ("B" if score >= 80 else ("C" if score >= 70 else ("D" if score >= 60 else "F")))
    return {"score": score, "grade": grade, "breakdown": breakdown}


# ---------------------------------------------------------------------------
# High Risk Users (original)
# ---------------------------------------------------------------------------

def get_high_risk_users(client: Any) -> list:
    """Correlate events and return the top-10 highest-risk users."""
    failed_logins = client.get_failed_logins()
    lockouts = client.get_user_lockouts()
    privilege_changes = client.get_privilege_changes()

    risk: dict[str, dict] = {}

    def _ensure(username: str) -> None:
        if username not in risk:
            risk[username] = {"username": username, "risk_score": 0, "risk_factors": [], "last_activity": None}

    for event in failed_logins:
        u = event.get("username", "unknown")
        _ensure(u)
        risk[u]["risk_score"] += 5
        reason = event.get("reason", "unknown")
        risk[u]["risk_factors"].append(f"Failed login ({reason})")
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
        risk[u]["risk_factors"].append(f"Privilege change: {event.get('old_role')} → {event.get('new_role')}")
        ts = event.get("timestamp")
        if ts and (risk[u]["last_activity"] is None or ts > risk[u]["last_activity"]):
            risk[u]["last_activity"] = ts

    for entry in risk.values():
        entry["risk_factors"] = list(dict.fromkeys(entry["risk_factors"]))[:5]
        entry["risk_score"] = min(entry["risk_score"], 100)

    return sorted(risk.values(), key=lambda x: x["risk_score"], reverse=True)[:10]


# ---------------------------------------------------------------------------
# Compliance Summary (original)
# ---------------------------------------------------------------------------

def get_compliance_summary(client: Any) -> dict:
    """Return compliance scores for all frameworks."""
    compliance_data = client.get_compliance_data()
    return {fw: details.get("score", 0) for fw, details in compliance_data.items()}


# ---------------------------------------------------------------------------
# Security Trends (original — kept for backward compat)
# ---------------------------------------------------------------------------

def get_security_trends() -> dict:
    """Return mock 30-day trend data for time-series charts."""
    random.seed(0)
    today = datetime.utcnow().date()
    dates, fl_trend, lo_trend = [], [], []
    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        dates.append(day.isoformat())
        fl_trend.append(random.randint(0, 8))
        lo_trend.append(random.randint(0, 3))
    return {"dates": dates, "failed_logins": fl_trend, "lockouts": lo_trend}


# ---------------------------------------------------------------------------
# Identity Summary (original)
# ---------------------------------------------------------------------------

def get_identity_summary(client: Any) -> dict:
    """Return a consolidated identity summary."""
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


# ---------------------------------------------------------------------------
# ITDR Score (new)
# ---------------------------------------------------------------------------

def calculate_itdr_score(client: Any) -> dict:
    """Calculate weighted ITDR score using all 10 risk categories (0–100)."""
    weights = config.RISK_WEIGHTS
    thresholds = config.ALERT_THRESHOLDS

    def _penalise(count: int, critical: int, high: int) -> float:
        if count == 0:
            return 100.0
        if count >= critical:
            return max(0.0, 100.0 - (count / max(critical, 1)) * 60)
        if count >= high:
            return max(10.0, 100.0 - (count / max(high, 1)) * 40)
        return max(20.0, 100.0 - (count / max(high, 1)) * 20)

    fl = len(client.get_failed_logins())
    lo = len(client.get_user_lockouts())
    iu = len(client.get_inactive_users())
    pc = len(client.get_privilege_changes())
    mfa_issues = sum(1 for u in client.get_mfa_status() if u.get("is_admin") and not u.get("mfa_enabled"))
    it = len(client.get_impossible_travel_alerts())
    ah = len(client.get_after_hours_logins())
    sa = len(client.get_service_account_abuse())
    lm = len(client.get_lateral_movement())
    sha = len(client.get_shadow_admins())

    scores = {
        "failed_logins": _penalise(fl, thresholds["failed_logins_critical"], thresholds["failed_logins_high"]),
        "lockouts": _penalise(lo, thresholds["lockouts_critical"], thresholds["lockouts_high"]),
        "inactive_users": max(0.0, 100.0 - (iu / max(thresholds["inactive_users_warning"], 1)) * 30),
        "privilege_changes": max(0.0, 100.0 - (pc / max(thresholds["privilege_changes_warning"], 1)) * 30),
        "mfa_violations": _penalise(mfa_issues, thresholds["mfa_violations_critical"], thresholds["mfa_violations_high"]),
        "impossible_travel": _penalise(it, thresholds["impossible_travel_critical"], thresholds["impossible_travel_high"]),
        "after_hours_logins": max(0.0, 100.0 - (ah / max(thresholds["after_hours_logins_warning"], 1)) * 30),
        "service_account_abuse": _penalise(sa, thresholds["service_account_abuse_critical"], thresholds["service_account_abuse_high"]),
        "lateral_movement": _penalise(lm, thresholds["lateral_movement_critical"], thresholds["lateral_movement_high"]),
        "shadow_admins": max(0.0, 100.0 - (sha / max(thresholds["shadow_admins_warning"], 1)) * 30),
    }

    total = sum(scores[cat] * weights[cat] for cat in weights)
    total = round(total, 1)
    grade = "A" if total >= 90 else ("B" if total >= 80 else ("C" if total >= 70 else ("D" if total >= 60 else "F")))

    return {
        "itdr_score": total,
        "grade": grade,
        "category_scores": {k: round(v, 1) for k, v in scores.items()},
        "weights": weights,
    }


# ---------------------------------------------------------------------------
# Attack Pattern Detection (new)
# ---------------------------------------------------------------------------

def detect_attack_patterns(client: Any) -> list:
    """Identify attack patterns in event data."""
    patterns = []
    failed = client.get_failed_logins()
    lockouts = client.get_user_lockouts()

    # Brute force: same user with many failures
    user_failures: dict[str, int] = defaultdict(int)
    for e in failed:
        user_failures[e.get("username", "")] += 1
    brute_force_users = [u for u, cnt in user_failures.items() if cnt >= 5]
    if brute_force_users:
        patterns.append({
            "pattern": "brute_force",
            "mitre_id": "T1110.001",
            "affected_users": brute_force_users[:10],
            "event_count": sum(user_failures[u] for u in brute_force_users),
            "description": f"Brute force detected against {len(brute_force_users)} account(s).",
            "severity": "High",
        })

    # Password spray: many users, same source IP
    ip_users: dict[str, set] = defaultdict(set)
    for e in failed:
        ip_users[e.get("ip_address", "")].add(e.get("username", ""))
    spray_ips = {ip: users for ip, users in ip_users.items() if len(users) >= 5}
    if spray_ips:
        patterns.append({
            "pattern": "password_spray",
            "mitre_id": "T1110.003",
            "affected_users": list(list(spray_ips.values())[0])[:10],
            "source_ips": list(spray_ips.keys())[:5],
            "event_count": sum(len(u) for u in spray_ips.values()),
            "description": f"Password spray from {len(spray_ips)} IP(s) targeting multiple accounts.",
            "severity": "High",
        })

    # Credential stuffing: large volume with "Bad password" pattern from external IPs
    external_bad_pwd = [e for e in failed if e.get("reason") == "Bad password"
                        and not e.get("ip_address", "").startswith("192.168")]
    if len(external_bad_pwd) >= 10:
        patterns.append({
            "pattern": "credential_stuffing",
            "mitre_id": "T1110.004",
            "affected_users": list({e.get("username") for e in external_bad_pwd})[:10],
            "event_count": len(external_bad_pwd),
            "description": f"Credential stuffing: {len(external_bad_pwd)} external bad-password attempts.",
            "severity": "High",
        })

    # Impossible travel
    travel = client.get_impossible_travel_alerts()
    if travel:
        patterns.append({
            "pattern": "impossible_travel",
            "mitre_id": "T1078",
            "affected_users": [e.get("username") for e in travel][:10],
            "event_count": len(travel),
            "description": f"{len(travel)} impossible-travel event(s) detected.",
            "severity": "Critical",
        })

    # Lateral movement
    lateral = client.get_lateral_movement()
    if lateral:
        patterns.append({
            "pattern": "lateral_movement",
            "mitre_id": "T1021",
            "affected_users": list({e.get("username") for e in lateral})[:10],
            "event_count": len(lateral),
            "description": f"{len(lateral)} lateral-movement event(s) across the environment.",
            "severity": "Critical",
        })

    return patterns


# ---------------------------------------------------------------------------
# MITRE ATT&CK Coverage (new)
# ---------------------------------------------------------------------------

def get_mitre_attack_coverage(client: Any) -> list:
    """Map active threats to MITRE ATT&CK techniques."""
    mapping = config.MITRE_ATTACK_MAPPING
    patterns = detect_attack_patterns(client)
    lateral = client.get_lateral_movement()
    shadow = client.get_shadow_admins()

    covered: dict[str, dict] = {}

    for p in patterns:
        mid = p.get("mitre_id", "")
        if mid:
            covered[mid] = {
                "technique_id": mid,
                "technique_name": p["pattern"].replace("_", " ").title(),
                "tactic": _mitre_tactic(mid),
                "active_events": p["event_count"],
                "severity": p["severity"],
                "affected_users": p.get("affected_users", []),
            }

    for e in lateral:
        mid = e.get("mitre_technique_id", "T1021")
        if mid not in covered:
            covered[mid] = {
                "technique_id": mid,
                "technique_name": e.get("technique", "Lateral Movement"),
                "tactic": "Lateral Movement",
                "active_events": 0,
                "severity": "Critical",
                "affected_users": [],
            }
        covered[mid]["active_events"] += 1
        u = e.get("username")
        if u and u not in covered[mid]["affected_users"]:
            covered[mid]["affected_users"].append(u)

    # Shadow admin → Persistence
    if shadow:
        covered["T1098.003"] = {
            "technique_id": "T1098.003",
            "technique_name": "Account Manipulation: Shadow Admin",
            "tactic": "Persistence",
            "active_events": len(shadow),
            "severity": "High",
            "affected_users": [e.get("username") for e in shadow[:10]],
        }

    return sorted(covered.values(), key=lambda x: x["active_events"], reverse=True)


def _mitre_tactic(technique_id: str) -> str:
    """Map technique ID prefix to tactic name."""
    mapping = {
        "T1110": "Credential Access",
        "T1078": "Initial Access",
        "T1021": "Lateral Movement",
        "T1098": "Persistence",
        "T1556": "Credential Access",
        "T1047": "Execution",
        "T1569": "Execution",
        "T1484": "Defense Evasion",
        "T1201": "Discovery",
        "T1136": "Persistence",
        "T1550": "Lateral Movement",
    }
    prefix = technique_id.split(".")[0]
    return mapping.get(prefix, "Unknown")


# ---------------------------------------------------------------------------
# Zero Trust Score (new)
# ---------------------------------------------------------------------------

def calculate_zero_trust_score(client: Any) -> dict:
    """Score zero trust readiness across five pillars."""
    mfa_users = client.get_mfa_status()
    total_mfa = len(mfa_users)
    mfa_enabled = sum(1 for u in mfa_users if u.get("mfa_enabled"))
    mfa_rate = (mfa_enabled / max(total_mfa, 1)) * 100

    priv_inv = client.get_privileged_account_inventory()
    mfa_priv = sum(1 for u in priv_inv if u.get("mfa_enabled"))
    priv_mfa_rate = (mfa_priv / max(len(priv_inv), 1)) * 100

    shadow = client.get_shadow_admins()
    orphaned = client.get_orphaned_accounts()
    inactive = client.get_inactive_users()

    identity_score = round((mfa_rate * 0.5 + priv_mfa_rate * 0.3 + max(0, 100 - len(shadow) * 3) * 0.2), 1)
    device_score = 72.0  # placeholder — would come from endpoint data
    network_score = round(max(0, 100 - len(client.get_lateral_movement()) * 5), 1)
    application_score = round(max(0, 100 - len(client.get_service_account_abuse()) * 4), 1)
    data_score = round(max(0, 100 - (len(orphaned) + len(inactive)) * 0.3), 1)

    overall = round((identity_score * 0.35 + device_score * 0.20 + network_score * 0.20 +
                     application_score * 0.15 + data_score * 0.10), 1)

    return {
        "overall_zero_trust_score": overall,
        "pillars": {
            "Identity": round(identity_score, 1),
            "Device": round(device_score, 1),
            "Network": round(network_score, 1),
            "Application": round(application_score, 1),
            "Data": round(data_score, 1),
        },
        "mfa_adoption_rate": round(mfa_rate, 1),
        "privileged_mfa_rate": round(priv_mfa_rate, 1),
    }


# ---------------------------------------------------------------------------
# Peer Group Analysis (new)
# ---------------------------------------------------------------------------

def get_peer_group_analysis(client: Any) -> list:
    """Compare each department's risk posture against the organisation average."""
    risk_profiles = client.get_user_risk_profiles()

    dept_scores: dict[str, list] = defaultdict(list)
    for user in risk_profiles:
        dept = user.get("department", "Unknown")
        dept_scores[dept].append(user.get("risk_score", 0))

    if not dept_scores:
        return []

    all_scores = [s for scores in dept_scores.values() for s in scores]
    org_avg = sum(all_scores) / max(len(all_scores), 1)

    result = []
    for dept, scores in dept_scores.items():
        avg = sum(scores) / max(len(scores), 1)
        result.append({
            "department": dept,
            "avg_risk_score": round(avg, 1),
            "user_count": len(scores),
            "vs_org_avg": round(avg - org_avg, 1),
            "highest_risk": max(scores),
            "at_risk_users": sum(1 for s in scores if s >= 60),
        })

    return sorted(result, key=lambda x: x["avg_risk_score"], reverse=True)


# ---------------------------------------------------------------------------
# Risk Velocity (new)
# ---------------------------------------------------------------------------

def get_risk_velocity(client: Any) -> list:
    """Return users whose risk scores are increasing the fastest."""
    profiles = client.get_user_risk_profiles()
    timeline = client.get_attack_timeline()

    recent_activity: dict[str, int] = defaultdict(int)
    for event in timeline:
        recent_activity[event.get("username", "")] += 1

    velocity = []
    for user in profiles:
        uname = user.get("username", "")
        score = user.get("risk_score", 0)
        activity = recent_activity.get(uname, 0)
        vel = round(score * 0.6 + activity * 5, 1)
        velocity.append({
            "username": uname,
            "current_risk_score": score,
            "recent_events": activity,
            "risk_velocity": min(vel, 100),
            "risk_level": user.get("risk_level", "Low"),
            "department": user.get("department", "Unknown"),
        })

    return sorted(velocity, key=lambda x: x["risk_velocity"], reverse=True)[:20]


# ---------------------------------------------------------------------------
# Identity Attack Surface (new)
# ---------------------------------------------------------------------------

def get_identity_attack_surface(client: Any) -> dict:
    """Calculate the total identity attack surface."""
    domain = client.get_domain_overview()
    priv_inv = client.get_privileged_account_inventory()
    shadow = client.get_shadow_admins()
    orphaned = client.get_orphaned_accounts()
    inactive = client.get_inactive_users()
    mfa_users = client.get_mfa_status()

    total_users = domain.get("total_users", 0)
    admin_users = domain.get("admin_users", 0)
    no_mfa = sum(1 for u in mfa_users if not u.get("mfa_enabled"))
    dormant_priv = sum(1 for u in priv_inv if u.get("is_dormant"))
    overdue_pwd = sum(1 for u in priv_inv if u.get("password_age_days", 0) > 180)

    surface_score = (
        (admin_users / max(total_users, 1)) * 100 * 0.25
        + (no_mfa / max(len(mfa_users), 1)) * 100 * 0.25
        + (len(shadow) / max(total_users, 1)) * 1000 * 0.20
        + (len(orphaned) / max(total_users, 1)) * 1000 * 0.15
        + (dormant_priv / max(len(priv_inv), 1)) * 100 * 0.15
    )

    return {
        "attack_surface_score": round(min(surface_score, 100), 1),
        "total_users": total_users,
        "privileged_accounts": admin_users,
        "accounts_without_mfa": no_mfa,
        "shadow_admins": len(shadow),
        "orphaned_accounts": len(orphaned),
        "inactive_accounts": len(inactive),
        "dormant_privileged_accounts": dormant_priv,
        "privileged_accounts_overdue_password": overdue_pwd,
        "risk_label": "Critical" if surface_score > 60 else ("High" if surface_score > 40 else ("Medium" if surface_score > 20 else "Low")),
    }
