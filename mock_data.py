"""
mock_data.py — Generates realistic mock AD360 data for all data categories.

All data is returned in the same structure that the real AD360 REST API would
return, so the rest of the application can treat mock and live data identically.
"""

from datetime import datetime, timedelta
import random


# Seed for reproducible results during development
random.seed(42)

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _ts(days_ago: float = 0, hours_ago: float = 0) -> str:
    """Return an ISO-8601 timestamp relative to *now*."""
    dt = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _random_ip() -> str:
    """Generate a random RFC-1918 private IPv4 address."""
    return f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"


# ---------------------------------------------------------------------------
# Mock data generators
# ---------------------------------------------------------------------------

def get_failed_logins() -> list:
    """Return 35 mock failed-login events."""
    reasons = [
        "Bad password",
        "Account locked",
        "Unknown username",
        "Expired password",
        "Disabled account",
    ]
    users = [
        "john.doe", "jane.smith", "bob.admin", "alice.hr",
        "charlie.dev", "diana.ops", "eve.finance", "frank.it",
        "grace.marketing", "henry.sales", "ivan.support", "julia.legal",
    ]
    domains = ["CORP", "INTERNAL", "EXTRANET"]

    entries = []
    for i in range(35):
        entries.append({
            "username": random.choice(users),
            "domain": random.choice(domains),
            "ip_address": _random_ip(),
            "timestamp": _ts(days_ago=random.uniform(0, 30)),
            "reason": random.choice(reasons),
        })
    return entries


def get_user_lockouts() -> list:
    """Return 8 mock user-lockout records."""
    users = [
        ("john.doe", "CORP"),
        ("bob.admin", "CORP"),
        ("alice.hr", "INTERNAL"),
        ("charlie.dev", "INTERNAL"),
        ("diana.ops", "CORP"),
        ("eve.finance", "EXTRANET"),
        ("frank.it", "CORP"),
        ("grace.marketing", "INTERNAL"),
    ]
    entries = []
    for username, domain in users:
        entries.append({
            "username": username,
            "domain": domain,
            "locked_at": _ts(days_ago=random.uniform(0, 7)),
            "unlock_status": random.choice(["auto_unlocked", "admin_unlocked", "pending"]),
        })
    return entries


def get_inactive_users() -> list:
    """Return 42 mock inactive-user records."""
    first_names = [
        "Aaron", "Bella", "Carlos", "Donna", "Ethan", "Fiona", "George",
        "Hannah", "Isaac", "Jessica", "Kevin", "Laura", "Mike", "Nina",
        "Oscar", "Paula", "Quinn", "Rachel", "Steve", "Tina",
    ]
    last_names = [
        "Anderson", "Brown", "Chen", "Davis", "Evans", "Foster", "Garcia",
        "Hill", "Ingram", "Jones", "King", "Lopez", "Miller", "Nelson",
        "Owen", "Parker", "Quinn", "Reed", "Scott", "Taylor",
    ]
    domains = ["CORP", "INTERNAL", "EXTRANET"]

    entries = []
    seen: set = set()
    while len(entries) < 42:
        first = random.choice(first_names)
        last = random.choice(last_names)
        uname = f"{first.lower()}.{last.lower()}"
        if uname in seen:
            continue
        seen.add(uname)
        days = random.randint(31, 365)
        entries.append({
            "username": uname,
            "domain": random.choice(domains),
            "last_login": _ts(days_ago=days),
            "days_inactive": days,
            "has_admin_rights": random.random() < 0.15,
        })
    return entries


def get_privilege_changes() -> list:
    """Return 12 mock privilege-change events."""
    changes = [
        ("john.doe", "bob.admin", "role_added", "User", "Domain Admin"),
        ("alice.hr", "svc.provisioner", "role_added", "Read-Only", "HR Manager"),
        ("charlie.dev", "bob.admin", "role_removed", "Local Admin", "Developer"),
        ("diana.ops", "svc.provisioner", "role_added", "Operator", "Server Admin"),
        ("eve.finance", "bob.admin", "role_added", "User", "Finance Manager"),
        ("frank.it", "svc.provisioner", "role_added", "Read-Only", "IT Admin"),
        ("grace.marketing", "bob.admin", "role_removed", "Marketing Lead", "User"),
        ("henry.sales", "svc.provisioner", "role_added", "User", "Sales Manager"),
        ("ivan.support", "bob.admin", "role_added", "Read-Only", "Support Lead"),
        ("julia.legal", "svc.provisioner", "role_added", "User", "Legal Counsel"),
        ("kevin.dev", "bob.admin", "role_removed", "Developer", "User"),
        ("laura.finance", "svc.provisioner", "role_added", "User", "Finance Analyst"),
    ]
    domains = ["CORP", "INTERNAL"]
    entries = []
    for username, changed_by, change_type, old_role, new_role in changes:
        entries.append({
            "username": username,
            "domain": random.choice(domains),
            "changed_by": changed_by,
            "change_type": change_type,
            "timestamp": _ts(days_ago=random.uniform(0, 30)),
            "old_role": old_role,
            "new_role": new_role,
        })
    return entries


def get_domain_overview() -> dict:
    """Return a mock domain-overview statistics dictionary."""
    return {
        "total_users": 850,
        "active_users": 712,
        "disabled_users": 96,
        "locked_users": 8,
        "admin_users": 34,
        "groups_count": 127,
        "ous_count": 18,
    }


def get_mfa_status() -> list:
    """Return mock MFA-enabled status for all users."""
    all_users = [
        "john.doe", "jane.smith", "bob.admin", "alice.hr",
        "charlie.dev", "diana.ops", "eve.finance", "frank.it",
        "grace.marketing", "henry.sales", "ivan.support", "julia.legal",
        "kevin.dev", "laura.finance", "mike.ops", "nina.hr",
        "oscar.it", "paula.sales", "quinn.dev", "rachel.legal",
    ]
    entries = []
    for username in all_users:
        # Admins without MFA create a critical alert in the alerts engine
        is_admin = "admin" in username or username in ("diana.ops", "frank.it")
        mfa = random.random() < (0.95 if is_admin else 0.65)
        entries.append({
            "username": username,
            "mfa_enabled": mfa,
            "is_admin": is_admin,
        })
    return entries


def get_password_policy() -> dict:
    """Return a mock password policy configuration."""
    return {
        "min_length": 8,          # Below recommended 12 — triggers a warning
        "complexity": True,
        "max_age_days": 90,
        "history_count": 5,       # Below recommended 10 — triggers a warning
    }


def get_compliance_data() -> dict:
    """Return mock compliance scores for GDPR, HIPAA, and PCI-DSS."""
    return {
        "GDPR": {
            "score": 72,
            "checks": {
                "data_encryption": True,
                "access_logging": True,
                "consent_management": False,
                "data_minimization": True,
                "breach_notification": False,
                "right_to_erasure": True,
            },
        },
        "HIPAA": {
            "score": 68,
            "checks": {
                "access_controls": True,
                "audit_logs": True,
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "workforce_training": False,
                "incident_response": False,
            },
        },
        "PCI_DSS": {
            "score": 81,
            "checks": {
                "network_segmentation": True,
                "strong_authentication": True,
                "patch_management": True,
                "vulnerability_scanning": True,
                "access_restriction": True,
                "security_testing": False,
            },
        },
    }
