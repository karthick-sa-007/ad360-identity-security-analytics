"""
config.py — Centralized configuration for AD360 Identity Security Analytics.

Loads environment variables and exposes runtime settings, risk-score weights,
and alert thresholds to the rest of the application.
"""

import os
from dotenv import load_dotenv

# Load .env file if present (ignored when env vars are already set)
load_dotenv()

# ---------------------------------------------------------------------------
# AD360 connection settings
# ---------------------------------------------------------------------------
AD360_BASE_URL: str = os.getenv("AD360_BASE_URL", "https://your-ad360-instance:8082")
AD360_AUTH_TOKEN: str = os.getenv("AD360_AUTH_TOKEN", "your_token_here")

# When True the application uses simulated data from mock_data.py instead of
# making real HTTP calls to an AD360 instance.
USE_MOCK_DATA: bool = os.getenv("USE_MOCK_DATA", "true").lower() in ("true", "1", "yes")

# Notification settings
ALERT_EMAIL: str = os.getenv("ALERT_EMAIL", "admin@yourcompany.com")

# Organization settings
ORG_NAME: str = os.getenv("ORG_NAME", "Acme Corporation")
ENVIRONMENT: str = os.getenv("ENVIRONMENT", "Production")

# ---------------------------------------------------------------------------
# Risk score bounds
# ---------------------------------------------------------------------------
MAX_RISK_SCORE: int = 100

# ---------------------------------------------------------------------------
# Risk score weights  (must sum to 1.0)
# ---------------------------------------------------------------------------
RISK_WEIGHTS: dict = {
    "failed_logins": 0.15,
    "lockouts": 0.10,
    "inactive_users": 0.10,
    "privilege_changes": 0.10,
    "mfa_violations": 0.15,
    "impossible_travel": 0.15,
    "after_hours_logins": 0.05,
    "service_account_abuse": 0.10,
    "lateral_movement": 0.05,
    "shadow_admins": 0.05,
}

# ---------------------------------------------------------------------------
# Alert thresholds
# ---------------------------------------------------------------------------
ALERT_THRESHOLDS: dict = {
    "failed_logins_critical": 50,
    "failed_logins_high": 20,
    "lockouts_critical": 10,
    "lockouts_high": 5,
    "inactive_users_warning": 30,
    "privilege_changes_warning": 10,
    "mfa_violations_critical": 5,
    "mfa_violations_high": 2,
    "impossible_travel_critical": 3,
    "impossible_travel_high": 1,
    "after_hours_logins_warning": 20,
    "service_account_abuse_critical": 5,
    "service_account_abuse_high": 2,
    "lateral_movement_critical": 3,
    "lateral_movement_high": 1,
    "shadow_admins_warning": 10,
    "orphaned_accounts_warning": 20,
    "dormant_privileged_days": 90,
    "password_age_critical_days": 180,
    "contractor_inactive_days": 60,
}

# ---------------------------------------------------------------------------
# Compliance frameworks
# ---------------------------------------------------------------------------
COMPLIANCE_FRAMEWORKS: list = [
    "GDPR", "HIPAA", "SOX", "PCI_DSS", "ISO_27001", "NIST_800_53", "CIS_AD"
]

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping — alert name prefix → technique ID
# ---------------------------------------------------------------------------
MITRE_ATTACK_MAPPING: dict = {
    "Impossible Travel": "T1078",
    "Admin Without MFA": "T1556",
    "Lateral Movement": "T1021",
    "Service Account Interactive Login": "T1078.003",
    "Excessive Failed Logins": "T1110",
    "Unapproved Emergency Privilege Change": "T1098",
    "Password Spray": "T1110.003",
    "Credential Stuffing": "T1110.004",
    "Shadow Admin": "T1098.003",
    "Dormant Privileged Account": "T1078.002",
    "After-Hours Privileged Access": "T1078",
    "Multiple Lockouts Same IP": "T1110.001",
    "Orphaned Admin Account": "T1098",
    "High Inactive Users": "T1078.004",
    "Frequent Privilege Changes": "T1098",
    "JML Process Overdue": "T1136",
    "MFA Bypass": "T1556.006",
    "Contractor Over-privileged": "T1078",
    "Service Account Password Age": "T1078.003",
    "GPO Modified": "T1484.001",
    "Weak Password Policy": "T1201",
    "Single-Factor Admin Console": "T1556",
    "Shared Account": "T1078",
    "Password Never Expires": "T1201",
    "Brute Force": "T1110.001",
}
