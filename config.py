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

# ---------------------------------------------------------------------------
# Risk score weights  (must sum to 1.0)
# ---------------------------------------------------------------------------
RISK_WEIGHTS: dict = {
    "failed_logins": 0.30,
    "lockouts": 0.25,
    "inactive_users": 0.20,
    "privilege_changes": 0.25,
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
}
