"""
ad360_client.py — AD360 REST API client.

When USE_MOCK_DATA is True (the default) every method returns data from
mock_data.py.  When USE_MOCK_DATA is False the client makes authenticated
HTTP GET requests to the real AD360 REST API.
"""

import logging
from typing import Any

import requests

import config
import mock_data

logger = logging.getLogger(__name__)


class AD360Client:
    """Thin wrapper around the AD360 REST API (or mock data)."""

    def __init__(self, base_url: str = config.AD360_BASE_URL,
                 auth_token: str = config.AD360_AUTH_TOKEN) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.use_mock = config.USE_MOCK_DATA
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get(self, endpoint: str) -> Any:
        """Perform a GET request and return parsed JSON or an empty dict."""
        url = f"{self.base_url}{endpoint}"
        try:
            resp = self._session.get(url, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            logger.error("Connection error reaching %s", url)
        except requests.exceptions.Timeout:
            logger.error("Timeout reaching %s", url)
        except requests.exceptions.HTTPError as exc:
            logger.error("HTTP error from %s: %s", url, exc)
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error calling %s: %s", url, exc)
        return {}

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def get_failed_logins(self) -> list:
        """Return failed-login events."""
        if self.use_mock:
            return mock_data.get_failed_logins()
        data = self._get("/api/v1/reports/failed-logins")
        return data.get("data", []) if isinstance(data, dict) else []

    def get_user_lockouts(self) -> list:
        """Return user-lockout records."""
        if self.use_mock:
            return mock_data.get_user_lockouts()
        data = self._get("/api/v1/reports/user-lockouts")
        return data.get("data", []) if isinstance(data, dict) else []

    def get_inactive_users(self) -> list:
        """Return inactive-user records."""
        if self.use_mock:
            return mock_data.get_inactive_users()
        data = self._get("/api/v1/reports/inactive-users")
        return data.get("data", []) if isinstance(data, dict) else []

    def get_privilege_changes(self) -> list:
        """Return privilege-change events."""
        if self.use_mock:
            return mock_data.get_privilege_changes()
        data = self._get("/api/v1/reports/privilege-changes")
        return data.get("data", []) if isinstance(data, dict) else []

    def get_domain_overview(self) -> dict:
        """Return domain-overview statistics."""
        if self.use_mock:
            return mock_data.get_domain_overview()
        data = self._get("/api/v1/domain/overview")
        return data if isinstance(data, dict) else {}

    def get_mfa_status(self) -> list:
        """Return MFA-status records for all users."""
        if self.use_mock:
            return mock_data.get_mfa_status()
        data = self._get("/api/v1/users/mfa-status")
        return data.get("data", []) if isinstance(data, dict) else []

    def get_password_policy(self) -> dict:
        """Return the active password policy."""
        if self.use_mock:
            return mock_data.get_password_policy()
        data = self._get("/api/v1/policy/password")
        return data if isinstance(data, dict) else {}

    def get_compliance_data(self) -> dict:
        """Return compliance scores and check results."""
        if self.use_mock:
            return mock_data.get_compliance_data()
        data = self._get("/api/v1/compliance/summary")
        return data if isinstance(data, dict) else {}
