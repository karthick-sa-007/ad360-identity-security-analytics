"""
alerts.py — Alerting engine for AD360 Identity Security Analytics.

Defines AlertRule dataclass and AlertsEngine which evaluates all rules
against live (or mock) AD360 data and returns triggered alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List

import config


@dataclass
class AlertRule:
    """Describes a single alert rule."""

    name: str
    severity: str          # Critical | High | Medium | Low
    condition: Callable    # callable(client) -> bool
    message: str
    remediation: str


@dataclass
class TriggeredAlert:
    """Represents a rule that has fired."""

    name: str
    severity: str
    message: str
    remediation: str
    details: dict = field(default_factory=dict)


class AlertsEngine:
    """Evaluates all configured alert rules against AD360 data."""

    def __init__(self) -> None:
        self._rules: List[AlertRule] = self._build_rules()

    # ------------------------------------------------------------------
    # Rule definitions
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rules() -> List[AlertRule]:
        thresholds = config.ALERT_THRESHOLDS

        rules = [
            # ---- Critical ------------------------------------------------
            AlertRule(
                name="Critical: Excessive Failed Logins",
                severity="Critical",
                condition=lambda c: len(c.get_failed_logins())
                >= thresholds["failed_logins_critical"],
                message=(
                    f"Failed login count has exceeded the critical threshold "
                    f"({thresholds['failed_logins_critical']})."
                ),
                remediation=(
                    "1. Investigate source IPs in the failed-login report.\n"
                    "2. Block offending IPs at the firewall.\n"
                    "3. Enable account lockout policies.\n"
                    "4. Enable geo-restriction if applicable."
                ),
            ),
            AlertRule(
                name="Critical: Admin Accounts Without MFA",
                severity="Critical",
                condition=lambda c: any(
                    u.get("is_admin") and not u.get("mfa_enabled")
                    for u in c.get_mfa_status()
                ),
                message="One or more admin accounts do not have MFA enabled.",
                remediation=(
                    "1. Identify admin accounts without MFA in the MFA status report.\n"
                    "2. Enforce MFA enrollment immediately for all admin accounts.\n"
                    "3. Consider using conditional-access policies.\n"
                    "4. Audit all privileged accounts for MFA compliance."
                ),
            ),
            # ---- High ----------------------------------------------------
            AlertRule(
                name="High: Elevated Failed Logins",
                severity="High",
                condition=lambda c: (
                    thresholds["failed_logins_high"]
                    <= len(c.get_failed_logins())
                    < thresholds["failed_logins_critical"]
                ),
                message=(
                    f"Failed login count is above the high threshold "
                    f"({thresholds['failed_logins_high']})."
                ),
                remediation=(
                    "1. Review the failed-login report for patterns.\n"
                    "2. Check for credential-stuffing activity.\n"
                    "3. Notify affected users to change passwords.\n"
                    "4. Consider enabling CAPTCHA or rate limiting."
                ),
            ),
            AlertRule(
                name="High: Excessive Account Lockouts",
                severity="High",
                condition=lambda c: len(c.get_user_lockouts())
                >= thresholds["lockouts_critical"],
                message=(
                    f"Account lockouts have exceeded the critical threshold "
                    f"({thresholds['lockouts_critical']})."
                ),
                remediation=(
                    "1. Review the lockout report for affected usernames.\n"
                    "2. Determine if lockouts are user error or a brute-force attempt.\n"
                    "3. Unlock accounts after verifying user identity.\n"
                    "4. Strengthen lockout duration/threshold settings if needed."
                ),
            ),
            # ---- Medium --------------------------------------------------
            AlertRule(
                name="Medium: High Number of Inactive Users",
                severity="Medium",
                condition=lambda c: len(c.get_inactive_users())
                >= thresholds["inactive_users_warning"],
                message=(
                    f"Inactive user count has exceeded the warning threshold "
                    f"({thresholds['inactive_users_warning']})."
                ),
                remediation=(
                    "1. Review the inactive-users report.\n"
                    "2. Disable accounts inactive for more than 90 days.\n"
                    "3. Follow the leavers process for accounts with no activity.\n"
                    "4. Schedule a quarterly access review."
                ),
            ),
            AlertRule(
                name="Medium: Frequent Privilege Changes",
                severity="Medium",
                condition=lambda c: len(c.get_privilege_changes())
                >= thresholds["privilege_changes_warning"],
                message=(
                    f"Privilege changes have exceeded the warning threshold "
                    f"({thresholds['privilege_changes_warning']})."
                ),
                remediation=(
                    "1. Review all recent privilege changes in the report.\n"
                    "2. Confirm each change was authorised via the change-management process.\n"
                    "3. Revoke any unauthorised privilege elevations.\n"
                    "4. Implement a least-privilege access model."
                ),
            ),
            # ---- Low -----------------------------------------------------
            AlertRule(
                name="Low: Weak Password Policy",
                severity="Low",
                condition=lambda c: (
                    c.get_password_policy().get("min_length", 99) < 12
                    or c.get_password_policy().get("history_count", 99) < 10
                ),
                message=(
                    "The current password policy does not meet recommended standards "
                    "(minimum length < 12 or history count < 10)."
                ),
                remediation=(
                    "1. Increase minimum password length to at least 12 characters.\n"
                    "2. Set password history to at least 10 previous passwords.\n"
                    "3. Consider enabling passphrase support.\n"
                    "4. Review and align policy with NIST SP 800-63B guidelines."
                ),
            ),
        ]
        return rules

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate_all(self, client: Any) -> List[TriggeredAlert]:
        """Evaluate all rules and return a list of triggered alerts."""
        triggered: List[TriggeredAlert] = []
        for rule in self._rules:
            try:
                if rule.condition(client):
                    triggered.append(
                        TriggeredAlert(
                            name=rule.name,
                            severity=rule.severity,
                            message=rule.message,
                            remediation=rule.remediation,
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                # Never let a broken rule crash the whole evaluation
                triggered.append(
                    TriggeredAlert(
                        name=f"Error evaluating rule: {rule.name}",
                        severity="Low",
                        message=str(exc),
                        remediation="Investigate rule configuration.",
                    )
                )

        # Sort: Critical → High → Medium → Low
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        triggered.sort(key=lambda a: order.get(a.severity, 99))
        return triggered
