"""
alerts.py — Enterprise ITDR alerting engine for AD360 Identity Security Analytics.

Defines 25+ alert rules across Critical/High/Medium/Low severities with
MITRE ATT&CK mappings, remediations, and affected user context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List

import config


@dataclass
class AlertRule:
    """Describes a single alert rule."""
    name: str
    severity: str
    condition: Callable
    message: str
    remediation: list          # 4-step list
    mitre_technique_id: str = ""
    affected_users: list = field(default_factory=list)


@dataclass
class TriggeredAlert:
    """Represents a rule that has fired."""
    name: str
    severity: str
    message: str
    remediation: list
    mitre_technique_id: str = ""
    affected_users: list = field(default_factory=list)
    details: dict = field(default_factory=dict)


class AlertsEngine:
    """Evaluates all configured ITDR alert rules against AD360 data."""

    def __init__(self) -> None:
        self._rules: List[AlertRule] = self._build_rules()

    @staticmethod
    def _build_rules() -> List[AlertRule]:
        t = config.ALERT_THRESHOLDS
        rules = [

            # ================================================================
            # CRITICAL (6)
            # ================================================================

            AlertRule(
                name="Critical: Impossible Travel Detected",
                severity="Critical",
                condition=lambda c: len(c.get_impossible_travel_alerts()) >= t["impossible_travel_high"],
                message=(
                    f"Impossible-travel events detected: a user has authenticated from two "
                    f"geographically distant locations within an impossibly short timeframe."
                ),
                remediation=[
                    "Immediately block the suspicious session and force re-authentication.",
                    "Verify with the user whether the travel is legitimate or account is compromised.",
                    "Reset credentials and revoke all active tokens for affected accounts.",
                    "Enable conditional-access policies to restrict logins from unexpected locations.",
                ],
                mitre_technique_id="T1078",
            ),

            AlertRule(
                name="Critical: Admin Accounts Without MFA",
                severity="Critical",
                condition=lambda c: any(
                    u.get("is_admin") and not u.get("mfa_enabled") for u in c.get_mfa_status()
                ),
                message="One or more admin accounts do not have MFA enabled — highest priority risk.",
                remediation=[
                    "Identify all admin accounts without MFA in the MFA status report.",
                    "Enforce MFA enrollment immediately for all privileged accounts.",
                    "Apply conditional-access policies requiring MFA for admin consoles.",
                    "Audit all privileged accounts for MFA compliance weekly.",
                ],
                mitre_technique_id="T1556",
            ),

            AlertRule(
                name="Critical: Lateral Movement Detected",
                severity="Critical",
                condition=lambda c: len(c.get_lateral_movement()) >= t["lateral_movement_high"],
                message=(
                    "Lateral movement activity has been detected. An attacker may be traversing "
                    "the network using stolen credentials or exploitation techniques."
                ),
                remediation=[
                    "Isolate affected systems from the network immediately.",
                    "Identify the attack path and block the source credentials.",
                    "Rotate all credentials on affected systems and adjacent hosts.",
                    "Conduct a full incident-response investigation and preserve forensics.",
                ],
                mitre_technique_id="T1021",
            ),

            AlertRule(
                name="Critical: Service Account Interactive Login",
                severity="Critical",
                condition=lambda c: any(
                    e.get("abuse_type") == "interactive_login" for e in c.get_service_account_abuse()
                ),
                message=(
                    "A service account has been used for an interactive login session. "
                    "Service accounts should never be used interactively."
                ),
                remediation=[
                    "Block interactive logins for all service accounts via GPO.",
                    "Investigate the session to determine if the account was compromised.",
                    "Rotate the service account credentials immediately.",
                    "Migrate service accounts to Group Managed Service Accounts (gMSA).",
                ],
                mitre_technique_id="T1078.003",
            ),

            AlertRule(
                name="Critical: Excessive Failed Logins",
                severity="Critical",
                condition=lambda c: len(c.get_failed_logins()) >= t["failed_logins_critical"],
                message=(
                    f"Failed login count has exceeded the critical threshold ({t['failed_logins_critical']}). "
                    "This may indicate a brute-force or credential-stuffing attack."
                ),
                remediation=[
                    "Investigate source IPs in the failed-login report for attack patterns.",
                    "Block offending IPs at the perimeter firewall and WAF.",
                    "Enable account lockout policies and CAPTCHA on login endpoints.",
                    "Enable geo-restriction and anomaly-based authentication policies.",
                ],
                mitre_technique_id="T1110",
            ),

            AlertRule(
                name="Critical: Unapproved Emergency Privilege Change",
                severity="Critical",
                condition=lambda c: any(
                    e.get("is_emergency_change") and e.get("approval_status") == "emergency"
                    for e in c.get_privilege_changes()
                ),
                message=(
                    "An emergency privilege escalation was performed without a linked approved "
                    "change ticket. This is a critical governance violation."
                ),
                remediation=[
                    "Immediately review and revoke the unapproved privilege change.",
                    "Investigate who made the change and why no ticket was raised.",
                    "Enforce mandatory change-management approval workflows.",
                    "Alert the CISO and security team for immediate review.",
                ],
                mitre_technique_id="T1098",
            ),

            # ================================================================
            # HIGH (7)
            # ================================================================

            AlertRule(
                name="High: Password Spray Attack",
                severity="High",
                condition=lambda c: any(
                    e.get("attack_pattern") == "password_spray" for e in c.get_failed_logins()
                ),
                message=(
                    "Password spray activity detected: multiple accounts are being targeted "
                    "with a small number of common passwords from one or more IPs."
                ),
                remediation=[
                    "Block source IPs involved in the spray at the firewall.",
                    "Force password reset for all targeted accounts.",
                    "Enable Smart Lockout or equivalent to slow spray attempts.",
                    "Deploy anomalous login detection and alert on spray patterns.",
                ],
                mitre_technique_id="T1110.003",
            ),

            AlertRule(
                name="High: Credential Stuffing Detected",
                severity="High",
                condition=lambda c: any(
                    e.get("attack_pattern") == "credential_stuffing" for e in c.get_failed_logins()
                ),
                message=(
                    "Credential stuffing detected: large volumes of external bad-password attempts "
                    "suggest use of leaked credential lists."
                ),
                remediation=[
                    "Enable Have I Been Pwned or similar breach detection integration.",
                    "Force password resets for affected accounts.",
                    "Block or rate-limit offending IP ranges at the perimeter.",
                    "Enforce MFA to prevent success even with valid credentials.",
                ],
                mitre_technique_id="T1110.004",
            ),

            AlertRule(
                name="High: Shadow Admin Accounts Identified",
                severity="High",
                condition=lambda c: len(c.get_shadow_admins()) >= t["shadow_admins_warning"],
                message=(
                    f"Shadow admin accounts detected ({t['shadow_admins_warning']}+): accounts with "
                    "indirect administrative control over Active Directory without explicit membership."
                ),
                remediation=[
                    "Run BloodHound or equivalent to map all indirect admin paths.",
                    "Remove unnecessary permissions that enable shadow admin control.",
                    "Review and remediate WriteDACL, GenericAll, and GenericWrite on privileged objects.",
                    "Implement a tiered administration model to contain privilege paths.",
                ],
                mitre_technique_id="T1098.003",
            ),

            AlertRule(
                name="High: Dormant Privileged Account Activity",
                severity="High",
                condition=lambda c: any(
                    u.get("is_dormant") and u.get("last_used") is not None
                    for u in c.get_privileged_account_inventory()
                ),
                message=(
                    "A previously dormant privileged account has shown recent activity. "
                    "This may indicate credential theft and unauthorized use."
                ),
                remediation=[
                    "Immediately verify with the account owner whether the activity is legitimate.",
                    "Disable the account pending investigation if activity is unverified.",
                    "Rotate credentials and revoke all active tokens.",
                    "Review dormant privileged accounts quarterly and disable after 90 days.",
                ],
                mitre_technique_id="T1078.002",
            ),

            AlertRule(
                name="High: After-Hours Privileged Access",
                severity="High",
                condition=lambda c: any(
                    e.get("is_privileged_account") for e in c.get_after_hours_logins()
                ),
                message=(
                    "A privileged account has logged in outside business hours. "
                    "After-hours privileged access is a high-risk indicator."
                ),
                remediation=[
                    "Verify the after-hours access with the account owner immediately.",
                    "Implement time-based access restrictions for privileged accounts.",
                    "Require JIT (Just-In-Time) elevation for all after-hours privileged work.",
                    "Enable automated alerts for all privileged out-of-hours logins.",
                ],
                mitre_technique_id="T1078",
            ),

            AlertRule(
                name="High: Multiple Lockouts from Same IP",
                severity="High",
                condition=lambda c: (
                    lambda lockouts: any(
                        sum(1 for l in lockouts if l.get("source_ip") == ip) >= 3
                        for ip in {e.get("source_ip") for e in lockouts}
                    )
                )(c.get_user_lockouts()),
                message=(
                    "Multiple account lockouts originating from the same IP address — "
                    "indicative of automated brute-force or spray attempts."
                ),
                remediation=[
                    "Block the source IP at the firewall immediately.",
                    "Review all accounts locked from this IP and verify their integrity.",
                    "Enable IP reputation services in your authentication pipeline.",
                    "Increase lockout threshold sensitivity and alerting.",
                ],
                mitre_technique_id="T1110.001",
            ),

            AlertRule(
                name="High: Orphaned Admin Accounts",
                severity="High",
                condition=lambda c: any(
                    e.get("has_admin_rights") for e in c.get_orphaned_accounts()
                ),
                message=(
                    "Orphaned accounts with admin rights detected. These accounts have no "
                    "active manager association and present an uncontrolled privilege risk."
                ),
                remediation=[
                    "Disable all orphaned admin accounts immediately pending review.",
                    "Revoke admin rights from all accounts where the manager has left.",
                    "Implement automated deprovisioning when manager relationships are terminated.",
                    "Run a monthly orphaned account report and require IT review.",
                ],
                mitre_technique_id="T1098",
            ),

            # ================================================================
            # MEDIUM (7)
            # ================================================================

            AlertRule(
                name="Medium: High Number of Inactive Users",
                severity="Medium",
                condition=lambda c: len(c.get_inactive_users()) >= t["inactive_users_warning"],
                message=(
                    f"Inactive user count ({t['inactive_users_warning']}+) exceeds warning threshold. "
                    "Inactive accounts expand the attack surface unnecessarily."
                ),
                remediation=[
                    "Review the inactive-users report and categorise by risk level.",
                    "Disable accounts inactive for more than 90 days.",
                    "Initiate leavers workflow for accounts with no return date.",
                    "Schedule a quarterly access review for all user accounts.",
                ],
                mitre_technique_id="T1078.004",
            ),

            AlertRule(
                name="Medium: Frequent Privilege Changes",
                severity="Medium",
                condition=lambda c: len(c.get_privilege_changes()) >= t["privilege_changes_warning"],
                message=(
                    f"Privilege changes have exceeded the warning threshold ({t['privilege_changes_warning']}). "
                    "Excessive changes may indicate misconfiguration or privilege creep."
                ),
                remediation=[
                    "Review all recent privilege changes and verify authorisation.",
                    "Confirm each change was raised through the change-management process.",
                    "Revoke any unapproved privilege elevations immediately.",
                    "Implement a least-privilege access model and access review cycle.",
                ],
                mitre_technique_id="T1098",
            ),

            AlertRule(
                name="Medium: JML Process Overdue",
                severity="Medium",
                condition=lambda c: any(
                    e.get("status") == "overdue" for e in c.get_joiners_movers_leavers()
                ),
                message=(
                    "One or more Joiner/Mover/Leaver access change requests are overdue. "
                    "Delayed deprovisioning leaves ex-employees with active access."
                ),
                remediation=[
                    "Immediately process all overdue leaver deprovisioning requests.",
                    "Alert the IT provisioning team and line managers for completion.",
                    "Set automated SLA reminders at 3, 7, and 14 days.",
                    "Report overdue JML items to the CISO weekly.",
                ],
                mitre_technique_id="T1136",
            ),

            AlertRule(
                name="Medium: MFA Bypass Attempts Detected",
                severity="Medium",
                condition=lambda c: any(
                    u.get("bypass_count_30days", 0) > 0 for u in c.get_mfa_status()
                ),
                message=(
                    "MFA bypass attempts have been detected for one or more accounts. "
                    "This may indicate MFA fatigue attacks or misconfigured bypass policies."
                ),
                remediation=[
                    "Identify accounts with bypass activity and investigate each case.",
                    "Remove any standing MFA bypass exemptions that are no longer justified.",
                    "Enable MFA number matching to prevent push-notification fatigue attacks.",
                    "Alert users about phishing-resistant MFA options (FIDO2, passkeys).",
                ],
                mitre_technique_id="T1556.006",
            ),

            AlertRule(
                name="Medium: Contractor Over-Privileged Accounts",
                severity="Medium",
                condition=lambda c: any(
                    u.get("employee_type") == "contractor" and u.get("has_admin_rights")
                    for u in c.get_inactive_users()
                ),
                message=(
                    "Contractor accounts with administrative rights have been identified. "
                    "Contractors should operate under least-privilege principles."
                ),
                remediation=[
                    "Review all contractor accounts with admin rights.",
                    "Remove admin privileges and apply least-privilege access.",
                    "Ensure all contractor access has defined end dates.",
                    "Review contractor access quarterly and deactivate on contract end.",
                ],
                mitre_technique_id="T1078",
            ),

            AlertRule(
                name="Medium: Service Account Password Age",
                severity="Medium",
                condition=lambda c: any(
                    u.get("password_age_days", 0) > t["password_age_critical_days"]
                    for u in c.get_privileged_account_inventory()
                ),
                message=(
                    f"Service or privileged account passwords older than "
                    f"{t['password_age_critical_days']} days detected."
                ),
                remediation=[
                    "Immediately rotate passwords for all over-age service accounts.",
                    "Migrate service accounts to Group Managed Service Accounts (gMSA).",
                    "Set a maximum password age of 90 days for all privileged accounts.",
                    "Implement automated password rotation via a PAM solution.",
                ],
                mitre_technique_id="T1078.003",
            ),

            AlertRule(
                name="Medium: Service Account Abuse Detected",
                severity="Medium",
                condition=lambda c: len(c.get_service_account_abuse()) >= t["service_account_abuse_high"],
                message=(
                    "Service account abuse has been detected. Service accounts are being "
                    "used in ways that deviate from their intended purpose."
                ),
                remediation=[
                    "Review all service account abuse events and classify each incident.",
                    "Restrict service accounts to specific hosts using the 'Log On To' attribute.",
                    "Implement service account activity monitoring and alerting.",
                    "Audit all service accounts for kerberoastable SPNs.",
                ],
                mitre_technique_id="T1078.003",
            ),

            # ================================================================
            # LOW (5)
            # ================================================================

            AlertRule(
                name="Low: Weak Password Policy",
                severity="Low",
                condition=lambda c: (
                    c.get_password_policy().get("min_length", 99) < 12
                    or c.get_password_policy().get("history_count", 99) < 10
                ),
                message=(
                    "The password policy does not meet recommended standards: "
                    "minimum length < 12 or history count < 10."
                ),
                remediation=[
                    "Increase minimum password length to at least 12 characters.",
                    "Set password history to at least 10 previous passwords.",
                    "Consider enabling passphrase support per NIST SP 800-63B.",
                    "Review and align the policy with current NIST / CIS benchmarks.",
                ],
                mitre_technique_id="T1201",
            ),

            AlertRule(
                name="Low: User Inactive 30–60 Days",
                severity="Low",
                condition=lambda c: any(
                    30 <= u.get("days_inactive", 0) <= 60 for u in c.get_inactive_users()
                ),
                message="Users with 30–60 days of inactivity detected. Proactive review is recommended.",
                remediation=[
                    "Notify managers of users approaching the 60-day inactivity threshold.",
                    "Confirm whether users are on authorised leave or have left the organisation.",
                    "Prepare disable workflows to trigger at 90 days inactivity.",
                    "Implement automated inactivity notifications to line managers.",
                ],
                mitre_technique_id="T1078.004",
            ),

            AlertRule(
                name="Low: Single-Factor Admin Console Access",
                severity="Low",
                condition=lambda c: any(
                    u.get("is_admin") and not u.get("mfa_enabled") for u in c.get_mfa_status()
                ),
                message=(
                    "Admin console access is possible using single-factor authentication. "
                    "All admin console access should require MFA."
                ),
                remediation=[
                    "Enforce MFA for all admin console and privileged management plane access.",
                    "Deploy Privileged Access Workstations (PAWs) for admin tasks.",
                    "Implement conditional access requiring compliant devices for admin access.",
                    "Remove all admin standing access and require JIT elevation.",
                ],
                mitre_technique_id="T1556",
            ),

            AlertRule(
                name="Low: Shared Account Usage Detected",
                severity="Low",
                condition=lambda c: any(
                    "svc." in u.get("username", "") and u.get("abused_by_user") != u.get("service_account")
                    for u in c.get_service_account_abuse()
                ),
                message=(
                    "Shared or generic accounts are being used interactively. "
                    "All access must be individually attributable for audit purposes."
                ),
                remediation=[
                    "Identify all shared accounts and assign individual ownership.",
                    "Disable shared accounts and provide individual accounts to each user.",
                    "Implement a PAM solution to control shared account access with full attribution.",
                    "Ensure all accounts map to a single named individual in your access reviews.",
                ],
                mitre_technique_id="T1078",
            ),

            AlertRule(
                name="Low: Privileged Accounts with Password Never Expires",
                severity="Low",
                condition=lambda c: any(
                    u.get("password_age_days", 0) > 365 for u in c.get_privileged_account_inventory()
                ),
                message=(
                    "Privileged accounts with passwords older than 365 days detected. "
                    "This violates least-privilege and rotation best practices."
                ),
                remediation=[
                    "Immediately rotate passwords for all flagged privileged accounts.",
                    "Unset the 'Password Never Expires' attribute on all privileged accounts.",
                    "Enforce a 90-day maximum password age via Fine-Grained Password Policy.",
                    "Adopt a PAM solution with automated rotation for all privileged accounts.",
                ],
                mitre_technique_id="T1201",
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
                            mitre_technique_id=rule.mitre_technique_id,
                            affected_users=rule.affected_users,
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                triggered.append(
                    TriggeredAlert(
                        name=f"Error evaluating: {rule.name}",
                        severity="Low",
                        message=str(exc),
                        remediation=["Investigate rule configuration."],
                    )
                )

        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        triggered.sort(key=lambda a: order.get(a.severity, 99))
        return triggered
