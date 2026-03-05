"""
mock_data.py — Enterprise-grade mock AD360 data for all identity security categories.

All data mirrors the real AD360 REST API response structure so the rest of the
application treats mock and live data identically.
"""

from datetime import datetime, timedelta
import random

random.seed(42)

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _ts(days_ago: float = 0, hours_ago: float = 0) -> str:
    dt = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _date(days_ago: float = 0) -> str:
    d = (datetime.utcnow() - timedelta(days=days_ago)).date()
    return d.isoformat()


def _random_ip() -> str:
    return f"192.168.{random.randint(1, 20)}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ---------------------------------------------------------------------------
# User pool (1200 users)
# ---------------------------------------------------------------------------

_FIRST_NAMES = [
    "Aaron","Adam","Alice","Amanda","Amy","Andrew","Angela","Anna","Anthony","Ashley",
    "Barbara","Benjamin","Betty","Bob","Brandon","Brian","Carol","Charles","Charlotte","Chelsea",
    "Chris","Christina","Christopher","Claire","Daniel","David","Deborah","Diana","Donald","Dorothy",
    "Douglas","Dylan","Edward","Elizabeth","Emily","Eric","Ethan","Eve","Fiona","Frank",
    "Gary","George","Grace","Gregory","Hannah","Henry","Ian","Ivan","Jack","Jacob",
    "James","Jane","Jason","Jennifer","Jessica","John","Jonathan","Joseph","Julia","Justin",
    "Karen","Katherine","Kelly","Kevin","Laura","Lauren","Leonard","Linda","Lisa","Luke",
    "Maria","Mark","Mary","Matthew","Michael","Michelle","Mike","Morgan","Nancy","Nathan",
    "Nicholas","Nicole","Nina","Noah","Oliver","Oscar","Patricia","Paul","Paula","Peter",
    "Philip","Quinn","Rachel","Rebecca","Richard","Robert","Ryan","Sandra","Sarah","Scott",
    "Sean","Sophia","Stephanie","Steve","Steven","Susan","Thomas","Timothy","Tyler","Victoria",
    "Walter","William","Zachary","Zoe",
]

_LAST_NAMES = [
    "Adams","Allen","Anderson","Bailey","Baker","Bennett","Brooks","Brown","Campbell","Carter",
    "Chen","Clark","Collins","Cook","Cooper","Davis","Edwards","Evans","Fisher","Foster",
    "Garcia","Green","Hall","Harris","Hill","Howard","Hughes","Jackson","James","Johnson",
    "Jones","Kelly","King","Lee","Lewis","Lopez","Martin","Martinez","Miller","Mitchell",
    "Moore","Morgan","Morris","Nelson","Parker","Patel","Perez","Phillips","Price","Reed",
    "Richardson","Roberts","Robinson","Rodriguez","Ross","Russell","Scott","Shaw","Singh","Smith",
    "Stewart","Sullivan","Taylor","Thomas","Thompson","Turner","Walker","Ward","White","Williams",
    "Wilson","Wright","Young","Zhang",
]

_DEPARTMENTS = [
    "Engineering","Finance","HR","IT Operations","Legal","Marketing","Operations",
    "Sales","Security","Executive","DevOps","Cloud","Compliance","Audit","Support",
]

_EMPLOYEE_TYPES = ["full_time", "contractor", "vendor", "intern", "service_account"]
_DOMAINS = ["CORP", "INTERNAL", "EXTRANET", "DMZCORP"]
_DEVICE_TYPES = ["Windows Workstation", "Mac Laptop", "Linux Server", "Mobile (iOS)", "Mobile (Android)", "VDI"]
_LOCATIONS = [
    {"city": "New York", "country": "US"},
    {"city": "London", "country": "UK"},
    {"city": "Frankfurt", "country": "DE"},
    {"city": "Chicago", "country": "US"},
    {"city": "Austin", "country": "US"},
    {"city": "Toronto", "country": "CA"},
    {"city": "Sydney", "country": "AU"},
    {"city": "Singapore", "country": "SG"},
    {"city": "Tokyo", "country": "JP"},
    {"city": "Paris", "country": "FR"},
    {"city": "Mumbai", "country": "IN"},
    {"city": "Dubai", "country": "AE"},
]

random.seed(42)

def _build_user_pool(n: int = 1200) -> list:
    pool = []
    seen: set = set()
    rng = random.Random(42)
    while len(pool) < n:
        fn = rng.choice(_FIRST_NAMES)
        ln = rng.choice(_LAST_NAMES)
        uname = f"{fn.lower()}.{ln.lower()}"
        if uname in seen:
            uname = f"{fn.lower()}.{ln.lower()}{rng.randint(1,99)}"
        seen.add(uname)
        dept = rng.choice(_DEPARTMENTS)
        pool.append({
            "username": uname,
            "display_name": f"{fn} {ln}",
            "domain": rng.choice(_DOMAINS),
            "department": dept,
            "employee_type": rng.choice(_EMPLOYEE_TYPES),
            "manager": f"{rng.choice(_FIRST_NAMES).lower()}.{rng.choice(_LAST_NAMES).lower()}",
            "is_admin": rng.random() < 0.04,
        })
    return pool

_USER_POOL = _build_user_pool(1200)
_USERS = [u["username"] for u in _USER_POOL]
_ADMIN_USERS = [u["username"] for u in _USER_POOL if u["is_admin"]]


# ---------------------------------------------------------------------------
# Failed Logins
# ---------------------------------------------------------------------------

def get_failed_logins() -> list:
    """Return 150+ failed-login events."""
    rng = random.Random(42)
    reasons = [
        "Bad password", "Account locked", "Unknown username",
        "Expired password", "Disabled account", "Smart card required",
        "Outside logon hours", "Workstation restriction",
    ]
    attack_patterns = [
        "brute_force", "password_spray", "credential_stuffing",
        "manual", "manual", "manual",
    ]
    entries = []
    for i in range(155):
        u = rng.choice(_USERS)
        pool_entry = next((p for p in _USER_POOL if p["username"] == u), {})
        loc = rng.choice(_LOCATIONS)
        hour = rng.randint(0, 23)
        entries.append({
            "username": u,
            "domain": pool_entry.get("domain", rng.choice(_DOMAINS)),
            "ip_address": _random_ip() if rng.random() < 0.6 else _random_external_ip(),
            "timestamp": _ts(days_ago=rng.uniform(0, 30)),
            "reason": rng.choice(reasons),
            "location": loc,
            "device_type": rng.choice(_DEVICE_TYPES),
            "is_after_hours": hour < 7 or hour > 19,
            "attack_pattern": rng.choice(attack_patterns),
        })
    return entries


# ---------------------------------------------------------------------------
# User Lockouts
# ---------------------------------------------------------------------------

def get_user_lockouts() -> list:
    """Return 45+ user-lockout records."""
    rng = random.Random(42)
    entries = []
    users_sample = rng.sample(_USERS, 45)
    for u in users_sample:
        pool_entry = next((p for p in _USER_POOL if p["username"] == u), {})
        entries.append({
            "username": u,
            "domain": pool_entry.get("domain", rng.choice(_DOMAINS)),
            "locked_at": _ts(days_ago=rng.uniform(0, 30)),
            "unlock_status": rng.choice(["auto_unlocked", "admin_unlocked", "pending"]),
            "lockout_count_30days": rng.randint(1, 12),
            "is_repeat_offender": rng.random() < 0.3,
            "source_ip": _random_ip() if rng.random() < 0.7 else _random_external_ip(),
        })
    return entries


# ---------------------------------------------------------------------------
# Inactive Users
# ---------------------------------------------------------------------------

def get_inactive_users() -> list:
    """Return 180+ inactive-user records."""
    rng = random.Random(42)
    entries = []
    users_sample = rng.sample(_USER_POOL, 185)
    for u in users_sample:
        days = rng.randint(31, 730)
        risk = "Critical" if days > 365 or u["is_admin"] else ("High" if days > 180 else ("Medium" if days > 90 else "Low"))
        entries.append({
            "username": u["username"],
            "domain": u["domain"],
            "last_login": _ts(days_ago=days),
            "days_inactive": days,
            "has_admin_rights": u["is_admin"],
            "has_active_sessions": rng.random() < 0.05,
            "has_active_tokens": rng.random() < 0.08,
            "department": u["department"],
            "manager": u["manager"],
            "employee_type": u["employee_type"],
            "risk_level": risk,
        })
    return entries


# ---------------------------------------------------------------------------
# Privilege Changes
# ---------------------------------------------------------------------------

def get_privilege_changes() -> list:
    """Return 65+ privilege-change events."""
    rng = random.Random(42)
    roles = ["User", "Local Admin", "Domain Admin", "Server Admin", "Read-Only",
             "Backup Operator", "Account Operator", "Schema Admin", "Enterprise Admin",
             "Help Desk", "Security Analyst", "Finance Manager", "HR Manager"]
    change_types = ["role_added", "role_removed", "group_added", "group_removed", "owner_changed"]
    entries = []
    for i in range(68):
        u = rng.choice(_USERS)
        changed_by = rng.choice(_ADMIN_USERS) if _ADMIN_USERS else "svc.provisioner"
        old_r = rng.choice(roles)
        new_r = rng.choice([r for r in roles if r != old_r])
        is_emergency = rng.random() < 0.1
        entries.append({
            "username": u,
            "domain": rng.choice(_DOMAINS),
            "changed_by": changed_by,
            "change_type": rng.choice(change_types),
            "timestamp": _ts(days_ago=rng.uniform(0, 30)),
            "old_role": old_r,
            "new_role": new_r,
            "approval_status": "emergency" if is_emergency else rng.choice(["approved", "pending", "rejected"]),
            "ticket_id": f"CHG{rng.randint(10000, 99999)}" if not is_emergency else None,
            "is_emergency_change": is_emergency,
        })
    return entries


# ---------------------------------------------------------------------------
# Impossible Travel Alerts
# ---------------------------------------------------------------------------

def get_impossible_travel_alerts() -> list:
    """Return 12+ impossible-travel detections."""
    rng = random.Random(42)
    pairs = [
        ({"city": "New York", "country": "US"}, {"city": "London", "country": "UK"}, 5570),
        ({"city": "Chicago", "country": "US"}, {"city": "Singapore", "country": "SG"}, 15060),
        ({"city": "Austin", "country": "US"}, {"city": "Tokyo", "country": "JP"}, 11200),
        ({"city": "Toronto", "country": "CA"}, {"city": "Dubai", "country": "AE"}, 11200),
        ({"city": "London", "country": "UK"}, {"city": "Sydney", "country": "AU"}, 16993),
        ({"city": "Paris", "country": "FR"}, {"city": "Mumbai", "country": "IN"}, 7200),
        ({"city": "Frankfurt", "country": "DE"}, {"city": "New York", "country": "US"}, 6200),
        ({"city": "Singapore", "country": "SG"}, {"city": "London", "country": "UK"}, 10840),
        ({"city": "New York", "country": "US"}, {"city": "Tokyo", "country": "JP"}, 10840),
        ({"city": "Chicago", "country": "US"}, {"city": "Moscow", "country": "RU"}, 8755),
        ({"city": "Austin", "country": "US"}, {"city": "Beijing", "country": "CN"}, 11660),
        ({"city": "London", "country": "UK"}, {"city": "Cape Town", "country": "ZA"}, 9680),
        ({"city": "New York", "country": "US"}, {"city": "Frankfurt", "country": "DE"}, 6200),
        ({"city": "Toronto", "country": "CA"}, {"city": "Singapore", "country": "SG"}, 15000),
    ]
    entries = []
    users_sample = rng.sample(_USERS, len(pairs))
    for idx, (loc1, loc2, dist) in enumerate(pairs):
        time_diff = rng.randint(15, 180)
        risk = 95 if time_diff < 60 else (80 if time_diff < 120 else 65)
        entries.append({
            "username": users_sample[idx],
            "location_1": loc1,
            "location_2": loc2,
            "distance_km": dist,
            "time_diff_minutes": time_diff,
            "risk_score": risk,
            "is_vpn_detected": rng.random() < 0.25,
            "timestamp": _ts(days_ago=rng.uniform(0, 14)),
        })
    return entries


# ---------------------------------------------------------------------------
# After-Hours Logins
# ---------------------------------------------------------------------------

def get_after_hours_logins() -> list:
    """Return 80+ after-hours login events."""
    rng = random.Random(42)
    resources = [
        "File Server", "VPN Gateway", "Email Server", "HR System",
        "Finance ERP", "Active Directory Admin", "Azure Portal",
        "Domain Controller", "Backup System", "Code Repository",
    ]
    days_of_week = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    entries = []
    for i in range(85):
        u = rng.choice(_USERS)
        pool_entry = next((p for p in _USER_POOL if p["username"] == u), {})
        # After hours: before 7am or after 8pm, or weekends
        hour = rng.choice(list(range(0, 6)) + list(range(20, 24)))
        dow = rng.choice(days_of_week)
        entries.append({
            "username": u,
            "domain": pool_entry.get("domain", rng.choice(_DOMAINS)),
            "timestamp": _ts(days_ago=rng.uniform(0, 30)),
            "hour": hour,
            "day_of_week": dow,
            "ip_address": _random_ip() if rng.random() < 0.7 else _random_external_ip(),
            "location": rng.choice(_LOCATIONS),
            "resource_accessed": rng.choice(resources),
            "is_privileged_account": pool_entry.get("is_admin", False) or rng.random() < 0.15,
        })
    return entries


# ---------------------------------------------------------------------------
# Service Account Abuse
# ---------------------------------------------------------------------------

def get_service_account_abuse() -> list:
    """Return 20+ service-account abuse events."""
    rng = random.Random(42)
    svc_accounts = [
        "svc.backup", "svc.monitoring", "svc.deploy", "svc.reporting",
        "svc.scan", "svc.integration", "svc.replication", "svc.provisioner",
        "svc.scheduler", "svc.vault",
    ]
    abuse_types = [
        "interactive_login", "password_changed_by_human", "used_from_unexpected_host",
        "kerberoasting_target", "pass_the_hash", "delegation_abuse",
        "excessive_privilege_use", "used_outside_maintenance_window",
    ]
    target_systems = [
        "DC01.corp.local", "FILE-SERVER-01", "SQL-PROD-01", "BACKUP-SRV",
        "MGMT-HOST", "EXCHANGE-01", "SHAREPOINT-01", "AZURE-CONNECTOR",
    ]
    entries = []
    for i in range(22):
        svc = rng.choice(svc_accounts)
        abuser = rng.choice(_USERS)
        entries.append({
            "service_account": svc,
            "domain": rng.choice(_DOMAINS),
            "abused_by_user": abuser,
            "timestamp": _ts(days_ago=rng.uniform(0, 30)),
            "abuse_type": rng.choice(abuse_types),
            "source_ip": _random_ip() if rng.random() < 0.6 else _random_external_ip(),
            "target_system": rng.choice(target_systems),
        })
    return entries


# ---------------------------------------------------------------------------
# Lateral Movement
# ---------------------------------------------------------------------------

def get_lateral_movement() -> list:
    """Return 15+ lateral-movement detections."""
    rng = random.Random(42)
    systems = [
        "WS-FINANCE-01", "WS-HR-02", "SRV-DC01", "SRV-FILE01", "SRV-BACKUP",
        "SRV-MGMT", "KIOSK-LOBBY", "DEV-LAPTOP-05", "SRV-SQL01", "DMZ-HOST01",
        "JUMP-BOX-01", "AZURE-MGMT", "SRV-EXCHANGE",
    ]
    techniques = [
        ("Pass-the-Hash", "T1550.002"),
        ("Pass-the-Ticket", "T1550.003"),
        ("Overpass-the-Hash", "T1550.002"),
        ("Remote Desktop Protocol", "T1021.001"),
        ("SMB/Windows Admin Shares", "T1021.002"),
        ("WMI Execution", "T1047"),
        ("Service Execution", "T1569.002"),
        ("PowerShell Remoting", "T1021.006"),
        ("DCOM Lateral Movement", "T1021.003"),
    ]
    entries = []
    for i in range(16):
        u = rng.choice(_USERS)
        src = rng.choice(systems)
        tgt = rng.choice([s for s in systems if s != src])
        tech, mid = rng.choice(techniques)
        entries.append({
            "username": u,
            "source_system": src,
            "target_system": tgt,
            "timestamp": _ts(days_ago=rng.uniform(0, 14)),
            "technique": tech,
            "mitre_technique_id": mid,
            "risk_score": rng.randint(60, 98),
        })
    return entries


# ---------------------------------------------------------------------------
# Shadow Admins
# ---------------------------------------------------------------------------

def get_shadow_admins() -> list:
    """Return 25+ shadow admin detections."""
    rng = random.Random(42)
    admin_paths = [
        "Member of 'Helpdesk' → owns 'Domain Admins' group",
        "WriteDACL on AdminSDHolder container",
        "GenericWrite on Domain Admin account",
        "ForceChangePassword on 5 admin accounts",
        "Member of 'GPO Admins' → GPO linked to Domain Controllers OU",
        "DCSync rights via extended rights on domain",
        "AllExtendedRights on krbtgt account",
        "WriteDACL on AdminSDHolder → can grant self DA rights",
        "Owns 'Account Operators' group",
        "GenericAll on 'Server Operators' group",
    ]
    entries = []
    users_sample = rng.sample(_USERS, 26)
    for idx, u in enumerate(users_sample):
        pool_entry = next((p for p in _USER_POOL if p["username"] == u), {})
        entries.append({
            "username": u,
            "domain": pool_entry.get("domain", rng.choice(_DOMAINS)),
            "department": pool_entry.get("department", rng.choice(_DEPARTMENTS)),
            "indirect_admin_path": rng.choice(admin_paths),
            "permissions_count": rng.randint(2, 15),
            "last_used": _ts(days_ago=rng.uniform(1, 90)),
            "discovery_date": _date(days_ago=rng.uniform(1, 30)),
            "risk_level": rng.choice(["Critical", "Critical", "High", "High", "Medium"]),
        })
    return entries


# ---------------------------------------------------------------------------
# Orphaned Accounts
# ---------------------------------------------------------------------------

def get_orphaned_accounts() -> list:
    """Return 30+ orphaned account records."""
    rng = random.Random(42)
    entries = []
    users_sample = rng.sample(_USER_POOL, 32)
    for u in users_sample:
        days = rng.randint(90, 900)
        entries.append({
            "username": u["username"],
            "domain": u["domain"],
            "created_date": _date(days_ago=rng.uniform(365, 1825)),
            "last_login": _ts(days_ago=days),
            "manager": None,  # manager no longer in directory = orphaned
            "department": u["department"],
            "has_admin_rights": u["is_admin"],
            "has_active_sessions": rng.random() < 0.04,
            "days_since_last_login": days,
        })
    return entries


# ---------------------------------------------------------------------------
# Privileged Account Inventory
# ---------------------------------------------------------------------------

def get_privileged_account_inventory() -> list:
    """Return 40+ privileged account records."""
    rng = random.Random(42)
    priv_types = [
        "Domain Admin", "Enterprise Admin", "Schema Admin",
        "Backup Operator", "Account Operator", "Server Admin",
        "Local Admin (multiple hosts)", "Azure Global Admin",
        "Exchange Admin", "DNS Admin",
    ]
    review_statuses = ["reviewed", "overdue", "pending_review", "exempted"]
    entries = []
    users_sample = rng.sample(_USERS, 42)
    for u in users_sample:
        pwd_age = rng.randint(1, 400)
        entries.append({
            "username": u,
            "privilege_type": rng.choice(priv_types),
            "assigned_date": _date(days_ago=rng.uniform(30, 730)),
            "last_used": _ts(days_ago=rng.uniform(0, 180)),
            "mfa_enabled": rng.random() < 0.78,
            "is_dormant": rng.random() < 0.2,
            "password_age_days": pwd_age,
            "review_status": rng.choice(review_statuses),
        })
    return entries


# ---------------------------------------------------------------------------
# Joiners / Movers / Leavers
# ---------------------------------------------------------------------------

def get_joiners_movers_leavers() -> list:
    """Return 50+ JML process records."""
    rng = random.Random(42)
    event_types = ["joiner", "mover", "leaver"]
    statuses = ["completed", "overdue", "in_progress", "failed"]
    entries = []
    users_sample = rng.sample(_USER_POOL, 52)
    for u in users_sample:
        etype = rng.choice(event_types)
        old_dept = u["department"]
        new_dept = rng.choice(_DEPARTMENTS) if etype == "mover" else (u["department"] if etype == "joiner" else None)
        days_to_complete = rng.randint(0, 30)
        status = "overdue" if days_to_complete > 14 else rng.choice(statuses)
        entries.append({
            "username": u["username"],
            "event_type": etype,
            "event_date": _date(days_ago=rng.uniform(0, 90)),
            "old_department": old_dept if etype in ("mover", "leaver") else None,
            "new_department": new_dept,
            "manager": u["manager"],
            "access_provisioned": etype == "joiner" and rng.random() < 0.85,
            "access_deprovisioned": etype == "leaver" and rng.random() < 0.7,
            "days_to_complete": days_to_complete,
            "status": status,
        })
    return entries


# ---------------------------------------------------------------------------
# Compliance Data (7 frameworks)
# ---------------------------------------------------------------------------

def get_compliance_data() -> dict:
    """Return compliance scores and checks for 7 frameworks."""
    return {
        "GDPR": {
            "score": 72,
            "checks": {
                "data_encryption_at_rest": True,
                "data_encryption_in_transit": True,
                "access_logging": True,
                "consent_management": False,
                "data_minimization": True,
                "breach_notification_process": False,
                "right_to_erasure": True,
                "privacy_impact_assessment": False,
                "data_processor_agreements": True,
                "cross_border_transfer_controls": False,
                "dpo_appointed": True,
                "legitimate_basis_documented": True,
            },
        },
        "HIPAA": {
            "score": 68,
            "checks": {
                "access_controls": True,
                "audit_controls": True,
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "workforce_training": False,
                "incident_response_plan": False,
                "phi_access_reviews": True,
                "business_associate_agreements": True,
                "minimum_necessary_standard": False,
                "contingency_plan": True,
            },
        },
        "SOX": {
            "score": 79,
            "checks": {
                "segregation_of_duties": True,
                "privileged_access_reviews": True,
                "change_management_controls": True,
                "audit_trail_integrity": True,
                "financial_system_access_review": False,
                "user_access_certification": False,
                "itgc_documentation": True,
                "logical_access_controls": True,
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
                "encryption_of_card_data": True,
                "anti_virus_protection": True,
                "firewall_configuration": True,
                "default_credentials_changed": False,
            },
        },
        "ISO_27001": {
            "score": 74,
            "checks": {
                "isms_scope_defined": True,
                "risk_assessment_process": True,
                "risk_treatment_plan": True,
                "security_policy": True,
                "asset_management": False,
                "access_control_policy": True,
                "cryptography_policy": True,
                "physical_security": True,
                "operations_security": True,
                "communications_security": False,
                "supplier_relationships": False,
                "incident_management": True,
                "business_continuity": True,
                "compliance_monitoring": False,
                "internal_audit": True,
            },
        },
        "NIST_800_53": {
            "score": 71,
            "checks": {
                "access_control_policy": True,
                "account_management": True,
                "least_privilege": False,
                "separation_of_duties": True,
                "audit_and_accountability": True,
                "identification_and_authentication": True,
                "incident_response": False,
                "configuration_management": True,
                "system_communications_protection": True,
                "risk_assessment": True,
                "security_assessment": False,
                "system_integrity": True,
            },
        },
        "CIS_AD": {
            "score": 66,
            "checks": {
                "domain_admin_count_minimized": False,
                "local_admin_accounts_reviewed": True,
                "service_accounts_use_gmsa": False,
                "krbtgt_password_rotated": False,
                "ad_recycle_bin_enabled": True,
                "secure_ldap_enabled": True,
                "smb_signing_enforced": True,
                "nlm_authentication_level": True,
                "lm_hash_disabled": True,
                "admin_count_attribute_reviewed": False,
                "privileged_access_workstations": False,
                "tiered_admin_model": False,
                "jit_access_implemented": False,
                "ad_audit_policy_configured": True,
                "gpo_link_hygiene": False,
                "stale_computer_objects_removed": True,
                "dns_security_extensions": False,
                "schema_admin_empty": True,
                "enterprise_admin_empty": False,
                "protected_users_group_used": False,
            },
        },
    }


# ---------------------------------------------------------------------------
# Password Policy
# ---------------------------------------------------------------------------

def get_password_policy() -> dict:
    return {
        "min_length": 8,
        "complexity": True,
        "max_age_days": 90,
        "history_count": 5,
        "lockout_threshold": 5,
        "lockout_duration": 30,
        "fine_grained_policies_count": 3,
    }


# ---------------------------------------------------------------------------
# MFA Status
# ---------------------------------------------------------------------------

def get_mfa_status() -> list:
    """Return extended MFA status for all users."""
    rng = random.Random(42)
    methods = ["Microsoft Authenticator", "Google Authenticator", "FIDO2 Key", "SMS OTP", "Hardware Token", "None"]
    entries = []
    for u in _USER_POOL[:200]:
        is_admin = u["is_admin"]
        mfa_on = rng.random() < (0.95 if is_admin else 0.65)
        method = rng.choice(methods[:5]) if mfa_on else "None"
        entries.append({
            "username": u["username"],
            "mfa_enabled": mfa_on,
            "is_admin": is_admin,
            "department": u["department"],
            "mfa_method": method,
            "enrollment_date": _date(days_ago=rng.uniform(30, 730)) if mfa_on else None,
            "last_mfa_used": _ts(days_ago=rng.uniform(0, 30)) if mfa_on else None,
            "bypass_count_30days": rng.randint(0, 3) if mfa_on else 0,
        })
    return entries


# ---------------------------------------------------------------------------
# Domain Overview
# ---------------------------------------------------------------------------

def get_domain_overview() -> dict:
    return {
        "total_users": 1200,
        "active_users": 987,
        "disabled_users": 162,
        "locked_users": 45,
        "admin_users": 48,
        "groups_count": 342,
        "ous_count": 38,
        "forest_name": "corp.acme.local",
        "domain_count": 3,
        "dc_count": 6,
        "site_count": 4,
        "gpo_count": 87,
        "trust_relationships": 2,
        "privileged_groups_count": 12,
    }


# ---------------------------------------------------------------------------
# Attack Timeline (30-day, 100+ events)
# ---------------------------------------------------------------------------

def get_attack_timeline() -> list:
    """Return a 30-day timeline of 100+ security events, sorted by timestamp."""
    rng = random.Random(42)
    event_types = [
        "failed_login", "account_lockout", "privilege_escalation",
        "impossible_travel", "after_hours_login", "service_account_abuse",
        "lateral_movement", "shadow_admin_detected", "mfa_bypass",
        "password_spray", "credential_stuffing", "new_admin_created",
    ]
    severity_map = {
        "failed_login": "Medium",
        "account_lockout": "High",
        "privilege_escalation": "Critical",
        "impossible_travel": "Critical",
        "after_hours_login": "Medium",
        "service_account_abuse": "High",
        "lateral_movement": "Critical",
        "shadow_admin_detected": "High",
        "mfa_bypass": "Critical",
        "password_spray": "High",
        "credential_stuffing": "High",
        "new_admin_created": "High",
    }
    entries = []
    for i in range(110):
        etype = rng.choice(event_types)
        u = rng.choice(_USERS)
        entries.append({
            "event_type": etype,
            "username": u,
            "timestamp": _ts(days_ago=rng.uniform(0, 30)),
            "severity": severity_map[etype],
            "source_ip": _random_ip() if rng.random() < 0.6 else _random_external_ip(),
            "details": f"{etype.replace('_', ' ').title()} detected for {u}",
        })
    entries.sort(key=lambda e: e["timestamp"], reverse=True)
    return entries


# ---------------------------------------------------------------------------
# Security Trends (90-day)
# ---------------------------------------------------------------------------

def get_security_trends() -> dict:
    """Return 90-day trend data for all event categories."""
    rng = random.Random(42)
    today = datetime.utcnow().date()
    dates, fl, lo, it, ah, sa, lm = [], [], [], [], [], [], []
    for i in range(89, -1, -1):
        day = today - timedelta(days=i)
        dates.append(day.isoformat())
        fl.append(rng.randint(0, 12))
        lo.append(rng.randint(0, 5))
        it.append(rng.randint(0, 2))
        ah.append(rng.randint(0, 8))
        sa.append(rng.randint(0, 3))
        lm.append(rng.randint(0, 2))
    return {
        "dates": dates,
        "failed_logins": fl,
        "lockouts": lo,
        "impossible_travel": it,
        "after_hours_logins": ah,
        "service_account_abuse": sa,
        "lateral_movement": lm,
    }


# ---------------------------------------------------------------------------
# User Risk Profiles (top 50)
# ---------------------------------------------------------------------------

def get_user_risk_profiles() -> list:
    """Return top-50 user risk profiles for UEBA analysis."""
    rng = random.Random(42)
    risk_factors_pool = [
        "Multiple failed logins", "Account locked out",
        "After-hours privileged access", "Impossible travel detected",
        "Service account used interactively", "MFA bypass attempt",
        "Lateral movement detected", "Shadow admin path identified",
        "Dormant account with active tokens", "Privilege escalation",
        "Unreviewed privileged access", "Access outside working location",
    ]
    recommendations_pool = [
        "Enforce MFA immediately",
        "Reset credentials and review access",
        "Disable account pending investigation",
        "Conduct access review",
        "Apply least-privilege model",
        "Enable conditional access policy",
        "Review and revoke shadow admin paths",
        "Rotate service account credentials",
    ]
    entries = []
    users_sample = rng.sample(_USER_POOL, 50)
    for u in users_sample:
        score = rng.randint(20, 98)
        level = "Critical" if score >= 80 else ("High" if score >= 60 else ("Medium" if score >= 40 else "Low"))
        factors = rng.sample(risk_factors_pool, rng.randint(1, 5))
        peer_avg = max(10, score - rng.randint(5, 25))
        entries.append({
            "username": u["username"],
            "department": u["department"],
            "risk_score": score,
            "risk_level": level,
            "risk_factors": factors,
            "baseline_deviation": round(rng.uniform(0.1, 3.5), 2),
            "peer_group_avg_risk": peer_avg,
            "last_activity": _ts(days_ago=rng.uniform(0, 14)),
            "recommendations": rng.sample(recommendations_pool, rng.randint(1, 3)),
        })
    entries.sort(key=lambda e: e["risk_score"], reverse=True)
    return entries


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------

def get_executive_summary() -> dict:
    """Return KPIs for CISO executive dashboard."""
    return {
        "overall_health_score": 63,
        "month_over_month_change": -4,
        "top_3_risks": [
            "Lateral movement activity detected in 3 segments",
            "12 privileged accounts without MFA enforcement",
            "26 shadow admin paths identified across 3 domains",
        ],
        "compliance_average": 73,
        "incidents_this_month": 27,
        "incidents_last_month": 31,
        "mttr_hours": 4.2,
        "open_critical_alerts": 6,
        "resolved_this_week": 14,
    }
