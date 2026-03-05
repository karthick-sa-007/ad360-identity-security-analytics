"""
api_server.py — Flask REST API server for AD360 Identity Security Analytics.

Exposes all AD360 data endpoints as REST API routes (GET requests returning
JSON). Suitable for integration with dashboards, SIEM tools, and other
consumers that cannot use the MCP stdio transport.
"""

from datetime import datetime, timezone
from flask import Flask, jsonify

from ad360_client import AD360Client
from analytics import (
    calculate_itdr_score,
    detect_attack_patterns,
    get_mitre_attack_coverage,
    calculate_zero_trust_score,
    get_high_risk_users,
    get_compliance_summary,
)
from alerts import AlertsEngine

app = Flask(__name__)
_client = AD360Client()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,OPTIONS"
    return response


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": _now()})


# ── Core analytics ────────────────────────────────────────────────────────────

@app.route("/api/v1/score", methods=["GET"])
def identity_security_score():
    try:
        data = calculate_itdr_score(_client)
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/itdr-score", methods=["GET"])
def itdr_score():
    try:
        data = calculate_itdr_score(_client)
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/zero-trust-score", methods=["GET"])
def zero_trust_score():
    try:
        data = calculate_zero_trust_score(_client)
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/attack-patterns", methods=["GET"])
def attack_patterns():
    try:
        data = detect_attack_patterns(_client)
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/mitre-coverage", methods=["GET"])
def mitre_coverage():
    try:
        data = get_mitre_attack_coverage(_client)
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/compliance", methods=["GET"])
def compliance():
    try:
        data = get_compliance_summary(_client)
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/high-risk-users", methods=["GET"])
def high_risk_users():
    try:
        data = get_high_risk_users(_client)
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.route("/api/v1/alerts", methods=["GET"])
def active_alerts():
    try:
        alerts = AlertsEngine().evaluate_all(_client)
        data = [
            {
                "name": a.name,
                "severity": a.severity,
                "message": a.message,
                "mitre_technique_id": a.mitre_technique_id,
                "remediation": a.remediation,
            }
            for a in alerts
        ]
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AD360 client endpoints ────────────────────────────────────────────────────

@app.route("/api/v1/failed-logins", methods=["GET"])
def failed_logins():
    try:
        data = _client.get_failed_logins()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/user-lockouts", methods=["GET"])
def user_lockouts():
    try:
        data = _client.get_user_lockouts()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/inactive-users", methods=["GET"])
def inactive_users():
    try:
        data = _client.get_inactive_users()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/privilege-changes", methods=["GET"])
def privilege_changes():
    try:
        data = _client.get_privilege_changes()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/domain-overview", methods=["GET"])
def domain_overview():
    try:
        data = _client.get_domain_overview()
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/mfa-status", methods=["GET"])
def mfa_status():
    try:
        data = _client.get_mfa_status()
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/impossible-travel", methods=["GET"])
def impossible_travel():
    try:
        data = _client.get_impossible_travel_alerts()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/after-hours-logins", methods=["GET"])
def after_hours_logins():
    try:
        data = _client.get_after_hours_logins()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/service-account-abuse", methods=["GET"])
def service_account_abuse():
    try:
        data = _client.get_service_account_abuse()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/lateral-movement", methods=["GET"])
def lateral_movement():
    try:
        data = _client.get_lateral_movement()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/shadow-admins", methods=["GET"])
def shadow_admins():
    try:
        data = _client.get_shadow_admins()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/orphaned-accounts", methods=["GET"])
def orphaned_accounts():
    try:
        data = _client.get_orphaned_accounts()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/privileged-inventory", methods=["GET"])
def privileged_inventory():
    try:
        data = _client.get_privileged_account_inventory()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/jml", methods=["GET"])
def jml_status():
    try:
        data = _client.get_joiners_movers_leavers()
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/attack-timeline", methods=["GET"])
def attack_timeline():
    try:
        data = _client.get_attack_timeline()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/user-risk-profiles", methods=["GET"])
def user_risk_profiles():
    try:
        data = _client.get_user_risk_profiles()
        return jsonify({"data": data, "count": len(data), "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/executive-summary", methods=["GET"])
def executive_summary():
    try:
        data = _client.get_executive_summary()
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/security-trends", methods=["GET"])
def security_trends():
    try:
        data = _client.get_security_trends()
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/identity-attack-surface", methods=["GET"])
def identity_attack_surface():
    try:
        data = _client.get_identity_attack_surface()
        return jsonify({"data": data, "timestamp": _now()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
