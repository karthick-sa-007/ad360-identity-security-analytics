"""
mcp_server.py — MCP-compatible HTTP server exposing AD360 analytics as REST endpoints.

Run with:
    python mcp_server.py

The server listens on port 8090 by default.
"""

import logging
from dataclasses import asdict
from typing import Any

from flask import Flask, jsonify, request

from ad360_client import AD360Client
from analytics import (
    calculate_security_score,
    get_compliance_summary,
    get_high_risk_users,
    get_identity_summary,
)
from alerts import AlertsEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Shared client instance (uses mock data by default)
_client = AD360Client()
_alerts_engine = AlertsEngine()

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _ok(data: Any) -> Any:
    """Wrap a payload in a standard success envelope."""
    return jsonify({"status": "ok", "data": data})


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "get_identity_security_score",
        "method": "POST",
        "path": "/tools/get_identity_security_score",
        "description": "Returns the overall identity security score, grade, and per-category breakdown.",
    },
    {
        "name": "get_high_risk_users",
        "method": "POST",
        "path": "/tools/get_high_risk_users",
        "description": "Returns the top 10 highest-risk users with risk scores and contributing factors.",
    },
    {
        "name": "get_active_alerts",
        "method": "POST",
        "path": "/tools/get_active_alerts",
        "description": "Returns all currently triggered security alerts with remediation guidance.",
    },
    {
        "name": "get_compliance_summary",
        "method": "POST",
        "path": "/tools/get_compliance_summary",
        "description": "Returns GDPR, HIPAA, and PCI-DSS compliance readiness percentages.",
    },
    {
        "name": "get_domain_overview",
        "method": "POST",
        "path": "/tools/get_domain_overview",
        "description": "Returns domain statistics (total users, active, disabled, locked, admin counts).",
    },
    {
        "name": "get_failed_logins",
        "method": "POST",
        "path": "/tools/get_failed_logins",
        "description": "Returns the list of recent failed-login events.",
    },
    {
        "name": "get_privilege_changes",
        "method": "POST",
        "path": "/tools/get_privilege_changes",
        "description": "Returns recent privilege-change events.",
    },
    {
        "name": "get_inactive_users",
        "method": "POST",
        "path": "/tools/get_inactive_users",
        "description": "Returns the list of inactive user accounts.",
    },
]


@app.get("/tools")
def list_tools():
    """List all available MCP tools."""
    return _ok(TOOLS)


# ---------------------------------------------------------------------------
# Tool endpoints
# ---------------------------------------------------------------------------

@app.post("/tools/get_identity_security_score")
def tool_identity_security_score():
    """Return security score + grade."""
    try:
        result = calculate_security_score(_client)
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_identity_security_score")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_high_risk_users")
def tool_high_risk_users():
    """Return top risky users."""
    try:
        result = get_high_risk_users(_client)
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_high_risk_users")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_active_alerts")
def tool_active_alerts():
    """Return all triggered alerts."""
    try:
        alerts = _alerts_engine.evaluate_all(_client)
        return _ok([asdict(a) for a in alerts])
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_active_alerts")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_compliance_summary")
def tool_compliance_summary():
    """Return compliance readiness percentages."""
    try:
        result = get_compliance_summary(_client)
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_compliance_summary")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_domain_overview")
def tool_domain_overview():
    """Return domain statistics."""
    try:
        result = _client.get_domain_overview()
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_domain_overview")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_failed_logins")
def tool_failed_logins():
    """Return failed-login events."""
    try:
        result = _client.get_failed_logins()
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_failed_logins")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_privilege_changes")
def tool_privilege_changes():
    """Return privilege-change events."""
    try:
        result = _client.get_privilege_changes()
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_privilege_changes")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.post("/tools/get_inactive_users")
def tool_inactive_users():
    """Return inactive users list."""
    try:
        result = _client.get_inactive_users()
        return _ok(result)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error in get_inactive_users")
        return jsonify({"status": "error", "message": str(exc)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting AD360 MCP server on port 8090 …")
    app.run(host="0.0.0.0", port=8090, debug=False)
