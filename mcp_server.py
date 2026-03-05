"""
mcp_server.py — MCP (Model Context Protocol) server for AD360 iSOC.

Exposes 15 identity-security tools via the official MCP Python SDK using
stdio transport. Connect this server to any MCP-compatible AI assistant.
"""

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("ad360-isoc")
_client = AD360Client()


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


# ── Tool definitions ──────────────────────────────────────────────────────────

TOOLS = [
    Tool(
        name="get_identity_security_score",
        description="Get the overall ITDR (Identity Threat Detection & Response) security score with breakdown by risk category.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_active_alerts",
        description="Get all active security alerts sorted by severity (Critical → Low) with MITRE ATT&CK technique IDs and remediation steps.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_high_risk_users",
        description="Get the top 10 highest-risk users with risk scores, factors, and last activity timestamps.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_impossible_travel_alerts",
        description="Get impossible-travel detections where users authenticated from geographically impossible locations.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_compliance_summary",
        description="Get compliance scores for all 7 frameworks: GDPR, HIPAA, SOX, PCI_DSS, ISO_27001, NIST_800_53, CIS_AD.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_domain_overview",
        description="Get Active Directory domain statistics: user counts, DC count, GPO count, trust relationships, privileged groups.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_failed_logins",
        description="Get recent failed login events with username, IP, location, device type, and attack pattern classification.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_lateral_movement",
        description="Get lateral movement detections with source/target systems, MITRE technique IDs, and risk scores.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_shadow_admins",
        description="Get shadow admin accounts that have indirect administrative control over Active Directory.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_orphaned_accounts",
        description="Get orphaned accounts where the manager has left the organisation but the account remains active.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_privileged_inventory",
        description="Get the privileged account inventory with MFA status, dormancy, password age, and review status.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_jml_status",
        description="Get Joiner/Mover/Leaver process status including overdue items and access provisioning state.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_mitre_coverage",
        description="Get the MITRE ATT&CK technique coverage map showing active threats mapped to ATT&CK techniques.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_zero_trust_score",
        description="Get the Zero Trust readiness score across 5 pillars: Identity, Device, Network, Application, Data.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="get_executive_summary",
        description="Get the CISO executive summary with health score, top risks, compliance average, incident counts, and MTTR.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
]


@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "get_identity_security_score":
            result = calculate_itdr_score(_client)
        elif name == "get_active_alerts":
            alerts = AlertsEngine().evaluate_all(_client)
            result = [
                {
                    "name": a.name,
                    "severity": a.severity,
                    "message": a.message,
                    "mitre_technique_id": a.mitre_technique_id,
                    "remediation": a.remediation,
                }
                for a in alerts
            ]
        elif name == "get_high_risk_users":
            result = get_high_risk_users(_client)
        elif name == "get_impossible_travel_alerts":
            result = _client.get_impossible_travel_alerts()
        elif name == "get_compliance_summary":
            result = get_compliance_summary(_client)
        elif name == "get_domain_overview":
            result = _client.get_domain_overview()
        elif name == "get_failed_logins":
            result = _client.get_failed_logins()
        elif name == "get_lateral_movement":
            result = _client.get_lateral_movement()
        elif name == "get_shadow_admins":
            result = _client.get_shadow_admins()
        elif name == "get_orphaned_accounts":
            result = _client.get_orphaned_accounts()
        elif name == "get_privileged_inventory":
            result = _client.get_privileged_account_inventory()
        elif name == "get_jml_status":
            result = _client.get_joiners_movers_leavers()
        elif name == "get_mitre_coverage":
            result = get_mitre_attack_coverage(_client)
        elif name == "get_zero_trust_score":
            result = calculate_zero_trust_score(_client)
        elif name == "get_executive_summary":
            result = _client.get_executive_summary()
        else:
            result = {"error": f"Unknown tool: {name}"}

        return [TextContent(type="text", text=_json(result))]

    except Exception as exc:
        logger.error("Tool %s failed: %s", name, exc)
        return [TextContent(type="text", text=_json({"error": str(exc)}))]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
