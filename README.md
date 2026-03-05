# AD360 Identity Security Analytics — Enterprise iSOC

An enterprise-grade **Identity Security Operations Center (iSOC)** built on top of ManageEngine AD360.  
Provides real-time identity threat detection, compliance reporting, and AI-assisted investigation via MCP.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AD360 iSOC Platform                       │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│  Streamlit   │  Flask REST  │  MCP Server  │  Report Generator  │
│  Dashboard   │  API Server  │  (stdio)     │  (PDF via fpdf2)   │
│ dashboard.py │api_server.py │mcp_server.py │report_generator.py │
├──────────────┴──────────────┴──────────────┴────────────────────┤
│                      Analytics Engine (analytics.py)             │
│   ITDR Score · Attack Patterns · MITRE Coverage · Zero Trust     │
├─────────────────────────────────────────────────────────────────┤
│                    Alerts Engine (alerts.py)                     │
│              25+ rules · MITRE ATT&CK · Auto-remediation         │
├─────────────────────────────────────────────────────────────────┤
│                   AD360 Client (ad360_client.py)                 │
│          Mock Data ←→ Live AD360 REST API (config-driven)        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your AD360 URL, token, and organisation settings
```

### 3. Run the Dashboard

```bash
streamlit run dashboard.py
```

### 4. Run the REST API Server

```bash
python api_server.py
# API available at http://localhost:5000/api/v1/
```

### 5. Run the MCP Server (for AI assistants)

```bash
python mcp_server.py
```

---

## Dashboard Tabs

| Tab | Audience | Key Features |
|-----|----------|-------------|
| �� Executive Summary | CISO | Health score gauge, KPIs, top risks, compliance radar, 90-day trends |
| 🚨 Threat Detection | SOC Analyst | Active alerts (MITRE-mapped), attack patterns, impossible travel, after-hours heatmap, attack timeline |
| 👤 Identity Governance | IT Admin | JML table, orphaned accounts, privileged inventory, shadow admins |
| 📋 Compliance & Audit | GRC Team | 7-framework scorecard, radar chart, per-check drill-downs, PDF export |
| 🔍 User Risk Profiles | Security Analyst | Search, top-10 high-risk users, risk histogram, department heatmap |

---

## Connecting to Real AD360

1. Set `USE_MOCK_DATA=false` in your `.env` file
2. Set `AD360_BASE_URL` to your instance URL (e.g., `https://ad360.corp.local:8082`)
3. Generate an API token in AD360: **Admin → API Configuration → Generate Token**
4. Set `AD360_AUTH_TOKEN` to the generated token

The client (`ad360_client.py`) will automatically switch from mock data to live REST API calls.

---

## MCP Server Setup (AI Assistant Integration)

The MCP server exposes 15 identity-security tools to any MCP-compatible AI assistant (Claude, GitHub Copilot, etc.).

### Tools Available

| Tool | Description |
|------|-------------|
| `get_identity_security_score` | ITDR score with 10-category breakdown |
| `get_active_alerts` | All triggered alerts with MITRE IDs |
| `get_high_risk_users` | Top 10 risk-scored users |
| `get_impossible_travel_alerts` | Geographic anomaly detections |
| `get_compliance_summary` | 7-framework compliance scores |
| `get_domain_overview` | AD domain statistics |
| `get_failed_logins` | Failed login events |
| `get_lateral_movement` | Lateral movement detections |
| `get_shadow_admins` | Indirect admin path analysis |
| `get_orphaned_accounts` | Accounts without active managers |
| `get_privileged_inventory` | Privileged account inventory |
| `get_jml_status` | Joiner/Mover/Leaver status |
| `get_mitre_coverage` | MITRE ATT&CK technique mapping |
| `get_zero_trust_score` | Zero Trust pillar scores |
| `get_executive_summary` | CISO KPI dashboard |

### Claude Desktop Configuration

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ad360-isoc": {
      "command": "python",
      "args": ["/path/to/mcp_server.py"],
      "env": {
        "USE_MOCK_DATA": "true"
      }
    }
  }
}
```

---

## Compliance Frameworks

| Framework | Focus Area | Checks |
|-----------|-----------|--------|
| GDPR | Data Privacy (EU) | 12 checks |
| HIPAA | Healthcare Data (US) | 10 checks |
| SOX | Financial Controls | 8 checks |
| PCI DSS | Payment Card Security | 10 checks |
| ISO 27001 | Information Security Management | 15 checks |
| NIST 800-53 | Federal Security Controls | 12 checks |
| CIS AD | Active Directory Hardening | 20 checks |

---

## MITRE ATT&CK Coverage

The platform maps threats to the following MITRE ATT&CK techniques:

| Technique | ID | Tactic |
|-----------|-----|--------|
| Brute Force | T1110 | Credential Access |
| Password Spraying | T1110.003 | Credential Access |
| Credential Stuffing | T1110.004 | Credential Access |
| Valid Accounts | T1078 | Initial Access |
| Lateral Movement (RDP) | T1021.001 | Lateral Movement |
| Pass-the-Hash | T1550.002 | Lateral Movement |
| Account Manipulation | T1098 | Persistence |
| Modify Authentication Process | T1556 | Credential Access |
| GPO Modification | T1484.001 | Defense Evasion |
| Password Policy Discovery | T1201 | Discovery |

---

## Project Structure

```
ad360-identity-security-analytics/
├── dashboard.py          # Streamlit iSOC dashboard (5 tabs)
├── mcp_server.py         # MCP server (15 tools, stdio transport)
├── api_server.py         # Flask REST API (28 endpoints)
├── ad360_client.py       # AD360 REST API client
├── analytics.py          # ITDR analytics engine
├── alerts.py             # 25+ alert rules engine
├── mock_data.py          # Enterprise mock data (1200 users)
├── report_generator.py   # PDF report generation (fpdf2)
├── config.py             # Centralized configuration
├── requirements.txt      # Python dependencies
├── .env.example          # Environment variable template
└── README.md             # This file
```

---

## Risk Categories & Weights

| Category | Weight | Description |
|----------|--------|-------------|
| Failed Logins | 15% | Authentication failure events |
| MFA Violations | 15% | Admin accounts without MFA |
| Impossible Travel | 15% | Geographic authentication anomalies |
| Service Account Abuse | 10% | Service account misuse |
| Lockouts | 10% | Account lockout events |
| Inactive Users | 10% | Dormant account risk |
| Privilege Changes | 10% | Unauthorized privilege escalation |
| Lateral Movement | 5% | Internal network traversal |
| After-Hours Logins | 5% | Out-of-hours access anomalies |
| Shadow Admins | 5% | Indirect administrative control |

---

## License

MIT License — see LICENSE file for details.
