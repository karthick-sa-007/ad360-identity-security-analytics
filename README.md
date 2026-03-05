# 🔐 AD360 Identity Security Analytics

A production-quality **Python** program that provides real-time identity security monitoring, risk analysis, and compliance tracking on top of **ManageEngine AD360** — with full mock-data support so it runs out-of-the-box without a live AD360 instance.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   dashboard.py (Streamlit UI)           │
│   KPIs · Score Gauge · Alerts · Risk Users · Charts     │
└───────────────────────┬─────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
  analytics.py      alerts.py      mcp_server.py
  (scoring/trends)  (rule engine)  (Flask REST API :8090)
        │               │
        └───────┬───────┘
                ▼
          ad360_client.py
          (REST client / mock dispatcher)
                │
        ┌───────┴────────┐
        ▼                ▼
   mock_data.py     AD360 REST API
   (simulated data) (real instance)
                │
            config.py  ←  .env
```

---

## Features

- 🎯 **Security Score** — weighted 0-100 score with letter grade (A-F)
- ⚠️ **High-Risk User Detection** — correlates failed logins, lockouts, and privilege changes
- 🚨 **Alert Engine** — 7 rules across Critical / High / Medium / Low severities with actionable remediation steps
- 📋 **Compliance Tracking** — GDPR, HIPAA, and PCI-DSS readiness percentages
- 📈 **30-Day Trends** — time-series charts for failed logins and lockouts
- 🏢 **Domain Overview** — user distribution pie chart and admin vs regular bar chart
- 🔌 **MCP REST API** — 8 JSON endpoints for integration with other tools (port 8090)
- 🧪 **Mock Data Mode** — works out-of-the-box without a real AD360 instance

---

## Prerequisites

- Python 3.9 or later
- pip

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/karthick-sa-007/ad360-identity-security-analytics.git
cd ad360-identity-security-analytics

# 2. (Optional) Create and activate a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the Dashboard

```bash
streamlit run dashboard.py
```

Open your browser at **http://localhost:8501**.

---

## Running the MCP Server

```bash
python mcp_server.py
```

The Flask server starts on **http://localhost:8090**.

---

## Connecting to a Real AD360 Instance

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and set your real values:
   ```
   AD360_BASE_URL=https://your-ad360-instance:8082
   AD360_AUTH_TOKEN=your_token_here
   USE_MOCK_DATA=false
   ALERT_EMAIL=admin@yourcompany.com
   ```
3. Start the dashboard or MCP server as normal.

---

## MCP Server API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET    | `/tools` | List all available tools |
| POST   | `/tools/get_identity_security_score` | Security score + grade |
| POST   | `/tools/get_high_risk_users` | Top 10 risky users |
| POST   | `/tools/get_active_alerts` | All triggered alerts |
| POST   | `/tools/get_compliance_summary` | GDPR / HIPAA / PCI-DSS scores |
| POST   | `/tools/get_domain_overview` | Domain user statistics |
| POST   | `/tools/get_failed_logins` | Failed login events |
| POST   | `/tools/get_privilege_changes` | Privilege change events |
| POST   | `/tools/get_inactive_users` | Inactive user accounts |

### Example

```bash
# List tools
curl http://localhost:8090/tools

# Get security score
curl -X POST http://localhost:8090/tools/get_identity_security_score

# Get active alerts
curl -X POST http://localhost:8090/tools/get_active_alerts
```

---

## Project Structure

```
ad360-identity-security-analytics/
├── README.md             ← This file
├── requirements.txt      ← Python dependencies
├── .env.example          ← Environment variable template
├── config.py             ← Centralised configuration
├── mock_data.py          ← Simulated AD360 data generators
├── ad360_client.py       ← AD360 REST API client
├── analytics.py          ← Scoring, risk, compliance, trend engines
├── alerts.py             ← Alert rules and evaluation engine
├── mcp_server.py         ← Flask MCP-compatible REST API server
└── dashboard.py          ← Streamlit interactive dashboard
```

---

## Screenshots

> _Coming soon — run `streamlit run dashboard.py` to see the live dashboard._

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.
