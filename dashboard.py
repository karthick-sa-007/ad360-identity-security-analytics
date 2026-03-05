"""
dashboard.py — Streamlit dashboard for AD360 Identity Security Analytics.

Run with:
    streamlit run dashboard.py
"""

from __future__ import annotations

import datetime
from dataclasses import asdict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from ad360_client import AD360Client
from alerts import AlertsEngine
from analytics import (
    calculate_security_score,
    get_compliance_summary,
    get_high_risk_users,
    get_security_trends,
)

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="🔐 AD360 Identity Security Analytics",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

if "last_updated" not in st.session_state:
    st.session_state["last_updated"] = datetime.datetime.now()

if "client" not in st.session_state:
    st.session_state["client"] = AD360Client()

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🔐 AD360 Analytics")
    st.markdown("---")

    client: AD360Client = st.session_state["client"]

    # Connection status
    mode_label = "🟢 Mock Data" if client.use_mock else "🔵 Live AD360"
    st.markdown(f"**Connection:** {mode_label}")

    st.markdown("---")

    if st.button("🔄 Refresh Data", use_container_width=True):
        # Bust the Streamlit cache and record timestamp
        st.cache_data.clear()
        st.session_state["last_updated"] = datetime.datetime.now()
        st.session_state["client"] = AD360Client()
        client = st.session_state["client"]
        st.success("Data refreshed!")

    last_updated: datetime.datetime = st.session_state["last_updated"]
    st.markdown(f"**Last updated:**  \n{last_updated.strftime('%Y-%m-%d %H:%M:%S')}")

    st.markdown("---")
    st.markdown(
        "📖 [Documentation](https://github.com/karthick-sa-007/ad360-identity-security-analytics)"
    )

# ---------------------------------------------------------------------------
# Load all data (cached per session refresh)
# ---------------------------------------------------------------------------


@st.cache_data(ttl=300)
def load_all_data(_client_key: str) -> dict:
    """Load and return all analytics data.  _client_key forces cache invalidation."""
    _c = AD360Client()
    score_data = calculate_security_score(_c)
    high_risk = get_high_risk_users(_c)
    compliance = get_compliance_summary(_c)
    trends = get_security_trends()
    alerts = AlertsEngine().evaluate_all(_c)
    failed_logins = _c.get_failed_logins()
    lockouts = _c.get_user_lockouts()
    inactive = _c.get_inactive_users()
    priv_changes = _c.get_privilege_changes()
    domain_overview = _c.get_domain_overview()
    return {
        "score_data": score_data,
        "high_risk": high_risk,
        "compliance": compliance,
        "trends": trends,
        "alerts": [asdict(a) for a in alerts],
        "failed_logins": failed_logins,
        "lockouts": lockouts,
        "inactive": inactive,
        "priv_changes": priv_changes,
        "domain_overview": domain_overview,
    }


data = load_all_data(str(st.session_state["last_updated"]))

score_data = data["score_data"]
score: float = score_data["score"]
grade: str = score_data["grade"]
breakdown: dict = score_data["breakdown"]
high_risk: list = data["high_risk"]
compliance: dict = data["compliance"]
trends: dict = data["trends"]
alerts: list = data["alerts"]
failed_logins: list = data["failed_logins"]
lockouts: list = data["lockouts"]
inactive: list = data["inactive"]
priv_changes: list = data["priv_changes"]
domain_overview: dict = data["domain_overview"]

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("# 🔐 AD360 Identity Security Analytics")
st.markdown(
    "Real-time identity security monitoring, risk analysis, and compliance tracking."
)

score_color = "green" if score > 80 else ("orange" if score >= 60 else "red")
st.markdown(
    f"<h2 style='color:{score_color};'>Overall Security Score: {score}/100 &nbsp; Grade: {grade}</h2>",
    unsafe_allow_html=True,
)

st.markdown("---")

# ---------------------------------------------------------------------------
# KPI Row
# ---------------------------------------------------------------------------

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("🚫 Failed Logins", len(failed_logins), delta=f"+{len(failed_logins)}", delta_color="inverse")
kpi2.metric("🔒 Account Lockouts", len(lockouts), delta=f"+{len(lockouts)}", delta_color="inverse")
kpi3.metric("💤 Inactive Users", len(inactive), delta=f"+{len(inactive)}", delta_color="inverse")
kpi4.metric("🔑 Privilege Changes", len(priv_changes), delta=f"+{len(priv_changes)}", delta_color="inverse")

st.markdown("---")

# ---------------------------------------------------------------------------
# Security Score Gauge + Compliance Radar
# ---------------------------------------------------------------------------

gauge_col, compliance_col = st.columns(2)

with gauge_col:
    st.subheader("🎯 Security Score Gauge")
    fig_gauge = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=score,
            title={"text": f"Security Score (Grade {grade})"},
            delta={"reference": 80},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": score_color},
                "steps": [
                    {"range": [0, 60], "color": "#ffcccc"},
                    {"range": [60, 80], "color": "#fff3cc"},
                    {"range": [80, 100], "color": "#ccffcc"},
                ],
                "threshold": {
                    "line": {"color": "red", "width": 4},
                    "thickness": 0.75,
                    "value": 60,
                },
            },
        )
    )
    fig_gauge.update_layout(height=350, margin={"t": 40, "b": 10})
    st.plotly_chart(fig_gauge, use_container_width=True)

with compliance_col:
    st.subheader("📋 Compliance Readiness")
    comp_df = pd.DataFrame(
        {"Framework": list(compliance.keys()), "Score (%)": list(compliance.values())}
    )
    fig_comp = px.bar(
        comp_df,
        x="Framework",
        y="Score (%)",
        color="Score (%)",
        color_continuous_scale=["#ff4444", "#ffaa00", "#44bb44"],
        range_color=[0, 100],
        text="Score (%)",
    )
    fig_comp.update_traces(texttemplate="%{text}%", textposition="outside")
    fig_comp.update_layout(
        height=350,
        yaxis_range=[0, 110],
        coloraxis_showscale=False,
        margin={"t": 40, "b": 10},
    )
    st.plotly_chart(fig_comp, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Alerts Section
# ---------------------------------------------------------------------------

st.subheader("🚨 Active Security Alerts")

SEVERITY_ICONS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}
SEVERITY_COLORS = {
    "Critical": "#ff4444",
    "High": "#ff8800",
    "Medium": "#ffcc00",
    "Low": "#44bb44",
}

if alerts:
    for alert in alerts:
        icon = SEVERITY_ICONS.get(alert["severity"], "⚪")
        color = SEVERITY_COLORS.get(alert["severity"], "#cccccc")
        with st.expander(
            f"{icon} **{alert['severity']}** — {alert['name']}", expanded=False
        ):
            st.markdown(f"**Message:** {alert['message']}")
            st.markdown(
                f"<div style='background-color:{color}22;padding:8px;border-left:4px solid {color};border-radius:4px'>"
                f"<strong>Remediation:</strong><br><pre style='margin:0'>{alert['remediation']}</pre></div>",
                unsafe_allow_html=True,
            )
else:
    st.success("✅ No active alerts. Security posture looks good!")

st.markdown("---")

# ---------------------------------------------------------------------------
# High Risk Users Table
# ---------------------------------------------------------------------------

st.subheader("⚠️ Top High-Risk Users")

if high_risk:
    risk_rows = []
    for u in high_risk:
        risk_rows.append(
            {
                "Username": u["username"],
                "Risk Score": u["risk_score"],
                "Risk Factors": ", ".join(u["risk_factors"]),
                "Last Activity": u.get("last_activity") or "N/A",
            }
        )
    risk_df = pd.DataFrame(risk_rows)

    def _color_risk(val: int):
        if val >= 70:
            return "background-color: #ff4444; color: white"
        if val >= 40:
            return "background-color: #ff8800; color: white"
        return "background-color: #ffcc00"

    styled_df = risk_df.style.map(_color_risk, subset=["Risk Score"])
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
else:
    st.info("No high-risk users detected.")

st.markdown("---")

# ---------------------------------------------------------------------------
# 30-Day Trend Charts
# ---------------------------------------------------------------------------

st.subheader("📈 30-Day Security Trends")

trend_col1, trend_col2 = st.columns(2)

with trend_col1:
    trend_df_fl = pd.DataFrame(
        {"Date": trends["dates"], "Failed Logins": trends["failed_logins"]}
    )
    fig_fl = px.line(
        trend_df_fl,
        x="Date",
        y="Failed Logins",
        title="Failed Logins (Last 30 Days)",
        markers=True,
        color_discrete_sequence=["#e74c3c"],
    )
    fig_fl.update_layout(height=300, margin={"t": 40, "b": 10})
    st.plotly_chart(fig_fl, use_container_width=True)

with trend_col2:
    trend_df_lo = pd.DataFrame(
        {"Date": trends["dates"], "Lockouts": trends["lockouts"]}
    )
    fig_lo = px.line(
        trend_df_lo,
        x="Date",
        y="Lockouts",
        title="Account Lockouts (Last 30 Days)",
        markers=True,
        color_discrete_sequence=["#e67e22"],
    )
    fig_lo.update_layout(height=300, margin={"t": 40, "b": 10})
    st.plotly_chart(fig_lo, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Domain Overview
# ---------------------------------------------------------------------------

st.subheader("🏢 Domain Overview")

dom_col1, dom_col2 = st.columns(2)

with dom_col1:
    user_dist = {
        "Active": domain_overview.get("active_users", 0),
        "Disabled": domain_overview.get("disabled_users", 0),
        "Locked": domain_overview.get("locked_users", 0),
    }
    fig_pie = px.pie(
        names=list(user_dist.keys()),
        values=list(user_dist.values()),
        title="User Distribution",
        color_discrete_sequence=["#2ecc71", "#e74c3c", "#e67e22"],
    )
    fig_pie.update_layout(height=350, margin={"t": 40, "b": 10})
    st.plotly_chart(fig_pie, use_container_width=True)

with dom_col2:
    admin_count = domain_overview.get("admin_users", 0)
    regular_count = domain_overview.get("total_users", 0) - admin_count
    fig_bar = px.bar(
        x=["Admin Users", "Regular Users"],
        y=[admin_count, regular_count],
        title="Admin vs Regular Users",
        color=["Admin Users", "Regular Users"],
        color_discrete_map={"Admin Users": "#e74c3c", "Regular Users": "#3498db"},
    )
    fig_bar.update_layout(
        height=350, showlegend=False, margin={"t": 40, "b": 10}
    )
    st.plotly_chart(fig_bar, use_container_width=True)

st.markdown("---")

# ---------------------------------------------------------------------------
# Raw Data Tabs
# ---------------------------------------------------------------------------

st.subheader("📊 Raw Data")

tab1, tab2, tab3, tab4 = st.tabs(
    ["🚫 Failed Logins", "🔒 User Lockouts", "💤 Inactive Users", "🔑 Privilege Changes"]
)

with tab1:
    if failed_logins:
        st.dataframe(pd.DataFrame(failed_logins), use_container_width=True, hide_index=True)
    else:
        st.info("No failed-login data available.")

with tab2:
    if lockouts:
        st.dataframe(pd.DataFrame(lockouts), use_container_width=True, hide_index=True)
    else:
        st.info("No lockout data available.")

with tab3:
    if inactive:
        st.dataframe(pd.DataFrame(inactive), use_container_width=True, hide_index=True)
    else:
        st.info("No inactive-user data available.")

with tab4:
    if priv_changes:
        st.dataframe(pd.DataFrame(priv_changes), use_container_width=True, hide_index=True)
    else:
        st.info("No privilege-change data available.")

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#888;'>AD360 Identity Security Analytics — "
    "Built with ❤️ using Streamlit &amp; ManageEngine AD360</div>",
    unsafe_allow_html=True,
)
