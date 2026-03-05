"""
dashboard.py — Enterprise iSOC Streamlit dashboard for AD360 Identity Security Analytics.

5 role-based tabs: Executive Summary, Threat Detection, Identity Governance,
Compliance & Audit, User Risk Profiles.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime

import config
from ad360_client import AD360Client
from analytics import (
    calculate_security_score, get_high_risk_users, get_compliance_summary,
    calculate_itdr_score, detect_attack_patterns, get_mitre_attack_coverage,
    calculate_zero_trust_score, get_peer_group_analysis, get_risk_velocity,
    get_identity_attack_surface,
)
from alerts import AlertsEngine

# ── Color scheme ──────────────────────────────────────────────────────────────
COLORS = {
    "Critical": "#ff4444",
    "High":     "#ff8800",
    "Medium":   "#ffcc00",
    "Low":      "#44bb44",
    "Info":     "#3498db",
    "bg":       "#0e1117",
    "card":     "#1c2333",
}

st.set_page_config(
    page_title="AD360 iSOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Data loading with caching ─────────────────────────────────────────────────

@st.cache_data(ttl=300)
def load_client_data():
    client = AD360Client()
    return {
        "client": client,
        "failed_logins": client.get_failed_logins(),
        "lockouts": client.get_user_lockouts(),
        "inactive": client.get_inactive_users(),
        "priv_changes": client.get_privilege_changes(),
        "mfa_status": client.get_mfa_status(),
        "password_policy": client.get_password_policy(),
        "compliance": client.get_compliance_data(),
        "domain": client.get_domain_overview(),
        "impossible_travel": client.get_impossible_travel_alerts(),
        "after_hours": client.get_after_hours_logins(),
        "service_abuse": client.get_service_account_abuse(),
        "lateral": client.get_lateral_movement(),
        "shadow_admins": client.get_shadow_admins(),
        "orphaned": client.get_orphaned_accounts(),
        "priv_inventory": client.get_privileged_account_inventory(),
        "jml": client.get_joiners_movers_leavers(),
        "timeline": client.get_attack_timeline(),
        "risk_profiles": client.get_user_risk_profiles(),
        "exec_summary": client.get_executive_summary(),
        "trends": client.get_security_trends(),
    }


def severity_color(severity: str) -> str:
    return COLORS.get(severity, COLORS["Info"])


def color_metric(label: str, value, delta=None, help_text: str = ""):
    st.metric(label=label, value=value, delta=delta, help=help_text)


def build_gauge(score: float, title: str = "Health Score") -> go.Figure:
    if score >= 75:
        color = COLORS["Low"]
    elif score >= 50:
        color = COLORS["Medium"]
    elif score >= 25:
        color = COLORS["High"]
    else:
        color = COLORS["Critical"]

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": title, "font": {"size": 18}},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 25],  "color": "#2d0a0a"},
                {"range": [25, 50], "color": "#2d1a0a"},
                {"range": [50, 75], "color": "#2d2a0a"},
                {"range": [75, 100],"color": "#0a2d0a"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 2},
                "thickness": 0.75,
                "value": score,
            },
        },
    ))
    fig.update_layout(height=250, margin=dict(t=40, b=0, l=20, r=20),
                      paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    return fig


# ── Sidebar ───────────────────────────────────────────────────────────────────

def render_sidebar(data: dict) -> None:
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-shield-green.png", width=64)
        st.title("AD360 iSOC")
        st.caption(f"Org: **{config.ORG_NAME}** | Env: **{config.ENVIRONMENT}**")
        st.divider()

        summary = data["exec_summary"]
        health = summary.get("overall_health_score", 0)
        st.metric("Overall Health", f"{health}/100",
                  delta=summary.get("health_trend", 0),
                  delta_color="normal")
        st.progress(int(health) / 100)
        st.divider()

        engine = AlertsEngine()
        triggered = engine.evaluate_all(data["client"])
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for a in triggered:
            counts[a.severity] = counts.get(a.severity, 0) + 1

        st.subheader("🚨 Active Alerts")
        cols = st.columns(4)
        for i, (sev, cnt) in enumerate(counts.items()):
            cols[i].metric(sev, cnt)

        st.divider()
        st.caption(f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")
        if st.button("🔄 Refresh Data"):
            st.cache_data.clear()
            st.rerun()


# ── Tab 1: Executive Summary ──────────────────────────────────────────────────

def render_executive_summary(data: dict) -> None:
    summary = data["exec_summary"]
    trends  = data["trends"]

    st.header("🏠 Executive Summary — CISO View")

    # Health gauge + KPI row
    col_gauge, col_kpis = st.columns([1, 3])
    with col_gauge:
        health = summary.get("overall_health_score", 0)
        st.plotly_chart(build_gauge(health, "Identity Health Score"),
                        use_container_width=True)

    with col_kpis:
        kc = st.columns(4)
        kpi_items = [
            ("Total Users",          summary.get("total_users", 0),           None),
            ("Active Threats",       summary.get("active_threats", 0),        None),
            ("Compliance Score",     f"{summary.get('compliance_score', 0)}%", None),
            ("Critical Alerts",      summary.get("critical_alerts", 0),       None),
        ]
        for i, (label, val, delta) in enumerate(kpi_items):
            kc[i].metric(label, val, delta)

    st.divider()

    # Compliance radar
    col_radar, col_trend = st.columns(2)
    with col_radar:
        st.subheader("📊 Compliance Framework Scores")
        frameworks = summary.get("compliance_scores", {})
        if frameworks:
            fig = go.Figure(go.Scatterpolar(
                r=list(frameworks.values()),
                theta=list(frameworks.keys()),
                fill="toself",
                line_color=COLORS["Info"],
            ))
            fig.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                paper_bgcolor="rgba(0,0,0,0)", font_color="white",
                height=350, margin=dict(t=20, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)

    with col_trend:
        st.subheader("📈 90-Day Security Trend")
        if trends:
            df_t = pd.DataFrame(trends)
            if "date" in df_t.columns and "security_score" in df_t.columns:
                fig2 = px.line(df_t, x="date", y="security_score",
                               color_discrete_sequence=[COLORS["Info"]])
                fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                                   font_color="white", height=350,
                                   margin=dict(t=20, b=20))
                st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # Top risks table
    st.subheader("⚠️ Top Identity Risks")
    risks = summary.get("top_risks", [])
    if risks:
        df_r = pd.DataFrame(risks)
        st.dataframe(df_r, use_container_width=True, hide_index=True)


# ── Tab 2: Threat Detection ───────────────────────────────────────────────────

def render_threat_detection(data: dict) -> None:
    st.header("🚨 Threat Detection — SOC Analyst View")

    engine   = AlertsEngine()
    triggered = engine.evaluate_all(data["client"])

    # Alert cards
    if triggered:
        st.subheader(f"🔔 {len(triggered)} Active Alerts")
        for alert in sorted(triggered, key=lambda a: ["Critical","High","Medium","Low"].index(a.severity)):
            color = severity_color(alert.severity)
            with st.expander(f"[{alert.severity}] {alert.name}", expanded=(alert.severity == "Critical")):
                st.markdown(f"**Message:** {alert.message}")
                if alert.mitre_technique_id:
                    st.markdown(f"**MITRE ATT&CK:** `{{alert.mitre_technique_id}}`")
                if alert.affected_users:
                    st.markdown(f"**Affected Users:** {{len(alert.affected_users)}}")
                st.markdown("**Remediation Steps:**")
                for i, step in enumerate(alert.remediation, 1):
                    st.markdown(f"{{i}}. {{step}}")
    else:
        st.success("✅ No active alerts detected.")

    st.divider()

    col1, col2 = st.columns(2)

    # Impossible travel
    with col1:
        st.subheader("🌍 Impossible Travel Alerts")
        travel = data["impossible_travel"]
        if travel:
            df_tr = pd.DataFrame(travel)
            if {"username", "location_1", "location_2", "time_diff_hours"}.issubset(df_tr.columns):
                st.dataframe(df_tr[["username", "location_1", "location_2", "time_diff_hours"]],
                             use_container_width=True, hide_index=True)
        else:
            st.info("No impossible travel events detected.")

    # After-hours heatmap
    with col2:
        st.subheader("🌙 After-Hours Login Heatmap")
        after = data["after_hours"]
        if after:
            df_ah = pd.DataFrame(after)
            if {"hour", "day_of_week", "count"}.issubset(df_ah.columns):
                pivot = df_ah.pivot_table(index="day_of_week", columns="hour", values="count", fill_value=0)
                fig = px.imshow(pivot, color_continuous_scale="Reds",
                                labels=dict(color="Logins"))
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                                  font_color="white", height=300,
                                  margin=dict(t=20, b=20))
                st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # MITRE ATT&CK coverage
    st.subheader("🎯 MITRE ATT&CK Coverage")
    mitre = get_mitre_attack_coverage(data["client"])
    if mitre:
        df_m = pd.DataFrame(list(mitre.items()), columns=["Technique", "Count"])
        fig_m = px.bar(df_m, x="Technique", y="Count",
                       color_discrete_sequence=[COLORS["Critical"]])
        fig_m.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                            font_color="white", height=300,
                            margin=dict(t=20, b=20))
        st.plotly_chart(fig_m, use_container_width=True)

    # Attack timeline
    st.subheader("⏱️ Attack Event Timeline")
    timeline = data["timeline"]
    if timeline:
        df_tl = pd.DataFrame(timeline)
        if {"timestamp", "event_type", "username", "severity"}.issubset(df_tl.columns):
            st.dataframe(df_tl[["timestamp", "event_type", "username", "severity"]],
                         use_container_width=True, hide_index=True)


# ── Tab 3: Identity Governance ────────────────────────────────────────────────

def render_identity_governance(data: dict) -> None:
    st.header("👤 Identity Governance — IT Admin View")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Orphaned Accounts",   len(data["orphaned"]))
    with col2:
        st.metric("Shadow Admins",       len(data["shadow_admins"]))
    with col3:
        jml = data["jml"]
        leavers = [u for u in jml if u.get("status") == "leaver"] if jml else []
        st.metric("Pending Leavers",     len(leavers))

    st.divider()

    col_jml, col_priv = st.columns(2)

    with col_jml:
        st.subheader("🔄 Joiners / Movers / Leavers")
        if jml:
            df_jml = pd.DataFrame(jml)
            if "status" in df_jml.columns:
                counts = df_jml["status"].value_counts().reset_index()
                counts.columns = ["Status", "Count"]
                fig = px.pie(counts, names="Status", values="Count",
                             color_discrete_map={
                                 "joiner": COLORS["Low"],
                                 "mover":  COLORS["Info"],
                                 "leaver": COLORS["Critical"],
                             })
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                                  font_color="white", height=300,
                                  margin=dict(t=20, b=20))
                st.plotly_chart(fig, use_container_width=True)

    with col_priv:
        st.subheader("🔑 Privileged Account Inventory")
        priv = data["priv_inventory"]
        if priv:
            df_p = pd.DataFrame(priv)
            cols_show = [c for c in ["username", "privilege_level", "department", "last_used"] if c in df_p.columns]
            if cols_show:
                st.dataframe(df_p[cols_show], use_container_width=True, hide_index=True)

    st.divider()

    col_shadow, col_orphan = st.columns(2)

    with col_shadow:
        st.subheader("👁️ Shadow Admins")
        shadows = data["shadow_admins"]
        if shadows:
            df_s = pd.DataFrame(shadows)
            st.dataframe(df_s, use_container_width=True, hide_index=True)
        else:
            st.success("No shadow admins detected.")

    with col_orphan:
        st.subheader("🗑️ Orphaned Accounts")
        orphaned = data["orphaned"]
        if orphaned:
            df_o = pd.DataFrame(orphaned)
            st.dataframe(df_o, use_container_width=True, hide_index=True)
        else:
            st.success("No orphaned accounts detected.")


# ── Tab 4: Compliance & Audit ─────────────────────────────────────────────────

def render_compliance(data: dict) -> None:
    st.header("📋 Compliance & Audit — GRC View")

    compliance = data["compliance"]

    if not compliance:
        st.warning("No compliance data available.")
        return

    # Framework scorecard
    st.subheader("🏆 Framework Scorecard")
    frameworks = config.COMPLIANCE_FRAMEWORKS
    cols = st.columns(len(frameworks))
    for i, fw in enumerate(frameworks):
        score = compliance.get(fw, {}).get("score", 0) if isinstance(compliance.get(fw), dict) else compliance.get(fw, 0)
        color = "normal" if score >= 75 else "inverse"
        cols[i].metric(fw, f"{score}%%", delta=None)

    st.divider()

    # Per-framework drill-down
    for fw in frameworks:
        fw_data = compliance.get(fw, {})
        if not fw_data:
            continue
        with st.expander(f"📂 {fw} — Detailed Checks"):
            checks = fw_data.get("checks", []) if isinstance(fw_data, dict) else []
            if checks:
                df_c = pd.DataFrame(checks)
                st.dataframe(df_c, use_container_width=True, hide_index=True)
            else:
                score = fw_data.get("score", fw_data) if isinstance(fw_data, dict) else fw_data
                st.write(f"Score: **{score}%%**")

    st.divider()

    # PDF export placeholder
    st.subheader("📥 Export Reports")
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        if st.button("📄 Generate Executive PDF Report"):
            try:
                from report_generator import ReportGenerator
                rg = ReportGenerator(data)
                pdf_bytes = rg.generate_executive_report()
                st.download_button("⬇️ Download Executive Report",
                                   data=pdf_bytes,
                                   file_name="isoc_executive_report.pdf",
                                   mime="application/pdf")
            except Exception as e:
                st.error(f"Report generation failed: {e}")
    with col_e2:
        if st.button("📋 Generate Compliance PDF Report"):
            try:
                from report_generator import ReportGenerator
                rg = ReportGenerator(data)
                pdf_bytes = rg.generate_compliance_report()
                st.download_button("⬇️ Download Compliance Report",
                                   data=pdf_bytes,
                                   file_name="isoc_compliance_report.pdf",
                                   mime="application/pdf")
            except Exception as e:
                st.error(f"Report generation failed: {e}")


# ── Tab 5: User Risk Profiles ─────────────────────────────────────────────────

def render_user_risk_profiles(data: dict) -> None:
    st.header("🔍 User Risk Profiles — Deep Dive")

    risk_profiles = data["risk_profiles"]
    if not risk_profiles:
        st.warning("No user risk profile data available.")
        return

    df_rp = pd.DataFrame(risk_profiles)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Risk Score Distribution")
        if "risk_score" in df_rp.columns:
            fig = px.histogram(df_rp, x="risk_score", nbins=20,
                               color_discrete_sequence=[COLORS["High"]])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                              font_color="white", height=300,
                              margin=dict(t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("🏢 Department Risk Heatmap")
        if {"department", "risk_score"}.issubset(df_rp.columns):
            dept_risk = df_rp.groupby("department")["risk_score"].mean().reset_index()
            dept_risk.columns = ["Department", "Avg Risk Score"]
            fig2 = px.bar(dept_risk, x="Department", y="Avg Risk Score",
                          color="Avg Risk Score",
                          color_continuous_scale=["#44bb44", "#ffcc00", "#ff8800", "#ff4444"])
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                               font_color="white", height=300,
                               margin=dict(t=20, b=20))
            st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # Per-user risk card
    st.subheader("👤 User Risk Card Lookup")
    if "username" in df_rp.columns:
        selected_user = st.selectbox("Select a user:", df_rp["username"].sort_values().tolist())
        user_row = df_rp[df_rp["username"] == selected_user]
        if not user_row.empty:
            u = user_row.iloc[0].to_dict()
            col_u1, col_u2, col_u3 = st.columns(3)
            col_u1.metric("Risk Score",  u.get("risk_score", "N/A"))
            col_u2.metric("Department",  u.get("department", "N/A"))
            col_u3.metric("Risk Level",  u.get("risk_level", "N/A"))
            with st.expander("📋 Full Risk Details"):
                st.json(u)

    st.divider()

    # Top 20 high-risk users
    st.subheader("🔝 Top 20 High-Risk Users")
    if "risk_score" in df_rp.columns:
        top20 = df_rp.nlargest(20, "risk_score")
        cols_show = [c for c in ["username", "department", "risk_score", "risk_level", "last_login"] if c in top20.columns]
        st.dataframe(top20[cols_show], use_container_width=True, hide_index=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    data = load_client_data()
    render_sidebar(data)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🏠 Executive Summary",
        "🚨 Threat Detection",
        "👤 Identity Governance",
        "📋 Compliance & Audit",
        "🔍 User Risk Profiles",
    ])

    with tab1:
        render_executive_summary(data)
    with tab2:
        render_threat_detection(data)
    with tab3:
        render_identity_governance(data)
    with tab4:
        render_compliance(data)
    with tab5:
        render_user_risk_profiles(data)


if __name__ == "__main__":
    main()