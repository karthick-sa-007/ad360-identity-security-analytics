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
        bar_color = COLORS["Low"]
    elif score >= 60:
        bar_color = COLORS["Medium"]
    elif score >= 40:
        bar_color = COLORS["High"]
    else:
        bar_color = COLORS["Critical"]

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": title, "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": bar_color, "thickness": 0.25},
            "steps": [
                {"range": [0, 40],  "color": "#3a1a1a"},
                {"range": [40, 60], "color": "#3a2a1a"},
                {"range": [60, 75], "color": "#3a3a1a"},
                {"range": [75, 100], "color": "#1a3a1a"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 3},
                "thickness": 0.8,
                "value": score,
            },
        },
        number={"suffix": "/100", "font": {"size": 28}},
    ))
    fig.update_layout(height=260, margin=dict(t=40, b=10, l=20, r=20),
                      paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    return fig


# ── Sidebar ───────────────────────────────────────────────────────────────────

def render_sidebar(data: dict):
    with st.sidebar:
        st.title("🛡️ AD360 iSOC")
        st.subheader(config.ORG_NAME)

        env = config.ENVIRONMENT
        if env == "Production":
            st.markdown(f"<span style='background:#1a7a1a;padding:2px 8px;border-radius:4px;'>{env}</span>",
                        unsafe_allow_html=True)
        elif env == "Staging":
            st.markdown(f"<span style='background:#7a7a00;padding:2px 8px;border-radius:4px;'>{env}</span>",
                        unsafe_allow_html=True)
        else:
            st.markdown(f"<span style='background:#444;padding:2px 8px;border-radius:4px;'>{env}</span>",
                        unsafe_allow_html=True)

        st.caption(f"**Connection:** {'Mock Data' if config.USE_MOCK_DATA else 'Live AD360'}")
        st.caption(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if st.button("🔄 Refresh Data"):
            st.cache_data.clear()
            st.rerun()

        st.divider()
        st.subheader("Filters")

        domain_info = data.get("domain", {})
        domains = domain_info.get("domains", ["corp.local"])
        if isinstance(domains, str):
            domains = [domains]
        st.multiselect("Domain", options=domains, default=domains, key="filter_domain")

        departments = ["All", "IT", "Finance", "HR", "Engineering", "Sales", "Operations", "Executive"]
        st.multiselect("Department", options=departments, default=["All"], key="filter_dept")

        st.selectbox("Date Range", options=["Last 7 days", "Last 30 days", "Last 90 days"],
                     index=1, key="filter_range")

        st.divider()
        if st.button("📥 Export PDF"):
            st.info("PDF export available from Compliance tab")


# ── Tab 1: Executive Summary ──────────────────────────────────────────────────

def render_executive_summary(data: dict):
    st.header("🏠 Executive Summary — CISO View")

    exec_data = data.get("exec_summary", {})
    health_score = exec_data.get("overall_health_score", 0)
    open_critical = exec_data.get("open_critical_alerts", 0)
    incidents_month = exec_data.get("incidents_this_month", 0)
    mom_change = exec_data.get("month_over_month_change", 0)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        color_metric("🏥 Health Score", f"{health_score}/100",
                     help_text="Overall identity security health (0–100)")
    with col2:
        color_metric("🚨 Open Critical Alerts", open_critical,
                     help_text="Currently open critical-severity alerts")
    with col3:
        color_metric("📅 Incidents This Month", incidents_month,
                     help_text="Total security incidents logged this month")
    with col4:
        delta_label = f"{abs(mom_change)}% {'↑' if mom_change > 0 else '↓'}"
        color_metric("📈 MoM Change", delta_label,
                     help_text="Month-over-month change in incident volume")

    st.divider()

    col_gauge, col_risks = st.columns([1, 1])

    with col_gauge:
        fig_gauge = build_gauge(health_score, "Identity Security Health")
        st.plotly_chart(fig_gauge, use_container_width=True)
        st.caption("🔍 Health score aggregates posture across MFA, privilege hygiene, threat signals, "
                   "and compliance. Scores below 60 require immediate executive attention.")

    with col_risks:
        st.subheader("⚠️ Top 3 Risks")
        top_risks = exec_data.get("top_risks", [])
        if top_risks:
            for i, risk in enumerate(top_risks[:3]):
                severity = risk.get("severity", "High")
                title = risk.get("title", f"Risk {i+1}")
                description = risk.get("description", "")
                if severity == "Critical":
                    st.error(f"**{title}** — {description}")
                elif severity == "High":
                    st.warning(f"**{title}** — {description}")
                else:
                    st.info(f"**{title}** — {description}")
        else:
            st.success("✅ No critical risks identified at this time.")

    st.divider()
    st.subheader("📊 Compliance Framework Scores")

    compliance = data.get("compliance", {})
    frameworks = config.COMPLIANCE_FRAMEWORKS
    scores = [compliance.get(fw, {}).get("score", 0) for fw in frameworks]

    if any(s > 0 for s in scores):
        bar_colors = [COLORS["Low"] if s >= 80 else COLORS["Medium"] if s >= 60
                      else COLORS["High"] if s >= 40 else COLORS["Critical"] for s in scores]
        fig_bar = go.Figure(go.Bar(
            x=frameworks,
            y=scores,
            marker_color=bar_colors,
            text=[f"{s}%" for s in scores],
            textposition="outside",
        ))
        fig_bar.update_layout(
            yaxis=dict(range=[0, 110], title="Score (%)"),
            xaxis_title="Framework",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            height=320,
            margin=dict(t=20, b=40),
            showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)
        st.caption("📋 Compliance scores reflect the percentage of passing controls per framework. "
                   "Scores below 80% indicate material compliance gaps requiring remediation plans.")
    else:
        st.info("No compliance data available.")

    st.divider()
    st.subheader("📈 90-Day Security Trend")

    trends = data.get("trends", {})
    trend_keys = ["failed_logins", "lockouts", "lateral_movement", "after_hours_logins"]
    trend_labels = {
        "failed_logins": "Failed Logins",
        "lockouts": "Lockouts",
        "lateral_movement": "Lateral Movement",
        "after_hours_logins": "After-Hours Logins",
    }
    trend_colors = {
        "failed_logins": COLORS["Critical"],
        "lockouts": COLORS["High"],
        "lateral_movement": COLORS["Medium"],
        "after_hours_logins": COLORS["Info"],
    }

    fig_trend = go.Figure()
    has_trend_data = False
    for key in trend_keys:
        series = trends.get(key, [])
        if series:
            has_trend_data = True
            fig_trend.add_trace(go.Scatter(
                y=series,
                name=trend_labels[key],
                mode="lines+markers",
                line=dict(color=trend_colors[key], width=2),
                marker=dict(size=4),
            ))
    if has_trend_data:
        fig_trend.update_layout(
            xaxis_title="Days Ago",
            yaxis_title="Event Count",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            height=320,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(t=40, b=40),
        )
        st.plotly_chart(fig_trend, use_container_width=True)
        st.caption("📉 90-day rolling trend across key threat indicators. Upward trends in failed logins "
                   "or lateral movement may indicate an active campaign — correlate with threat intel.")
    else:
        st.info("No trend data available.")


# ── Tab 2: Threat Detection ───────────────────────────────────────────────────

def render_threat_detection(data: dict):
    st.header("🚨 Threat Detection — SOC Analyst View")

    st.subheader("🔔 Active Alerts")
    client = data["client"]
    engine = AlertsEngine()
    triggered = engine.evaluate(client)

    if triggered:
        severity_order = ["Critical", "High", "Medium", "Low"]
        grouped = {s: [] for s in severity_order}
        for alert in triggered:
            grouped.setdefault(alert.severity, []).append(alert)

        for sev in severity_order:
            alerts_in_group = grouped.get(sev, [])
            if not alerts_in_group:
                continue
            st.markdown(f"#### {sev} ({len(alerts_in_group)})")
            for alert in alerts_in_group:
                label = f"**{alert.name}**"
                if alert.mitre_technique_id:
                    label += f" `[{alert.mitre_technique_id}]`"
                with st.expander(label, expanded=(sev == "Critical")):
                    st.markdown(f"**Message:** {alert.message}")
                    if alert.affected_users:
                        st.markdown(f"**Affected Users:** {', '.join(str(u) for u in alert.affected_users[:10])}")
                    st.markdown("**Remediation Steps:**")
                    for i, step in enumerate(alert.remediation, 1):
                        st.markdown(f"{i}. {step}")
    else:
        st.success("✅ No alerts triggered. Identity posture looks healthy.")

    st.divider()
    st.subheader("🔍 Attack Pattern Analysis")

    patterns = detect_attack_patterns(client)
    if patterns:
        for pattern in patterns:
            p_name = pattern.get("pattern", "Unknown Pattern")
            p_conf = pattern.get("confidence", "")
            p_desc = pattern.get("description", "")
            p_users = pattern.get("affected_users", [])
            conf_color = (COLORS["Critical"] if p_conf == "High"
                          else COLORS["High"] if p_conf == "Medium" else COLORS["Low"])
            st.markdown(
                f"<div style='border-left:4px solid {conf_color};padding:8px 12px;"
                f"background:{COLORS['card']};margin-bottom:8px;border-radius:4px;'>"
                f"<b>{p_name}</b> &nbsp; "
                f"<span style='color:{conf_color};font-size:0.85em;'>Confidence: {p_conf}</span><br>"
                f"<span style='font-size:0.9em;'>{p_desc}</span>"
                + (f"<br><span style='font-size:0.8em;color:#aaa;'>Affected: "
                   f"{', '.join(str(u) for u in p_users[:5])}</span>" if p_users else "")
                + "</div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("No attack patterns detected in the current dataset.")

    st.divider()
    st.subheader("🎯 MITRE ATT&CK Coverage")

    mitre_data = get_mitre_attack_coverage(client)
    if mitre_data:
        df_mitre = pd.DataFrame(mitre_data)
        st.dataframe(df_mitre, use_container_width=True, hide_index=True)
        st.caption("📌 MITRE ATT&CK technique coverage mapped from active alert rules. "
                   "Gaps in coverage indicate detection blind spots.")
    else:
        st.info("No MITRE ATT&CK coverage data available.")

    st.divider()
    col_heatmap, col_travel = st.columns(2)

    with col_heatmap:
        st.subheader("🕐 After-Hours Login Heatmap")
        after_hours = data.get("after_hours", [])
        if after_hours:
            days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            hours = list(range(0, 24))
            z = [[0] * len(days) for _ in hours]
            for login in after_hours:
                h = login.get("hour", 0)
                d = login.get("day_of_week", 0)
                if 0 <= h < 24 and 0 <= d < 7:
                    z[h][d] += 1
            fig_heat = go.Figure(go.Heatmap(
                z=z,
                x=days,
                y=[f"{h:02d}:00" for h in hours],
                colorscale="Reds",
                showscale=True,
            ))
            fig_heat.update_layout(
                xaxis_title="Day of Week",
                yaxis_title="Hour of Day",
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="white",
                height=380,
                margin=dict(t=20, b=40),
            )
            st.plotly_chart(fig_heat, use_container_width=True)
            st.caption("🌙 Login density outside business hours (evenings, weekends). "
                       "Bright cells indicate frequent after-hours access — investigate for insider risk.")
        else:
            st.info("No after-hours login data available.")

    with col_travel:
        st.subheader("✈️ Impossible Travel Events")
        travel = data.get("impossible_travel", [])
        if travel:
            df_travel = pd.DataFrame(travel)
            display_cols = [c for c in ["username", "location_1", "location_2",
                                        "distance_km", "time_diff_minutes", "risk_score"]
                            if c in df_travel.columns]
            st.dataframe(df_travel[display_cols] if display_cols else df_travel,
                         use_container_width=True, hide_index=True)
            st.caption("🌍 Accounts logging in from geographically impossible locations within "
                       "minutes — strong indicator of credential compromise.")
        else:
            st.info("No impossible travel events detected.")

    st.divider()
    st.subheader("⏱️ Attack Timeline (Last 20 Events)")

    timeline = data.get("timeline", [])
    if timeline:
        recent = timeline[-20:]
        rows = []
        for evt in recent:
            sev = evt.get("severity", "Info")
            rows.append({
                "Timestamp": evt.get("timestamp", ""),
                "Event": evt.get("event", ""),
                "User": evt.get("username", ""),
                "Severity": sev,
                "Source IP": evt.get("source_ip", ""),
                "Details": evt.get("details", ""),
            })
        df_timeline = pd.DataFrame(rows)

        _TIMELINE_COLORS = {
            "Critical": "background-color:#3a0000",
            "High":     "background-color:#3a1a00",
            "Medium":   "background-color:#2a2a00",
            "Low":      "background-color:#002a00",
        }

        def _color_row(row):
            c = _TIMELINE_COLORS.get(row["Severity"], "")
            return [c] * len(row)

        st.dataframe(
            df_timeline.style.apply(_color_row, axis=1),
            use_container_width=True,
            hide_index=True,
        )
        st.caption("🕵️ Chronological attack timeline. Red rows indicate critical-severity events "
                   "that may form part of a multi-stage intrusion chain.")
    else:
        st.info("No attack timeline data available.")


# ── Tab 3: Identity Governance ────────────────────────────────────────────────

def render_identity_governance(data: dict):
    st.header("�� Identity Governance — IT Admin View")

    priv_inv = data.get("priv_inventory", [])
    shadow = data.get("shadow_admins", [])
    orphaned = data.get("orphaned", [])
    jml = data.get("jml", [])

    overdue_jml = [j for j in jml if j.get("overdue", False)]

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("👑 Total Privileged Accounts", len(priv_inv))
    with col2:
        st.metric("👥 Shadow Admins", len(shadow),
                  delta=f"{len(shadow)} detected", delta_color="inverse")
    with col3:
        st.metric("🚫 Orphaned Accounts", len(orphaned),
                  delta=f"{len(orphaned)} unresolved", delta_color="inverse")
    with col4:
        st.metric("⏰ JML Overdue", len(overdue_jml),
                  delta=f"{len(overdue_jml)} actions", delta_color="inverse")

    st.divider()
    st.subheader("🔄 Joiners / Movers / Leavers Process")
    if jml:
        df_jml = pd.DataFrame(jml)

        def _jml_row(row):
            if row.get("overdue"):
                return [f"background-color:{COLORS['Critical']};color:white"] * len(row)
            status = str(row.get("status", "")).lower()
            if status == "pending":
                return [f"background-color:{COLORS['High']}"] * len(row)
            return [""] * len(row)

        display_cols = [c for c in ["username", "type", "status", "days_pending",
                                    "manager", "department", "overdue"] if c in df_jml.columns]
        styled = df_jml[display_cols].style.apply(_jml_row, axis=1) if display_cols else df_jml.style
        st.dataframe(styled, use_container_width=True, hide_index=True)
        st.caption("📋 JML lifecycle status. Red rows are overdue — access changes not completed "
                   "within SLA risk policy violations and potential insider threat vectors.")
    else:
        st.info("No JML data available.")

    st.divider()
    col_orp, col_shadow = st.columns(2)

    with col_orp:
        st.subheader("🚫 Orphaned Accounts")
        if orphaned:
            df_orp = pd.DataFrame(orphaned)

            def _orp_row(row):
                if row.get("has_admin_rights"):
                    return [f"background-color:{COLORS['Critical']};color:white"] * len(row)
                return [""] * len(row)

            display_cols = [c for c in ["username", "last_logon", "has_admin_rights",
                                        "days_inactive", "account_type"] if c in df_orp.columns]
            styled = df_orp[display_cols].style.apply(_orp_row, axis=1) if display_cols else df_orp.style
            st.dataframe(styled, use_container_width=True, hide_index=True)
            st.caption("🔴 Accounts with no corresponding active user. "
                       "Red rows have admin rights — immediate review required.")
        else:
            st.success("✅ No orphaned accounts detected.")

    with col_shadow:
        st.subheader("👥 Shadow Admins")
        if shadow:
            df_shadow = pd.DataFrame(shadow)

            def _shadow_row(row):
                risk = str(row.get("risk_level", "")).lower()
                if risk == "critical":
                    return [f"background-color:{COLORS['Critical']};color:white"] * len(row)
                if risk == "high":
                    return [f"background-color:{COLORS['High']}"] * len(row)
                if risk == "medium":
                    return [f"background-color:{COLORS['Medium']}"] * len(row)
                return [""] * len(row)

            display_cols = [c for c in ["username", "risk_level", "indirect_path",
                                        "effective_permissions", "discovered"] if c in df_shadow.columns]
            styled = df_shadow[display_cols].style.apply(_shadow_row, axis=1) if display_cols else df_shadow.style
            st.dataframe(styled, use_container_width=True, hide_index=True)
            st.caption("⚠️ Users with effective admin rights via indirect group membership. "
                       "Shadow admins bypass standard privileged account controls.")
        else:
            st.success("✅ No shadow admins detected.")

    st.divider()
    st.subheader("🔑 Privileged Account Inventory")
    if priv_inv:
        df_priv = pd.DataFrame(priv_inv)

        def _priv_row(row):
            if row.get("dormant"):
                return [f"background-color:{COLORS['Critical']};color:white"] * len(row)
            age = row.get("password_age_days", 0)
            if isinstance(age, (int, float)) and age > config.ALERT_THRESHOLDS.get("password_age_critical_days", 180):
                return [f"background-color:{COLORS['High']}"] * len(row)
            return [""] * len(row)

        display_cols = [c for c in ["username", "account_type", "password_age_days",
                                    "last_logon", "dormant", "mfa_enabled",
                                    "privilege_level"] if c in df_priv.columns]
        styled = df_priv[display_cols].style.apply(_priv_row, axis=1) if display_cols else df_priv.style
        st.dataframe(styled, use_container_width=True, hide_index=True)
        st.caption("🔐 Full privileged account inventory. Red = dormant (unused >90 days), "
                   "orange = password older than 180 days. Both represent material access risk.")
    else:
        st.info("No privileged account inventory available.")


# ── Tab 4: Compliance & Audit ─────────────────────────────────────────────────

def render_compliance_audit(data: dict):
    st.header("📋 Compliance & Audit — GRC View")

    compliance = data.get("compliance", {})
    frameworks = config.COMPLIANCE_FRAMEWORKS

    st.subheader("📊 Framework Scorecard")
    cols = st.columns(len(frameworks))
    for col, fw in zip(cols, frameworks):
        fw_data = compliance.get(fw, {})
        score = fw_data.get("score", 0)
        delta_color = "normal" if score >= 80 else "inverse"
        with col:
            st.metric(fw.replace("_", " "), f"{score}%", delta_color=delta_color)

    st.divider()
    col_radar, col_detail = st.columns([1, 1])

    with col_radar:
        st.subheader("🕸️ Compliance Radar")
        scores = [compliance.get(fw, {}).get("score", 0) for fw in frameworks]
        fw_labels = [fw.replace("_", " ") for fw in frameworks]

        fig_radar = go.Figure(go.Scatterpolar(
            r=scores + [scores[0]],
            theta=fw_labels + [fw_labels[0]],
            fill="toself",
            fillcolor="rgba(52,152,219,0.2)",
            line=dict(color=COLORS["Info"], width=2),
            marker=dict(size=6, color=COLORS["Info"]),
            name="Compliance Score",
        ))
        fig_radar.update_layout(
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(size=9)),
                angularaxis=dict(tickfont=dict(size=10)),
            ),
            showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            height=360,
            margin=dict(t=20, b=20, l=40, r=40),
        )
        st.plotly_chart(fig_radar, use_container_width=True)
        st.caption("🕸️ Radar view of compliance posture across all 7 frameworks. "
                   "Gaps toward the center indicate frameworks requiring focused remediation.")

    with col_detail:
        st.subheader("📁 Per-Framework Drill-Down")
        for fw in frameworks:
            fw_data = compliance.get(fw, {})
            fw_score = fw_data.get("score", 0)
            checks = fw_data.get("checks", [])
            label = f"{fw.replace('_', ' ')} — {fw_score}%"
            with st.expander(label, expanded=False):
                if checks:
                    for check in checks:
                        check_name = check.get("name", "Unknown check")
                        passed = check.get("passed", False)
                        icon = "✅" if passed else "❌"
                        detail = check.get("detail", "")
                        st.markdown(f"{icon} **{check_name}**" + (f": {detail}" if detail else ""))
                else:
                    st.info("No detailed check data available for this framework.")

    st.divider()
    st.subheader("🔒 CIS Active Directory — Detailed Breakdown")
    cis_data = compliance.get("CIS_AD", {})
    cis_checks = cis_data.get("checks", [])
    if cis_checks:
        df_cis = pd.DataFrame(cis_checks)
        if "passed" in df_cis.columns:
            df_cis["Status"] = df_cis["passed"].apply(lambda x: "✅ Pass" if x else "❌ Fail")
        display_cols = [c for c in ["name", "Status", "detail", "control_id",
                                    "priority"] if c in df_cis.columns]
        st.dataframe(df_cis[display_cols] if display_cols else df_cis,
                     use_container_width=True, hide_index=True)
        pass_count = sum(1 for c in cis_checks if c.get("passed"))
        fail_count = len(cis_checks) - pass_count
        st.caption(f"📋 CIS AD benchmark: **{pass_count} controls passing**, "
                   f"**{fail_count} controls failing**. Address failed controls in priority order.")
    else:
        st.info("No CIS AD check data available.")

    st.divider()
    st.subheader("📄 Generate Compliance Report")

    if st.button("📄 Generate PDF Report"):
        try:
            from report_generator import generate_compliance_report  # noqa: PLC0415
            pdf_bytes = generate_compliance_report(data)
            st.download_button(
                label="⬇️ Download PDF Report",
                data=pdf_bytes,
                file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
            )
        except ImportError:
            st.warning("⚠️ PDF generation module (report_generator) is not installed. "
                       "Install it or contact your administrator to enable this feature.")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Failed to generate report: {exc}")


# ── Tab 5: User Risk Profiles ─────────────────────────────────────────────────

def render_user_risk_profiles(data: dict):
    st.header("🔍 User Risk Profiles — Deep Dive")

    risk_profiles = data.get("risk_profiles", [])

    search_term = st.text_input("🔎 Search username", placeholder="Enter username to search…")

    st.divider()
    st.subheader("🏆 Top 10 High-Risk Users")

    client = data["client"]
    high_risk = get_high_risk_users(client)

    if high_risk:
        top10 = high_risk[:10]
        cols_per_row = 2
        for i in range(0, len(top10), cols_per_row):
            row_users = top10[i:i + cols_per_row]
            cols = st.columns(cols_per_row)
            for col, user in zip(cols, row_users):
                score = user.get("risk_score", 0)
                username = user.get("username", "Unknown")
                factors = user.get("risk_factors", [])
                recommendations = user.get("recommendations", [])
                if score >= 75:
                    card_color = COLORS["Critical"]
                elif score >= 50:
                    card_color = COLORS["High"]
                elif score >= 25:
                    card_color = COLORS["Medium"]
                else:
                    card_color = COLORS["Low"]
                with col:
                    st.markdown(
                        f"<div style='border:2px solid {card_color};border-radius:8px;"
                        f"padding:12px;margin-bottom:12px;background:{COLORS['card']};'>"
                        f"<h4 style='color:{card_color};margin:0;'>👤 {username}</h4>"
                        f"<p style='font-size:1.4em;font-weight:bold;margin:4px 0;color:{card_color};'>"
                        f"Risk Score: {score}</p>"
                        + (f"<p style='font-size:0.85em;margin:4px 0;'>"
                           f"⚠️ {' · '.join(str(f) for f in factors[:3])}</p>" if factors else "")
                        + (f"<p style='font-size:0.8em;color:#aaa;margin:4px 0;'>"
                           f"💡 {recommendations[0]}</p>" if recommendations else "")
                        + "</div>",
                        unsafe_allow_html=True,
                    )
    else:
        st.info("No high-risk user data available.")

    st.divider()
    col_hist, col_dept = st.columns(2)

    with col_hist:
        st.subheader("📊 Risk Score Distribution")
        if risk_profiles:
            scores = [p.get("risk_score", 0) for p in risk_profiles]
            fig_hist = px.histogram(
                x=scores,
                nbins=20,
                labels={"x": "Risk Score", "y": "User Count"},
                color_discrete_sequence=[COLORS["High"]],
            )
            fig_hist.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="white",
                height=300,
                margin=dict(t=20, b=40),
                bargap=0.05,
            )
            st.plotly_chart(fig_hist, use_container_width=True)
            st.caption("📊 Distribution of user risk scores across the organisation. "
                       "Right-skewed distributions indicate a concentrated high-risk user population.")
        else:
            st.info("No risk profile data for histogram.")

    with col_dept:
        st.subheader("🏢 Department Risk Heatmap")
        if risk_profiles:
            dept_scores: dict = {}
            for p in risk_profiles:
                dept = p.get("department", "Unknown")
                score = p.get("risk_score", 0)
                dept_scores.setdefault(dept, []).append(score)
            dept_avg = {dept: round(sum(s) / len(s), 1) for dept, s in dept_scores.items()}
            df_dept = pd.DataFrame(list(dept_avg.items()), columns=["Department", "Avg Risk Score"])
            df_dept = df_dept.sort_values("Avg Risk Score", ascending=False)

            bar_colors = [
                COLORS["Critical"] if s >= 75 else COLORS["High"] if s >= 50
                else COLORS["Medium"] if s >= 25 else COLORS["Low"]
                for s in df_dept["Avg Risk Score"]
            ]
            fig_dept = go.Figure(go.Bar(
                x=df_dept["Department"],
                y=df_dept["Avg Risk Score"],
                marker_color=bar_colors,
                text=[f"{s}" for s in df_dept["Avg Risk Score"]],
                textposition="outside",
            ))
            fig_dept.update_layout(
                yaxis=dict(range=[0, 110], title="Avg Risk Score"),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="white",
                height=300,
                margin=dict(t=20, b=40),
                showlegend=False,
            )
            st.plotly_chart(fig_dept, use_container_width=True)
            st.caption("🏢 Average risk score per department. Departments shown in red or orange "
                       "should prioritise security awareness training and access reviews.")
        else:
            st.info("No department risk data available.")

    st.divider()
    st.subheader("👤 Individual User Detail")

    if search_term:
        matched = [p for p in risk_profiles
                   if search_term.lower() in str(p.get("username", "")).lower()]
        if matched:
            for user in matched[:3]:
                username = user.get("username", "Unknown")
                score = user.get("risk_score", 0)
                factors = user.get("risk_factors", [])
                recs = user.get("recommendations", [])
                dept = user.get("department", "N/A")
                last_activity = user.get("last_activity", "N/A")
                mfa = user.get("mfa_enabled", None)

                card_color = (COLORS["Critical"] if score >= 75 else
                              COLORS["High"] if score >= 50 else
                              COLORS["Medium"] if score >= 25 else COLORS["Low"])
                with st.expander(f"👤 {username} — Risk Score: {score}", expanded=True):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Risk Score", score)
                    c2.metric("Department", dept)
                    c3.metric("MFA Enabled", "✅ Yes" if mfa else "❌ No" if mfa is False else "N/A")
                    st.markdown(f"**Last Activity:** {last_activity}")
                    if factors:
                        st.markdown("**Risk Factors:**")
                        for f in factors:
                            st.markdown(f"- ⚠️ {f}")
                    if recs:
                        st.markdown("**Recommendations:**")
                        for r in recs:
                            st.markdown(f"- 💡 {r}")
        else:
            st.warning(f"No user found matching **'{search_term}'**.")
    else:
        st.info("Enter a username above to view a detailed individual risk profile.")


# ── Main entry point ──────────────────────────────────────────────────────────

def main():
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
        render_compliance_audit(data)
    with tab5:
        render_user_risk_profiles(data)


if __name__ == "__main__":
    main()
