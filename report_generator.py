from datetime import date
from fpdf import FPDF


def _safe(text: str) -> str:
    """Replace non-latin-1 characters with ASCII equivalents for fpdf2 core fonts."""
    replacements = {
        "\u2013": "-", "\u2014": "-", "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"', "\u2022": "*", "\u2026": "...",
        "\u2192": "->", "\u2190": "<-", "\u00b7": ".", "\u00a0": " ",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _get_attr(obj, key, default=""):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _add_header(pdf: FPDF, title: str):
    pdf.set_fill_color(30, 58, 138)
    pdf.rect(0, 0, 210, 20, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_xy(10, 5)
    pdf.cell(0, 10, _safe(title), ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(8)


def _add_section_title(pdf: FPDF, title: str):
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_fill_color(220, 230, 255)
    pdf.cell(0, 8, _safe(title), ln=True, fill=True)
    pdf.ln(2)


def _add_kv(pdf: FPDF, label: str, value: str):
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(70, 7, _safe(label + ":"), ln=False)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, _safe(str(value)), ln=True)


def _add_table(pdf: FPDF, headers: list, rows: list, col_widths: list):
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(200, 210, 240)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 8, _safe(str(h)), border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    for row in rows:
        for i, cell in enumerate(row):
            pdf.cell(col_widths[i], 7, _safe(str(cell)), border=1)
        pdf.ln()
    pdf.ln(3)


def generate_executive_report(data: dict) -> bytes:
    ex = data.get("exec_summary", {})
    alerts = data.get("alerts", [])
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Page 1: Executive Summary ---
    pdf.add_page()
    _add_header(pdf, "AD360 Identity Security Analytics - Executive Report")

    org = ex.get("org_name", "Organization")
    report_date = ex.get("report_date", str(date.today()))
    health = ex.get("overall_health_score", "N/A")
    compliance_avg = ex.get("compliance_average", "N/A")
    mom_change = ex.get("month_over_month_change", "N/A")

    _add_section_title(pdf, "Executive Summary")
    _add_kv(pdf, "Organization", org)
    _add_kv(pdf, "Report Date", report_date)
    _add_kv(pdf, "Overall Health Score", f"{health}/100")
    _add_kv(pdf, "Compliance Average", f"{compliance_avg}%")
    _add_kv(pdf, "Month-over-Month Change", str(mom_change))
    pdf.ln(4)

    _add_section_title(pdf, "Key Performance Indicators")
    kpi_rows = [
        ["Incidents This Month", str(ex.get("incidents_this_month", 0))],
        ["Incidents Last Month", str(ex.get("incidents_last_month", 0))],
        ["Mean Time to Resolve (hrs)", str(ex.get("mttr_hours", 0))],
        ["Open Critical Alerts", str(ex.get("open_critical_alerts", 0))],
        ["Resolved This Week", str(ex.get("resolved_this_week", 0))],
    ]
    _add_table(pdf, ["Metric", "Value"], kpi_rows, [110, 70])

    _add_section_title(pdf, "Top 3 Risks")
    risks = ex.get("top_3_risks", [])
    pdf.set_font("Helvetica", "", 10)
    for i, risk in enumerate(risks[:3], 1):
        pdf.cell(0, 7, _safe(f"  {i}. {risk}"), ln=True)
    pdf.ln(3)

    # --- Page 2: Threat Summary ---
    pdf.add_page()
    _add_header(pdf, "AD360 Identity Security Analytics - Threat Summary")

    _add_section_title(pdf, "Threat Activity Overview")
    threat_rows = [
        ["Failed Logins", str(len(data.get("failed_logins", [])))],
        ["Account Lockouts", str(len(data.get("lockouts", [])))],
        ["Impossible Travel Events", str(len(data.get("impossible_travel", [])))],
        ["Lateral Movement Events", str(len(data.get("lateral", [])))],
        ["Shadow Admin Accounts", str(len(data.get("shadow_admins", [])))],
    ]
    _add_table(pdf, ["Threat Category", "Count"], threat_rows, [120, 60])

    _add_section_title(pdf, "Active Alerts")
    alert_rows = []
    for a in alerts:
        name = _get_attr(a, "name", "Unknown")
        severity = _get_attr(a, "severity", "Unknown")
        alert_rows.append([name[:60], str(severity)])
    if alert_rows:
        _add_table(pdf, ["Alert Name", "Severity"], alert_rows, [140, 40])
    else:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 7, "  No active alerts.", ln=True)
    pdf.ln(3)

    # --- Page 3: Recommendations ---
    pdf.add_page()
    _add_header(pdf, "AD360 Identity Security Analytics - Recommendations")

    _add_section_title(pdf, "Top Remediation Recommendations")
    pdf.set_font("Helvetica", "", 10)

    seen = []
    counter = 1
    for a in alerts:
        remediation = _get_attr(a, "remediation", "")
        if remediation and remediation not in seen:
            seen.append(remediation)
            pdf.set_font("Helvetica", "B", 10)
            alert_name = _get_attr(a, "name", "Alert")
            pdf.cell(0, 7, _safe(f"{counter}. [{alert_name}]"), ln=True)
            pdf.set_font("Helvetica", "", 10)
            if isinstance(remediation, list):
                for step in remediation:
                    pdf.cell(0, 6, _safe(f"   - {str(step)[:100]}"), ln=True)
            else:
                pdf.cell(0, 6, _safe(f"   {str(remediation)[:100]}"), ln=True)
            pdf.ln(1)
            counter += 1

    if counter == 1:
        pdf.set_font("Helvetica", "I", 10)
        pdf.cell(0, 7, _safe("  No specific recommendations at this time."), ln=True)

    return bytes(pdf.output())


def generate_compliance_report(data: dict) -> bytes:
    compliance = data.get("compliance", {})
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Cover Page ---
    pdf.add_page()
    pdf.set_fill_color(30, 58, 138)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_xy(0, 80)
    pdf.cell(210, 15, _safe("AD360 Identity Security"), align="C", ln=True)
    pdf.cell(210, 15, _safe("Compliance Report"), align="C", ln=True)
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 14)
    ex = data.get("exec_summary", {})
    pdf.cell(210, 10, _safe(ex.get("org_name", "Organization")), align="C", ln=True)
    pdf.cell(210, 10, _safe(str(ex.get("report_date", str(date.today())))), align="C", ln=True)
    pdf.set_text_color(0, 0, 0)

    # --- Compliance Scorecard ---
    pdf.add_page()
    _add_header(pdf, "AD360 Identity Security Analytics - Compliance Scorecard")
    _add_section_title(pdf, "Framework Score Summary")

    frameworks = ["GDPR", "HIPAA", "SOX", "PCI_DSS", "ISO_27001", "NIST_800_53", "CIS_AD"]
    score_rows = []
    for fw in frameworks:
        fw_data = compliance.get(fw, {})
        score = fw_data.get("score", "N/A")
        checks = fw_data.get("checks", {})
        total = len(checks)
        passed = sum(1 for v in checks.values() if v is True or v == "Pass")
        score_rows.append([fw.replace("_", " "), f"{score}%", f"{passed}/{total}"])

    _add_table(pdf, ["Framework", "Score", "Checks Passed"], score_rows, [90, 50, 50])

    # --- Per-framework detail pages ---
    for fw in frameworks:
        fw_data = compliance.get(fw, {})
        if not fw_data:
            continue
        checks = fw_data.get("checks", {})
        if not checks:
            continue

        pdf.add_page()
        _add_header(pdf, f"AD360 - {fw.replace('_', ' ')} Compliance Detail")

        score = fw_data.get("score", "N/A")
        _add_section_title(pdf, f"{fw.replace('_', ' ')} - Score: {score}%")

        check_rows = []
        for check_name, result in checks.items():
            if result is True or result == "Pass":
                status = "Pass"
            elif result is False or result == "Fail":
                status = "Fail"
            else:
                status = str(result)
            check_rows.append([check_name[:80], status])

        _add_table(pdf, ["Check", "Result"], check_rows, [150, 30])

    return bytes(pdf.output())
