"""
pages/4_📄_Report_Generator.py — Report Generation Streamlit Page
"""
import streamlit as st
import os
from datetime import datetime
from dotenv import load_dotenv
from utils.styles import inject_global_css
from utils.helpers import page_header, section_header, severity_badge

load_dotenv()
st.set_page_config(page_title="Report Generator | Obsidian Circuit", page_icon="📄", layout="wide")
inject_global_css()

if "report_findings" not in st.session_state:
    st.session_state.report_findings = {}
if "vt_api_key" not in st.session_state:
    st.session_state.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

page_header("📄", "REPORT GENERATOR", "Compile forensic findings into professional reports for technical and non-technical audiences")
st.markdown("---")

findings = st.session_state.report_findings

# ---- Check for queued findings ----
if not findings:
    st.markdown("""
    <div style='background: linear-gradient(135deg, #0a0a1e, #111130);
         border: 2px dashed #222255; border-radius: 16px; padding: 60px;
         text-align: center; margin-top: 20px;'>
        <div style='font-size: 3rem; margin-bottom: 16px;'>📋</div>
        <div style='color: #556688; font-size: 1rem; margin-bottom: 8px;'>No findings queued yet</div>
        <div style='color: #334466; font-size: 0.85rem;'>
            Go to <b>File Analysis</b>, <b>Network Analysis</b>, or <b>Log Analysis</b> and click 
            <b>"Add to Report"</b> after analyzing a file.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ---- Queued modules overview ----
section_header("📦", "Queued Analysis Modules")
sev_colors = {"SAFE": "#00ff9f", "INFO": "#00d4ff", "WARNING": "#ff9900", "CRITICAL": "#ff3333"}

cols = st.columns(len(findings))
for i, (mod_name, mod_data) in enumerate(findings.items()):
    overall = mod_data.get("overall_severity", "INFO")
    color = sev_colors.get(overall, "#aaa")
    icon_map = {"File Analysis": "🔬", "Network Analysis": "🌐", "Log Analysis": "📋"}
    icon = icon_map.get(mod_name, "📊")
    with cols[i]:
        st.markdown(f"""
        <div class='stat-card' style='border-color:{color}33;'>
            <div style='font-size:1.8rem;'>{icon}</div>
            <div class='stat-num' style='color:{color}; font-size:1rem;'>{mod_name}</div>
            <div class='stat-label' style='color:{color};'>{overall}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---- Case Details Form ----
section_header("🗂️", "Case Details")

col1, col2, col3 = st.columns(3)
with col1:
    analyst_name = st.text_input("Analyst Name", value=st.session_state.get("analyst_name", ""),
                                  placeholder="e.g. John Smith")
    st.session_state.analyst_name = analyst_name
with col2:
    case_id = st.text_input("Case ID", value=st.session_state.get("case_id", ""),
                              placeholder="e.g. CASE-2026-001")
    st.session_state.case_id = case_id
with col3:
    case_date = st.text_input("Investigation Date",
                               value=datetime.now().strftime("%Y-%m-%d"),
                               placeholder="YYYY-MM-DD")

st.markdown("<br>", unsafe_allow_html=True)

# ---- Auto-generate executive summary ----
section_header("📝", "Executive Summary")

def build_auto_summary(findings: dict) -> str:
    lines = []
    total_critical = sum(1 for m in findings.values()
                         for f in m.get("all_findings", []) if f.get("severity") == "CRITICAL")
    total_warning  = sum(1 for m in findings.values()
                         for f in m.get("all_findings", []) if f.get("severity") == "WARNING")
    modules = list(findings.keys())

    lines.append(f"This investigation was conducted on {datetime.now().strftime('%B %d, %Y')} "
                 f"using the Obsidian Circuit DFIR Platform. The following module(s) were analyzed: "
                 f"{', '.join(modules)}.")
    lines.append("")

    if total_critical > 0:
        lines.append(f"CRITICAL: The investigation identified {total_critical} high-severity finding(s) that "
                     f"require immediate attention. These findings indicate a significant risk to the environment "
                     f"and should be escalated to the security team without delay.")
    elif total_warning > 0:
        lines.append(f"The investigation found {total_warning} warning-level indicator(s). "
                     f"While these do not indicate confirmed compromise, they warrant further investigation.")
    else:
        lines.append("No critical or high-severity indicators were found. The analyzed artifacts appear normal "
                     "at the surface level. A manual deep-dive review is still recommended.")

    lines.append("")

    for mod_name, mod_data in findings.items():
        overall = mod_data.get("overall_severity", "SAFE")
        all_f = mod_data.get("all_findings", [])
        crit_f = [f for f in all_f if f.get("severity") == "CRITICAL"]
        warn_f = [f for f in all_f if f.get("severity") == "WARNING"]
        lines.append(f"{mod_name}: Overall risk level is {overall}. "
                     f"Found {len(crit_f)} critical and {len(warn_f)} warning indicator(s).")

    lines.append("")
    lines.append("Full technical details are provided in the module sections below. "
                 "All recommendations should be reviewed and actioned according to your organization's incident response plan.")
    return "\n".join(lines)

auto_summary = build_auto_summary(findings)
exec_summary = st.text_area(
    "Executive Summary (auto-generated, editable)",
    value=auto_summary,
    height=220,
    help="This summary is written for non-technical reviewers. You can edit it before generating the report."
)

st.markdown("<br>", unsafe_allow_html=True)

# ---- Findings Preview ----
with st.expander("🔍 Preview All Queued Findings", expanded=False):
    for mod_name, mod_data in findings.items():
        st.markdown(f"#### {mod_name}")
        for f in mod_data.get("all_findings", []):
            sev = f.get("severity", "INFO")
            badge = severity_badge(sev)
            st.markdown(f"<div class='finding-{sev.lower()}'>{badge} — {f.get('description', '')}</div>",
                        unsafe_allow_html=True)
        st.markdown("---")

# ---- Generate Report ----
section_header("⬇️", "Generate & Download Report")

col_pdf, col_html, col_manage = st.columns([1, 1, 1])

from modules.report_generator import generate_html_report, generate_pdf_report

with col_pdf:
    try:
        pdf_bytes = generate_pdf_report(analyst_name, case_id, case_date, exec_summary, findings)
        filename = f"obsidian_circuit_{case_id or 'report'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        st.download_button(
            label="🖨️ Download PDF Report",
            data=pdf_bytes,
            file_name=filename,
            mime="application/pdf",
            use_container_width=True,
            type="primary"
        )
    except Exception as e:
        st.error(f"PDF generation failed: {e}")

with col_html:
    try:
        html_str = generate_html_report(analyst_name, case_id, case_date, exec_summary, findings)
        filename = f"obsidian_circuit_{case_id or 'report'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        st.download_button(
            label="🌐 Download HTML Report",
            data=html_str.encode("utf-8"),
            file_name=filename,
            mime="text/html",
            use_container_width=True
        )
    except Exception as e:
        st.error(f"HTML generation failed: {e}")

with col_manage:
    if st.button("🗑️ Clear All Queued Findings", use_container_width=True):
        st.session_state.report_findings = {}
        st.rerun()

st.markdown("""
<br>
<div style='background: #0a0a1e; border: 1px solid #1a1a4a; border-radius: 10px; padding: 16px 20px; font-size: 0.82rem; color: #556688;'>
    <b style='color: #00d4ff;'>📌 Report Notes:</b><br>
    • <b>HTML report</b>: Dark-themed, browser-viewable, can be printed as PDF from browser (Ctrl+P).<br>
    • <b>PDF report</b>: Formatted for professional distribution and archiving.<br>
    • Reports are generated locally and never sent to external servers.
</div>
""", unsafe_allow_html=True)
