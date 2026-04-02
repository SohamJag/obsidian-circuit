"""
Obsidian Circuit - Main Application Entry Point
A modular DFIR tool built with Python and Streamlit
"""
import streamlit as st
from utils.styles import inject_global_css

# --- Page Configuration ---
st.set_page_config(
    page_title="Obsidian Circuit | DFIR Tool",
    page_icon="🔮",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'About': "**Obsidian Circuit** — Modular DFIR Tool v1.0\nBuilt for cybersecurity professionals, students, and forensic analysts."
    }
)

inject_global_css()

# Initialize session state
if "report_findings" not in st.session_state:
    st.session_state.report_findings = {}
if "vt_api_key" not in st.session_state:
    st.session_state.vt_api_key = ""
if "analyst_name" not in st.session_state:
    st.session_state.analyst_name = ""
if "case_id" not in st.session_state:
    st.session_state.case_id = ""

# --- Sidebar Global Settings ---
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding: 10px 0 20px 0;'>
        <span style='font-size:2.5rem;'>🔮</span>
        <div style='font-size:1.3rem; font-weight:800; 
             background: linear-gradient(90deg, #00d4ff, #8b00ff);
             -webkit-background-clip: text; -webkit-text-fill-color: transparent;
             letter-spacing:2px;'>Obsidian Circuit</div>
        <div style='color:#666; font-size:0.75rem; letter-spacing:1px;'>DFIR PLATFORM v1.0</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style='color:#444; font-size:0.7rem; text-align:center;'>
        Navigate using pages above↑<br>
        <span style='color:#00d4ff;'>●</span> File Analysis &nbsp;
        <span style='color:#8b00ff;'>●</span> Network &nbsp;
        <span style='color:#00ff9f;'>●</span> Logs
    </div>
    """, unsafe_allow_html=True)

# --- Home Content ---
st.markdown("""
<div class='hero-banner'>
    <div class='hero-title'>🔮 OBSIDIAN CIRCUIT</div>
    <div class='hero-sub'>Digital Forensics & Incident Response Platform</div>
</div>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class='module-card card-blue'>
        <div class='module-icon'>🔬</div>
        <div class='module-name'>File Analysis</div>
        <div class='module-desc'>Extract file metadata and cryptographic hashes. Detect MIME mismatches,
        suspicious timestamps, unsafe permissions, and scan against VirusTotal threat intel.</div>
        <div class='module-tag'>→ Page: File Analysis</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class='module-card card-purple'>
        <div class='module-icon'>🌐</div>
        <div class='module-name'>Network Analysis</div>
        <div class='module-desc'>Parse .pcap captures to detect port scans, DNS tunneling,
        data exfiltration, and visualize traffic patterns with interactive charts.</div>
        <div class='module-tag'>→ Page: Network Analysis</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class='module-card card-green'>
        <div class='module-icon'>📋</div>
        <div class='module-name'>Log Analysis</div>
        <div class='module-desc'>Classify auth/access log entries. Detect brute-force attacks,
        unauthorized access, suspicious path traversal, and external uploads.</div>
        <div class='module-tag'>→ Page: Log Analysis</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Stats row
col_a, col_b, col_c, col_d = st.columns(4)
with col_a:
    st.markdown("""<div class='stat-card'><div class='stat-num'>3</div><div class='stat-label'>Analysis Modules</div></div>""", unsafe_allow_html=True)
with col_b:
    st.markdown("""<div class='stat-card'><div class='stat-num'>15+</div><div class='stat-label'>Detection Rules</div></div>""", unsafe_allow_html=True)
with col_c:
    st.markdown("""<div class='stat-card'><div class='stat-num'>PDF+HTML</div><div class='stat-label'>Report Formats</div></div>""", unsafe_allow_html=True)
with col_d:
    st.markdown("""<div class='stat-card'><div class='stat-num'>VT</div><div class='stat-label'>Threat Intel</div></div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("""
<div style='background: linear-gradient(135deg, #111130, #1a1a3e); border: 1px solid #222255;
     border-radius: 12px; padding: 20px 28px;'>
    <b style='color:#00d4ff;'>🚀 Quick Start</b><br><br>
    <span style='color:#aaa;'>
    1. Use the <b style='color:#fff;'>sidebar navigation</b> to select a module.<br>
    2. Upload your file (binary, .pcap, or log file).<br>
    3. Click <b style='color:#fff;'>Analyze</b> and review findings.<br>
    4. Click <b style='color:#00ff9f;'>Add to Report</b> to queue findings.<br>
    5. Head to <b style='color:#fff;'>Report Generator</b> to export a professional PDF/HTML report.
    </span>
</div>
""", unsafe_allow_html=True)
