"""
utils/helpers.py — Shared utilities for Obsidian Circuit
"""
import streamlit as st
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": "#ff3333",
    "WARNING":  "#ff9900",
    "INFO":     "#00d4ff",
    "SAFE":     "#00ff9f",
    "LOW":      "#aaaacc",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "WARNING":  "🟠",
    "INFO":     "🔵",
    "SAFE":     "🟢",
    "LOW":      "⚪",
}

SEVERITY_CLASS = {
    "CRITICAL": "finding-critical",
    "WARNING":  "finding-warning",
    "INFO":     "finding-info",
    "SAFE":     "finding-safe",
    "LOW":      "finding-info",
}

BADGE_CLASS = {
    "CRITICAL": "badge-critical",
    "WARNING":  "badge-warning",
    "INFO":     "badge-info",
    "SAFE":     "badge-safe",
    "LOW":      "badge-info",
}


def severity_badge(level: str) -> str:
    cls = BADGE_CLASS.get(level.upper(), "badge-info")
    emoji = SEVERITY_EMOJI.get(level.upper(), "⚪")
    return f"<span class='{cls}'>{emoji} {level.upper()}</span>"


def finding_card(title: str, description: str, severity: str, detail: str = "") -> str:
    cls = SEVERITY_CLASS.get(severity.upper(), "finding-info")
    badge = severity_badge(severity)
    detail_html = f"<div style='margin-top:8px; color:#777799; font-size:0.82rem; font-family:\"JetBrains Mono\",monospace;'>{detail}</div>" if detail else ""
    return f"""
    <div class='{cls}'>
        <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;'>
            <span style='font-weight:600; color:#e0e0f0;'>{title}</span>
            {badge}
        </div>
        <div style='color:#aaaacc; font-size:0.88rem;'>{description}</div>
        {detail_html}
    </div>
    """


def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def format_timestamp(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def add_to_report(module: str, findings: dict):
    """Queue module findings into session state for report generation."""
    if "report_findings" not in st.session_state:
        st.session_state.report_findings = {}
    st.session_state.report_findings[module] = findings
    st.success(f"✅ **{module}** findings added to report queue!")


def page_header(icon: str, title: str, subtitle: str):
    st.markdown(f"""
    <div class='page-title'>{icon} {title}</div>
    <div class='page-subtitle'>{subtitle}</div>
    """, unsafe_allow_html=True)


def section_header(icon: str, title: str):
    st.markdown(f"""
    <div class='section-header'>
        <span style='font-size:1.4rem;'>{icon}</span>
        <h3>{title}</h3>
    </div>
    """, unsafe_allow_html=True)
