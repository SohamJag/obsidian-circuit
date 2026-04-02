"""
pages/3_📋_Log_Analysis.py — Log Analysis Streamlit Page
Session state persistence + detailed output
"""
import streamlit as st
import plotly.express as px
import pandas as pd
import os
from dotenv import load_dotenv
from utils.styles import inject_global_css
from utils.helpers import page_header, section_header, finding_card, add_to_report
from modules.log_analysis import analyze_log

load_dotenv()
st.set_page_config(page_title="Log Analysis | Obsidian Circuit", page_icon="📋", layout="wide")
inject_global_css()

if "report_findings" not in st.session_state:
    st.session_state.report_findings = {}

page_header("📋", "LOG ANALYSIS",
            "Parse auth/access logs · Brute-force detection · Scanner agents · Suspicious path access")
st.markdown("---")

# Sample files tip
with st.expander("💡 Sample Test Files — click to see what's available in `sample_data/`", expanded=False):
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown("""
        **🔴 `sample_auth.log`** → Log Type: `auth`  
        SSH brute-force + successful compromise from `203.0.113.45`

        **🔴 `sample_windows_events.csv`** → Log Type: `windows`  
        Windows Event 4625 brute-force + 4624 successful logon
        """)
    with col_s2:
        st.markdown("""
        **🟠 `sample_apache.log`** → Log Type: `apache`  
        sqlmap/nikto agents, `/.env`, `/.git` access, 5MB POST

        **🔴 `sample_siem_generic.log`** → Log Type: `generic`  
        Log4Shell, C2 beacon, ransomware, SQL injection keywords
        """)
    st.info("📂 `c:\\\\Users\\\\SOHAM\\\\OBSIDIAN CIRCUIT FRESH\\\\sample_data\\\\`")

col_up, col_type = st.columns([3, 1])
with col_up:
    uploaded = st.file_uploader("Upload a log file", type=["log", "txt", "csv", "out"],
                                 help="auth.log · Apache/Nginx · Windows Event CSV · generic text logs")
with col_type:
    log_type = st.selectbox("Log Type", ["auto", "auth", "apache", "windows", "generic"],
                             help="'auto' attempts automatic detection")

# --- State persistence ---
if uploaded is not None:
    try:
        raw_content = uploaded.read().decode("utf-8", errors="replace")
    except Exception as e:
        st.error(f"❌ Could not read file: {e}")
        st.stop()
    with st.spinner("⚙️ Analyzing log entries..."):
        result = analyze_log(raw_content, log_type)
    st.session_state["la_result"] = result
elif "la_result" in st.session_state:
    result = st.session_state["la_result"]
    st.info(f"📋 Showing cached log analysis. Upload a new file to re-analyze.")
else:
    result = None

if result is None:
    st.markdown("""
    <div style='background:linear-gradient(135deg,#0a0a1e,#111130); border:2px dashed #222255;
         border-radius:16px; padding:60px; text-align:center; margin-top:20px;'>
        <div style='font-size:3rem; margin-bottom:16px;'>📋</div>
        <div style='color:#556688;'>Upload a log file to begin analysis</div>
        <div style='color:#334466; font-size:0.8rem; margin-top:8px;'>
            Supports: Linux auth.log · Apache/Nginx access logs · Windows Event Log CSV · Generic text logs
        </div>
    </div>""", unsafe_allow_html=True)
    st.stop()

# ---- Overview Metrics ----
sev_colors = {"SAFE": "#00ff9f", "INFO": "#00d4ff", "WARNING": "#ff9900", "CRITICAL": "#ff3333"}
sev_col = sev_colors.get(result["overall_severity"], "#aaa")

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:{sev_col};'>
        {result['overall_severity']}</div><div class='stat-label'>Overall Severity</div></div>""",
        unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class='stat-card'><div class='stat-num'>{result['total_lines']:,}</div>
        <div class='stat-label'>Total Lines</div></div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class='stat-card'><div class='stat-num'>{result['parsed_events']:,}</div>
        <div class='stat-label'>Parsed Events</div></div>""", unsafe_allow_html=True)
with c4:
    failed_total = sum(result.get("failed_logins_by_ip", {}).values())
    st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:#ff9900;'>{failed_total}</div>
        <div class='stat-label'>Failed Logins</div></div>""", unsafe_allow_html=True)
with c5:
    threat_count = len([f for f in result["all_findings"] if f.get("severity") in ("CRITICAL", "WARNING")])
    t_col = "#ff3333" if result["overall_severity"] == "CRITICAL" else "#ff9900" if result["overall_severity"] == "WARNING" else "#00ff9f"
    st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:{t_col};'>{threat_count}</div>
        <div class='stat-label'>Threat Findings</div></div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ====== TABS ======

tab_flags, tab_stats, tab_events, tab_intel = st.tabs([
    "🚨 Suspicious Flags", "📊 Statistics", "📜 Event Stream", "🔬 Attacker Intelligence"
])

with tab_flags:
    section_header("🚨", "Suspicious Flags")
    actual_flags = [f for f in result["all_findings"] if f.get("severity") not in ("SAFE",)]
    if actual_flags:
        for f in actual_flags:
            extra = []
            if "ip" in f:           extra.append(f"<b>IP:</b> {f['ip']}")
            if "failed_count" in f: extra.append(f"<b>Failed logins:</b> {f['failed_count']}")
            if "success_count" in f and f["success_count"] > 0:
                extra.append(f"<b>⚠️ Successful logins after failures:</b> {f['success_count']}")
            if "path" in f:         extra.append(f"<b>Path:</b> {f['path']}")
            if "agent" in f:        extra.append(f"<b>Agent:</b> <code>{f['agent'][:60]}</code>")
            if "error_count" in f:  extra.append(f"<b>Error responses:</b> {f['error_count']}")
            if "size_bytes" in f:   extra.append(f"<b>Upload size:</b> {f['size_bytes']//1024} KB")
            detail = ("  ·  ".join(extra) + "<br>" if extra else "") + f"💡 {f.get('recommendation', '')}"
            title = f.get("description", "")[:90]
            st.markdown(finding_card(title, f.get("description", ""), f.get("severity", "INFO"), detail),
                        unsafe_allow_html=True)
    else:
        st.markdown(finding_card("No Suspicious Activity Detected",
                                 "No brute-force, scanner agents, or suspicious path accesses found.",
                                 "SAFE", "💡 Manual review of raw logs is still recommended."),
                    unsafe_allow_html=True)


with tab_stats:
    col_a, col_b = st.columns(2)

    with col_a:
        section_header("🎯", "Top Attacker IPs (Failed Logins)")
        failed = result.get("failed_logins_by_ip", {})
        if failed:
            failed_df = pd.DataFrame(list(failed.items()), columns=["IP", "Failed Attempts"])
            failed_df = failed_df.sort_values("Failed Attempts", ascending=True).tail(10)
            fig = px.bar(failed_df, x="Failed Attempts", y="IP", orientation="h",
                        color="Failed Attempts",
                        color_continuous_scale=[[0, "rgba(255,51,51,0.15)"], [1, "rgb(255,51,51)"]])
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                             font_color="#e0e0f0", coloraxis_showscale=False, margin=dict(t=10, b=10))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No failed login data extracted.")

    with col_b:
        section_header("📊", "Event Severity Breakdown")
        events = result.get("events", [])
        if events:
            sev_counts = {}
            for e in events:
                s = e.get("severity", "INFO")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            sev_df = pd.DataFrame(list(sev_counts.items()), columns=["Severity", "Count"])
            color_map = {"CRITICAL": "#ff3333", "WARNING": "#ff9900", "INFO": "#00d4ff", "SAFE": "#00ff9f"}
            fig2 = px.pie(sev_df, names="Severity", values="Count",
                         color="Severity", color_discrete_map=color_map, hole=0.4)
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#e0e0f0", legend=dict(bgcolor="rgba(0,0,0,0)"),
                              margin=dict(t=10, b=10))
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No events to chart.")

    st.markdown("<br>", unsafe_allow_html=True)
    
    # 1. Hourly Activity Timeline (Full Width Anchor)
    hour_counts = result.get("hour_counts", {})
    if hour_counts:
        section_header("🕐", "Hourly Activity Timeline")
        hours_sorted = sorted(hour_counts.items())
        h_df = pd.DataFrame(hours_sorted, columns=["Hour", "Events"])
        h_df["Hour_Label"] = h_df["Hour"].apply(lambda h: f"{h:02d}:00")
        fig_h = px.bar(h_df, x="Hour_Label", y="Events",
                      color="Events",
                      color_continuous_scale=[[0,"rgba(0,212,255,0.2)"],[1,"rgb(0,212,255)"]],
                      text="Events")
        fig_h.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                           font_color="#e0e0f0", coloraxis_showscale=False,
                           xaxis_title="Hour of Day", yaxis_title="Event Count",
                           margin=dict(t=10, b=10))
        fig_h.update_traces(textposition="outside")
        st.plotly_chart(fig_h, use_container_width=True)
        peak_hour = max(hour_counts, key=hour_counts.get)
        st.caption(f"Peak activity at **{peak_hour:02d}:00** with {hour_counts[peak_hour]} events. "
                  f"Unusual late-night or off-hours spikes may indicate automated attacks.")
        st.markdown("<br>", unsafe_allow_html=True)

    # 2. Web Metrics Row (Methods & Status)
    method_counts = result.get("method_counts", {})
    status_counts = result.get("status_counts", {})
    if method_counts or status_counts:
        col_w1, col_w2 = st.columns(2)
        with col_w1:
            if method_counts:
                section_header("📡", "HTTP Method Breakdown")
                method_df = pd.DataFrame(list(method_counts.items()), columns=["Method", "Count"])
                method_colors = {"GET": "#00d4ff", "POST": "#8b00ff", "PUT": "#ff9900",
                                "DELETE": "#ff3333", "HEAD": "#00ff9f", "OPTIONS": "#555"}
                fig_m = px.bar(method_df.sort_values("Count", ascending=False),
                              x="Method", y="Count",
                              color="Method", color_discrete_map=method_colors, text="Count")
                fig_m.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                   font_color="#e0e0f0", showlegend=False, margin=dict(t=10, b=10))
                fig_m.update_traces(textposition="outside")
                st.plotly_chart(fig_m, use_container_width=True)
        with col_w2:
            if status_counts:
                section_header("📈", "HTTP Status Code Breakdown")
                status_df = pd.DataFrame(list(status_counts.items()), columns=["Status", "Count"])
                status_df["Category"] = status_df["Status"].apply(
                    lambda s: "5xx Server Error" if s >= 500 else
                              "4xx Client Error" if s >= 400 else
                              "3xx Redirect" if s >= 300 else "2xx Success")
                cat_colors = {"2xx Success": "#00ff9f", "3xx Redirect": "#00d4ff",
                              "4xx Client Error": "#ff9900", "5xx Server Error": "#ff3333"}
                fig3 = px.bar(status_df.sort_values("Status"), x="Status", y="Count",
                             color="Category", color_discrete_map=cat_colors, text="Count")
                fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                  font_color="#e0e0f0", margin=dict(t=10, b=10))
                st.plotly_chart(fig3, use_container_width=True)
        st.markdown("<br>", unsafe_allow_html=True)

    # 3. Web Intel Row (User Agents & Paths)
    agent_counts = result.get("agent_counts", {})
    top_paths = result.get("top_paths", [])
    if agent_counts or top_paths:
        col_ua1, col_ua2 = st.columns(2)
        with col_ua1:
            if agent_counts:
                section_header("🕵️", "User-Agent Frequency")
                with st.expander(f"View {len(agent_counts)} User-Agents", expanded=True):
                    agent_df = pd.DataFrame(list(agent_counts.items()), columns=["User-Agent", "Requests"])
                    agent_df = agent_df.sort_values("Requests", ascending=False)
                    st.dataframe(agent_df, use_container_width=True, hide_index=True)
                    st.caption("Unfamiliar or tool-like agents (curl, python-requests, sqlmap) may indicate automated scanning.")
        with col_ua2:
            if top_paths:
                section_header("🔗", "Most Accessed Paths")
                with st.expander(f"View {len(top_paths)} Paths", expanded=True):
                    paths_df = pd.DataFrame(top_paths, columns=["Path", "Hits"])
                    def highlight_path(row):
                        sensitive = ["admin", ".env", ".git", "passwd", "phpMyAdmin", "backup", "wp-admin"]
                        if any(s in row["Path"] for s in sensitive):
                            return ["background: rgba(255,51,51,0.1)", "color: #ff9999"]
                        return ["", ""]
                    st.dataframe(paths_df.style.apply(highlight_path, axis=1),
                                 use_container_width=True, hide_index=True)
        st.markdown("<br>", unsafe_allow_html=True)

    # 4. Windows Log Row (Event IDs & Logon Types)
    event_id_counts = result.get("event_id_counts", {})
    logon_types = result.get("logon_types", {})
    if event_id_counts or logon_types:
        col_win1, col_win2 = st.columns(2)
        with col_win1:
            if event_id_counts:
                WIN_EVENT_IDS = {
                    "4625": "Failed Logon", "4624": "Successful Logon", "4634": "Logoff",
                    "4648": "Explicit Credentials", "4776": "Credential Validation",
                    "4688": "Process Created", "7045": "Service Installed",
                }
                section_header("🪟", "Windows Event ID Breakdown")
                eid_rows = [(WIN_EVENT_IDS.get(eid, f"Event {eid}"), eid, count)
                            for eid, count in sorted(event_id_counts.items(), key=lambda x: -x[1])]
                eid_df = pd.DataFrame(eid_rows, columns=["Event Name", "Event ID", "Count"])
                st.dataframe(eid_df, use_container_width=True, hide_index=True)
        with col_win2:
            if logon_types:
                section_header("🔐", "Logon Type Distribution")
                lt_df = pd.DataFrame(list(logon_types.items()), columns=["Logon Type", "Count"])
                fig_lt = px.pie(lt_df, names="Logon Type", values="Count", hole=0.4,
                               color_discrete_sequence=["#00d4ff","#00ff9f","#ff9900","#ff3333","#8b00ff"])
                fig_lt.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                    font_color="#e0e0f0", legend=dict(bgcolor="rgba(0,0,0,0)"),
                                    margin=dict(t=10, b=10))
                st.plotly_chart(fig_lt, use_container_width=True)
                st.caption("RDP (Type 10) and Network (Type 3) logins from external IPs are high-risk indicators.")
        st.markdown("<br>", unsafe_allow_html=True)

    # 5. Auth Log Row (Targeted Accounts & Success/Fail Ratio)
    failed_users = result.get("top_failed_users", {})
    total_success = sum(result.get("success_logins_by_ip", {}).values())
    total_failed  = sum(result.get("failed_logins_by_ip", {}).values())
    if failed_users or (total_failed > 0 or total_success > 0):
        col_auth1, col_auth2 = st.columns(2)
        with col_auth1:
            if failed_users:
                section_header("👤", "Most Targeted Accounts")
                users_df = pd.DataFrame(list(failed_users.items()), columns=["Username", "Failed Attempts"])
                users_df = users_df.sort_values("Failed Attempts", ascending=False)
                st.dataframe(users_df.head(10), use_container_width=True, hide_index=True)
        with col_auth2:
            if total_failed > 0 or total_success > 0:
                section_header("⚖️", "Login Success vs Failure Ratio")
                col_r1, col_r2 = st.columns(2)
                with col_r1:
                    st.metric("Total Failed Logins", f"{total_failed:,}")
                with col_r2:
                    st.metric("Total Successful Logins", f"{total_success:,}")
                st.markdown("<br>", unsafe_allow_html=True)
                ratio = round(total_failed / max(total_success, 1), 1)
                st.metric("Failed:Success Ratio", f"{ratio}:1",
                          delta="High — Brute Force" if ratio > 10 else "Normal")


with tab_events:
    section_header("📜", "Parsed Event Stream")
    events = result.get("events", [])
    if events:
        col_sev, col_cat = st.columns(2)
        with col_sev:
            sev_filter = st.multiselect("Filter Severity",
                ["CRITICAL", "WARNING", "INFO", "SAFE"], default=["CRITICAL", "WARNING", "INFO"])
        with col_cat:
            all_cats = sorted(set(e.get("category", "OTHER") for e in events))
            cat_filter = st.multiselect("Filter Category", all_cats, default=all_cats)

        filtered = [e for e in events
                    if e.get("severity", "INFO") in sev_filter
                    and e.get("category", "OTHER") in cat_filter]

        if filtered:
            display_cols = ["timestamp", "ip", "user", "event", "severity", "category"]
            ev_df = pd.DataFrame([{k: e.get(k, "-") for k in display_cols} for e in filtered])
            ev_df.columns = ["Timestamp", "IP", "User", "Event", "Severity", "Category"]
            st.dataframe(ev_df, use_container_width=True, height=450)
            st.caption(f"Showing {len(filtered):,} of {len(events):,} events")

            # Raw log lines expander
            with st.expander("📄 View Raw Log Lines for Selected Events"):
                for e in filtered[:50]:
                    raw = e.get("raw", "")
                    if raw:
                        sev = e.get("severity", "INFO")
                        col = sev_colors.get(sev, "#aaa")
                        st.markdown(f"<div style='font-family:monospace; font-size:0.78rem; "
                                    f"color:{col}; border-left:2px solid {col}; "
                                    f"padding:4px 10px; margin:2px 0;'>{raw}</div>",
                                    unsafe_allow_html=True)
        else:
            st.info("No events match your filters.")
    else:
        st.info("No parseable events found in log.")


with tab_intel:
    section_header("🔬", "Attacker Intelligence Summary")
    failed = result.get("failed_logins_by_ip", {})
    success = result.get("success_logins_by_ip", {})

    if failed or success:
        all_ips = sorted(set(list(failed.keys()) + list(success.keys())))
        intel_rows = []
        for ip in all_ips:
            f_count = failed.get(ip, 0)
            s_count = success.get(ip, 0)
            is_external = not any(ip.startswith(p) for p in
                ("10.", "192.168.", "172.", "127.", "::1"))
            status = "🔴 COMPROMISED" if f_count >= 5 and s_count > 0 else \
                     "🟠 BRUTE FORCE" if f_count >= 5 else \
                     "🟢 NORMAL" if f_count == 0 else "🔵 SUSPICIOUS"
            intel_rows.append({
                "IP Address": ip,
                "Origin": "🌍 External" if is_external else "🏠 Internal",
                "Failed": f_count,
                "Successful": s_count,
                "Assessment": status,
            })

        intel_df = pd.DataFrame(intel_rows).sort_values("Failed", ascending=False)
        st.dataframe(intel_df, use_container_width=True, hide_index=True)

        # IPs with both failures and successes = highest risk
        compromised = [(ip, failed.get(ip, 0), success.get(ip, 0))
                       for ip in all_ips if failed.get(ip, 0) >= 3 and success.get(ip, 0) > 0]
        if compromised:
            st.markdown("<br>", unsafe_allow_html=True)
            section_header("🔑", "Likely Compromised Accounts")
            for ip, fc, sc in compromised:
                st.markdown(f"""
                <div class='finding-critical'>
                    <b style='color:#ff3333;'>🔴 HIGH RISK: {ip}</b><br>
                    <span style='color:#ffaaaa;'>{fc} failed attempts followed by {sc} successful login(s). 
                    This pattern strongly indicates a <b>successful brute-force attack</b>.</span><br>
                    <span style='color:#ff9900; font-size:0.82rem;'>
                    💡 Immediately check what this IP did after logging in. Review session activity, 
                    file changes, and lateral movement indicators.
                    </span>
                </div>""", unsafe_allow_html=True)
    else:
        st.info("No IP-level login intelligence available for this log format.")



st.markdown("---")
st.markdown("### 📋 Add to Report")
col_l1, col_l2 = st.columns(2)
with col_l1:
    inc_l_flags = st.checkbox("🚨 Suspicious Flags", value=True)
    inc_l_stats = st.checkbox("📊 Statistics", value=True)
with col_l2:
    inc_l_events = st.checkbox("📜 Event Stream", value=False)
    inc_l_intel = st.checkbox("🔬 Attacker Intelligence", value=True)

if st.button("➕ Add Selected to Report", type="primary", use_container_width=True):
    rep_data = {
        "overall_severity": result.get("overall_severity", "INFO"),
        "log_type": result.get("log_type", "unknown")
    }
    if inc_l_stats:
        rep_data["total_lines"] = result.get("total_lines")
        rep_data["parsed_events"] = result.get("parsed_events")
        rep_data["hour_counts"] = result.get("hour_counts", {})
        rep_data["agent_counts"] = result.get("agent_counts", {})
        rep_data["event_id_counts"] = result.get("event_id_counts", {})
        rep_data["logon_types"] = result.get("logon_types", {})
        rep_data["method_counts"] = result.get("method_counts", {})
        rep_data["status_counts"] = result.get("status_counts", {})
        rep_data["top_paths"] = result.get("top_paths", [])
    if inc_l_flags or inc_l_intel:
        rep_data["all_findings"] = result.get("all_findings", [])
    if inc_l_intel:
        rep_data["failed_logins_by_ip"] = result.get("failed_logins_by_ip", {})
        rep_data["success_logins_by_ip"] = result.get("success_logins_by_ip", {})
    if inc_l_events:
        rep_data["events"] = result.get("events", [])
    from utils.helpers import add_to_report
    add_to_report("Log Analysis", rep_data)
