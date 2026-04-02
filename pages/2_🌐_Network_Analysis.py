"""
pages/2_🌐_Network_Analysis.py — Network Analysis Streamlit Page
Session state persistence: results survive page navigation
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import os
from dotenv import load_dotenv
from utils.styles import inject_global_css
from utils.helpers import page_header, section_header, finding_card, format_bytes, add_to_report
from modules.network_analysis import analyze_pcap

load_dotenv()
st.set_page_config(page_title="Network Analysis | Obsidian Circuit", page_icon="🌐", layout="wide")
inject_global_css()

if "report_findings" not in st.session_state:
    st.session_state.report_findings = {}

page_header("🌐", "NETWORK ANALYSIS",
            "Parse .pcap captures · Port scan detection · DNS tunneling · Data exfiltration · Traffic visualization")
st.markdown("---")

st.info("💡 **Tip**: Download sample pcap files from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) to test this module. Requires **Npcap** on Windows ([npcap.com](https://npcap.com)).")

uploaded = st.file_uploader("Upload a .pcap or .pcapng file", type=["pcap", "pcapng", "cap"])

# --- State persistence ---
if uploaded is not None:
    with st.spinner("⚙️ Parsing packets and running detection algorithms..."):
        result = analyze_pcap(uploaded.read())
    if "error" not in result:
        st.session_state["na_result"] = result
    else:
        st.error(f"❌ Analysis failed: {result['error']}")
        st.stop()
elif "na_result" in st.session_state:
    result = st.session_state["na_result"]
    st.info(f"📋 Showing cached network analysis. Upload a new .pcap to re-analyze.")
else:
    result = None

if result is None:
    st.markdown("""
    <div style='background:linear-gradient(135deg,#0a0a1e,#111130); border:2px dashed #222255;
         border-radius:16px; padding:60px; text-align:center; margin-top:20px;'>
        <div style='font-size:3rem; margin-bottom:16px;'>🌐</div>
        <div style='color:#556688; font-size:1rem;'>Upload a .pcap or .pcapng capture file to begin analysis</div>
        <div style='color:#334466; font-size:0.8rem; margin-top:8px;'>
            Detects: Port Scans · DNS Tunneling · Data Exfiltration · Traffic Anomalies
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
    st.markdown(f"""<div class='stat-card'><div class='stat-num'>{result['total_packets']:,}</div>
        <div class='stat-label'>Total Packets</div></div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class='stat-card'><div class='stat-num'>{result['unique_ips']}</div>
        <div class='stat-label'>Unique IPs</div></div>""", unsafe_allow_html=True)
with c4:
    st.markdown(f"""<div class='stat-card'><div class='stat-num'>{result['dns_queries_total']}</div>
        <div class='stat-label'>DNS Queries</div></div>""", unsafe_allow_html=True)
with c5:
    total_findings = len([f for f in result["all_findings"] if f.get("severity") not in ("SAFE", "INFO")])
    findings_col = "#ff3333" if result["overall_severity"] == "CRITICAL" else "#ff9900" if result["overall_severity"] == "WARNING" else "#00ff9f"
    st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:{findings_col};'>{total_findings}</div>
        <div class='stat-label'>Threat Findings</div></div>""", unsafe_allow_html=True)

st.markdown(f"<div style='color:#444;font-size:0.8rem;margin:8px 0 20px 0;'>⏱️ Capture: "
            f"<b style='color:#aaa;'>{result['start_time']}</b> → <b style='color:#aaa;'>{result['end_time']}</b> "
            f"({result['duration_seconds']}s)</div>", unsafe_allow_html=True)


# ====== TABS ======
tab_flags, tab_overview, tab_conn, tab_det, tab_adv = st.tabs([
    "🚨 Suspicious Flags", "📊 Traffic Overview", "🗺️ Connections", "🔬 Detection Details", "🧬 Advanced Analysis"
])

with tab_flags:
    section_header("🚨", "Suspicious Flags")
    flagged = [f for f in result["all_findings"] if f.get("severity") not in ("SAFE",)]
    if flagged:
        for f in flagged:
            src = f.get("src_ip", "")
            title = f"[{src}] " if src else ""
            title += f.get("description", "Finding")[:85]
            rec = f.get("recommendation", "")
            extra = []
            if "port_count" in f:
                extra.append(f"<b>Unique ports:</b> {f['port_count']}")
            if "bytes_sent" in f:
                extra.append(f"<b>Bytes sent:</b> {format_bytes(f['bytes_sent'])}")
            if "external_dests" in f:
                extra.append(f"<b>External dests:</b> {', '.join(f['external_dests'][:3])}")
            if "query_count" in f:
                extra.append(f"<b>Queries:</b> {f['query_count']}")
            detail = ("  ·  ".join(extra) + "<br>" if extra else "") + (f"💡 {rec}" if rec else "")
            st.markdown(finding_card(title[:90], f.get("description", ""), f.get("severity", "INFO"), detail),
                        unsafe_allow_html=True)
    else:
        st.markdown(finding_card("No Suspicious Network Patterns Detected",
                                 "Traffic capture appears normal across all detection rules.",
                                 "SAFE", "💡 Manual packet inspection is still recommended for thorough analysis."),
                    unsafe_allow_html=True)


with tab_overview:
    col_a, col_b = st.columns(2)
    with col_a:
        section_header("📡", "Protocol Distribution")
        if result["protocol_counts"]:
            proto_df = pd.DataFrame(list(result["protocol_counts"].items()), columns=["Protocol", "Packets"])
            fig = px.pie(proto_df, names="Protocol", values="Packets",
                        color_discrete_sequence=["#00d4ff", "#8b00ff", "#00ff9f", "#ff9900", "#ff3333"],
                        hole=0.4)
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                             font_color="#e0e0f0", legend=dict(bgcolor="rgba(0,0,0,0)"),
                             margin=dict(t=20, b=20))
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        section_header("🏆", "Top Talkers (by bytes out)")
        if result["top_talkers"]:
            tt_df = pd.DataFrame(result["top_talkers"], columns=["IP", "Bytes"])
            tt_df["Label"] = tt_df["Bytes"].apply(format_bytes)
            fig2 = px.bar(tt_df, x="Bytes", y="IP", orientation="h",
                         color="Bytes",
                         color_continuous_scale=[[0, "rgba(0,100,150,0.3)"], [1, "rgb(0,212,255)"]],
                         text="Label")
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                               font_color="#e0e0f0", yaxis=dict(autorange="reversed"),
                               coloraxis_showscale=False, margin=dict(t=20, b=20))
            fig2.update_traces(textposition="outside")
            st.plotly_chart(fig2, use_container_width=True)

    # Summary stats table
    section_header("📋", "Capture Summary")
    summary_rows = [
        ("Total Packets",      f"{result['total_packets']:,}"),
        ("Unique IPs",         str(result["unique_ips"])),
        ("DNS Queries",        str(result["dns_queries_total"])),
        ("Capture Start",      result["start_time"]),
        ("Capture End",        result["end_time"]),
        ("Duration",           f"{result['duration_seconds']}s"),
        ("Port Scan Alerts",   str(len(result.get("port_scan_findings", [])))),
        ("DNS Alerts",         str(len(result.get("dns_findings", [])))),
        ("Exfil Alerts",       str(len(result.get("exfil_findings", [])))),
    ]
    tbl = "<table class='info-table'>" + "".join(
        f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in summary_rows
    ) + "</table>"
    st.markdown(tbl, unsafe_allow_html=True)


with tab_conn:
    section_header("🗺️", "Connection Log (sample)")
    if result["connections_sample"]:
        conn_df = pd.DataFrame(result["connections_sample"])
        cols = [c for c in ["src", "dst", "proto", "sport", "dport", "size", "flags"] if c in conn_df.columns]
        conn_df = conn_df[cols].rename(columns={
            "src": "Source IP", "dst": "Dest IP", "proto": "Protocol",
            "sport": "Src Port", "dport": "Dst Port", "size": "Size (B)", "flags": "TCP Flags"
        })
        # Filters
        col_filter1, col_filter2 = st.columns(2)
        with col_filter1:
            proto_filter = st.multiselect("Filter Protocol", ["TCP", "UDP", "ICMP"],
                                          default=["TCP", "UDP"])
        with col_filter2:
            ip_filter = st.text_input("Filter by IP (source or dest)", placeholder="e.g. 192.168.1.1")

        df_show = conn_df
        if proto_filter:
            df_show = df_show[df_show["Protocol"].isin(proto_filter)]
        if ip_filter.strip():
            mask = (df_show["Source IP"].str.contains(ip_filter, na=False) |
                    df_show["Dest IP"].str.contains(ip_filter, na=False))
            df_show = df_show[mask]

        st.dataframe(df_show, use_container_width=True, height=420)
        st.caption(f"Showing {len(df_show):,} of {len(conn_df):,} sampled connections")
    else:
        st.info("No connection data available.")


with tab_det:
    section_header("🔬", "Detection Details by Category")

    cols_det = st.columns(3)
    cat_data = [
        ("🎯 Port Scan Detection", result.get("port_scan_findings", []), cols_det[0]),
        ("🔡 DNS Anomalies",       result.get("dns_findings", []),       cols_det[1]),
        ("📤 Data Exfiltration",   result.get("exfil_findings", []),     cols_det[2]),
    ]
    for title, findings, col in cat_data:
        with col:
            st.markdown(f"**{title}**")
            if findings:
                for f in findings:
                    sev = f.get("severity", "INFO")
                    badge = f"<span class='badge-{sev.lower()}'>{sev}</span>"
                    ip = f.get("src_ip", "")
                    desc = f.get("description", "")[:120]
                    st.markdown(f"""<div class='{("finding-critical" if sev=="CRITICAL" else "finding-warning")}'>
                        {badge}<br><b style='color:#e0e0f0;'>{ip}</b><br>
                        <span style='color:#aaa;font-size:0.82rem;'>{desc}</span></div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("<div class='finding-safe'><span class='badge-safe'>SAFE</span><br>"
                            "<span style='color:#aaa;font-size:0.82rem;'>No findings.</span></div>",
                            unsafe_allow_html=True)


with tab_adv:
    col_adv1, col_adv2 = st.columns(2)

    with col_adv1:
        section_header("🚩", "TCP Flag Distribution")
        tcp_flags = result.get("tcp_flags", {})
        if tcp_flags:
            flags_df = pd.DataFrame(list(tcp_flags.items()), columns=["Flag", "Count"])
            flag_colors = {"SYN": "#00d4ff", "ACK": "#00ff9f", "RST": "#ff3333",
                           "FIN": "#ff9900", "PSH": "#8b00ff"}
            fig_flags = px.bar(flags_df, x="Flag", y="Count",
                              color="Flag",
                              color_discrete_map=flag_colors,
                              text="Count")
            fig_flags.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                   font_color="#e0e0f0", showlegend=False, margin=dict(t=10, b=10))
            fig_flags.update_traces(textposition="outside")
            st.plotly_chart(fig_flags, use_container_width=True)
            st.caption("High RST count = port scan rejections. High SYN vs ACK = SYN scan or incomplete handshakes.")
        else:
            st.info("No TCP packets in capture.")

    with col_adv2:
        section_header("🌐", "IP Type Classification")
        ip_class = result.get("ip_classification", {})
        if ip_class:
            cls_df = pd.DataFrame(list(ip_class.items()), columns=["Type", "Count"])
            fig_cls = px.pie(cls_df, names="Type", values="Count", hole=0.4,
                            color_discrete_sequence=["#00d4ff","#00ff9f","#ff9900","#8b00ff"])
            fig_cls.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                 font_color="#e0e0f0", legend=dict(bgcolor="rgba(0,0,0,0)"),
                                 margin=dict(t=10, b=10))
            st.plotly_chart(fig_cls, use_container_width=True)

    st.markdown("<br>", unsafe_allow_html=True)
    section_header("🔌", "Top Destination Ports")
    top_ports = result.get("top_dst_ports", [])
    if top_ports:
        ports_df = pd.DataFrame(top_ports, columns=["Port", "Packets"])
        # Add service name annotations
        COMMON_PORTS = {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",25:"SMTP",53:"DNS",
                        3389:"RDP",445:"SMB",3306:"MySQL",8080:"HTTP-Alt",
                        23:"Telnet",110:"POP3",143:"IMAP",6667:"IRC"}
        ports_df["Service"] = ports_df["Port"].apply(lambda p: COMMON_PORTS.get(p, f"Port {p}"))
        ports_df["Label"] = ports_df.apply(lambda r: f"{r['Service']} ({r['Packets']})", axis=1)
        fig_ports = px.bar(ports_df.head(15), x="Packets", y="Service", orientation="h",
                          color="Packets",
                          color_continuous_scale=[[0,"rgba(139,0,255,0.2)"],[1,"rgb(139,0,255)"]],
                          text="Packets")
        fig_ports.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                               font_color="#e0e0f0", yaxis=dict(autorange="reversed"),
                               coloraxis_showscale=False, margin=dict(t=10, b=10))
        fig_ports.update_traces(textposition="outside")
        st.plotly_chart(fig_ports, use_container_width=True)
    else:
        st.info("No port data available.")

    st.markdown("<br>", unsafe_allow_html=True)
    col_adv3, col_adv4 = st.columns(2)

    with col_adv3:
        section_header("🔡", "Top Queried DNS Domains")
        dns_domains = result.get("dns_top_domains", [])
        if dns_domains:
            with st.expander("View DNS Domains", expanded=False):
                dns_df = pd.DataFrame(dns_domains, columns=["Domain", "Queries"])
                st.dataframe(dns_df, use_container_width=True, hide_index=True)
                st.caption("Long subdomains may indicate DNS tunneling.")
        else:
            st.info("No DNS queries found in capture.")
            
    with col_adv4:
        section_header("⚠️", "Suspicious Port Hits")
        susp_ports = result.get("susp_port_findings", [])
        if susp_ports:
            with st.expander(f"View {len(susp_ports)} Suspicious Ports", expanded=True):
                for sp in susp_ports:
                    st.markdown(finding_card(
                        f"Port {sp.get('port')} — {sp.get('label','')}",
                        sp.get("description",""),
                        "WARNING",
                        f"💡 {sp.get('recommendation','')}"
                    ), unsafe_allow_html=True)
        else:
            st.markdown("<div style='color:#555; padding-top:10px; font-size:0.88rem;'>✅ No connections to known suspicious/malicious ports detected.</div>",
                        unsafe_allow_html=True)



st.markdown("---")
st.markdown("### 📋 Add to Report")
col_n1, col_n2, col_n3 = st.columns(3)
with col_n1:
    inc_n_flags = st.checkbox("🚨 Suspicious Flags", value=True)
    inc_n_over = st.checkbox("📊 Traffic Overview", value=True)
with col_n2:
    inc_n_conn = st.checkbox("🗺️ Connections", value=False)
    inc_n_det = st.checkbox("🔬 Detection Details", value=True)
with col_n3:
    inc_n_adv = st.checkbox("🧬 Advanced Analysis", value=True)

if st.button("➕ Add Selected to Report", type="primary", use_container_width=True):
    rep_data = {
        "overall_severity": result.get("overall_severity", "INFO"),
        "start_time": result.get("start_time"),
        "end_time": result.get("end_time"),
        "duration_seconds": result.get("duration_seconds")
    }
    if inc_n_over:
        rep_data["total_packets"] = result.get("total_packets")
        rep_data["unique_ips"] = result.get("unique_ips")
        rep_data["protocol_counts"] = result.get("protocol_counts", {})
        rep_data["top_talkers"] = result.get("top_talkers", [])
    if inc_n_conn:
        rep_data["connections_sample"] = result.get("connections_sample", [])
    if inc_n_flags or inc_n_det:
        rep_data["all_findings"] = result.get("all_findings", [])
    if inc_n_adv:
        rep_data["tcp_flags_breakdown"] = result.get("tcp_flags", {})
        top_dst = result.get("top_dst_ports", [])
        rep_data["top_dest_ports"] = {p: c for p, c in top_dst} if top_dst else {}
        rep_data["ip_classes"] = result.get("ip_classification", {})
        top_dns = result.get("dns_top_domains", [])
        rep_data["dns_query_counts"] = {d: c for d, c in top_dns} if top_dns else {}
    from utils.helpers import add_to_report
    add_to_report("Network Analysis", rep_data)
