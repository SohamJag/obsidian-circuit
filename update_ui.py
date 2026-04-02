import os
import re

ui_file = r"""    st.markdown("---")
    st.markdown("### 📋 Add to Report")
    col_chk1, col_chk2, col_chk3, col_chk4 = st.columns(4)
    with col_chk1:
        inc_f_flags = st.checkbox("🚨 Suspicious Flags", value=True)
        inc_f_integ = st.checkbox("🔐 Integrity Verification", value=True)
    with col_chk2:
        inc_f_meta = st.checkbox("📊 Metadata", value=True)
        inc_f_entropy = st.checkbox("🌡️ Entropy Meter", value=True)
    with col_chk3:
        inc_f_hash = st.checkbox("🔑 Hashes", value=True)
        inc_f_raw = st.checkbox("🧩 Raw Findings", value=False)
    with col_chk4:
        inc_f_deep = st.checkbox("🗂️ Deep Scan", value=True)
        
    if st.button("➕ Add Selected to Report", type="primary", use_container_width=True):
        rep_data = {
            "overall_severity": result.get("overall_severity", "INFO"),
            "filename": result.get("filename", "Unknown"),
            "file_size": result.get("file_size", 0),
        }
        if inc_f_flags or inc_f_raw:
            rep_data["flags"] = result.get("flags", [])
            rep_data["all_findings"] = result.get("flags", [])
        if inc_f_entropy:
            rep_data["entropy"] = result.get("entropy")
            rep_data["printable_ratio"] = result.get("printable_ratio")
        if inc_f_hash or inc_f_integ:
            rep_data["hashes"] = result.get("hashes", {})
        if inc_f_deep:
            rep_data["embedded_urls"] = result.get("embedded_urls", [])
            rep_data["embedded_ips"] = result.get("embedded_ips", [])
            rep_data["hex_dump"] = result.get("hex_dump", "")
        
        from utils.helpers import add_to_report
        add_to_report("File Analysis", rep_data)

"""

ui_net = r"""
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
"""

ui_log = r"""
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
    if inc_l_flags or inc_l_intel:
        rep_data["all_findings"] = result.get("all_findings", [])
    from utils.helpers import add_to_report
    add_to_report("Log Analysis", rep_data)
"""

def clean_file(path, is_file_analysis=False):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Remove function defs
    content = re.sub(r'^[ \t]*def render_add_to_report.*?\n(?:[ \t]+.*?\n)*', '', content, flags=re.MULTILINE)
    # Remove calls
    content = re.sub(r'^[ \t]*render_add_to_report\([^)]*\)\n', '', content, flags=re.MULTILINE)

    if is_file_analysis:
        content = re.sub(r'^else:\s*\n\s*st\.markdown\("""\s*\n\s*<div style=\'background:linear-gradient', 
                 ui_file + r'else:\n    st.markdown("""\n    <div style=\'background:linear-gradient', 
                 content, flags=re.MULTILINE)
    elif "Network" in path:
        content += "\n" + ui_net
    elif "Log" in path:
        content += "\n" + ui_log

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

clean_file("pages/1_🔬_File_Analysis.py", True)
clean_file("pages/2_🌐_Network_Analysis.py", False)
clean_file("pages/3_📋_Log_Analysis.py", False)
print("Updated all 3 UI files.")
