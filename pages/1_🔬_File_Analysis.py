"""
pages/1_🔬_File_Analysis.py — File Analysis Streamlit Page
Session state persistence: results survive page navigation
"""
import streamlit as st
import os
from dotenv import load_dotenv
from utils.styles import inject_global_css
from utils.helpers import page_header, section_header, finding_card, format_bytes, add_to_report
from utils.virustotal import vt_hash_lookup, render_vt_result
from modules.file_analysis import analyze_file

load_dotenv()
st.set_page_config(page_title="File Analysis | Obsidian Circuit", page_icon="🔬", layout="wide")
inject_global_css()

# --- Session state init ---
if not st.session_state.get("vt_api_key"):
    st.session_state.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
if "report_findings" not in st.session_state:
    st.session_state.report_findings = {}

page_header("🔬", "FILE ANALYSIS",
            "Metadata · Hashes · Entropy · MIME & Magic Byte check · Integrity Verification · VirusTotal")
st.markdown("---")

# Sample tip expander
with st.expander("💡 Sample Test Files — click to see what's available in `sample_data/`", expanded=False):
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown("""
        **🟠 `sample_mime_mismatch.pdf`** — CRITICAL finding demo
        Text file disguised as PDF — triggers MIME + Magic Bytes mismatch.
        **Test**: Upload → Findings tab → expect 🔴 CRITICAL flags.
        """)
    with col_s2:
        st.markdown("""
        **🟢 `sample_clean.pdf`** — Clean file demo
        Valid minimal PDF. Expect 🟢 SAFE + run VirusTotal lookup on Hashes tab.
        """)
    st.info("📂 `c:\\\\Users\\\\SOHAM\\\\OBSIDIAN CIRCUIT FRESH\\\\sample_data\\\\` — or upload any real file.")

# --- File uploader ---
uploaded = st.file_uploader("Upload any file for forensic analysis", type=None,
                             help="Supports any file type. Max 200 MB.")

# --- Determine result to show (new upload OR cached) ---
if uploaded is not None:
    with st.spinner("⚙️ Analyzing file — computing hashes, entropy, MIME detection..."):
        result = analyze_file(uploaded)
    st.session_state["fa_result"] = result
    st.session_state["fa_vt_result"] = None  # reset VT on new upload
elif "fa_result" in st.session_state:
    result = st.session_state["fa_result"]
    st.info(f"📋 Showing cached analysis for **{result['filename']}**. Upload a new file to re-analyze.")
else:
    result = None

# --- Display results ---
if result:
    # ---- Severity color ----
    sev_colors = {"SAFE": "#00ff9f", "INFO": "#00d4ff", "WARNING": "#ff9900", "CRITICAL": "#ff3333"}
    sev_col = sev_colors.get(result["overall_severity"], "#aaa")

    # ---- Top metrics ----
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:{sev_col};'>
            {result['overall_severity']}</div><div class='stat-label'>Overall Severity</div></div>""",
            unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='stat-card'><div class='stat-num'>{result['flag_count']}</div>
            <div class='stat-label'>Suspicious Flags</div></div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='stat-card'><div class='stat-num'>{format_bytes(result['file_size'])}</div>
            <div class='stat-label'>File Size</div></div>""", unsafe_allow_html=True)
    with c4:
        entropy = result.get("entropy", 0)
        ent_color = "#ff3333" if entropy > 7.5 else "#ff9900" if entropy > 6.8 else "#00ff9f"
        st.markdown(f"""<div class='stat-card'><div class='stat-num' style='color:{ent_color};'>
            {entropy:.2f}</div><div class='stat-label'>Entropy (0-8)</div></div>""", unsafe_allow_html=True)
    with c5:
        st.markdown(f"""<div class='stat-card'><div class='stat-num'>
            {result.get('printable_ratio', 0)}%</div>
            <div class='stat-label'>Printable Chars</div></div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)


    # ====== DETAIL TABS ======
    tab_flags, tab_integrity, tab_meta, tab_entropy, tab_hashes, tab_raw, tab_deep = st.tabs([
        "🚨 Suspicious Flags", "🔐 Integrity Verification", "📊 Metadata", "🌡️ Entropy Meter", "🔑 Hashes", "🧩 Raw Findings", "🗂️ Deep Scan"
    ])

    with tab_flags:
        section_header("🚨", "Suspicious Flags")
        actual_flags = [f for f in result["flags"] if f["severity"] != "SAFE"]
        if actual_flags:
            for flag in actual_flags:
                st.markdown(finding_card(flag["title"], flag["description"], flag["severity"],
                                         f"💡 {flag['recommendation']}"), unsafe_allow_html=True)
        else:
            st.markdown(finding_card(
                "No Suspicious Indicators Found",
                "File metadata, MIME type, entropy, and permissions appear normal.",
                "SAFE", "💡 Always verify the file source regardless of automated scan results."
            ), unsafe_allow_html=True)
            

    with tab_integrity:
        section_header("🔐", "File Integrity Verification")
        st.markdown("""<div style='color:#7788bb; font-size:0.88rem; margin-bottom:12px;'>
            Paste a known-good baseline hash to verify the file has not been tampered with.
            Supports MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars).
        </div>""", unsafe_allow_html=True)

        col_b1, col_b2 = st.columns([4, 1])
        with col_b1:
            baseline_hash = st.text_input(
                "Baseline Hash",
                placeholder="e.g. a1b2c3d4... (paste the original / trusted hash here)",
                help="This hash comes from a trusted source — vendor website, NIST, VirusTotal, etc.",
                key="integrity_baseline"
            )
        with col_b2:
            st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
            check_btn = st.button("🔍 Verify", use_container_width=True)

        if baseline_hash or check_btn:
            baseline_clean = baseline_hash.strip().lower()
            hashes = result["hashes"]
            match_algo = None
            for algo, val in hashes.items():
                if val == baseline_clean:
                    match_algo = algo
                    break

            hash_len = len(baseline_clean)
            algo_guess = {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(hash_len, None)

            if match_algo:
                st.markdown(f"""
                <div class='finding-safe'>
                    <div style='font-size:1.3rem; font-weight:800; color:#00ff9f; margin-bottom:8px;'>
                        ✅ INTEGRITY VERIFIED
                    </div>
                    <div style='color:#aaa;'>The file's <b style='color:#e0e0f0;'>{match_algo.upper()}</b> hash 
                    matches the provided baseline. <b>No tampering detected.</b></div>
                    <div style='font-family:monospace; color:#00ff9f; font-size:0.8rem; margin-top:8px;'>
                        {baseline_clean}
                    </div>
                </div>""", unsafe_allow_html=True)
            elif baseline_clean:
                current_hash = hashes.get(algo_guess.lower() if algo_guess else "", "N/A")
                st.markdown(f"""
                <div class='finding-critical'>
                    <div style='font-size:1.3rem; font-weight:800; color:#ff3333; margin-bottom:8px;'>
                        🔴 TAMPERED — HASH MISMATCH DETECTED
                    </div>
                    <div style='color:#ffaaaa; margin-bottom:12px;'>
                        The file does <b>NOT</b> match the provided baseline hash. 
                        The file may have been modified, corrupted, or replaced.
                    </div>
                    <table style='width:100%; font-size:0.82rem; font-family:monospace;'>
                        <tr><td style='color:#777; width:120px;'>Algorithm:</td>
                            <td style='color:#e0e0f0;'>{algo_guess or "Unknown (check hash length)"}</td></tr>
                        <tr><td style='color:#777;'>Expected:</td>
                            <td style='color:#ff9999;'>{baseline_clean}</td></tr>
                        <tr><td style='color:#777;'>Got:</td>
                            <td style='color:#ff3333;'>{current_hash if current_hash != "N/A" else "N/A — hash length doesn't match MD5/SHA1/SHA256"}</td></tr>
                    </table>
                    <div style='margin-top:10px; color:#ff9900; font-size:0.83rem;'>
                        💡 Recommendation: Do not trust this file. Preserve it as evidence and obtain a clean copy from a trusted source.
                    </div>
                </div>""", unsafe_allow_html=True)


    with tab_meta:
        section_header("📊", "File Metadata")
        meta_rows = [
            ("Filename",           result["filename"]),
            ("Extension",          result["extension"] or "None"),
            ("Detected MIME",      result["detected_mime"]),
            ("File Size",          format_bytes(result["file_size"])),
            ("Permissions",        result["permissions"]),
            ("World-Writable",     "⚠️ YES" if result["is_world_writable"] else "✅ No"),
            ("Executable Bit",     "⚠️ YES" if result["is_executable"] else "No"),
            ("Shannon Entropy",    f"{result.get('entropy', 0):.4f} / 8.00"),
            ("Printable Ratio",    f"{result.get('printable_ratio', 0):.1f}%"),
        ]
        table_html = "<table class='info-table'>" + "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in meta_rows
        ) + "</table>"
        st.markdown(table_html, unsafe_allow_html=True)



    with tab_entropy:
        section_header("🌡️", "Entropy Analysis")
        ent = result.get("entropy", 0)
        ent_pct = int((ent / 8.0) * 100)
        ent_color = "#ff3333" if ent > 7.5 else "#ff9900" if ent > 6.8 else "#00d4ff" if ent > 4 else "#00ff9f"
        ent_label = "🔴 Encrypted/Packed" if ent > 7.5 else "🟠 High — Review" if ent > 6.8 else "🔵 Normal" if ent > 3 else "🟢 Very Low"
        st.markdown(f"""
        <div style='margin-top:10px; margin-bottom:10px;'>
            <div style='color:#7788bb; font-size:0.8rem; margin-bottom:8px; letter-spacing:1px; font-weight:bold;'>ENTROPY METER</div>
            <div style='background:#111130; border-radius:8px; height:18px; overflow:hidden; border:1px solid #222255;'>
                <div style='background:{ent_color}; width:{ent_pct}%; height:100%; border-radius:8px;
                    box-shadow: 0 0 12px {ent_color}88; transition: width 0.5s;'></div>
            </div>
            <div style='display:flex; justify-content:space-between; margin-top:6px;'>
                <span style='color:#555; font-size:0.75rem;'>0 (uniform)</span>
                <span style='color:{ent_color}; font-size:0.82rem;'>{ent:.4f} bits — {ent_label}</span>
                <span style='color:#555; font-size:0.75rem;'>8 (random)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


    with tab_hashes:
        section_header("🔑", "Cryptographic Hashes")
        st.markdown("<div style='color:#7788bb; margin-bottom:16px; font-size:0.88rem;'>Use these to verify integrity or cross-reference threat intel databases. Paste one into the Integrity Verifier above.</div>",
                    unsafe_allow_html=True)
        for algo, val in result["hashes"].items():
            st.markdown(f"<div style='color:#aaa; font-size:0.78rem; margin-top:12px; text-transform:uppercase; letter-spacing:1px;'>📌 {algo}</div>",
                        unsafe_allow_html=True)
            st.markdown(f"<div class='hash-box'>{val}</div>", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        section_header("🧬", "VirusTotal Threat Intelligence")
        vt_key = st.session_state.get("vt_api_key", "")
        if vt_key:
            vt_c1, vt_c2, vt_c3 = st.columns(3)
            with vt_c1:
                if st.button("🔍 Check MD5", use_container_width=True, key="vt_btn_md5"):
                    with st.spinner("Querying VirusTotal (MD5)..."):
                        st.session_state["fa_vt_result"] = vt_hash_lookup(result["hashes"]["md5"], vt_key)
            with vt_c2:
                if st.button("🔍 Check SHA1", use_container_width=True, key="vt_btn_sha1"):
                    with st.spinner("Querying VirusTotal (SHA1)..."):
                        st.session_state["fa_vt_result"] = vt_hash_lookup(result["hashes"]["sha1"], vt_key)
            with vt_c3:
                if st.button("🔍 Check SHA256", use_container_width=True, key="vt_btn_sha256"):
                    with st.spinner("Querying VirusTotal (SHA256)..."):
                        st.session_state["fa_vt_result"] = vt_hash_lookup(result["hashes"]["sha256"], vt_key)
            
            if st.session_state.get("fa_vt_result"):
                render_vt_result(st.session_state["fa_vt_result"])
        else:
            st.info("ℹ️ Configure VIRUSTOTAL_API_KEY in the `.env` file to enable threat intelligence lookup.")


    with tab_raw:
        section_header("🧩", "All Findings (Raw)")
        for flag in result["flags"]:
            st.markdown(finding_card(flag["title"], flag["description"], flag["severity"],
                                     f"💡 {flag.get('recommendation', '')}"), unsafe_allow_html=True)


    with tab_deep:
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            section_header("🔗", "Embedded URLs")
            urls = result.get("embedded_urls", [])
            if urls:
                with st.expander(f"View {len(urls)} URLs", expanded=True):
                    for url in urls:
                        st.markdown(f"<div style='font-family:monospace; font-size:0.8rem; color:#00d4ff; "
                                    f"word-break:break-all; padding:4px 8px; margin:2px 0; "
                                    f"background:#0a0a2e; border-left:2px solid #00d4ff; border-radius:3px;'>"
                                    f"{url}</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='color:#555;'>No embedded URLs found.</div>", unsafe_allow_html=True)

        with col_d2:
            section_header("🌐", "Embedded IP Addresses")
            ips = result.get("embedded_ips", [])
            if ips:
                with st.expander(f"View {len(ips)} IPs", expanded=True):
                    for ip in ips:
                        is_priv = any(ip.startswith(p) for p in ("10.", "192.168.", "172.", "127."))
                        color   = "#aaa" if is_priv else "#ff9900"
                        label   = "private" if is_priv else "external"
                        st.markdown(f"<div style='font-family:monospace; font-size:0.82rem; color:{color}; "
                                    f"padding:4px 8px; margin:2px 0; background:#0a0a2e; "
                                    f"border-left:2px solid {color}; border-radius:3px;'>"
                                    f"{ip} <span style='color:#555; font-size:0.72rem;'>({label})</span></div>",
                                    unsafe_allow_html=True)
            else:
                st.markdown("<div style='color:#555;'>No embedded IPs found.</div>", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        section_header("🔬", "Hex Dump (first 64 bytes)")
        hex_dump = result.get("hex_dump", "")
        if hex_dump:
            with st.expander("View Hex Dump", expanded=False):
                st.markdown(f"<pre style='background:#050510; color:#00ff9f; font-family:monospace; "
                            f"font-size:0.78rem; padding:16px; border-radius:8px; overflow-x:auto; "
                            f"border:1px solid #111133;'>{hex_dump}</pre>", unsafe_allow_html=True)
                st.caption("Offset  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   ASCII")
        else:
            st.info("File is empty — no bytes to display.")


    st.markdown("---")
    st.markdown("### 📋 Add to Report")
    col_chk1, col_chk2, col_chk3, col_chk4 = st.columns(4)
    with col_chk1:
        inc_f_flags = st.checkbox("🚨 Suspicious Flags", value=True)
        inc_f_integ = st.checkbox("🔐 Integrity Verification", value=True)
        inc_f_vt    = st.checkbox("🦠 VirusTotal Scan", value=True)
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
        if inc_f_meta:
            rep_data["detected_mime"] = result.get("detected_mime", "Unknown")
            rep_data["permissions"] = result.get("permissions", "Unknown")
            rep_data["is_world_writable"] = result.get("is_world_writable", False)
            rep_data["is_executable"] = result.get("is_executable", False)
        if inc_f_flags or inc_f_raw:
            rep_data["flags"] = result.get("flags", [])
            rep_data["all_findings"] = result.get("flags", [])
        if inc_f_entropy:
            rep_data["entropy"] = result.get("entropy")
            rep_data["printable_ratio"] = result.get("printable_ratio")
        if inc_f_hash:
            rep_data["hashes"] = result.get("hashes", {})
        if inc_f_integ:
            baseline = st.session_state.get("integrity_baseline", "").strip().lower()
            if baseline:
                # check if it matches any
                match_algo = next((algo for algo, val in result.get("hashes", {}).items() if val == baseline), None)
                rep_data["baseline_hash"] = baseline
                rep_data["baseline_match"] = match_algo
        if inc_f_vt and "fa_vt_result" in st.session_state and st.session_state["fa_vt_result"]:
            rep_data["vt_results"] = st.session_state["fa_vt_result"]
            
        if inc_f_deep:
            rep_data["embedded_urls"] = result.get("embedded_urls", [])
            rep_data["embedded_ips"] = result.get("embedded_ips", [])
            rep_data["hex_dump"] = result.get("hex_dump", "")
        
        from utils.helpers import add_to_report
        add_to_report("File Analysis", rep_data)

else:
    st.markdown("""
    <div style=\'background:linear-gradient(135deg,#0a0a1e,#111130); border:2px dashed #222255;
         border-radius:16px; padding:60px; text-align:center; margin-top:20px;'>
        <div style='font-size:3rem; margin-bottom:16px;'>🔬</div>
        <div style='color:#556688; font-size:1rem;'>Upload any file above to begin forensic analysis</div>
        <div style='color:#334466; font-size:0.8rem; margin-top:8px;'>
            Supports: .exe · .pdf · .jpg · .png · .zip · .docx · any file type
        </div>
    </div>
    """, unsafe_allow_html=True)
