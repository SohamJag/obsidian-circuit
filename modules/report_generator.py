"""
modules/report_generator.py — Report Generation for Obsidian Circuit
Generates professional PDF and HTML reports for non-technical reviewers
"""
from datetime import datetime
from io import BytesIO


def _severity_to_risk(sev: str) -> str:
    return {"CRITICAL": "🔴 High Risk", "WARNING": "🟠 Medium Risk",
            "INFO": "🔵 Low Risk", "SAFE": "🟢 Clear"}.get(sev.upper(), "⚪ Unknown")


def _count_severities(all_findings: list) -> dict:
    counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "SAFE": 0}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts

import base64
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def _gen_bar(data_dict, title, orient='v', color='#00d4ff'):
    if not data_dict: return None
    fig, ax = plt.subplots(figsize=(5.5, 3))
    fig.patch.set_facecolor('#0a0a1a')
    ax.set_facecolor('#0a0a1a')
    keys = [str(k) for k in data_dict.keys()]
    vals = list(data_dict.values())
    if orient == 'v':
        ax.bar(keys, vals, color=color)
        plt.xticks(rotation=30, ha='right', color='#e0e0f0', fontsize=7)
    else:
        ax.barh(keys, vals, color=color)
        plt.yticks(color='#e0e0f0', fontsize=7)
    ax.tick_params(axis='x', colors='#e0e0f0')
    ax.tick_params(axis='y', colors='#e0e0f0')
    ax.spines['bottom'].set_color('#1a1a4a')
    ax.spines['left'].set_color('#1a1a4a')
    for spine in ['top', 'right']:
        ax.spines[spine].set_visible(False)
    ax.set_title(title, color='#ffffff', pad=10, fontsize=10, fontweight='bold')
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=120)
    plt.close(fig)
    return buf.getvalue()

def _gen_pie(data_dict, title, custom_colors=None):
    if not data_dict: return None
    fig, ax = plt.subplots(figsize=(4, 4))
    fig.patch.set_facecolor('#0a0a1a')
    if custom_colors:
        colors = custom_colors
    else:
        colors = ["#00d4ff", "#00ff9f", "#ff9900", "#ff3333", "#8b00ff", "#00a8cc"]
    keys = [str(k) for k in data_dict.keys()]
    vals = list(data_dict.values())
    wedges, texts, autotexts = ax.pie(vals, labels=keys, colors=colors[:len(keys)], autopct='%1.1f%%', textprops={'color': '#e0e0f0', 'fontsize': 8})
    plt.setp(texts, color='#e0e0f0')
    ax.set_title(title, color='#ffffff', pad=10, fontsize=10, fontweight='bold')
    buf = BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight', dpi=120)
    plt.close(fig)
    return buf.getvalue()

def __sanitize_for_pdf(text) -> str:
    """Sanitize unicode characters for fpdf2 standard fonts (latin-1 mapping)."""
    if not isinstance(text, str):
        return str(text)
    replacements = {
        "—": "-", "→": "->", "🔴": "[!]", "🟠": "[~]", 
        "🔵": "[i]", "🟢": "[OK]", "🔬": "", "🌐": "", 
        "📋": "", "📊": "", "🗂️": "", "✓": "v", "✗": "x", 
        "⚠️": "!", "🚨": "!", "✅": "OK", "📈": "", "🛡️": "",
        "🔐": "", "🪟": "", "📡": "", "🕵️": "", "🕐": "", "🗺️": "", "🧬": "",
        "•": "-", "‘": "'", "’": "'", "“": '"', "”": '"'
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode('latin-1', 'replace').decode('latin-1')

def __format_finding_desc(f: dict, is_html: bool = True) -> str:
    """Extract standard and dynamically varied details from a finding dict."""
    parts = []
    title = f.get("title")
    if title:
        parts.append(f"<b>{title}</b>" if is_html else f"Title: {title}")
        
    desc = f.get("description", "")
    if desc:
        parts.append(desc)
        
    extra = []
    if "port_count" in f: extra.append(f"Ports: {f['port_count']}")
    if "bytes_sent" in f: extra.append(f"Bytes Sent: {f['bytes_sent']}")
    if "external_dests" in f: extra.append(f"External Dests: {', '.join(f['external_dests'][:3])}")
    if "query_count" in f: extra.append(f"Queries: {f['query_count']}")
    if "ip" in f: extra.append(f"IP: {f['ip']}")
    if "failed_count" in f: extra.append(f"Failed Lgns: {f['failed_count']}")
    if "success_count" in f and f["success_count"] > 0: extra.append(f"Success post fails: {f['success_count']}")
    if "path" in f: extra.append(f"Path: {f['path']}")
    if "agent" in f: extra.append(f"Agent: {f['agent'][:40]}...")
    if "error_count" in f: extra.append(f"Err Responses: {f['error_count']}")
    if "size_bytes" in f: extra.append(f"Upload size: {f['size_bytes']//1024} KB")
    
    if extra:
        extras_line = " | ".join(extra)
        if is_html:
            parts.append(f"<div style='margin-top:6px; font-size:0.85em; color:#00d4ff;'>{extras_line}</div>")
        else:
            parts.append(f"[{extras_line}]")
            
    nl = "<br>" if is_html else "\n"
    return nl.join(parts)


def generate_html_report(analyst_name: str, case_id: str, case_date: str,
                          executive_summary: str, findings: dict) -> str:
    """Generate a styled HTML report string."""

    sections_html = ""
    total_critical = 0
    total_warning  = 0

    for module_name, module_data in findings.items():
        if not module_data:
            continue

        all_f = module_data.get("all_findings", [])
        sev_counts = _count_severities(all_f)
        total_critical += sev_counts["CRITICAL"]
        total_warning  += sev_counts["WARNING"]

        overall = module_data.get("overall_severity", "INFO")
        risk_text = _severity_to_risk(overall)

        # Build findings rows
        findings_rows = ""
        for f in all_f:
            sev = f.get("severity", "INFO").upper()
            sev_colors = {"CRITICAL": "#ff3333", "WARNING": "#ff9900", "INFO": "#00a8cc", "SAFE": "#00cc88"}
            color = sev_colors.get(sev, "#aaa")
            desc = __format_finding_desc(f, is_html=True)
            rec  = str(f.get("recommendation", ""))
            findings_rows += f"""
            <tr>
                <td style='color:{color}; font-weight:600; white-space:nowrap;'>{sev}</td>
                <td>{desc}</td>
                <td style='color:#aaa; font-size:0.85em;'>{rec}</td>
            </tr>"""

        # Detailed metrics HTML
        details_html = ""
        def add_detail(label, value, font_mono=False):
            nonlocal details_html
            val_style = "font-family: 'JetBrains Mono', monospace; font-size:0.85em; color:#00d4ff;" if font_mono else "color:#e0e0f0; font-size:0.9em;"
            details_html += f"<tr><td style='color:#7788bb; font-weight:600; font-size:0.85em; padding:4px 12px 4px 0; border:none; width: 160px;'>{label}</td><td style='{val_style} padding:4px 0; border:none;'>{value}</td></tr>"

        def add_header(title):
            nonlocal details_html
            details_html += f"<tr><td colspan='2' style='padding-top:15px; padding-bottom:5px; border-bottom:1px dashed #1a1a4a; color:#00ff9f; font-weight:bold; font-size:14px;'>{title}</td></tr>"

        if module_name == "File Analysis":
            if "detected_mime" in module_data or "permissions" in module_data:
                add_header("📊 Metadata")
                if "detected_mime" in module_data:
                    add_detail("MIME Type", module_data["detected_mime"])
                if "permissions" in module_data:
                    add_detail("Permissions", f"{module_data['permissions']} (World Write: {module_data.get('is_world_writable', False)}, Exec: {module_data.get('is_executable', False)})")
            
            if "baseline_hash" in module_data or "vt_results" in module_data:
                add_header("🔐 Integrity Verification")
                if "baseline_hash" in module_data:
                    match = module_data.get("baseline_match")
                    if match:
                        add_detail("Baseline Match", f"✅ Match found ({match.upper()})")
                    else:
                        add_detail("Baseline Match", "❌ NO MATCH")
                    add_detail("Baseline Hash", module_data["baseline_hash"], True)
                if "vt_results" in module_data:
                    vt = module_data["vt_results"]
                    add_detail("VirusTotal Scan", f"<b style='color:#ff3333'>{vt.get('malicious', 0)} malicious</b> / {vt.get('total', 0)} engines")
                    add_detail("VT Permalink", f"<a href='{vt.get('link', '#')}' style='color:#00d4ff'>View Full Report</a>")

            if "hashes" in module_data:
                add_header("🔑 Hashes")
                for algo, val in module_data["hashes"].items():
                    add_detail(algo.upper(), val, True)

            if "entropy" in module_data or "printable_ratio" in module_data:
                add_header("🌡️ Entropy Meter")
                if "entropy" in module_data:
                    add_detail("Entropy", f"{module_data['entropy']:.3f} (Shannon)")
                    ent_color = "#ff3333" if module_data["entropy"] > 7.5 else ("#ff9900" if module_data["entropy"] > 6.8 else "#00ff9f")
                    img = _gen_bar({"Entropy": module_data['entropy']}, "Entropy", 'h', ent_color)
                    b64 = base64.b64encode(img).decode('utf-8') if img else ""
                    if b64:
                        add_detail("Entropy Graph", f"<img src='data:image/png;base64,{b64}' style='width:300px; border-radius:4px; margin-top:8px;'>", False)
                if "printable_ratio" in module_data:
                    add_detail("Printable Ratio", f"{module_data['printable_ratio']}%")

            if module_data.get("all_findings"):
                sev_counts = _count_severities(module_data["all_findings"])
                sev_counts = {k: v for k, v in sev_counts.items() if v > 0}
                if sev_counts:
                    add_header("🚨 Finding Severities")
                    sev_colormap = {"CRITICAL": "#ff3333", "WARNING": "#ff9900", "INFO": "#00d4ff", "SAFE": "#00ff9f"}
                    colors_list = [sev_colormap.get(k, "#aaa") for k in sev_counts.keys()]
                    img = _gen_pie(sev_counts, "Finding Severities", custom_colors=colors_list)
                    b64 = base64.b64encode(img).decode('utf-8') if img else ""
                    if b64:
                        add_detail("Severities", f"<img src='data:image/png;base64,{b64}' style='width:250px; border-radius:4px; margin-top:8px;'>", False)

            if module_data.get("embedded_urls") or module_data.get("embedded_ips"):
                add_header("🗂️ Deep Scan")
                if module_data.get("embedded_urls"):
                    add_detail("Embedded URLs", "<br>".join(module_data["embedded_urls"][:10]), True)
                if module_data.get("embedded_ips"):
                    add_detail("Embedded IPs", ", ".join(module_data["embedded_ips"][:10]), True)

            if module_data.get("hex_dump"):
                add_header("🧩 Hex Dump")
                add_detail("Raw Bytes", f"<pre style='margin:0; font-size:0.75em;'>{module_data['hex_dump']}</pre>")
                
        elif module_name == "Network Analysis":
            if module_data.get("protocol_counts"):
                protos = ", ".join(f"{k}: {v}" for k, v in module_data["protocol_counts"].items())
                add_detail("Protocols", protos)
            if module_data.get("top_talkers"):
                talkers = "<br>".join(f"{ip} ({bytes/1024:.1f} KB out)" for ip, bytes in module_data["top_talkers"])
                add_detail("Top Talkers", talkers, True)
            if module_data.get("connections_sample"):
                conns = module_data["connections_sample"][:25]
                table_html = "<table class='findings-table'><tr><th>Src</th><th>Dst</th><th>Proto</th><th>Port</th></tr>"
                for c in conns:
                    table_html += f"<tr><td>{c.get('src','-')}</td><td>{c.get('dst','-')}</td><td>{c.get('proto','-')}</td><td>{c.get('dport','-')}</td></tr>"
                table_html += "</table>"
                add_detail(f"Connections ({len(conns)} shown)", table_html)
            if "tcp_flags_breakdown" in module_data:
                flags = ", ".join(f"{k}: {v}" for k, v in module_data["tcp_flags_breakdown"].items())
                img = _gen_bar(module_data["tcp_flags_breakdown"], "TCP Flags", 'v', "#00ff9f")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("TCP Flags", flags + f"<br><img src='data:image/png;base64,{b64}' style='width:300px; border-radius:4px; margin-top:8px;'>", False)
            if "top_dest_ports" in module_data:
                ports = ", ".join(f"Port {p} ({c} times)" for p, c in list(module_data["top_dest_ports"].items())[:8])
                img = _gen_bar(dict(list(module_data["top_dest_ports"].items())[:8]), "Top Dest Ports", 'h', "#8b00ff")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("Top Dest Ports", ports + f"<br><img src='data:image/png;base64,{b64}' style='width:300px; border-radius:4px; margin-top:8px;'>", False)
            if "ip_classes" in module_data:
                ip_cls = ", ".join(f"{k}: {v}" for k, v in module_data["ip_classes"].items())
                img = _gen_pie(module_data["ip_classes"], "IP Classification")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("IP Profile", ip_cls + f"<br><img src='data:image/png;base64,{b64}' style='width:250px; border-radius:4px; margin-top:8px;'>", False)
            if "dns_query_counts" in module_data:
                dns = "<br>".join(f"{domain} (x{count})" for domain, count in list(module_data["dns_query_counts"].items())[:10])
                add_detail("Top DNS Queries", dns, True)

        elif module_name == "Log Analysis":
            if "log_type" in module_data:
                add_detail("Log Type Detected", module_data["log_type"].upper())
            if module_data.get("method_counts"):
                methods = ", ".join(f"{m}: {c}" for m, c in module_data["method_counts"].items())
                img = _gen_bar(module_data["method_counts"], "HTTP Methods", 'v', "#00d4ff")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("HTTP Methods", methods + f"<br><img src='data:image/png;base64,{b64}' style='width:300px; border-radius:4px; margin-top:8px;'>", False)
            if module_data.get("status_counts"):
                stats = ", ".join(f"{s}: {c}" for s, c in module_data["status_counts"].items())
                img = _gen_bar(module_data["status_counts"], "HTTP Status Codes", 'v', "#ff9900")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("HTTP Status Codes", stats + f"<br><img src='data:image/png;base64,{b64}' style='width:300px; border-radius:4px; margin-top:8px;'>", False)
            if module_data.get("top_paths"):
                paths = "<br>".join(f"{p} ({c})" for p, c in module_data["top_paths"][:5])
                add_detail("Top Target Paths", paths, True)
            failed_logins = module_data.get("failed_logins_by_ip", {})
            success_logins = module_data.get("success_logins_by_ip", {})
            if failed_logins or success_logins:
                ips = set(failed_logins.keys()).union(set(success_logins.keys()))
                intel = "<br>".join(f"{ip}: {failed_logins.get(ip,0)} fails / {success_logins.get(ip,0)} success" for ip in sorted(ips, key=lambda i: -failed_logins.get(i,0))[:5])
                add_detail("Login Activity Intel", intel, True)
            if module_data.get("events"):
                evs = module_data["events"][:15]
                table = "<table class='findings-table'><tr><th>Time</th><th>Level</th><th>ID</th><th>Source</th></tr>"
                for ev in evs:
                    table += f"<tr><td>{ev.get('timestamp','-')}</td><td>{ev.get('level','-')}</td><td>{ev.get('event_id','-')}</td><td>{ev.get('source','-')}</td></tr>"
                table += "</table>"
                add_detail(f"Event Stream ({len(evs)} shown)", table, False)
            if "hour_counts" in module_data and module_data["hour_counts"]:
                peak_hour = max(module_data["hour_counts"], key=module_data["hour_counts"].get)
                img = _gen_bar({f"{h:02d}:00": c for h,c in sorted(module_data["hour_counts"].items())}, "Hourly Activity", 'v', "#00d4ff")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("Peak Activity", f"{peak_hour:02d}:00 hours ({module_data['hour_counts'][peak_hour]} events)<br><img src='data:image/png;base64,{b64}' style='width:400px; border-radius:4px; margin-top:8px;'>", False)
            if "agent_counts" in module_data and module_data["agent_counts"]:
                agents = "<br>".join(f"{agent} ({count})" for agent, count in sorted(module_data["agent_counts"].items(), key=lambda x: -x[1])[:5])
                add_detail("Top User Agents", agents, True)
            if "event_id_counts" in module_data and module_data["event_id_counts"]:
                eids = ", ".join(f"Event {eid} ({c})" for eid, c in module_data["event_id_counts"].items())
                add_detail("Windows Event IDs", eids)
            if "logon_types" in module_data and module_data["logon_types"]:
                lt = ", ".join(f"Type {k}: {v}" for k, v in module_data["logon_types"].items())
                img = _gen_pie(module_data["logon_types"], "Logon Types")
                b64 = base64.b64encode(img).decode('utf-8') if img else ""
                add_detail("Logon Types", lt + f"<br><img src='data:image/png;base64,{b64}' style='width:250px; border-radius:4px; margin-top:8px;'>", False)

        details_table = f"<table style='margin-bottom:20px; border:none;'>{details_html}</table>" if details_html else ""

        # Module stats snippet
        stats_items = []
        if "total_packets" in module_data:
            stats_items.append(f"Packets analyzed: <b>{module_data['total_packets']:,}</b>")
            stats_items.append(f"Unique IPs: <b>{module_data.get('unique_ips', 0)}</b>")
        if "total_lines" in module_data:
            stats_items.append(f"Log lines: <b>{module_data['total_lines']:,}</b>")
            stats_items.append(f"Parsed events: <b>{module_data.get('parsed_events', 0)}</b>")
        if "filename" in module_data:
            stats_items.append(f"File: <b>{module_data['filename']}</b>")
            stats_items.append(f"Size: <b>{module_data.get('file_size', 0) // 1024} KB</b>")
            for algo, val in module_data.get("hashes", {}).items():
                stats_items.append(f"{algo.upper()}: <code>{val[:24]}...</code>")

        stats_html = " &nbsp;|&nbsp; ".join(stats_items) if stats_items else ""

        icon_map = {"File Analysis": "🔬", "Network Analysis": "🌐", "Log Analysis": "📋"}
        icon = icon_map.get(module_name, "📊")

        risk_color_map = {"🔴 High Risk": "#ff3333", "🟠 Medium Risk": "#ff9900",
                          "🔵 Low Risk": "#00a8cc", "🟢 Clear": "#00cc88"}
        risk_text_color = risk_color_map.get(risk_text, "#aaa")
        stats_html_block = f'<p class="stats-bar">{stats_html}</p>' if stats_html else ''

        findings_table_html = f"""
            <h3 style='color:#ff0055; margin-bottom:5px;'>🚨 { 'Suspicious Flags' if module_name == 'File Analysis' else 'Findings & Recommendations' }</h3>
            <table class='findings-table'>
                <thead><tr><th>Severity</th><th>Finding</th><th>Recommendation</th></tr></thead>
                <tbody>{findings_rows}</tbody>
            </table>""" if all_f else ""

        sections_html += f"""
        <div class='section'>
            <div class='section-header'>
                <span class='section-icon'>{icon}</span>
                <div>
                    <h2>{module_name}</h2>
                    <span class='risk-badge' style='color:{risk_text_color};'>{risk_text}</span>
                </div>
            </div>
            {stats_html_block}
            {details_table}
            {findings_table_html}
        </div>
        """

    overall_risk = "🔴 HIGH RISK" if total_critical > 0 else ("🟠 MEDIUM RISK" if total_warning > 0 else "🟢 LOW RISK")
    overall_color = "#ff3333" if total_critical > 0 else ("#ff9900" if total_warning > 0 else "#00cc88")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Obsidian Circuit — DFIR Report | Case {case_id}</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=JetBrains+Mono&display=swap');
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Inter', sans-serif; background: #0a0a1a; color: #e0e0f0; line-height: 1.6; }}
    .page {{ max-width: 1100px; margin: 0 auto; padding: 40px 32px; }}

    /* Cover */
    .cover {{
        background: linear-gradient(135deg, #0d1b4b 0%, #1a0d4b 50%, #0d2b3b 100%);
        border: 1px solid #1e1e5a; border-radius: 16px;
        padding: 60px 48px; margin-bottom: 40px; position: relative; overflow: hidden;
    }}
    .cover::before {{
        content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
        background: linear-gradient(90deg, #00d4ff, #8b00ff, #00d4ff);
    }}
    .cover-logo {{ font-size: 3rem; margin-bottom: 12px; }}
    .cover-title {{
        font-size: 2.4rem; font-weight: 800; letter-spacing: 3px;
        background: linear-gradient(90deg, #00d4ff, #8b00ff);
        -webkit-background-clip: text; color: transparent;
        margin-bottom: 6px;
    }}
    .cover-subtitle {{ color: #7799bb; font-size: 0.9rem; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 32px; }}
    .cover-meta table {{ border-collapse: collapse; }}
    .cover-meta td {{ padding: 6px 24px 6px 0; color: #aaa; font-size: 0.9rem; }}
    .cover-meta td:first-child {{ color: #7788bb; font-weight: 600; min-width: 120px; }}

    /* Risk banner */
    .risk-banner {{
        border-radius: 12px; padding: 20px 28px; margin-bottom: 36px;
        border: 1px solid {overall_color}44;
        background: {overall_color}11;
        display: flex; align-items: center; gap: 20px;
    }}
    .risk-banner-score {{ font-size: 2.5rem; font-weight: 900; color: {overall_color}; }}
    .risk-banner-detail {{ flex: 1; }}
    .risk-banner-label {{ color: {overall_color}; font-weight: 700; font-size: 1.1rem; }}
    .risk-banner-counts {{ color: #999; font-size: 0.9rem; margin-top: 4px; }}

    /* Executive Summary */
    .exec-summary {{
        background: #111130; border: 1px solid #222255; border-radius: 12px;
        padding: 28px 32px; margin-bottom: 36px;
    }}
    .exec-summary h2 {{ color: #00d4ff; margin-bottom: 16px; font-size: 1.1rem; letter-spacing: 1px; text-transform: uppercase; }}
    .exec-summary p {{ color: #bbbbd0; line-height: 1.8; }}

    /* Sections */
    .section {{
        background: #0d0d28; border: 1px solid #1a1a4a; border-radius: 14px;
        padding: 28px 32px; margin-bottom: 28px;
    }}
    .section-header {{ display: flex; align-items: flex-start; gap: 16px; margin-bottom: 20px; }}
    .section-icon {{ font-size: 2rem; }}
    .section-header h2 {{ color: #e0e0f0; font-size: 1.3rem; font-weight: 700; margin-bottom: 4px; }}
    .risk-badge {{ font-size: 0.85rem; font-weight: 600; }}
    .stats-bar {{ color: #666688; font-size: 0.83rem; margin-bottom: 16px; }}
    .stats-bar code {{ font-family: 'JetBrains Mono'; color: #00d4ff; }}

    /* Findings table */
    .findings-table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    .findings-table th {{
        background: #0a0a1e; color: #7788bb; padding: 10px 14px;
        text-align: left; font-weight: 600; border-bottom: 1px solid #222255;
        text-transform: uppercase; font-size: 0.75rem; letter-spacing: 1px;
    }}
    .findings-table td {{ padding: 12px 14px; border-bottom: 1px solid #111130; vertical-align: top; }}
    .findings-table tr:last-child td {{ border-bottom: none; }}
    .findings-table tr:hover td {{ background: rgba(255,255,255,0.02); }}

    /* Footer */
    .footer {{ text-align: center; color: #333355; font-size: 0.78rem; margin-top: 48px; padding-top: 24px; border-top: 1px solid #111130; }}
    .footer strong {{ color: #555588; }}

    @media print {{
        body {{ background: white !important; color: #111 !important; }}
        .cover {{ background: #f0f4ff !important; }}
    }}
</style>
</head>
<body>
<div class="page">

    <!-- Cover -->
    <div class="cover">
        <div class="cover-logo">🔮</div>
        <div class="cover-title">OBSIDIAN CIRCUIT</div>
        <div class="cover-subtitle">Digital Forensics & Incident Response Report</div>
        <div class="cover-meta">
            <table>
                <tr><td>Case ID</td><td><b>{case_id or "N/A"}</b></td></tr>
                <tr><td>Analyst</td><td>{analyst_name or "N/A"}</td></tr>
                <tr><td>Date</td><td>{case_date or generated_at}</td></tr>
                <tr><td>Generated</td><td>{generated_at}</td></tr>
                <tr><td>Modules</td><td>{", ".join(findings.keys()) or "None"}</td></tr>
            </table>
        </div>
    </div>

    <!-- Overall Risk Banner -->
    <div class="risk-banner">
        <div class="risk-banner-score">{overall_risk.split()[0]}</div>
        <div class="risk-banner-detail">
            <div class="risk-banner-label">{overall_risk}</div>
            <div class="risk-banner-counts">
                🔴 {total_critical} Critical &nbsp;|&nbsp; 🟠 {total_warning} Warnings &nbsp;|&nbsp; 
                📦 {len(findings)} module(s) analyzed
            </div>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="exec-summary">
        <h2>📋 Executive Summary</h2>
        <p>{executive_summary.replace(chr(10), '<br>') if executive_summary else "No executive summary provided."}</p>
    </div>

    <!-- Module Sections -->
    {sections_html}

    <!-- Footer -->
    <div class="footer">
        <p>Generated by <strong>Obsidian Circuit DFIR Platform</strong> &nbsp;·&nbsp; {generated_at} &nbsp;·&nbsp; 
        This report is confidential. Handle in accordance with your organization's data classification policy.</p>
    </div>
</div>
</body>
</html>"""

    return html


def generate_pdf_report(analyst_name: str, case_id: str, case_date: str,
                         executive_summary: str, findings: dict) -> bytes:
    """Generate a styled PDF report using fpdf2."""
    try:
        from fpdf import FPDF
    except ImportError:
        raise ImportError("fpdf2 not installed. Run: pip install fpdf2")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(20, 20, 20)
    pdf.add_page()

    # ---- Colors ----
    C_BG       = (10, 10, 26)
    C_HEADER   = (0, 212, 255)
    C_TEXT     = (200, 200, 220)
    C_MUTED    = (100, 100, 150)
    C_WHITE    = (230, 230, 240)
    C_CRIT     = (255, 50, 50)
    C_WARN     = (255, 153, 0)
    C_INFO     = (0, 190, 220)
    C_SAFE     = (0, 220, 140)
    C_SECTION  = (20, 20, 60)

    # ---- Helpers ----
    def set_col(r, g, b):
        pdf.set_text_color(r, g, b)

    def sev_color(sev: str):
        return {"CRITICAL": C_CRIT, "WARNING": C_WARN, "INFO": C_INFO, "SAFE": C_SAFE}.get(sev.upper(), C_MUTED)

    def __pdf_kv(label, value, label_w=45):
        if pdf.get_y() > 260:
            pdf.add_page()
            pdf.set_fill_color(*C_BG)
            pdf.rect(0, 0, 210, 297, "F")
        pdf.set_font("Helvetica", "B", 8)
        set_col(*C_MUTED)
        pdf.set_x(20)
        pdf.cell(label_w, 5, __sanitize_for_pdf(label + ":"), ln=False)
        pdf.set_font("Helvetica", "", 8)
        set_col(*C_WHITE)
        pdf.multi_cell(0, 5, __sanitize_for_pdf(str(value)))

    # ---- Page background ----
    pdf.set_fill_color(*C_BG)
    pdf.rect(0, 0, 210, 297, "F")

    # ---- Title Block ----
    pdf.set_fill_color(13, 27, 75)
    pdf.rect(0, 0, 210, 70, "F")

    pdf.set_font("Helvetica", "B", 24)
    set_col(*C_HEADER)
    pdf.set_xy(20, 18)
    pdf.cell(0, 10, "OBSIDIAN CIRCUIT", ln=True)

    pdf.set_font("Helvetica", "", 10)
    set_col(*C_MUTED)
    pdf.set_x(20)
    pdf.cell(0, 6, "Digital Forensics & Incident Response Report", ln=True)

    # ---- Metadata Table ----
    pdf.set_xy(20, 45)
    meta = [
        ("Case ID", case_id or "N/A"),
        ("Analyst", analyst_name or "N/A"),
        ("Date", case_date or datetime.now().strftime("%Y-%m-%d")),
        ("Modules", ", ".join(findings.keys()) or "None"),
    ]
    for label, val in meta:
        __pdf_kv(label, val, label_w=35)

    pdf.ln(10)

    # ---- Overall Risk ----
    total_critical = sum(1 for m in findings.values()
                         for f in m.get("all_findings", []) if f.get("severity") == "CRITICAL")
    total_warning  = sum(1 for m in findings.values()
                         for f in m.get("all_findings", []) if f.get("severity") == "WARNING")

    risk = "HIGH RISK" if total_critical > 0 else ("MEDIUM RISK" if total_warning > 0 else "LOW RISK")
    risk_color = C_CRIT if total_critical > 0 else (C_WARN if total_warning > 0 else C_SAFE)

    pdf.set_fill_color(*risk_color)
    pdf.set_x(20)
    pdf.set_font("Helvetica", "B", 14)
    set_col(*C_BG)
    pdf.cell(170, 12, f"  Overall Assessment: {risk}", fill=True, ln=True, align="L")
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 9)
    set_col(*C_MUTED)
    pdf.cell(0, 5, f"  Critical: {total_critical}  |  Warnings: {total_warning}  |  Modules analyzed: {len(findings)}", ln=True)
    pdf.ln(8)

    # ---- Executive Summary ----
    pdf.set_fill_color(*C_SECTION)
    pdf.set_x(20)
    pdf.set_font("Helvetica", "B", 11)
    set_col(*C_HEADER)
    pdf.cell(170, 8, "  EXECUTIVE SUMMARY", fill=True, ln=True)
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 9)
    set_col(*C_TEXT)
    pdf.set_x(20)
    summary_text = executive_summary or "No executive summary provided."
    pdf.multi_cell(170, 5, __sanitize_for_pdf(summary_text))
    pdf.ln(10)

    # ---- Module Sections ----
    icon_map = {"File Analysis": "[FILE]", "Network Analysis": "[NET]", "Log Analysis": "[LOG]"}

    for module_name, module_data in findings.items():
        if not module_data:
            continue

        pdf.add_page()
        pdf.set_fill_color(*C_BG)
        pdf.rect(0, 0, 210, 297, "F")

        overall = module_data.get("overall_severity", "INFO")
        mod_color = sev_color(overall)
        icon = icon_map.get(module_name, "[MOD]")

        # Module header
        pdf.set_fill_color(*mod_color)
        pdf.set_x(20)
        pdf.set_font("Helvetica", "B", 13)
        set_col(*C_BG)
        pdf.cell(170, 10, __sanitize_for_pdf(f"  {icon} {module_name.upper()}"), fill=True, ln=True)
        pdf.ln(4)

        # Basic Stats
        stats = []
        if "filename" in module_data:
            stats.append(f"File: {module_data['filename']} ({module_data.get('file_size', 0) // 1024} KB)")
        if "total_packets" in module_data:
            stats.append(f"Packets: {module_data['total_packets']:,}  |  Unique IPs: {module_data.get('unique_ips', 0)}")
        if "total_lines" in module_data:
            stats.append(f"Log lines: {module_data['total_lines']:,}  |  Events: {module_data.get('parsed_events', 0)}")
        
        for s in stats:
            pdf.set_x(20)
            pdf.set_font("Helvetica", "", 8)
            set_col(*C_MUTED)
            pdf.cell(0, 5, __sanitize_for_pdf(s), ln=True)
        pdf.ln(3)

        # Deep Details
        if module_name == "File Analysis":
            if "detected_mime" in module_data:
                __pdf_kv("Detected MIME Type", module_data["detected_mime"])
            if "permissions" in module_data:
                __pdf_kv("UNIX Permissions", f"{module_data['permissions']} (World Write: {module_data.get('is_world_writable', False)}, Exec: {module_data.get('is_executable', False)})")
            if "hashes" in module_data:
                for algo, val in module_data["hashes"].items():
                    __pdf_kv(algo.upper(), val)
            if "entropy" in module_data:
                __pdf_kv("Entropy", f"{module_data['entropy']:.3f} (Shannon)")
            if "printable_ratio" in module_data:
                __pdf_kv("Printable Char Ratio", f"{module_data['printable_ratio']}%")
            if "baseline_hash" in module_data:
                match = module_data.get("baseline_match")
                __pdf_kv("Baseline Hash", module_data["baseline_hash"][:50] + ("..." if len(module_data["baseline_hash"]) > 50 else ""))
                __pdf_kv("Integrity Result", f"Match found ({match.upper()})" if match else "NO MATCH (Tampered)")
            if "vt_results" in module_data:
                vt = module_data["vt_results"]
                __pdf_kv("VirusTotal Scan", f"{vt.get('malicious', 0)} malicious engines out of {vt.get('total', 0)}")
            if "entropy" in module_data:
                ent_color = "#ff3333" if module_data["entropy"] > 7.5 else ("#ff9900" if module_data["entropy"] > 6.8 else "#00ff9f")
                img = _gen_bar({"Entropy": module_data['entropy']}, "Entropy", 'h', ent_color)
                if img:
                    if pdf.get_y() > 230:
                        pdf.add_page(); pdf.set_fill_color(*C_BG); pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=90)
                    pdf.set_y(pdf.get_y() + 45)
                    pdf.ln(5)

            if module_data.get("all_findings"):
                sev_counts = _count_severities(module_data["all_findings"])
                sev_counts = {k: v for k, v in sev_counts.items() if v > 0}
                if sev_counts:
                    sev_colormap = {"CRITICAL": "#ff3333", "WARNING": "#ff9900", "INFO": "#00d4ff", "SAFE": "#00ff9f"}
                    colors_list = [sev_colormap.get(k, "#aaa") for k in sev_counts.keys()]
                    img = _gen_pie(sev_counts, "Finding Severities", custom_colors=colors_list)
                    if img:
                        if pdf.get_y() > 210:
                            pdf.add_page(); pdf.set_fill_color(*C_BG); pdf.rect(0, 0, 210, 297, "F")
                        pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=70)
                        pdf.set_y(pdf.get_y() + 70)
                        pdf.ln(5)

            if module_data.get("embedded_urls"):
                __pdf_kv("Embedded URLs Found", len(module_data["embedded_urls"]))
                for url in module_data["embedded_urls"][:15]:
                    pdf.set_x(25); set_col(*C_INFO); pdf.cell(0, 4, __sanitize_for_pdf("- " + url), ln=True)
            if module_data.get("embedded_ips"):
                __pdf_kv("Embedded IPs Found", len(module_data["embedded_ips"]))
                for ip in module_data["embedded_ips"][:15]:
                    pdf.set_x(25); set_col(*C_WARN); pdf.cell(0, 4, __sanitize_for_pdf("- " + ip), ln=True)
            if "hex_dump" in module_data and module_data["hex_dump"]:
                pdf.ln(2)
                __pdf_kv("Hex Dump (First 64 Bytes)", "")
                pdf.set_font("Courier", "", 7)
                set_col(180, 180, 180)
                for line in module_data["hex_dump"].split("\n"):
                    pdf.set_x(25)
                    pdf.cell(0, 4, __sanitize_for_pdf(line), ln=True)

        elif module_name == "Network Analysis":
            if module_data.get("protocol_counts"):
                protos_str = ", ".join(f"{k}: {v}" for k, v in module_data["protocol_counts"].items())
                __pdf_kv("Protocol Distribution", protos_str)
            if module_data.get("top_talkers"):
                __pdf_kv("Top Talkers (Data Transferred)", "")
                pdf.set_font("Courier", "", 8); set_col(180, 200, 220)
                pdf.set_x(25); pdf.cell(0, 4, f"{'IP ADDRESS':<20}  {'TRAFFIC VOL'}", ln=True)
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                for ip, bytes_out in list(module_data["top_talkers"])[:15]:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"{ip:<20}  {bytes_out/1024:.2f} KB"), ln=True)
            if module_data.get("connections_sample"):
                conns = module_data["connections_sample"][:25]
                __pdf_kv("Connections Sample", f"Showing {len(conns)} of {len(module_data['connections_sample'])}")
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                pdf.set_x(25); pdf.cell(0, 4, f"{'SRC IP':<16}  {'DST IP':<16}  {'PROTO'}  {'PORT'}", ln=True)
                for c in conns:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"{str(c.get('src','-'))[:15]:<16}  {str(c.get('dst','-'))[:15]:<16}  {str(c.get('proto','-'))[:5]:<5}  {str(c.get('dport','-'))[:5]}"), ln=True)
            if "tcp_flags_breakdown" in module_data:
                flags_str = ", ".join(f"{k}: {v}" for k, v in module_data["tcp_flags_breakdown"].items())
                __pdf_kv("TCP Flags", flags_str)
                img = _gen_bar(module_data["tcp_flags_breakdown"], "TCP Flags", 'v', "#00ff9f")
                if img:
                    if pdf.get_y() > 230:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=90)
                    pdf.set_y(pdf.get_y() + 50)
                    pdf.ln(5)
            if "top_dest_ports" in module_data:
                ports_str = ", ".join(f"Port {p} ({c} times)" for p, c in list(module_data["top_dest_ports"].items())[:8])
                __pdf_kv("Top Dest Ports", ports_str)
                img = _gen_bar(dict(list(module_data["top_dest_ports"].items())[:8]), "Top Dest Ports", 'h', "#8b00ff")
                if img:
                    if pdf.get_y() > 230:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=90)
                    pdf.set_y(pdf.get_y() + 50)
                    pdf.ln(5)
            if "ip_classes" in module_data:
                ip_cls_str = ", ".join(f"{k}: {v}" for k, v in module_data["ip_classes"].items())
                __pdf_kv("IP Classification", ip_cls_str)
                img = _gen_pie(module_data["ip_classes"], "IP Classification")
                if img:
                    if pdf.get_y() > 210:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=70)
                    pdf.set_y(pdf.get_y() + 70)
                    pdf.ln(5)
            if "dns_query_counts" in module_data:
                __pdf_kv("Top DNS Queries", "")
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                for domain, count in list(module_data["dns_query_counts"].items())[:12]:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"- {domain} ({count} reqs)"), ln=True)

        elif module_name == "Log Analysis":
            if "log_type" in module_data:
                __pdf_kv("Detected Log Type", module_data["log_type"].upper())
            if module_data.get("method_counts"):
                m_str = ", ".join(f"{m}: {c}" for m, c in module_data["method_counts"].items())
                __pdf_kv("HTTP Methods", m_str)
                img = _gen_bar(module_data["method_counts"], "HTTP Methods", 'v', "#00d4ff")
                if img:
                    if pdf.get_y() > 230:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=90)
                    pdf.set_y(pdf.get_y() + 50)
                    pdf.ln(5)
            if module_data.get("status_counts"):
                s_str = ", ".join(f"{s}: {c}" for s, c in module_data["status_counts"].items())
                __pdf_kv("HTTP Status", s_str)
                img = _gen_bar(module_data["status_counts"], "HTTP Status Codes", 'v', "#ff9900")
                if img:
                    if pdf.get_y() > 230:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=90)
                    pdf.set_y(pdf.get_y() + 50)
                    pdf.ln(5)
            if module_data.get("top_paths"):
                __pdf_kv("Top Target Paths", "")
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                for p, c in module_data["top_paths"][:6]:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"- {p} ({c})"), ln=True)
            failed_logins = module_data.get("failed_logins_by_ip", {})
            success_logins = module_data.get("success_logins_by_ip", {})
            if failed_logins or success_logins:
                __pdf_kv("Login Intel Map", "")
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                ips = set(failed_logins.keys()).union(set(success_logins.keys()))
                for ip in sorted(ips, key=lambda i: -failed_logins.get(i,0))[:6]:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"- {ip}: {failed_logins.get(ip,0)} fails / {success_logins.get(ip,0)} success"), ln=True)
            if module_data.get("events"):
                evs = module_data["events"][:25]
                __pdf_kv("Event Stream Detail", f"Showing {len(evs)} of {len(module_data['events'])}")
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                pdf.set_x(25); pdf.cell(0, 4, f"{'TIMESTAMP':<20}  {'LEVEL':<10}  {'ID':<5}  {'SOURCE'}", ln=True)
                for e in evs:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"{str(e.get('timestamp','-'))[:19]:<20}  {str(e.get('level','-'))[:9]:<10}  {str(e.get('event_id','-'))[:5]:<5}  {str(e.get('source','-'))[:30]}"), ln=True)
            if "hour_counts" in module_data and module_data["hour_counts"]:
                peak_hour = max(module_data["hour_counts"], key=module_data["hour_counts"].get)
                __pdf_kv("Peak Activity Hour", f"{peak_hour:02d}:00 hours with {module_data['hour_counts'][peak_hour]} events")
                img = _gen_bar({f"{h:02d}:00": c for h,c in sorted(module_data["hour_counts"].items())}, "Hourly Activity", 'v', "#00d4ff")
                if img:
                    if pdf.get_y() > 230:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=120)
                    pdf.set_y(pdf.get_y() + 65)
                    pdf.ln(5)
            if "agent_counts" in module_data and module_data["agent_counts"]:
                __pdf_kv("Top User Agents", "")
                pdf.set_font("Courier", "", 7); set_col(180, 180, 180)
                for agent, count in sorted(module_data["agent_counts"].items(), key=lambda x: -x[1])[:8]:
                    pdf.set_x(25); pdf.cell(0, 4, __sanitize_for_pdf(f"- {agent} ({count})"), ln=True)
            if "event_id_counts" in module_data and module_data["event_id_counts"]:
                eids = ", ".join(f"ID {eid}: {c}" for eid, c in module_data["event_id_counts"].items())
                __pdf_kv("Windows Event IDs", eids)
            if "logon_types" in module_data and module_data["logon_types"]:
                lt = ", ".join(f"Type {k}: {v}" for k, v in module_data["logon_types"].items())
                __pdf_kv("Logon Types", lt)
                img = _gen_pie(module_data["logon_types"], "Logon Types")
                if img:
                    if pdf.get_y() > 210:
                        pdf.add_page()
                        pdf.set_fill_color(*C_BG)
                        pdf.rect(0, 0, 210, 297, "F")
                    pdf.image(BytesIO(img), x=25, y=pdf.get_y(), w=70)
                    pdf.set_y(pdf.get_y() + 70)
                    pdf.ln(5)

        pdf.ln(6)

        # Findings table header
        all_findings = module_data.get("all_findings", [])
        if all_findings:
            if pdf.get_y() > 240:
                pdf.add_page()
                pdf.set_fill_color(*C_BG)
                pdf.rect(0, 0, 210, 297, "F")
            pdf.set_fill_color(*C_SECTION)
            pdf.set_font("Helvetica", "B", 8)
            set_col(*C_HEADER)
            pdf.set_x(20)
            pdf.cell(25, 7, "SEVERITY", fill=True, border=0)
            table_title = "🚨 SUSPICIOUS FLAGS & RECOMMENDATIONS" if module_name == "File Analysis" else "FINDING & RECOMMENDATION"
            pdf.cell(145, 7, __sanitize_for_pdf(table_title), fill=True, border=0, ln=True)
            pdf.ln(2)

            for finding in all_findings:
                if pdf.get_y() > 260:
                    pdf.add_page(); pdf.set_fill_color(*C_BG); pdf.rect(0, 0, 210, 297, "F")
                
                sev = finding.get("severity", "INFO").upper()
                desc = __sanitize_for_pdf(__format_finding_desc(finding, is_html=False))
                rec  = __sanitize_for_pdf(finding.get("recommendation", ""))
                fc   = sev_color(sev)

                pdf.set_x(20)
                pdf.set_font("Helvetica", "B", 8)
                set_col(*fc)
                y_start = pdf.get_y()
                pdf.cell(25, 5, sev)

                pdf.set_font("Helvetica", "", 8)
                set_col(*C_TEXT)
                pdf.set_xy(45, y_start)
                pdf.multi_cell(145, 4, desc, align="L")
                
                if rec:
                    pdf.set_x(45)
                    pdf.set_font("Helvetica", "I", 8)
                    set_col(*C_MUTED)
                    pdf.multi_cell(145, 4, f"Rec: {rec}", align="L")
                pdf.ln(3)

    # ---- Footer on last page ----
    pdf.set_y(-20)
    pdf.set_font("Helvetica", "", 7)
    set_col(*C_MUTED)
    pdf.cell(0, 5, f"Obsidian Circuit DFIR Platform  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  CONFIDENTIAL", align="C")

    return bytes(pdf.output())
