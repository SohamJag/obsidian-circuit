"""
utils/virustotal.py — VirusTotal API v3 wrapper for Obsidian Circuit
"""
import requests
import time
import streamlit as st


VT_BASE = "https://www.virustotal.com/api/v3"


def vt_hash_lookup(sha256: str, api_key: str) -> dict:
    """
    Query VirusTotal for a file hash report.
    Returns a structured result dict.
    """
    if not api_key or not sha256:
        return {"error": "No API key or hash provided."}

    headers = {"x-apikey": api_key}
    url = f"{VT_BASE}/files/{sha256}"

    try:
        resp = requests.get(url, headers=headers, timeout=15)

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results = data.get("last_analysis_results", {})

            malicious_engines = [
                engine for engine, res in results.items()
                if res.get("category") == "malicious"
            ]

            return {
                "found": True,
                "name": data.get("meaningful_name", sha256[:16] + "..."),
                "type": data.get("type_description", "Unknown"),
                "size": data.get("size", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "malicious_engines": malicious_engines[:10],  # top 10
                "reputation": data.get("reputation", 0),
                "first_seen": data.get("first_submission_date", None),
                "last_analysis": data.get("last_analysis_date", None),
                "tags": data.get("tags", []),
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }

        elif resp.status_code == 404:
            return {"found": False, "message": "Hash not found in VirusTotal database. File may be new or benign."}
        elif resp.status_code == 401:
            return {"error": "Invalid API key. Please check your VirusTotal API key."}
        elif resp.status_code == 429:
            return {"error": "Rate limit exceeded (4 requests/min for free tier). Please wait a moment."}
        else:
            return {"error": f"VirusTotal API error: HTTP {resp.status_code}"}

    except requests.Timeout:
        return {"error": "Request timed out. Check your internet connection."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


def render_vt_result(result: dict):
    """Render a VirusTotal result card in Streamlit."""
    if "error" in result:
        st.error(f"⚠️ VirusTotal: {result['error']}")
        return

    if not result.get("found"):
        st.markdown(f"""
        <div class='finding-safe'>
            <b>🟢 VirusTotal: Not Found</b><br>
            <span style='color:#aaa;'>{result.get('message', 'Clean or unknown file.')}</span>
        </div>
        """, unsafe_allow_html=True)
        return

    malicious = result["malicious"]
    total = result["total_engines"]
    suspicious = result["suspicious"]

    if malicious > 5:
        severity_class = "finding-critical"
        severity_label = "🔴 HIGH THREAT"
        border_color = "#ff3333"
    elif malicious > 0 or suspicious > 2:
        severity_class = "finding-warning"
        severity_label = "🟠 SUSPICIOUS"
        border_color = "#ff9900"
    else:
        severity_class = "finding-safe"
        severity_label = "🟢 CLEAN"
        border_color = "#00ff9f"

    st.markdown(f"""
    <div class='{severity_class}'>
        <div style='display:flex; justify-content:space-between; align-items:center;'>
            <b style='font-size:1rem;'>🧬 VirusTotal Analysis</b>
            <span style='font-size:1.1rem; font-weight:700; color:{border_color};'>{severity_label}</span>
        </div>
        <br>
        <div style='display:flex; gap:32px; flex-wrap:wrap;'>
            <div>
                <div style='font-size:2rem; font-weight:800; color:{border_color};'>{malicious}/{total}</div>
                <div style='color:#777; font-size:0.8rem;'>Engines Detected</div>
            </div>
            <div>
                <div style='font-size:2rem; font-weight:800; color:#ff9900;'>{suspicious}</div>
                <div style='color:#777; font-size:0.8rem;'>Suspicious</div>
            </div>
            <div>
                <div style='font-size:2rem; font-weight:800; color:#00ff9f;'>{result['harmless']}</div>
                <div style='color:#777; font-size:0.8rem;'>Harmless</div>
            </div>
        </div>
        {f"<div style='margin-top:12px; color:#ff6666; font-size:0.83rem;'><b>Detected by:</b> {', '.join(result['malicious_engines'])}</div>" if result['malicious_engines'] else ""}
        <div style='margin-top:10px;'>
            <a href='{result['link']}' target='_blank' 
               style='color:#00d4ff; font-size:0.82rem; text-decoration:none;'>
               🔗 View full report on VirusTotal →
            </a>
        </div>
    </div>
    """, unsafe_allow_html=True)
