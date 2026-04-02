# 🔮 Obsidian Circuit — DFIR Platform

A modular, GUI-based **Digital Forensics & Incident Response (DFIR)** tool built with Python and Streamlit.

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the app
streamlit run OBSIDIAN_CIRCUIT.py
```

The app opens at **http://localhost:8501**

---

## 📦 Modules

| Module | File Types | What It Detects |
|--------|-----------|-----------------|
| 🔬 File Analysis | Any file | MIME mismatch, magic bytes, hashes, VT lookup |
| 🌐 Network Analysis | `.pcap`, `.pcapng` | Port scans, DNS tunneling, data exfiltration |
| 📋 Log Analysis | `.log`, `.txt`, `.csv` | Brute-force, scanner agents, path traversal |
| 📄 Report Generator | — | PDF + HTML forensic reports |

## 🔑 VirusTotal API

The app comes **pre-configured** with the provided VirusTotal API key (stored in `.env`).
- Free tier: 4 requests/minute, 500/day
- Key can be changed via the sidebar → **Settings**

## 📁 Sample Test Files

```
sample_data/
├── sample_auth.log     # Linux auth.log with brute-force + successful compromise
└── sample_apache.log   # Apache log with sqlmap, nikto, sensitive path access
```

For `.pcap` test files, download from:
- https://www.malware-traffic-analysis.net/
- https://wiki.wireshark.org/SampleCaptures

> **Windows users**: Install [Npcap](https://npcap.com) for full pcap support (free).

## 🗂️ Project Structure

```
├── app.py                    # Main entry point
├── .env                      # API keys (pre-configured)
├── .streamlit/config.toml    # Dark theme config
├── modules/
│   ├── file_analysis.py      # File forensics logic
│   ├── network_analysis.py   # PCAP analysis logic
│   ├── log_analysis.py       # Log parsing & detection
│   └── report_generator.py   # PDF/HTML report generation
├── pages/
│   ├── 1_🔬_File_Analysis.py
│   ├── 2_🌐_Network_Analysis.py
│   ├── 3_📋_Log_Analysis.py
│   └── 4_📄_Report_Generator.py
├── utils/
│   ├── styles.py             # Dark cyberpunk CSS
│   ├── helpers.py            # Shared utilities
│   └── virustotal.py         # VT API wrapper
└── sample_data/              # Test files
```

## ⚠️ Legal Notice

This tool is intended for **authorized forensic investigations only**. Always ensure you have proper authorization before analyzing any system, network, or file.
