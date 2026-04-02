"""
utils/styles.py — Global CSS injection for Obsidian Circuit dark cyberpunk theme
"""
import streamlit as st


def inject_global_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    /* ===== BASE RESET ===== */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif !important;
    }

    /* ===== BACKGROUND ===== */
    .stApp {
        background: radial-gradient(ellipse at top left, #0d0d2b 0%, #0a0a1a 60%, #080818 100%) !important;
    }

    /* ===== SIDEBAR ===== */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d0d2b 0%, #0a0a1a 100%) !important;
        border-right: 1px solid #1a1a4a !important;
    }
    [data-testid="stSidebar"] .stSelectbox label,
    [data-testid="stSidebar"] p {
        color: #aaaacc !important;
    }

    /* ===== HERO BANNER ===== */
    .hero-banner {
        background: linear-gradient(135deg, #0d1b4b 0%, #1a0d4b 50%, #0d2b3b 100%);
        border: 1px solid #1e1e5a;
        border-radius: 16px;
        padding: 40px 48px;
        margin-bottom: 32px;
        position: relative;
        overflow: hidden;
    }
    .hero-banner::before {
        content: '';
        position: absolute;
        top: -50%; left: -50%;
        width: 200%; height: 200%;
        background: conic-gradient(from 0deg, transparent, rgba(0,212,255,0.05), transparent 30%);
        animation: rotate 8s linear infinite;
    }
    @keyframes rotate { to { transform: rotate(360deg); } }
    .hero-title {
        font-size: 2.8rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00d4ff, #8b00ff, #00d4ff);
        background-size: 200%;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: shimmer 3s linear infinite;
        letter-spacing: 3px;
        margin-bottom: 8px;
    }
    @keyframes shimmer { to { background-position: 200%; } }
    .hero-sub {
        color: #7799bb;
        font-size: 1rem;
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    /* ===== MODULE CARDS ===== */
    .module-card {
        border-radius: 14px;
        padding: 28px 24px;
        height: 280px;
        display: flex;
        flex-direction: column;
        border: 1px solid transparent;
        transition: transform 0.2s, box-shadow 0.2s;
        cursor: default;
    }
    .module-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 40px rgba(0,0,0,0.4);
    }
    .card-blue {
        background: linear-gradient(135deg, #0a1628, #0d2040);
        border-color: #00d4ff33;
        box-shadow: 0 0 20px rgba(0,212,255,0.08);
    }
    .card-blue:hover { box-shadow: 0 8px 32px rgba(0,212,255,0.2); }
    .card-purple {
        background: linear-gradient(135deg, #150a28, #200d40);
        border-color: #8b00ff33;
        box-shadow: 0 0 20px rgba(139,0,255,0.08);
    }
    .card-purple:hover { box-shadow: 0 8px 32px rgba(139,0,255,0.2); }
    .card-green {
        background: linear-gradient(135deg, #0a1a14, #0d2a1e);
        border-color: #00ff9f33;
        box-shadow: 0 0 20px rgba(0,255,159,0.08);
    }
    .card-green:hover { box-shadow: 0 8px 32px rgba(0,255,159,0.2); }
    .module-icon { font-size: 2.5rem; margin-bottom: 12px; }
    .module-name {
        font-size: 1.2rem; font-weight: 700; color: #e0e0f0;
        margin-bottom: 10px; letter-spacing: 1px;
    }
    .module-desc { color: #8888aa; font-size: 0.88rem; line-height: 1.6; }
    .module-tag {
        margin-top: auto; font-size: 0.78rem; color: #00d4ff;
        font-family: 'JetBrains Mono', monospace;
    }

    /* ===== STAT CARDS ===== */
    .stat-card {
        background: linear-gradient(135deg, #111130, #0d0d28);
        border: 1px solid #222255;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        transition: border-color 0.2s;
    }
    .stat-card:hover { border-color: #00d4ff55; }
    .stat-num {
        font-size: 1.8rem; font-weight: 800;
        background: linear-gradient(90deg, #00d4ff, #8b00ff);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .stat-label { color: #666688; font-size: 0.78rem; letter-spacing: 1px; margin-top: 4px; }

    /* ===== SECTION HEADERS ===== */
    .section-header {
        display: flex; align-items: center; gap: 12px;
        padding: 16px 20px;
        background: linear-gradient(90deg, #111130, transparent);
        border-left: 3px solid #00d4ff;
        border-radius: 0 8px 8px 0;
        margin: 24px 0 16px 0;
    }
    .section-header h2, .section-header h3 {
        margin: 0; color: #e0e0f0; font-weight: 700;
    }

    /* ===== FINDING CARDS ===== */
    .finding-critical {
        background: linear-gradient(135deg, #2a0a0a, #3a0808);
        border: 1px solid #ff333355;
        border-left: 3px solid #ff3333;
        border-radius: 10px; padding: 14px 18px; margin: 8px 0;
    }
    .finding-warning {
        background: linear-gradient(135deg, #2a1a0a, #3a2208);
        border: 1px solid #ff990033;
        border-left: 3px solid #ff9900;
        border-radius: 10px; padding: 14px 18px; margin: 8px 0;
    }
    .finding-info {
        background: linear-gradient(135deg, #0a1a2a, #0d2038);
        border: 1px solid #00d4ff22;
        border-left: 3px solid #00d4ff;
        border-radius: 10px; padding: 14px 18px; margin: 8px 0;
    }
    .finding-safe {
        background: linear-gradient(135deg, #0a2a14, #0d3018);
        border: 1px solid #00ff9f22;
        border-left: 3px solid #00ff9f;
        border-radius: 10px; padding: 14px 18px; margin: 8px 0;
    }

    /* ===== BADGES ===== */
    .badge-critical {
        background: #ff333322; color: #ff6666; border: 1px solid #ff333355;
        padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
    }
    .badge-warning {
        background: #ff990022; color: #ffaa44; border: 1px solid #ff990055;
        padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
    }
    .badge-info {
        background: #00d4ff22; color: #00d4ff; border: 1px solid #00d4ff55;
        padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
    }
    .badge-safe {
        background: #00ff9f22; color: #00ff9f; border: 1px solid #00ff9f55;
        padding: 2px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
    }

    /* ===== HASH DISPLAY ===== */
    .hash-box {
        background: #070714; border: 1px solid #222244;
        border-radius: 8px; padding: 10px 16px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem; color: #00d4ff;
        word-break: break-all; margin: 6px 0;
    }

    /* ===== INFO TABLE ===== */
    .info-table {
        width: 100%;
        border-collapse: collapse;
    }
    .info-table tr:nth-child(even) td {
        background: rgba(255,255,255,0.02);
    }
    .info-table td {
        padding: 8px 14px;
        border-bottom: 1px solid #1a1a3a;
        color: #c0c0e0;
        font-size: 0.88rem;
    }
    .info-table td:first-child {
        color: #7788bb; font-weight: 600; width: 180px;
    }

    /* ===== BUTTONS ===== */
    .stButton > button {
        background: linear-gradient(135deg, #1a1a4a, #0d2040) !important;
        border: 1px solid #00d4ff44 !important;
        color: #e0e0f0 !important;
        border-radius: 8px !important;
        transition: all 0.2s !important;
    }
    .stButton > button:hover {
        border-color: #00d4ff !important;
        box-shadow: 0 0 16px rgba(0,212,255,0.2) !important;
        transform: translateY(-1px) !important;
    }

    /* ===== METRICS ===== */
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, #111130, #0d0d28);
        border: 1px solid #222255;
        border-radius: 12px;
        padding: 16px !important;
    }

    /* ===== FILE UPLOADER ===== */
    [data-testid="stFileUploader"] {
        background: linear-gradient(135deg, #0a0a1e, #0d0d28) !important;
        border: 2px dashed #222255 !important;
        border-radius: 12px !important;
    }

    /* ===== TABS ===== */
    .stTabs [data-baseweb="tab-list"] {
        background: transparent !important;
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background: #111130 !important;
        border-radius: 8px 8px 0 0 !important;
        color: #7788bb !important;
        border: 1px solid #222255 !important;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #1a1a4a, #0d2040) !important;
        color: #00d4ff !important;
        border-color: #00d4ff44 !important;
    }

    /* ===== SCROLLBAR ===== */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #0a0a1a; }
    ::-webkit-scrollbar-thumb { background: #222255; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #00d4ff55; }

    /* ===== ALERTS ===== */
    .alert-box {
        border-radius: 10px; padding: 16px 20px; margin: 12px 0;
        display: flex; align-items: flex-start; gap: 12px;
    }
    .alert-critical { background: #2a0a0a; border: 1px solid #ff333355; }
    .alert-warning  { background: #2a1a0a; border: 1px solid #ff990044; }
    .alert-safe     { background: #0a2a14; border: 1px solid #00ff9f33; }

    /* ===== PAGE TITLE ===== */
    .page-title {
        font-size: 1.8rem; font-weight: 800; letter-spacing: 2px;
        background: linear-gradient(90deg, #00d4ff, #8b00ff);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        margin-bottom: 4px;
    }
    .page-subtitle { color: #556688; font-size: 0.9rem; margin-bottom: 24px; }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    </style>
    """, unsafe_allow_html=True)
