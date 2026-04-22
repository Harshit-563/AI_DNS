"""
DNS Threat Detection Dashboard
Real-time visualization and monitoring using Streamlit
"""

from datetime import datetime
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import os

from core.db_service import ThreatDatabase
from core.fastflux_integration import IntegratedThreatClassifier
from core.sniffer_manager import get_sniffer_manager

st.set_page_config(page_title="DNS Threat Detection Dashboard", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --bg-primary: #0d1117;
        --bg-secondary: #161b22;
        --bg-tertiary: #1c2128;
        --accent: #58a6ff;
        --accent-neon: #39ff14;
        --accent-warn: #ffa500;
        --accent-danger: #ff1744;
        --text-main: #e6edf3;
        --text-muted: #8b949e;
        --border: rgba(88, 166, 255, 0.12);
        --success: #3fb950;
        --warning: #ffa500;
        --danger: #f85149;
    }

    html, body, [data-testid="stAppViewContainer"], [data-testid="stVerticalBlockBorderWrapper"] {
        background-color: var(--bg-primary);
    }

    .stApp {
        background:
            radial-gradient(ellipse 1200px 800px at top right, rgba(88, 166, 255, 0.08), transparent 40%),
            radial-gradient(ellipse 1000px 1000px at bottom left, rgba(57, 255, 20, 0.06), transparent 50%),
            linear-gradient(135deg, #0d1117 0%, #161b22 100%);
        color: var(--text-main);
    }

    [data-testid="stHeader"] {
        background: rgba(13, 17, 23, 0.95);
        border-bottom: 1px solid var(--border);
    }

    [data-testid="stSidebar"] [data-testid="stVerticalBlockBorderWrapper"] {
        background: linear-gradient(180deg, #0d1117 0%, #161b22 100%);
        border-right: 2px solid var(--border);
    }

    [data-testid="stSidebar"] * {
        color: var(--text-main);
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }

    .hero-shell {
        padding: 2rem;
        border: 2px solid var(--border);
        border-radius: 14px;
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.8), rgba(13, 17, 23, 0.95));
        box-shadow: 
            0 0 20px rgba(88, 166, 255, 0.15),
            inset 0 1px 0 rgba(88, 166, 255, 0.08);
        margin-bottom: 2rem;
        position: relative;
        overflow: hidden;
    }

    .hero-shell::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(88, 166, 255, 0.3), transparent);
    }

    .hero-kicker {
        color: var(--accent-neon);
        text-transform: uppercase;
        letter-spacing: 0.15em;
        font-size: 0.75rem;
        font-weight: 800;
        margin-bottom: 0.5rem;
        display: inline-block;
        padding: 0.3rem 0.8rem;
        background: rgba(57, 255, 20, 0.1);
        border-radius: 6px;
        border: 1px solid rgba(57, 255, 20, 0.3);
    }

    .hero-title {
        font-size: 2.2rem;
        font-weight: 900;
        line-height: 1.2;
        margin-bottom: 0.5rem;
        background: linear-gradient(135deg, var(--text-main), var(--accent));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }

    .hero-copy {
        color: var(--text-muted);
        font-size: 0.95rem;
        margin: 0;
        font-weight: 400;
    }

    .section-card {
        padding: 1.5rem;
        border-radius: 12px;
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.6), rgba(28, 33, 40, 0.4));
        border: 1px solid var(--border);
        margin-bottom: 1.5rem;
        box-shadow: inset 0 1px 0 rgba(88, 166, 255, 0.06);
    }

    .section-title {
        color: var(--text-main);
        font-weight: 800;
        font-size: 1.05rem;
        margin-bottom: 0.4rem;
        letter-spacing: 0.02em;
    }

    .section-copy {
        color: var(--text-muted);
        margin: 0;
        font-size: 0.9rem;
    }

    .metric-shell {
        border-radius: 12px;
        border: 1px solid var(--border);
        padding: 1rem;
        background: linear-gradient(135deg, rgba(22, 27, 34, 0.7), rgba(28, 33, 40, 0.5));
        box-shadow: inset 0 1px 0 rgba(88, 166, 255, 0.06);
        transition: all 0.2s ease;
    }

    .metric-shell:hover {
        border-color: rgba(88, 166, 255, 0.3);
        box-shadow: 
            inset 0 1px 0 rgba(88, 166, 255, 0.1),
            0 0 15px rgba(88, 166, 255, 0.1);
    }

    .metric-shell.safe {
        border-color: rgba(63, 185, 80, 0.4);
        background: linear-gradient(135deg, rgba(25, 48, 30, 0.6), rgba(22, 27, 34, 0.8));
    }

    .metric-shell.safe:hover {
        border-color: rgba(63, 185, 80, 0.6);
        box-shadow: 
            inset 0 1px 0 rgba(63, 185, 80, 0.1),
            0 0 15px rgba(63, 185, 80, 0.15);
    }

    .metric-shell.watch {
        border-color: rgba(255, 165, 0, 0.4);
        background: linear-gradient(135deg, rgba(51, 40, 15, 0.6), rgba(40, 30, 10, 0.7));
    }

    .metric-shell.watch:hover {
        border-color: rgba(255, 165, 0, 0.6);
        box-shadow: 
            inset 0 1px 0 rgba(255, 165, 0, 0.1),
            0 0 15px rgba(255, 165, 0, 0.15);
    }

    .metric-shell.danger {
        border-color: rgba(248, 81, 73, 0.4);
        background: linear-gradient(135deg, rgba(58, 30, 26, 0.6), rgba(40, 20, 18, 0.7));
    }

    .metric-shell.danger:hover {
        border-color: rgba(248, 81, 73, 0.6);
        box-shadow: 
            inset 0 1px 0 rgba(248, 81, 73, 0.1),
            0 0 15px rgba(248, 81, 73, 0.15);
    }

    [data-testid="metric-container"] {
        background: transparent;
        border: none;
        box-shadow: none;
    }

    [data-testid="metric-container"] label,
    [data-testid="metric-container"] [data-testid="stMetricLabel"] {
        color: var(--text-muted);
        font-weight: 600;
        font-size: 0.85rem;
    }

    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: var(--text-main);
        font-weight: 900;
        font-size: 1.8rem;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background: rgba(22, 27, 34, 0.4);
        padding: 0.5rem;
        border-radius: 12px;
        border: 1px solid var(--border);
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 8px;
        color: var(--text-muted);
        padding: 0.6rem 1rem;
        font-weight: 600;
        transition: all 0.2s ease;
    }

    .stTabs [data-baseweb="tab"]:hover {
        color: var(--text-main);
        background: rgba(88, 166, 255, 0.08);
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(88, 166, 255, 0.2), rgba(88, 166, 255, 0.1));
        color: var(--accent);
        border: 1px solid rgba(88, 166, 255, 0.3);
    }

    .stButton > button,
    .stDownloadButton > button {
        background: linear-gradient(135deg, var(--accent), #3c89d1);
        color: #0d1117;
        border: none;
        border-radius: 8px;
        font-weight: 700;
        padding: 0.6rem 1.2rem;
        transition: all 0.2s ease;
        box-shadow: 0 4px 12px rgba(88, 166, 255, 0.2);
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        box-shadow: 0 6px 20px rgba(88, 166, 255, 0.3);
        transform: translateY(-2px);
    }

    .stTextInput input,
    .stNumberInput input,
    .stSelectbox div[data-baseweb="select"] > div {
        background: rgba(22, 27, 34, 0.8);
        color: var(--text-main);
        border: 1px solid var(--border);
        border-radius: 8px;
        font-size: 0.95rem;
    }

    .stTextInput input:focus,
    .stNumberInput input:focus {
        border-color: var(--accent);
        box-shadow: 0 0 10px rgba(88, 166, 255, 0.15);
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
    }

    [data-testid="stDataFrame"] tbody tr:nth-child(odd) {
        background-color: rgba(88, 166, 255, 0.04);
    }

    [data-testid="stDataFrame"] tbody tr:hover {
        background-color: rgba(88, 166, 255, 0.08);
    }

    [data-testid="stDataFrame"] thead {
        background-color: rgba(88, 166, 255, 0.12);
        border-bottom: 2px solid var(--border);
    }

    [data-testid="stDataFrame"] thead th {
        color: var(--accent);
        font-weight: 700;
        padding: 1rem;
    }

    .stAlert {
        border-radius: 10px;
        border: 1px solid var(--border);
    }

    .badge-status {
        display: inline-block;
        padding: 0.3rem 0.8rem;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.8rem;
    }

    .badge-benign {
        background: rgba(63, 185, 80, 0.15);
        color: var(--success);
        border: 1px solid rgba(63, 185, 80, 0.3);
    }

    .badge-suspicious {
        background: rgba(255, 165, 0, 0.15);
        color: var(--warning);
        border: 1px solid rgba(255, 165, 0, 0.3);
    }

    .badge-dga {
        background: rgba(248, 81, 73, 0.15);
        color: var(--danger);
        border: 1px solid rgba(248, 81, 73, 0.3);
    }

    .badge-fastflux {
        background: rgba(248, 81, 73, 0.15);
        color: var(--danger);
        border: 1px solid rgba(248, 81, 73, 0.3);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "api_url" not in st.session_state: st.session_state.api_url = "http://localhost:5000"
if "sniffer_interface" not in st.session_state: st.session_state.sniffer_interface = ""
if "latest_result" not in st.session_state: st.session_state.latest_result = None

@st.cache_resource
def get_database(): return ThreatDatabase()

@st.cache_resource
def get_sniffer(): return get_sniffer_manager()

@st.cache_resource
def get_local_classifier():
    model_path = Path("models") / "dns_best_model.pkl"
    return IntegratedThreatClassifier(
        model_path=str(model_path) if model_path.exists() else None
    )

db = get_database()
sniffer = get_sniffer()
classifier = get_local_classifier()

st.markdown(
    """
    <div class="hero-shell">
        <div class="hero-kicker">🛡️ Advanced Threat Detection</div>
        <div class="hero-title">DNS Threat Detection Dashboard</div>
        <p class="hero-copy">Real-time monitoring and classification of DNS queries using AI-powered threat analysis. Detect DGA, Fast-Flux, and suspicious domain patterns instantly.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

def render_section_card(title, copy):
    st.markdown(f'<div class="section-card"><div class="section-title">📊 {title}</div><p class="section-copy">{copy}</p></div>', unsafe_allow_html=True)

def metric_card(label, value, tone="default"):
    tone_class = "" if tone == "default" else f" {tone}"
    st.markdown(f'<div class="metric-shell{tone_class}">', unsafe_allow_html=True)
    st.metric(label, value)
    st.markdown("</div>", unsafe_allow_html=True)

def get_badge(status):
    """Generate HTML badge for threat status."""
    status_lower = str(status).lower()
    if "benign" in status_lower:
        return '<span class="badge-status badge-benign">✓ Benign</span>'
    elif "suspicious" in status_lower:
        return '<span class="badge-status badge-suspicious">⚠ Suspicious</span>'
    elif "dga" in status_lower:
        return '<span class="badge-status badge-dga">🔴 DGA</span>'
    elif "fast-flux" in status_lower or "fast_flux" in status_lower:
        return '<span class="badge-status badge-fastflux">🔴 Fast-Flux</span>'
    return f'<span class="badge-status">{status}</span>'

def normalize_prediction_label(result):
    if result.get("is_fastflux"):
        return "fast_flux"
    return result.get("status") or result.get("final_prediction") or "Unknown"

def resolve_final_class(result):
    if result.get("is_fastflux"):
        return 2
    if result.get("final_class") is not None:
        return int(result["final_class"])
    if result.get("final_class_int") is not None:
        return int(result["final_class_int"])

    label = str(normalize_prediction_label(result)).lower()
    class_map = {
        "benign": 0,
        "suspicious": 3,
        "dga": 1,
        "fast-flux": 2,
        "fast_flux": 2,
    }
    return class_map.get(label, 0)

def save_result_to_database(result, source_ip="dashboard_manual"):
    detection_id = db.insert_threat_detection(
        {
            "domain": result.get("domain"),
            "final_class": resolve_final_class(result),
            "confidence": float(result.get("confidence", 0.0)),
            "ff_score": float(result.get("ff_score", 0.0)),
            "is_fastflux": bool(result.get("is_fastflux", False)),
            "source_ip": source_ip,
            "model_version": "dashboard_manual",
        }
    )
    return detection_id

def classify_with_sniffer_fastflux_logic(domain, ttl, unique_ip_count, query_rate):
    ttl = int(ttl)
    unique_ip_count = max(int(unique_ip_count), 1)
    query_rate = max(float(query_rate), 1.0)

    result = classifier.classify(
        domain=domain,
        ttl=ttl,
        unique_ip_count=unique_ip_count,
        query_rate=query_rate,
    )
    fastflux = classifier.detect_fastflux(
        domain=domain,
        ttl=ttl,
        unique_ip_count=unique_ip_count,
        query_rate=query_rate,
    )

    prediction = result.get("final_prediction", "Benign")
    normalized = prediction if prediction != "Unknown" else "Benign"
    confidence = float(result.get("confidence", result.get("base_confidence", 0.5)))

    fastflux_analysis = result.get("fastflux_analysis") or {}
    if fastflux:
        fastflux_analysis.update(fastflux)

    ff_score = float(fastflux_analysis.get("fastflux_score", 0.0))
    is_fastflux = bool(fastflux_analysis.get("is_fastflux", False))

    if is_fastflux:
        normalized = "fast_flux"
        confidence = 100 * ff_score

    status = "Benign"
    if normalized == "Benign" and confidence >= 0.55:
        status = "Benign"
    elif normalized == "fast_flux":
        status = "fast_flux"
    elif normalized != "Benign" and confidence >= 0.62:
        status = normalized.upper()
    elif normalized != "Benign" and confidence >= 0.55:
        status = "SUSPICIOUS"

    return {
        "domain": domain,
        "label": normalized,
        "status": status,
        "final_prediction": normalized,
        "final_class": result.get("final_class"),
        "confidence": confidence,
        "recommendation": "BLOCK" if normalized != "Benign" else "ALLOW",
        "probabilities": {
            "base_prediction": result.get("base_prediction"),
            "base_class": result.get("base_class"),
            "base_confidence": float(result.get("base_confidence", 0.5)),
            "final_class": result.get("final_class"),
        },
        "is_fastflux": is_fastflux,
        "ff_score": ff_score,
        "fastflux_analysis": fastflux_analysis,
        "timestamp": datetime.now().isoformat(),
    }

def format_score_percent(value):
    value = float(value or 0)
    return f"{value:.1f}%" if value > 1 else f"{value:.1%}"

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("## 🎛️ Control Center")
    st.divider()
    
    st.markdown("### 🔌 API Configuration")
    api_url = st.text_input("API Base URL", value=st.session_state.api_url, help="Base URL for the threat classification API")
    st.session_state.api_url = api_url.rstrip("/")

    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.rerun()

    st.divider()
    
    st.markdown("### 📡 DNS Sniffer Control")
    sniffer_status = sniffer.get_status()
    st.session_state.sniffer_interface = st.text_input(
        "Network Interface",
        value=st.session_state.sniffer_interface,
        placeholder="Ethernet / Wi-Fi / eth0",
        help="Leave blank to auto-detect",
    )

    sniffer_col1, sniffer_col2 = st.columns(2, gap="small")
    with sniffer_col1:
        start_clicked = st.button("▶️ Start", use_container_width=True)
    with sniffer_col2:
        stop_clicked = st.button("⏹️ Stop", use_container_width=True)

    if start_clicked:
        interface = st.session_state.sniffer_interface.strip() or None
        if sniffer.start(interface=interface):
            st.success("✅ DNS sniffer started")
            st.rerun()
        else:
            error = sniffer.get_status().get("error") or "Sniffer could not be started"
            st.error(f"❌ {error}")

    if stop_clicked:
        if sniffer.stop():
            st.success("✅ DNS sniffer stopped")
            st.rerun()
        else:
            st.warning("⚠️ Sniffer is not running")

    st.divider()
    
    st.markdown("### 📊 Sniffer Status")
    running_tone = "safe" if sniffer_status.get("running") else "watch"
    col1, col2 = st.columns(2, gap="small")
    with col1:
        st.metric("State", "🟢 Active" if sniffer_status.get("running") else "🔴 Paused")
    with col2:
        st.metric("Packets", f"{sniffer_status.get('packets_received', 0):,}")
    
    st.metric("Classified", f"{sniffer_status.get('domains_classified', 0):,}")
    
    if sniffer_status.get("error"):
        st.error(f"⚠️ {sniffer_status['error']}")

tab1, tab2, tab3, tab4 = st.tabs(["Statistics", "Recent Detections", "Malicious Domains", "Manual Classification"])

# --- TAB 1: STATS ---
with tab1:
    render_section_card("Threat Statistics", "Real-time analysis of DNS queries and threat composition.")
    
    col_time, col_refresh = st.columns([3, 1])
    with col_time:
        hours = st.selectbox("📅 Time Period", [1, 6, 24, 72, 168], index=2, format_func=lambda h: f"{h}h" if h < 24 else f"{h//24}d")
    with col_refresh:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    stats = db.get_detection_stats(hours=hours)
    
    total = sum(stats.values())
    
    # Enhanced metric cards with better styling
    metric_cols = st.columns(5, gap="small")
    with metric_cols[0]:
        st.metric("📈 Total Queries", f"{total:,}", delta=f"Last {hours}h")
    with metric_cols[1]:
        benign_count = stats.get('0', 0)
        st.metric("✅ Benign", f"{benign_count:,}", delta=f"{(benign_count/max(total,1)*100):.1f}%")
    with metric_cols[2]:
        suspicious_count = stats.get('3', 0)
        st.metric("⚠️ Suspicious", f"{suspicious_count:,}", delta=f"{(suspicious_count/max(total,1)*100):.1f}%")
    with metric_cols[3]:
        dga_count = stats.get('1', 0)
        st.metric("🔴 DGA", f"{dga_count:,}", delta=f"{(dga_count/max(total,1)*100):.1f}%")
    with metric_cols[4]:
        fastflux_count = stats.get('2', 0)
        st.metric("🔴 Fast-Flux", f"{fastflux_count:,}", delta=f"{(fastflux_count/max(total,1)*100):.1f}%")

    st.divider()

    chart_col1, chart_col2 = st.columns([1.2, 0.8], gap="medium")
    composition_df = pd.DataFrame(
        {
            "Class": ["Benign", "Suspicious", "DGA", "Fast-Flux"],
            "Count": [
                stats.get("0", 0),
                stats.get("3", 0),
                stats.get("1", 0),
                stats.get("2", 0),
            ],
            "Color": ["#3fb950", "#ffa500", "#f85149", "#ff1744"],
        }
    )

    with chart_col1:
        st.subheader("📊 Threat Composition")
        fig_bar = go.Figure(
            data=[
                go.Bar(
                    x=composition_df["Class"],
                    y=composition_df["Count"],
                    marker=dict(color=composition_df["Color"], line=dict(color="rgba(88, 166, 255, 0.5)", width=2)),
                    text=composition_df["Count"],
                    textposition="outside",
                    textfont=dict(color="#e6edf3", size=12, family="monospace"),
                    hovertemplate="<b>%{x}</b><br>Count: %{y:,}<extra></extra>"
                )
            ]
        )
        fig_bar.update_layout(
            title=None,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(88,166,255,0.04)",
            font=dict(color="#e6edf3", family="monospace"),
            margin=dict(l=40, r=20, t=20, b=40),
            xaxis=dict(title=None, showgrid=False, showline=True, linewidth=1, linecolor="rgba(88,166,255,0.2)"),
            yaxis=dict(title="Count", gridcolor="rgba(88,166,255,0.1)", showline=True, linewidth=1, linecolor="rgba(88,166,255,0.2)"),
            hovermode="x unified",
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with chart_col2:
        st.subheader("🎯 Traffic Split")
        fig_donut = go.Figure(
            data=[
                go.Pie(
                    labels=composition_df["Class"],
                    values=composition_df["Count"],
                    hole=0.65,
                    marker=dict(colors=composition_df["Color"], line=dict(color="#0d1117", width=2)),
                    textinfo="label+percent",
                    textfont=dict(color="#e6edf3", size=11),
                    hovertemplate="<b>%{label}</b><br>Count: %{value:,}<br>Percentage: %{percent}<extra></extra>"
                )
            ]
        )
        fig_donut.update_layout(
            title=None,
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e6edf3", family="monospace"),
            margin=dict(l=20, r=20, t=20, b=20),
            showlegend=True,
            legend=dict(orientation="v", yanchor="top", y=0.9, xanchor="left", x=0),
        )
        st.plotly_chart(fig_donut, use_container_width=True)

# --- TAB 2 & 3: HISTORY ---
with tab2:
    render_section_card("Recent Detections", "Inspect the latest classified domains with detailed analysis.")
    
    col_limit, col_hours = st.columns(2)
    with col_limit:
        limit = st.number_input("Show last N records", value=30, min_value=5, max_value=100, step=5)
    with col_hours:
        hours_back = st.number_input("Within last N hours", value=24, min_value=1, max_value=168, step=1)
    
    detections = db.get_recent_detections(limit=limit, hours=hours_back)
    if detections:
        df = pd.DataFrame(detections)
        # SAFELY MAP DB INTEGERS TO STRINGS
        class_map = {0: "Benign", 3: "Suspicious", 1: "DGA", 2: "Fast-Flux"}
        df["final_class"] = df["final_class"].map(class_map).fillna("Unknown")
        df["ff_score"] = df["ff_score"].apply(lambda x: f"{x:.2%}" if x else "N/A")
        df["confidence"] = df["confidence"].apply(lambda x: format_score_percent(x) if x else "N/A")
        df["is_fastflux"] = df["is_fastflux"].apply(lambda x: "🔴 Yes" if x else "✓ No")
        df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        
        display_df = df[["domain", "final_class", "confidence", "ff_score", "is_fastflux", "timestamp"]].rename(columns={
            "domain": "Domain",
            "final_class": "Threat Type",
            "confidence": "Confidence",
            "ff_score": "FF Score",
            "is_fastflux": "Fast-Flux",
            "timestamp": "Timestamp"
        })
        
        st.dataframe(display_df, use_container_width=True, hide_index=True, height=400)
    else:
        st.info("📭 No detections found in the selected time period.")

with tab3:
    render_section_card("Malicious Domains", "Focus on confirmed high-risk domains detected in this period.")
    
    col_limit2, col_hours2 = st.columns(2)
    with col_limit2:
        limit2 = st.number_input("Show last N malicious records", value=30, min_value=5, max_value=100, step=5, key="mal_limit")
    with col_hours2:
        hours_back2 = st.number_input("Within last N hours", value=24, min_value=1, max_value=168, step=1, key="mal_hours")
    
    malicious = db.get_malicious_domains(hours=hours_back2, limit=limit2)
    if malicious:
        df = pd.DataFrame(malicious)
        class_map = {3: "Suspicious", 1: "DGA", 2: "Fast-Flux"}
        df["final_class"] = df["final_class"].map(class_map).fillna("Unknown")
        df["ff_score"] = df["ff_score"].apply(lambda x: f"{x:.2%}" if x else "N/A")
        df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        
        display_df2 = df[["domain", "final_class", "ff_score", "timestamp"]].rename(columns={
            "domain": "Domain",
            "final_class": "Threat Type",
            "ff_score": "FF Score",
            "timestamp": "Timestamp"
        })
        
        st.dataframe(display_df2, use_container_width=True, hide_index=True, height=400)
    else:
        st.info("✓ No malicious domains detected in the selected time period.")

# --- TAB 4: MANUAL CLASSIFICATION (BUG FIXED) ---
with tab4:
    render_section_card("Manual Domain Classification", "Submit a domain for real-time threat analysis and scoring.")
    
    st.subheader("🔍 Classification Input")
    domain = st.text_input("Domain Name", placeholder="example.com", help="Enter the domain you want to analyze")
    
    param_cols = st.columns(4, gap="small")
    with param_cols[0]:
        ttl = st.number_input("TTL (seconds)", value=3600, min_value=1, help="Time-to-Live value for DNS records")
    with param_cols[1]:
        unique_ips = st.number_input("Unique IPs", value=1, min_value=1, help="Number of unique IP addresses")
    with param_cols[2]:
        query_rate = st.number_input("Query Rate", value=100, min_value=1, help="Number of queries per period")
    with param_cols[3]:
        classify_button = st.button("🚀 Classify", use_container_width=True, type="primary")

    if classify_button and domain:
        with st.spinner("🔄 Analyzing domain..."):
            try:
                result = classify_with_sniffer_fastflux_logic(
                    domain=domain,
                    ttl=ttl,
                    unique_ip_count=unique_ips,
                    query_rate=query_rate,
                )

                if result:
                    st.session_state.latest_result = result
                    
                    # Display results with improved styling
                    st.subheader("📋 Classification Results")
                    
                    status_label = normalize_prediction_label(result)
                    if status_label == "fast_flux": 
                        display_text = "Fast-Flux"
                    else: 
                        display_text = status_label

                    # DETERMINE COLOR TONE
                    if display_text == "Benign": 
                        tone = "safe"
                        icon = "✅"
                    elif "SUSPICIOUS" in display_text.upper(): 
                        tone = "watch"
                        icon = "⚠️"
                    else: 
                        tone = "danger"
                        icon = "🔴"

                    result_cols = st.columns(4, gap="small")
                    with result_cols[0]:
                        st.metric("🌐 Domain", result.get("domain"), help="Analyzed domain name")
                    with result_cols[1]:
                        st.metric(f"{icon} Assessment", display_text, help="Threat classification")
                    with result_cols[2]:
                        conf_pct = result.get('confidence', 0)
                        st.metric("📊 Confidence", format_score_percent(conf_pct), help="Model confidence score")
                    with result_cols[3]:
                        ff_score = result.get('ff_score', 0)
                        st.metric("⚡ FF Score", f"{ff_score:.2%}", help="Fast-Flux detection score")

                    st.divider()
                    
                    # Detailed analysis box
                    st.markdown("#### 🔬 Detailed Analysis")
                    analysis_cols = st.columns(3)
                    with analysis_cols[0]:
                        st.markdown(f"""
                        **Model Prediction**  
                        {result.get('final_prediction', 'Unknown')}
                        """)
                    with analysis_cols[1]:
                        st.markdown(f"""
                        **Fast-Flux Status**  
                        {"🔴 Detected" if result.get('is_fastflux') else "✓ Not Detected"}
                        """)
                    with analysis_cols[2]:
                        st.markdown(f"""
                        **Recommendation**  
                        {"🛑 BLOCK" if display_text != "Benign" else "✓ ALLOW"}
                        """)
                else:
                    st.error("Classification failed: no result returned")
            except Exception as e:
                st.error(f"Classification failed: {e}")

    st.divider()
    
    if st.session_state.latest_result:
        st.subheader("💾 Save Result")
        latest = st.session_state.latest_result
        st.caption(f"Latest result for: **{latest.get('domain', 'Unknown domain')}**")
        
        col_save, col_clear = st.columns(2)
        with col_save:
            if st.button("💾 Save to Database", use_container_width=True):
                try:
                    detection_id = save_result_to_database(latest)
                    st.success(f"✅ Saved to database with detection ID: **{detection_id}**")
                except Exception as exc:
                    st.error(f"❌ Database save failed: {exc}")
        
        with col_clear:
            if st.button("🗑️ Clear Result", use_container_width=True):
                st.session_state.latest_result = None
                st.rerun()
