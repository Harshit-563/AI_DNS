"""
DNS Threat Detection Dashboard
Real-time visualization and monitoring using Streamlit
"""

from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
import os

from core.db_service import ThreatDatabase
from core.sniffer_manager import get_sniffer_manager

st.set_page_config(page_title="DNS Threat Detection Dashboard", page_icon="Shield", layout="wide")

st.markdown(
    """
    <style>
    :root {
        --bg-primary: #0a101a;
        --bg-secondary: #141f2e;
        --bg-tertiary: #1b2a3d;
        --accent: #f59e0b;
        --accent-soft: rgba(245, 158, 11, 0.18);
        --text-main: #f3f6fb;
        --text-muted: #9fb0c7;
        --border: rgba(159, 176, 199, 0.18);
        --success: #22c55e;
        --warning: #f59e0b;
        --danger: #ef4444;
    }

    .stApp {
        background:
            radial-gradient(circle at top right, rgba(245, 158, 11, 0.10), transparent 24%),
            radial-gradient(circle at top left, rgba(59, 130, 246, 0.10), transparent 18%),
            linear-gradient(180deg, #0a101a 0%, #0d1522 100%);
        color: var(--text-main);
    }

    [data-testid="stHeader"] {
        background: rgba(10, 16, 26, 0.85);
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #111a28 0%, #0d1522 100%);
        border-right: 1px solid var(--border);
    }

    [data-testid="stSidebar"] * {
        color: var(--text-main);
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    .hero-shell {
        padding: 1.4rem 1.5rem;
        border: 1px solid var(--border);
        border-radius: 22px;
        background: linear-gradient(135deg, rgba(20, 31, 46, 0.92), rgba(10, 16, 26, 0.96));
        box-shadow: 0 18px 45px rgba(0, 0, 0, 0.28);
        margin-bottom: 1rem;
    }

    .hero-kicker {
        color: var(--accent);
        text-transform: uppercase;
        letter-spacing: 0.16em;
        font-size: 0.76rem;
        font-weight: 700;
        margin-bottom: 0.45rem;
    }

    .hero-title {
        font-size: 2rem;
        font-weight: 800;
        line-height: 1.1;
        margin-bottom: 0.35rem;
    }

    .hero-copy {
        color: var(--text-muted);
        font-size: 0.98rem;
        margin: 0;
    }

    .section-card {
        padding: 1rem 1.1rem;
        border-radius: 18px;
        background: linear-gradient(180deg, rgba(20, 31, 46, 0.96), rgba(15, 23, 35, 0.98));
        border: 1px solid var(--border);
        margin-bottom: 1rem;
    }

    .section-title {
        color: var(--text-main);
        font-weight: 700;
        font-size: 1rem;
        margin-bottom: 0.3rem;
    }

    .section-copy {
        color: var(--text-muted);
        margin: 0;
    }

    .metric-shell {
        border-radius: 18px;
        border: 1px solid var(--border);
        padding: 0.35rem;
        background: linear-gradient(180deg, rgba(20, 31, 46, 0.95), rgba(12, 18, 29, 0.98));
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02);
    }

    .metric-shell.safe {
        border-color: rgba(34, 197, 94, 0.35);
        background: linear-gradient(180deg, rgba(16, 44, 30, 0.95), rgba(10, 24, 19, 0.98));
    }

    .metric-shell.watch {
        border-color: rgba(245, 158, 11, 0.38);
        background: linear-gradient(180deg, rgba(54, 37, 8, 0.95), rgba(30, 20, 4, 0.98));
    }

    .metric-shell.danger {
        border-color: rgba(239, 68, 68, 0.35);
        background: linear-gradient(180deg, rgba(58, 20, 24, 0.95), rgba(28, 10, 13, 0.98));
    }

    [data-testid="metric-container"] {
        background: transparent;
        border: none;
        box-shadow: none;
    }

    [data-testid="metric-container"] label,
    [data-testid="metric-container"] [data-testid="stMetricLabel"] {
        color: var(--text-muted);
    }

    [data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: var(--text-main);
        font-weight: 800;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.6rem;
        background: rgba(20, 31, 46, 0.55);
        padding: 0.45rem;
        border-radius: 16px;
        border: 1px solid var(--border);
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 12px;
        color: var(--text-muted);
        padding: 0.55rem 0.9rem;
    }

    .stTabs [aria-selected="true"] {
        background: var(--accent-soft);
        color: var(--text-main);
    }

    .stButton > button,
    .stDownloadButton > button {
        background: linear-gradient(135deg, #f59e0b, #d97706);
        color: #111827;
        border: none;
        border-radius: 12px;
        font-weight: 700;
    }

    .stTextInput input,
    .stNumberInput input,
    .stSelectbox div[data-baseweb="select"] > div {
        background: rgba(20, 31, 46, 0.9);
        color: var(--text-main);
        border: 1px solid var(--border);
        border-radius: 12px;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 18px;
        overflow: hidden;
    }

    .stAlert {
        border-radius: 14px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "api_url" not in st.session_state: st.session_state.api_url = "https://ai-dns.onrender.com"
if "sniffer_interface" not in st.session_state: st.session_state.sniffer_interface = ""
if "latest_result" not in st.session_state: st.session_state.latest_result = None

@st.cache_resource
def get_database(): return ThreatDatabase()

@st.cache_resource
def get_sniffer(): return get_sniffer_manager()

db = get_database()
sniffer = get_sniffer()

st.markdown(
    """
    <div class="hero-shell">
        <div class="hero-kicker">Threat Monitoring</div>
        <div class="hero-title">DNS Threat Detection Dashboard</div>
        <p class="hero-copy">To use the DNS sniffer, run it locally or on a remote server.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

def render_section_card(title, copy):
    st.markdown(f'<div class="section-card"><div class="section-title">{title}</div><p class="section-copy">{copy}</p></div>', unsafe_allow_html=True)

def metric_card(label, value, tone="default"):
    tone_class = "" if tone == "default" else f" {tone}"
    st.markdown(f'<div class="metric-shell{tone_class}">', unsafe_allow_html=True)
    st.metric(label, value)
    st.markdown("</div>", unsafe_allow_html=True)

def normalize_prediction_label(result):
    if result.get("is_fastflux"):
        return "fast_flux"
    return result.get("status") or result.get("final_prediction") or "Unknown"

def resolve_final_class(result):
    if result.get("final_class") is not None:
        return int(result["final_class"])

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

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("## 🛠️ Control Room")
    api_url = st.text_input("API Base URL", value=st.session_state.api_url)
    st.session_state.api_url = api_url.rstrip("/")

    if st.button("Refresh Dashboard", use_container_width=True):
        st.rerun()

    st.markdown("### DNS Sniffer")
    sniffer_status = sniffer.get_status()
    st.session_state.sniffer_interface = st.text_input(
        "Interface",
        value=st.session_state.sniffer_interface,
        placeholder="Ethernet / Wi-Fi / eth0",
        help="Leave blank to auto-detect if supported by the host.",
    )

    sniffer_col1, sniffer_col2 = st.columns(2)
    with sniffer_col1:
        start_clicked = st.button("Start Sniffer", use_container_width=True)
    with sniffer_col2:
        stop_clicked = st.button("Stop Sniffer", use_container_width=True)

    if start_clicked:
        interface = st.session_state.sniffer_interface.strip() or None
        if sniffer.start(interface=interface):
            st.success("DNS sniffer started.")
            st.rerun()
        else:
            error = sniffer.get_status().get("error") or "Sniffer could not be started."
            st.error(error)

    if stop_clicked:
        if sniffer.stop():
            st.success("DNS sniffer stopped.")
            st.rerun()
        else:
            st.warning("Sniffer is not running.")

    running_tone = "safe" if sniffer_status.get("running") else "watch"
    metric_card("Sniffer State", "Running" if sniffer_status.get("running") else "Stopped", tone=running_tone)
    metric_card("Packets", f"{sniffer_status.get('packets_received', 0):,}")
    metric_card("Classified", f"{sniffer_status.get('domains_classified', 0):,}")
    if sniffer_status.get("error"):
        st.error(sniffer_status["error"])

tab1, tab2, tab3, tab4 = st.tabs(["Statistics", "Recent Detections", "Malicious Domains", "Manual Classification"])

# --- TAB 1: STATS ---
with tab1:
    render_section_card("Threat Statistics", "Track total query volume and threat composition.")
    hours = st.selectbox("Time Period", [1, 6, 24, 72, 168], index=2)
    stats = db.get_detection_stats(hours=hours)
    
    total = sum(stats.values())
    metric_cols = st.columns(5)
    with metric_cols[0]: metric_card("Total Queries", f"{total:,}")
    with metric_cols[1]: metric_card("Benign", f"{stats.get('0', 0):,}", tone="safe")
    with metric_cols[2]: metric_card("Suspicious", f"{stats.get('3', 0):,}", tone="watch")
    with metric_cols[3]: metric_card("DGA", f"{stats.get('1', 0):,}", tone="danger")
    with metric_cols[4]: metric_card("Fast-Flux", f"{stats.get('2', 0):,}", tone="danger")

    chart_col1, chart_col2 = st.columns([1.15, 0.85])
    composition_df = pd.DataFrame(
        {
            "Class": ["Benign", "Suspicious", "DGA", "Fast-Flux"],
            "Count": [
                stats.get("0", 0),
                stats.get("3", 0),
                stats.get("1", 0),
                stats.get("2", 0),
            ],
            "Color": ["#22c55e", "#f59e0b", "#ef4444", "#fb7185"],
        }
    )

    with chart_col1:
        fig_bar = go.Figure(
            data=[
                go.Bar(
                    x=composition_df["Class"],
                    y=composition_df["Count"],
                    marker_color=composition_df["Color"],
                    text=composition_df["Count"],
                    textposition="outside",
                )
            ]
        )
        fig_bar.update_layout(
            title="Threat Composition",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(20,31,46,0.55)",
            font=dict(color="#f3f6fb"),
            margin=dict(l=20, r=20, t=50, b=20),
            xaxis=dict(title=None, showgrid=False),
            yaxis=dict(title="Count", gridcolor="rgba(159,176,199,0.12)"),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with chart_col2:
        fig_donut = go.Figure(
            data=[
                go.Pie(
                    labels=composition_df["Class"],
                    values=composition_df["Count"],
                    hole=0.62,
                    marker=dict(colors=composition_df["Color"]),
                    textinfo="label+percent",
                )
            ]
        )
        fig_donut.update_layout(
            title="Traffic Split",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f3f6fb"),
            margin=dict(l=20, r=20, t=50, b=20),
            showlegend=False,
        )
        st.plotly_chart(fig_donut, use_container_width=True)

# --- TAB 2 & 3: HISTORY ---
with tab2:
    render_section_card("Recent Detections", "Inspect the latest classified domains.")
    detections = db.get_recent_detections(limit=30, hours=24)
    if detections:
        df = pd.DataFrame(detections)
        # SAFELY MAP DB INTEGERS TO STRINGS
        class_map = {0: "Benign", 3: "Suspicious", 1: "DGA", 2: "Fast-Flux"}
        df["Class"] = df["final_class"].map(class_map).fillna("Unknown")
        df["FF Score"] = df["ff_score"].apply(lambda x: f"{x:.3f}")
        df["Confidence"] = df["confidence"].apply(lambda x: f"{x:.3f}")
        st.dataframe(df[["domain", "Class", "Confidence", "FF Score", "is_fastflux", "timestamp"]], use_container_width=True)

with tab3:
    render_section_card("Malicious Domains", "Focus on high-risk domains.")
    malicious = db.get_malicious_domains(hours=24, limit=30)
    if malicious:
        df = pd.DataFrame(malicious)
        class_map = {3: "Suspicious", 1: "DGA", 2: "Fast-Flux"}
        df["Class"] = df["final_class"].map(class_map).fillna("Unknown")
        st.dataframe(df[["domain", "Class", "ff_score", "timestamp"]], use_container_width=True)

# --- TAB 4: MANUAL CLASSIFICATION (BUG FIXED) ---
with tab4:
    render_section_card("Manual Domain Classification", "Submit a domain for live scoring.")
    
    domain = st.text_input("Domain to Classify", placeholder="example.com")
    col1, col2, col3, col4 = st.columns(4)
    with col1: ttl = st.number_input("TTL", value=3600)
    with col2: unique_ips = st.number_input("Unique IPs", value=1)
    with col3: query_rate = st.number_input("Query Rate", value=100)
    with col4: classify_button = st.button("Classify", use_container_width=True)

    if classify_button and domain:
        try:
            response = requests.post(
                f"{st.session_state.api_url}/api/v1/classify",
                json={"domain": domain, "ttl": ttl, "unique_ip_count": unique_ips, "query_rate": query_rate},
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                st.session_state.latest_result = result
                st.success("Classification complete")

                # EXACT MATCH TO API SNIFFER LOGIC
                status_label = normalize_prediction_label(result)
                if status_label == "fast_flux": 
                    display_text = "Fast-Flux"
                else: 
                    display_text = status_label

                # DETERMINE COLOR TONE
                if display_text == "Benign": tone = "safe"
                elif display_text == "SUSPICIOUS": tone = "watch"
                else: tone = "danger"

                col1, col2, col3, col4 = st.columns(4)
                with col1: metric_card("Domain", result.get("domain"))
                with col2: metric_card("Assessment", display_text, tone=tone)
                with col3: metric_card("Confidence", f"{result.get('confidence', 0):.3f}")
                with col4: metric_card("FF Score", f"{result.get('ff_score', 0):.3f}")

            else:
                st.error(f"Classification failed: {response.text}")
        except Exception as e:
            st.error(f"Error: Could not connect to API at {st.session_state.api_url}. Is Waitress running?")

    if st.session_state.latest_result:
        st.markdown("### Save Result")
        latest = st.session_state.latest_result
        st.caption(f"Latest result: {latest.get('domain', 'Unknown domain')}")
        if st.button("Save Latest Result to Database", use_container_width=True):
            try:
                detection_id = save_result_to_database(latest)
                st.success(f"Saved to database with detection ID {detection_id}.")
            except Exception as exc:
                st.error(f"Database save failed: {exc}")
