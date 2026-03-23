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

from db_service import ThreatDatabase
from sniffer_manager import get_sniffer_manager


st.set_page_config(
    page_title="DNS Threat Detection Dashboard",
    page_icon="Shield",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;600&display=swap');

    :root {
        --bg: #f4efe8;
        --panel: rgba(255, 252, 247, 0.9);
        --panel-strong: rgba(255, 250, 244, 0.97);
        --ink: #21313a;
        --muted: #64727b;
        --line: rgba(35, 64, 74, 0.12);
        --accent: #e17654;
        --accent-deep: #bf5f43;
        --teal: #2f5d67;
        --amber: #c79a52;
        --danger: #b14d3a;
        --shadow: 0 18px 42px rgba(35, 64, 74, 0.14);
    }

    .stApp {
        background:
            radial-gradient(circle at 0% 0%, rgba(225, 118, 84, 0.18), transparent 24%),
            radial-gradient(circle at 100% 0%, rgba(47, 93, 103, 0.14), transparent 22%),
            linear-gradient(180deg, #faf6f1 0%, var(--bg) 100%);
        color: var(--ink);
        font-family: "Space Grotesk", sans-serif;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #23404a 0%, #172d35 100%);
        border-right: 1px solid rgba(255, 255, 255, 0.06);
    }

    [data-testid="stSidebar"] * {
        color: #f7efe4 !important;
    }

    h1, h2, h3, h4 {
        font-family: "Space Grotesk", sans-serif !important;
        color: var(--ink);
        letter-spacing: -0.02em;
    }

    .hero-panel {
        background: linear-gradient(135deg, #203a44 0%, #325866 62%, #e17654 100%);
        border-radius: 28px;
        padding: 2rem 2.2rem;
        margin-bottom: 1.1rem;
        color: #fff8f1;
        box-shadow: 0 24px 56px rgba(28, 52, 60, 0.24);
        overflow: hidden;
        position: relative;
    }

    .hero-panel::after {
        content: "";
        position: absolute;
        right: -70px;
        bottom: -80px;
        width: 240px;
        height: 240px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(255,255,255,0.24), transparent 68%);
    }

    .hero-kicker {
        text-transform: uppercase;
        letter-spacing: 0.22em;
        font-size: 0.82rem;
        color: rgba(255, 240, 226, 0.78);
        margin-bottom: 0.8rem;
    }

    .hero-title {
        font-size: 2.5rem;
        line-height: 1.02;
        font-weight: 700;
        margin-bottom: 0.6rem;
    }

    .hero-copy {
        max-width: 760px;
        margin: 0;
        color: rgba(255, 243, 232, 0.88);
        font-size: 1rem;
    }

    .section-card {
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 24px;
        padding: 1rem 1.2rem;
        box-shadow: var(--shadow);
        margin-bottom: 1rem;
        backdrop-filter: blur(10px);
    }

    .section-title {
        font-size: 1.14rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }

    .section-copy {
        margin: 0;
        color: var(--muted);
        font-size: 0.96rem;
    }

    .metric-shell {
        background: linear-gradient(180deg, rgba(255,255,255,0.82), rgba(250,244,238,0.96));
        border: 1px solid rgba(35, 64, 74, 0.1);
        border-radius: 22px;
        padding: 0.95rem 1rem 0.6rem;
        box-shadow: 0 12px 28px rgba(35, 64, 74, 0.08);
    }

    .metric-shell.safe {
        background: linear-gradient(180deg, rgba(47,93,103,0.96), rgba(34,69,77,0.92));
    }

    .metric-shell.watch {
        background: linear-gradient(180deg, rgba(199,154,82,0.96), rgba(171,126,56,0.92));
    }

    .metric-shell.danger {
        background: linear-gradient(180deg, rgba(177,77,58,0.96), rgba(140,57,42,0.92));
    }

    .metric-shell.safe [data-testid="stMetricLabel"],
    .metric-shell.safe [data-testid="stMetricValue"],
    .metric-shell.watch [data-testid="stMetricLabel"],
    .metric-shell.watch [data-testid="stMetricValue"],
    .metric-shell.danger [data-testid="stMetricLabel"],
    .metric-shell.danger [data-testid="stMetricValue"] {
        color: #fff8f1;
    }

    [data-testid="stMetric"] {
        background: transparent;
        border: none;
        padding: 0;
    }

    [data-testid="stMetricLabel"] {
        color: var(--muted);
        font-size: 0.9rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    [data-testid="stMetricValue"] {
        color: var(--ink);
        font-size: 2rem;
        font-weight: 700;
    }

    [data-baseweb="tab-list"] {
        gap: 0.45rem;
        background: rgba(255, 250, 245, 0.82);
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 0.35rem;
        box-shadow: var(--shadow);
        margin-bottom: 1rem;
    }

    [data-baseweb="tab"] {
        border-radius: 14px;
        font-weight: 700;
        color: var(--muted);
        min-height: 48px;
    }

    [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(225,118,84,0.16), rgba(47,93,103,0.16)) !important;
        color: var(--ink) !important;
    }

    .stButton > button, .stDownloadButton > button {
        border-radius: 14px;
        border: 1px solid rgba(225, 118, 84, 0.24);
        background: linear-gradient(135deg, var(--accent) 0%, var(--accent-deep) 100%);
        color: #fff8f1;
        font-weight: 700;
        box-shadow: 0 12px 28px rgba(191, 95, 67, 0.24);
        transition: all 0.18s ease;
    }

    .stButton > button:hover, .stDownloadButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 16px 30px rgba(191, 95, 67, 0.28);
    }

    .stTextInput input, .stNumberInput input, .stTextArea textarea {
        border-radius: 14px !important;
        background: rgba(255, 248, 242, 0.98) !important;
        color: var(--ink) !important;
        border: 2px solid rgba(47, 93, 103, 0.32) !important;
        box-shadow: 0 10px 24px rgba(35, 64, 74, 0.08);
    }

    .stTextInput input::placeholder, .stTextArea textarea::placeholder {
        color: rgba(100, 114, 123, 0.9) !important;
    }

    .stTextInput label,
    .stNumberInput label,
    .stTextArea label,
    .stSelectbox label,
    .stMultiSelect label,
    .stSlider label,
    div[data-testid="stWidgetLabel"] label,
    div[data-testid="stWidgetLabel"] p {
        color: #314852 !important;
        font-weight: 700 !important;
        opacity: 1 !important;
        text-shadow: 0 1px 0 rgba(255, 255, 255, 0.35);
    }

    .stTextInput > div > div,
    .stNumberInput > div > div,
    .stTextArea > div > div {
        background: rgba(255, 248, 242, 0.98) !important;
        border-radius: 16px !important;
    }

    .stTextInput input:focus, .stNumberInput input:focus, .stTextArea textarea:focus {
        border-color: rgba(225, 118, 84, 0.62) !important;
        box-shadow: 0 0 0 1px rgba(225, 118, 84, 0.24), 0 14px 30px rgba(191, 95, 67, 0.16) !important;
    }

    div[data-testid="stSelectbox"] > div,
    div[data-testid="stMultiSelect"] > div {
        border-radius: 14px !important;
        background: rgba(255, 248, 242, 0.98) !important;
        border: 2px solid rgba(47, 93, 103, 0.28) !important;
        box-shadow: 0 10px 24px rgba(35, 64, 74, 0.08);
    }

    [data-testid="stAlert"] {
        background: linear-gradient(135deg, rgba(234, 242, 246, 0.96), rgba(244, 236, 229, 0.94)) !important;
        color: var(--ink) !important;
        border: 1px solid rgba(47, 93, 103, 0.18) !important;
        border-radius: 18px !important;
        box-shadow: 0 12px 28px rgba(35, 64, 74, 0.08);
    }

    [data-testid="stAlert"] * {
        color: var(--ink) !important;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: 18px;
        overflow: hidden;
        box-shadow: var(--shadow);
    }

    .status-pill {
        display: inline-block;
        border-radius: 999px;
        padding: 0.45rem 0.8rem;
        font-size: 0.84rem;
        font-weight: 700;
    }

    .status-live {
        background: rgba(47,93,103,0.12);
        color: var(--teal);
        border: 1px solid rgba(47,93,103,0.18);
    }

    .status-down {
        background: rgba(177,77,58,0.12);
        color: var(--danger);
        border: 1px solid rgba(177,77,58,0.18);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


if "api_url" not in st.session_state:
    st.session_state.api_url = "https://ai-dns.onrender.com"
if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 5


@st.cache_resource
def get_database():
    return ThreatDatabase()


@st.cache_resource
def get_sniffer():
    return get_sniffer_manager()


db = get_database()
sniffer = get_sniffer()


def render_section_card(title, copy):
    st.markdown(
        f"""
        <div class="section-card">
            <div class="section-title">{title}</div>
            <p class="section-copy">{copy}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label, value, tone="default", delta=None, delta_color="normal"):
    tone_class = "" if tone == "default" else f" {tone}"
    st.markdown(f'<div class="metric-shell{tone_class}">', unsafe_allow_html=True)
    st.metric(label, value, delta=delta, delta_color=delta_color)
    st.markdown("</div>", unsafe_allow_html=True)


def stylize_plot(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(255,255,255,0.58)",
        font=dict(family="Space Grotesk, sans-serif", color="#21313a"),
        margin=dict(l=28, r=24, t=56, b=28),
    )
    return fig




DEFAULT_API = os.getenv("API_URL", "https://ai-dns.onrender.com")

with st.sidebar:
    st.markdown("## 🛠️ Control Room")
    st.caption("Manage API connection, dashboard behavior, and monitoring status.")

    # =========================
    # API SETTINGS
    # =========================
    st.subheader("🌐 API Settings")

    api_url = st.text_input(
        "API Base URL",
        value=DEFAULT_API,
        help="Example: https://ai-dns.onrender.com"
    )

    st.session_state.api_url = api_url.rstrip("/")

    # Health check button
    if st.button("Check API Connection"):
        try:
            import requests
            res = requests.get(f"{st.session_state.api_url}/api/v1/health", timeout=3)
            if res.status_code == 200:
                st.success("✅ API Connected")
            else:
                st.warning(f"⚠️ API responded with {res.status_code}")
        except Exception as e:
            st.error(f"❌ API not reachable: {str(e)}")

    # =========================
    # DASHBOARD SETTINGS
    # =========================
    st.subheader("📊 Dashboard Settings")

    st.session_state.refresh_interval = st.slider(
        "Auto-refresh interval (seconds)",
        min_value=1,
        max_value=60,
        value=5
    )

    # =========================
    # SNIFFER CONTROL (SAFE MODE)
    # =========================
    st.subheader("🧠 Sensor Control")

    IS_PRODUCTION = os.getenv("ENV", "dev") == "prod"

    if IS_PRODUCTION:
        st.warning("⚠️ Sniffer control disabled in production (requires root access)")

        st.info("""
        In production:
        • Sniffer runs as a separate agent  
        • This dashboard only reads API data  
        """)
    else:
        col1, col2 = st.columns(2)

        with col1:
            if st.button("▶ Start Sniffer", use_container_width=True):
                try:
                    with st.spinner("Starting sniffer..."):
                        success = sniffer.start(interface=None)
                        if success:
                            st.success("Sniffer started")
                        else:
                            st.error(f"Failed: {sniffer.error_message}")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

        with col2:
            if st.button("⏹ Stop Sniffer", use_container_width=True):
                try:
                    with st.spinner("Stopping sniffer..."):
                        success = sniffer.stop()
                        if success:
                            st.success("Sniffer stopped")
                        else:
                            st.warning("Sniffer not running")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    # =========================
    # STATUS PANEL
    # =========================
    st.divider()
    st.subheader("📡 Sensor Status")

    try:
        status = sniffer.get_status()

        if status.get("running"):
            st.markdown(
                '<span class="status-pill status-live">🟢 LIVE SENSOR ONLINE</span>',
                unsafe_allow_html=True
            )

            uptime = int(status.get("uptime_seconds", 0))
            st.caption(f"Uptime: {uptime // 60}m {uptime % 60}s")

            stats = sniffer.get_stats()
            if stats:
                st.metric("Packets Captured", f"{stats.get('packets_received', 0):,}")
                st.metric("Queries Classified", f"{stats.get('domains_classified', 0):,}")
                st.metric("Threats Detected", f"{stats.get('threats_detected', 0):,}")
        else:
            st.markdown(
                '<span class="status-pill status-down">🔴 SENSOR OFFLINE</span>',
                unsafe_allow_html=True
            )

            if status.get("error"):
                st.caption(f"Error: {status['error']}")

    except Exception as e:
        st.error(f"Failed to fetch status: {str(e)}")

    st.divider()
    st.subheader("Database")
    try:
        if "db" in globals():
            db_stats = db.get_database_stats()
            st.metric("Total Detections", f"{db_stats['total_detections']:,}")
            st.metric("DB Size", f"{db_stats['database_size_bytes'] / 1024 / 1024:.2f} MB")
        else:
            st.warning("Database service not available")
    except Exception as e:
        st.error(f"Error getting DB stats: {e}")


        st.metric("DB Size", f"{db_stats['database_size_bytes'] / 1024 / 1024:.2f} MB")
    except Exception as e:
        st.error(f"Error getting DB stats: {e}")


st.markdown(
    """
    <section class="hero-panel">
        <div class="hero-kicker">Network Security Observatory</div>
        <div class="hero-title">DNS Threat Detection Dashboard</div>
        <p class="hero-copy">
            Review live detection trends, investigate suspicious domains, and manually test classification behavior from a single visual workspace.
        </p>
    </section>
    """,
    unsafe_allow_html=True,
)

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    [
        "Statistics",
        "Recent Detections",
        "Malicious Domains",
        "Manual Classification",
        "About",
    ]
)


with tab1:
    render_section_card(
        "Threat Statistics and Trends",
        "Track total query volume, threat composition, and how suspicious DNS activity changes across the selected time window.",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        hours = st.selectbox("Time Period", [1, 6, 24, 72, 168], index=2)
    with col3:
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    try:
        stats = db.get_detection_stats(hours=hours)
        total = sum(stats.values())
        benign = stats.get("0", 0)
        suspicious = stats.get("1", 0)
        dga = stats.get("2", 0)
        fastflux = stats.get("3", 0)
        threats = suspicious + dga + fastflux

        metric_cols = st.columns(5)
        with metric_cols[0]:
            metric_card("Total Queries", f"{total:,}")
        with metric_cols[1]:
            metric_card("Benign", f"{benign:,}", tone="safe")
        with metric_cols[2]:
            metric_card("Suspicious", f"{suspicious:,}", tone="watch", delta_color="off")
        with metric_cols[3]:
            metric_card("DGA", f"{dga:,}", tone="danger", delta_color="off")
        with metric_cols[4]:
            metric_card("Fast-Flux", f"{fastflux:,}", tone="danger", delta_color="off")

        st.divider()
        col1, col2 = st.columns(2)

        with col1:
            threat_data = pd.DataFrame(
                {
                    "Class": ["Benign", "Suspicious", "DGA", "Fast-Flux"],
                    "Count": [benign, suspicious, dga, fastflux],
                }
            )
            fig = px.pie(
                threat_data,
                values="Count",
                names="Class",
                title="Threat Classification Breakdown",
                color="Class",
                color_discrete_map={
                    "Benign": "#2f5d67",
                    "Suspicious": "#c79a52",
                    "DGA": "#e17654",
                    "Fast-Flux": "#b14d3a",
                },
            )
            fig.update_traces(textposition="inside", textinfo="percent+label", hole=0.36)
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Space Grotesk, sans-serif", color="#21313a"),
                legend=dict(orientation="h", y=-0.14),
                margin=dict(l=20, r=20, t=60, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            threat_rate = (threats / total * 100) if total > 0 else 0
            fig = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=threat_rate,
                    title={"text": "Threat Rate (%)"},
                    gauge={
                        "axis": {"range": [None, 100]},
                        "bar": {"color": "#e17654"},
                        "steps": [
                            {"range": [0, 5], "color": "#d8e5e8"},
                            {"range": [5, 20], "color": "#f1dfc2"},
                            {"range": [20, 100], "color": "#f4cabc"},
                        ],
                        "threshold": {
                            "line": {"color": "#8f4032", "width": 4},
                            "thickness": 0.75,
                            "value": 20,
                        },
                    },
                )
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Space Grotesk, sans-serif", color="#21313a"),
                margin=dict(l=24, r=24, t=60, b=18),
            )
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Daily Trend")
        daily_stats = db.get_daily_stats(days=7)

        if daily_stats:
            daily_df = pd.DataFrame(daily_stats)
            daily_df["date"] = pd.to_datetime(daily_df["date"])
            daily_df = daily_df.sort_values("date")

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["benign_count"], name="Benign", mode="lines+markers", line=dict(color="#2f5d67", width=3)))
            fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["suspicious_count"], name="Suspicious", mode="lines+markers", line=dict(color="#c79a52", width=3)))
            fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["dga_count"], name="DGA", mode="lines+markers", line=dict(color="#e17654", width=3)))
            fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["fastflux_count"], name="Fast-Flux", mode="lines+markers", line=dict(color="#b14d3a", width=3)))
            fig.update_layout(
                title="7-Day Threat Trend",
                xaxis_title="Date",
                yaxis_title="Count",
                hovermode="x unified",
                height=420,
                legend=dict(orientation="h", y=1.08, x=0),
            )
            st.plotly_chart(stylize_plot(fig), use_container_width=True)
    except Exception as e:
        st.error(f"Error loading statistics: {e}")


with tab2:
    render_section_card(
        "Recent Threat Detections",
        "Inspect the latest classified domains with timestamps, confidence, and fast-flux context.",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        limit = st.slider("Max Results", 5, 100, 20)
    with col2:
        hours = st.selectbox("Time Period (hours)", [1, 6, 24, 72, 168], index=2, key="recent_hours")
    with col3:
        if st.button("Refresh Detections", use_container_width=True):
            st.rerun()

    try:
        detections = db.get_recent_detections(limit=limit, hours=hours)
        if detections:
            df = pd.DataFrame(detections)

            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            if "final_class" in df.columns:
                class_map = {0: "Benign", 1: "Suspicious", 2: "DGA", 3: "Fast-Flux"}
                df["Class"] = df["final_class"].map(class_map)
            if "ff_score" in df.columns:
                df["FF Score"] = df["ff_score"].apply(lambda x: f"{x:.3f}")
            if "confidence" in df.columns:
                df["Confidence"] = df["confidence"].apply(lambda x: f"{x:.3f}")

            display_cols = [col for col in ["domain", "Class", "Confidence", "FF Score", "is_fastflux", "timestamp"] if col in df.columns]
            st.dataframe(df[display_cols].copy(), use_container_width=True, hide_index=True)
        else:
            st.info("No detections found in this time period")
    except Exception as e:
        st.error(f"Error loading detections: {e}")


with tab3:
    render_section_card(
        "Malicious Domains",
        "Focus on high-risk domains and export them for incident response or deeper analysis.",
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        limit = st.slider("Max Results", 5, 100, 30, key="malicious_limit")
    with col2:
        hours = st.selectbox("Time Period (hours)", [1, 6, 24, 72, 168], index=2, key="malicious_hours")
    with col3:
        if st.button("Refresh Malicious", use_container_width=True):
            st.rerun()

    try:
        malicious = db.get_malicious_domains(hours=hours, limit=limit)
        if malicious:
            df = pd.DataFrame(malicious)

            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
            if "final_class" in df.columns:
                class_map = {1: "Suspicious", 2: "DGA", 3: "Fast-Flux"}
                df["Class"] = df["final_class"].map(class_map)
            if "ff_score" in df.columns:
                df["FF Score"] = df["ff_score"].apply(lambda x: f"{x:.3f}")

            display_cols = [col for col in ["domain", "Class", "FF Score", "timestamp"] if col in df.columns]
            df_display = df[display_cols].copy()
            st.dataframe(df_display, use_container_width=True, hide_index=True)

            csv = df_display.to_csv(index=False)
            st.download_button(
                label="Download Malicious Domains (CSV)",
                data=csv,
                file_name=f"malicious_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )
        else:
            st.success("No malicious domains detected")
    except Exception as e:
        st.error(f"Error loading malicious domains: {e}")


with tab4:
    render_section_card(
        "Manual Domain Classification",
        "Submit a domain for live scoring and review the API verdict, confidence, and fast-flux signal.",
    )

    st.info("Submit a domain for real-time classification. The result is also stored in the database.")

    col1, col2 = st.columns([3, 1])
    with col1:
        domain = st.text_input("Domain to Classify", placeholder="example.com")
    with col2:
        st.empty()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        ttl = st.number_input("TTL", value=3600, min_value=0, max_value=2147483647)
    with col2:
        unique_ips = st.number_input("Unique IPs", value=1, min_value=0, max_value=10000)
    with col3:
        query_rate = st.number_input("Query Rate (per second)", value=100, min_value=0, max_value=1000000)
    with col4:
        classify_button = st.button("Classify", use_container_width=True)

    if classify_button and domain:
        try:
            response = requests.post(
                f"{st.session_state.api_url}/api/v1/classify",
                json={
                    "domain": domain,
                    "ttl": ttl,
                    "unique_ip_count": unique_ips,
                    "query_rate": query_rate,
                },
                timeout=5,
            )

            if response.status_code == 200:
                result = response.json()
                st.success("Classification complete")

                col1, col2, col3, col4 = st.columns(4)
                class_map = {0: "Benign", 1: "Suspicious", 2: "DGA", 3: "Fast-Flux"}
                class_name = class_map.get(result.get("final_class"), "Unknown")
                tone = "safe" if class_name == "Benign" else "watch" if class_name == "Suspicious" else "danger"

                with col1:
                    metric_card("Domain", result.get("domain", "N/A"))
                with col2:
                    metric_card("Assessment", class_name, tone=tone)
                with col3:
                    metric_card("Confidence", f"{result.get('confidence', 0):.3f}")
                with col4:
                    metric_card("FF Score", f"{result.get('ff_score', 0):.3f}")

                st.divider()
                st.subheader("Details")
                details_df = pd.DataFrame(
                    {
                        "Property": ["Domain", "Classification", "Confidence", "FF Score", "Is Fast-Flux", "Timestamp"],
                        "Value": [
                            result.get("domain"),
                            class_name,
                            f"{result.get('confidence', 0):.3f}",
                            f"{result.get('ff_score', 0):.3f}",
                            "Yes" if result.get("is_fastflux") else "No",
                            result.get("timestamp"),
                        ],
                    }
                )
                st.dataframe(details_df, use_container_width=True, hide_index=True)

                st.divider()
                st.subheader("Feedback")
                feedback_type = st.selectbox(
                    "Is this classification correct?",
                    ["Select...", "Correct", "False Positive", "False Negative"],
                )
                feedback_comment = st.text_area("Additional Comments (optional)")

                if st.button("Submit Feedback"):
                    recent = db.get_recent_detections(limit=1)
                    if recent:
                        detection_id = recent[0]["id"]
                        feedback_type_map = {"Correct": 0, "False Positive": 1, "False Negative": 2}
                        feedback_num = feedback_type_map.get(feedback_type, -1)

                        if feedback_num >= 0:
                            db.record_feedback(detection_id, feedback_num, feedback_comment)
                            st.success("Feedback recorded")
                        else:
                            st.warning("Please select a feedback type")
            else:
                st.error(f"Classification failed: {response.status_code}")
                st.error(response.text)
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to API at {st.session_state.api_url}. Is the API server running?")
        except Exception as e:
            st.error(f"Error: {e}")
    elif classify_button:
        st.warning("Please enter a domain")


with tab5:
    render_section_card(
        "About This Dashboard",
        "A Streamlit command center for DNS telemetry, threat classification, and analyst feedback workflows.",
    )

    st.markdown(
        """
        ### DNS Threat Detection System

        This dashboard provides real-time monitoring and classification of DNS threats.

        **Features**
        - Real-time threat detection using ML models
        - Live statistics and trend analysis
        - Manual domain classification
        - Full audit trail in SQLite
        - Fast-flux and DGA detection
        - DNS packet capture and monitoring

        **Components**
        - API Server: Flask REST API on port 5000
        - Database: SQLite with threat detections and metrics
        - Sniffer: Real-time DNS packet capture using Scapy
        - ML Models: Random Forest, XGBoost, Gradient Boosting, Logistic Regression

        **Threat Classes**
        - Benign: Safe domains
        - Suspicious: Potentially risky domains
        - DGA: Domain Generation Algorithm attacks
        - Fast-Flux: Fast-flux hosting networks
        """
    )

    st.divider()
    st.subheader("System Status")
    col1, col2, col3 = st.columns(3)

    with col1:
        try:
            response = requests.get(f"{st.session_state.api_url}/api/v1/health", timeout=2)
            if response.status_code == 200:
                st.success("API Server: Running")
            else:
                st.warning("API Server: Responding with errors")
        except Exception:
            st.error("API Server: Not responding")

    with col2:
        try:
            db_stats = db.get_database_stats()
            total = db_stats.get("total_detections", 0)
            st.info(f"Database: {total:,} detections")
        except Exception:
            st.error("Database: Connection error")

    with col3:
        status = sniffer.get_status()
        if status["running"]:
            st.success("Sniffer: Running")
        else:
            st.warning("Sniffer: Not running")

    st.divider()
    st.subheader("Support")
    st.write("Refer to the project documentation and repository notes for setup, architecture, and troubleshooting details.")
