"""
Network Intrusion Log Analyser - Main Streamlit Application

Professional SOC-style security analysis dashboard.
"""

import streamlit as st
import pandas as pd
from pathlib import Path
import sys

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parser.log_parser import LogParser
from app.database.db import DatabaseManager
from app.analysis.analytics import NetworkAnalytics
from app.detection.rules import ThreatDetectionEngine
from app.detection.incidents import IncidentCorrelator
from app.ml.predict import ThreatPredictor
from app.reporting.reports import ReportGenerator

# Page config
st.set_page_config(
    page_title="Network Intrusion Log Analyser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'db' not in st.session_state:
    st.session_state.db = DatabaseManager()
if 'logs_loaded' not in st.session_state:
    st.session_state.logs_loaded = False
if 'current_df' not in st.session_state:
    st.session_state.current_df = pd.DataFrame()
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'incidents' not in st.session_state:
    st.session_state.incidents = []
if 'ml_results' not in st.session_state:
    st.session_state.ml_results = pd.DataFrame()

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .alert-critical {
        background-color: #fee;
        border-left: 4px solid #d32f2f;
        padding: 1rem;
        border-radius: 0.3rem;
        margin: 0.5rem 0;
    }
    .alert-high {
        background-color: #fff3e0;
        border-left: 4px solid #f57c00;
        padding: 1rem;
        border-radius: 0.3rem;
        margin: 0.5rem 0;
    }
    .alert-medium {
        background-color: #fff8e1;
        border-left: 4px solid #fbc02d;
        padding: 1rem;
        border-radius: 0.3rem;
        margin: 0.5rem 0;
    }
    .alert-low {
        background-color: #f1f8e9;
        border-left: 4px solid #689f38;
        padding: 1rem;
        border-radius: 0.3rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🛡️ Network Intrusion Analyser")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Upload Logs", "Log Explorer", "Threat Detection",
     "Incidents", "IP Analysis", "ML Analysis", "Reports", "About"]
)

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Status:** {'✓ Logs Loaded' if st.session_state.logs_loaded else '⚠ No Logs'}")
if st.session_state.logs_loaded:
    event_count = st.session_state.db.get_event_count()
    st.sidebar.markdown(f"**Events:** {event_count:,}")

# Import page modules
from app.ui import dashboard, logs, threats, incidents, ip_analysis, ml_page, reports as reports_ui

# Route to pages
if page == "Dashboard":
    dashboard.show(st.session_state.db, st.session_state.current_df,
                   st.session_state.alerts, st.session_state.incidents)
elif page == "Upload Logs":
    from app.ui import upload
    upload.show(st.session_state.db)
elif page == "Log Explorer":
    logs.show(st.session_state.db)
elif page == "Threat Detection":
    threats.show(st.session_state.db, st.session_state.alerts)
elif page == "Incidents":
    incidents.show(st.session_state.db, st.session_state.incidents)
elif page == "IP Analysis":
    ip_analysis.show(st.session_state.db)
elif page == "ML Analysis":
    ml_page.show(st.session_state.db, st.session_state.ml_results)
elif page == "Reports":
    reports_ui.show(st.session_state.db)
elif page == "About":
    st.markdown('<p class="main-header">About This Project</p>', unsafe_allow_html=True)

    st.markdown("""
    ### Network Intrusion Log Analyser

    A professional web-based security analysis platform for detecting suspicious network behavior.

    **Features:**
    - Network log parsing and validation
    - Rule-based threat detection (port scanning, brute force, etc.)
    - Machine learning-based anomaly classification
    - Incident correlation and timeline analysis
    - Interactive dashboards and visualizations
    - Security report generation

    **Technology Stack:**
    - Python 3.14
    - Streamlit (Web UI)
    - Pandas (Data Analysis)
    - SQLite (Database)
    - Scikit-learn (Machine Learning)
    - Plotly (Visualization)

    **Detection Capabilities:**
    - Port Scanning
    - Repeated Connection Attempts (Brute Force)
    - Excessive Denied Traffic
    - High Connection Frequency
    - ML-based Anomaly Detection

    **Author:** College Project - Network Security Analysis

    **Version:** 1.0.0

    ---

    ### Important Notes

    - This system uses **simulated data** for demonstration purposes
    - ML model trained on **synthetic labeled data**
    - Detection requires human verification - avoid false accusations
    - Use terminology like "suspicious activity" and "requires investigation"
    - Suitable for college demonstration, learning, and portfolio

    ### Limitations

    - Analysis based on firewall logs only (no deep packet inspection)
    - Thresholds may require tuning for production use
    - ML model accuracy depends on training data quality
    - False positives possible - analyst review required
    """)
