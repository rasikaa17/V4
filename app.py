"""
app.py
-------
Main entry point for the AI Threat Intelligence Platform Streamlit
dashboard. Renders the SOC-style overview dashboard directly on
launch; use the sidebar to navigate to Threat Analysis or the full
Threat Database browser.
"""

import streamlit as st

from utils.dashboard_view import render_full_dashboard
from utils.ui import inject_css

st.set_page_config(
    page_title="AI Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_css()

st.sidebar.title("🛡️ Threat Intel Platform")
st.sidebar.caption("AI-assisted SOC dashboard")
st.sidebar.markdown("---")

st.title("🛡️ AI Threat Intelligence Platform")
st.caption("Real-time indicator scoring, SOC dashboard, and threat analytics")

render_full_dashboard()
