"""
pages/dashboard.py
--------------------
Standalone Dashboard page for Streamlit's multipage navigation.
Delegates to utils.dashboard_view so app.py and this page never
drift out of sync.
"""

import streamlit as st

from utils.dashboard_view import render_full_dashboard
from utils.ui import inject_css

st.set_page_config(page_title="Dashboard | Threat Intel", page_icon="🛡️", layout="wide")
inject_css()

st.title("📊 SOC Dashboard")
st.caption("Overview, distribution analytics, high-priority threats, and the full intelligence table")

render_full_dashboard()
