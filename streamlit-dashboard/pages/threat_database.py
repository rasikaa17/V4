"""
pages/threat_database.py
---------------------------
Full, searchable, filterable browser over every threat record in the
SQLite database (historical + analyst-submitted). Complements the
Dashboard's summarized view with a raw, exportable table.
"""

import os

import streamlit as st

from database import database as db
from utils.dashboard_view import render_filters
from utils.ui import inject_css

st.set_page_config(page_title="Threat Database | Threat Intel", page_icon="🗄️", layout="wide")
inject_css()

st.title("🗄️ Threat Database")
st.caption("Search, filter, and export the full threat-intelligence record set")

if db.is_empty():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db.seed_from_csv(os.path.join(base_dir, "data", "threat_data.csv"))

df = db.fetch_all()

if df.empty:
    st.warning("No records found in the database yet.")
    st.stop()

filtered = render_filters(df)

search_term = st.text_input("🔍 Search indicator", placeholder="Type part of an IP, domain, or hash...")
if search_term:
    filtered = filtered[filtered["indicator"].str.contains(search_term, case=False, na=False)]

st.caption(f"Showing {len(filtered)} of {len(df)} total records")

display_cols = [
    "indicator", "indicator_type", "threat_type", "risk_score", "priority",
    "confidence", "source", "timestamp", "status", "explanation", "recommended_action",
]
st.dataframe(filtered[display_cols], use_container_width=True, height=520)

csv_bytes = filtered[display_cols].to_csv(index=False).encode("utf-8")
st.download_button(
    "⬇️ Download filtered results as CSV",
    data=csv_bytes,
    file_name="threat_database_export.csv",
    mime="text/csv",
)
