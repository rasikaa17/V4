"""
ui.py
------
Shared Streamlit styling and small rendering helpers so the SOC
dashboard look stays consistent across app.py and every page.
"""

import streamlit as st

PRIORITY_COLORS = {
    "Critical": "#ff3b3b",
    "High": "#ff8c42",
    "Medium": "#ffd23f",
    "Low": "#3fd07c",
}

PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"]


def inject_css():
    st.markdown(
        """
        <style>
        .stApp { background-color: #0b0f19; }
        section[data-testid="stSidebar"] { background-color: #10141f; }
        h1, h2, h3 { font-family: 'Segoe UI', sans-serif; letter-spacing: 0.3px; }
        .metric-card {
            background: linear-gradient(145deg, #131828, #0e1220);
            border: 1px solid #232a3d;
            border-radius: 10px;
            padding: 18px 16px;
            text-align: center;
        }
        .metric-card .label { color: #8b93a7; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 1px; }
        .metric-card .value { font-size: 1.9rem; font-weight: 700; color: #f2f4f8; margin-top: 4px; }
        .priority-pill {
            display: inline-block; padding: 2px 10px; border-radius: 12px;
            font-size: 0.75rem; font-weight: 700; color: #0b0f19;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value, color: str = "#f2f4f8"):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="label">{label}</div>
            <div class="value" style="color:{color};">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def priority_pill(priority: str) -> str:
    color = PRIORITY_COLORS.get(priority, "#8b93a7")
    return f'<span class="priority-pill" style="background-color:{color};">{priority}</span>'
