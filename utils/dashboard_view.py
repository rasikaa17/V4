"""
dashboard_view.py
-------------------
Renders the core SOC dashboard (Overview, Threat Distribution,
Threat Intelligence Table, High-Priority Threats, Filters). Shared
between app.py (landing page) and pages/dashboard.py so there is a
single source of truth for the dashboard layout.
"""

import pandas as pd
import plotly.express as px
import streamlit as st

from database import database as db
from utils.ui import PRIORITY_ORDER, metric_card, priority_pill

PRIORITY_COLOR_MAP = {"Critical": "#ff3b3b", "High": "#ff8c42", "Medium": "#ffd23f", "Low": "#3fd07c"}


def render_filters(df: pd.DataFrame) -> pd.DataFrame:
    st.sidebar.markdown("### 🔍 Filters")

    priorities = st.sidebar.multiselect(
        "Priority", ["All"] + PRIORITY_ORDER, default=["All"], key="f_priority"
    )
    threat_types = st.sidebar.multiselect(
        "Threat Type", ["All"] + sorted(df["threat_type"].unique().tolist()), default=["All"], key="f_threat"
    )
    indicator_types = st.sidebar.multiselect(
        "Indicator Type", ["All"] + sorted(df["indicator_type"].unique().tolist()), default=["All"], key="f_indicator"
    )
    sources = st.sidebar.multiselect(
        "Source", ["All"] + sorted(df["source"].unique().tolist()), default=["All"], key="f_source"
    )

    min_date = df["timestamp"].min().date()
    max_date = df["timestamp"].max().date()
    date_range = st.sidebar.date_input(
        "Date range", value=(min_date, max_date), min_value=min_date, max_value=max_date, key="f_dates"
    )

    filtered = df.copy()
    if priorities and "All" not in priorities:
        filtered = filtered[filtered["priority"].isin(priorities)]
    if threat_types and "All" not in threat_types:
        filtered = filtered[filtered["threat_type"].isin(threat_types)]
    if indicator_types and "All" not in indicator_types:
        filtered = filtered[filtered["indicator_type"].isin(indicator_types)]
    if sources and "All" not in sources:
        filtered = filtered[filtered["source"].isin(sources)]
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start, end = date_range
        filtered = filtered[
            (filtered["timestamp"].dt.date >= start) & (filtered["timestamp"].dt.date <= end)
        ]

    return filtered


def render_overview(df: pd.DataFrame):
    st.markdown("### 📊 Overview")
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        metric_card("Total Threats", len(df))
    with c2:
        metric_card("Critical", (df["priority"] == "Critical").sum(), PRIORITY_COLOR_MAP["Critical"])
    with c3:
        metric_card("High", (df["priority"] == "High").sum(), PRIORITY_COLOR_MAP["High"])
    with c4:
        metric_card("Medium", (df["priority"] == "Medium").sum(), PRIORITY_COLOR_MAP["Medium"])
    with c5:
        metric_card("Low", (df["priority"] == "Low").sum(), PRIORITY_COLOR_MAP["Low"])
    with c6:
        avg_risk = round(df["risk_score"].mean(), 1) if len(df) else 0
        metric_card("Avg Risk Score", avg_risk)


def render_distribution(df: pd.DataFrame):
    st.markdown("### 📈 Threat Distribution")
    row1c1, row1c2 = st.columns(2)

    with row1c1:
        by_priority = df["priority"].value_counts().reindex(PRIORITY_ORDER).fillna(0)
        fig = px.bar(
            x=by_priority.index, y=by_priority.values, title="Threats by Priority",
            color=by_priority.index, color_discrete_map=PRIORITY_COLOR_MAP,
            labels={"x": "Priority", "y": "Count"},
        )
        fig.update_layout(showlegend=False, plot_bgcolor="#0b0f19", paper_bgcolor="#0b0f19", font_color="#e6e9f0")
        st.plotly_chart(fig, use_container_width=True)

    with row1c2:
        by_type = df["threat_type"].value_counts()
        fig2 = px.pie(names=by_type.index, values=by_type.values, title="Threats by Type", hole=0.45)
        fig2.update_layout(paper_bgcolor="#0b0f19", font_color="#e6e9f0")
        st.plotly_chart(fig2, use_container_width=True)

    row2c1, row2c2 = st.columns(2)
    with row2c1:
        by_ind = df["indicator_type"].value_counts()
        fig3 = px.bar(
            x=by_ind.values, y=by_ind.index, orientation="h", title="Threats by Indicator Type",
            labels={"x": "Count", "y": ""},
        )
        fig3.update_layout(plot_bgcolor="#0b0f19", paper_bgcolor="#0b0f19", font_color="#e6e9f0")
        st.plotly_chart(fig3, use_container_width=True)

    with row2c2:
        fig4 = px.histogram(df, x="risk_score", nbins=20, title="Risk Score Distribution")
        fig4.update_layout(plot_bgcolor="#0b0f19", paper_bgcolor="#0b0f19", font_color="#e6e9f0")
        st.plotly_chart(fig4, use_container_width=True)


def render_intel_table(df: pd.DataFrame):
    st.markdown("### 🗂️ Threat Intelligence Table")
    display_cols = [
        "indicator", "indicator_type", "threat_type", "risk_score",
        "priority", "confidence", "source", "timestamp", "status",
    ]
    sort_col = st.selectbox("Sort by", display_cols, index=3, key="sort_col")
    ascending = st.checkbox("Ascending", value=False, key="sort_asc")
    sorted_df = df[display_cols].sort_values(sort_col, ascending=ascending)
    st.dataframe(sorted_df, use_container_width=True, height=380)


def render_high_priority(df: pd.DataFrame):
    st.markdown("### 🚨 High-Priority Threats")
    top = df[df["priority"].isin(["Critical", "High"])].sort_values("risk_score", ascending=False).head(10)

    if top.empty:
        st.info("No Critical or High priority threats in the current filter selection.")
        return

    for _, row in top.iterrows():
        with st.container():
            c1, c2, c3 = st.columns([3, 1, 2])
            with c1:
                st.markdown(f"**{row['indicator']}**  \n{row['threat_type']}")
            with c2:
                st.markdown(priority_pill(row["priority"]), unsafe_allow_html=True)
                st.caption(f"Risk {int(row['risk_score'])} · Conf {int(row['confidence'])}%")
            with c3:
                reason = row.get("explanation", "See historical record for details.")
                action = row.get("recommended_action", "Escalate to SOC analyst for review.")
                st.caption(f"**Reason:** {reason}")
                st.caption(f"**Action:** {action}")
            st.divider()


def render_full_dashboard():
    if db.is_empty():
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db.seed_from_csv(os.path.join(base_dir, "data", "threat_data.csv"))

    df = db.fetch_all()
    if df.empty:
        st.warning("No threat data available yet.")
        return

    filtered = render_filters(df)
    render_overview(filtered)
    st.divider()
    render_distribution(filtered)
    st.divider()
    render_high_priority(filtered)
    st.divider()
    render_intel_table(filtered)
