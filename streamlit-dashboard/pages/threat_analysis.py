"""
pages/threat_analysis.py
--------------------------
Lets an analyst submit an IP address, URL/domain, or file hash and
runs it through the project's heuristic scoring pipeline
(ml/predict.py -> ml/feature_engineering.py -> utils/threat_scoring.py).
Results are also persisted to the SQLite database so they show up
in the Dashboard and Threat Database pages.
"""

from datetime import datetime

import streamlit as st

from database import database as db
from ml.predict import analyze_indicator
from utils.ui import inject_css, priority_pill

st.set_page_config(page_title="Threat Analysis | Threat Intel", page_icon="🔎", layout="wide")
inject_css()

st.title("🔎 Threat Analysis")
st.caption("Submit an indicator for real-time risk scoring using the project's rule-based scoring engine")

with st.form("analysis_form"):
    col1, col2 = st.columns([3, 1])
    with col1:
        indicator_input = st.text_input(
            "Indicator", placeholder="e.g. 185.22.14.9, login-secure-update.xyz, or a file hash"
        )
    with col2:
        indicator_type = st.selectbox(
            "Type", ["Auto-detect", "IP Address", "URL/Domain", "File Hash"]
        )
    submitted = st.form_submit_button("Analyze Indicator", use_container_width=True)

if submitted:
    if not indicator_input or not indicator_input.strip():
        st.error("Please enter an indicator to analyze.")
    else:
        result = analyze_indicator(indicator_input, indicator_type)

        st.markdown("---")
        st.markdown("### Result")

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Risk Score", result["risk_score"])
        with c2:
            st.markdown("**Priority**")
            st.markdown(priority_pill(result["priority"]), unsafe_allow_html=True)
        with c3:
            st.metric("Confidence", f"{result['confidence']}%")
        with c4:
            st.metric("Predicted Threat Type", result["threat_type"])

        st.markdown("**Indicator**")
        st.code(result["indicator"])
        st.markdown(f"**Indicator Type:** {result['indicator_type']}")

        st.markdown("**Explanation**")
        st.info(result["explanation"])

        st.markdown("**Recommended Defensive Action**")
        st.warning(result["recommended_action"])

        st.caption(f"Scored using model version: {result.get('model_version', 'unknown')}")

        record = {
            "indicator": result["indicator"],
            "indicator_type": result["indicator_type"],
            "threat_type": result["threat_type"],
            "risk_score": result["risk_score"],
            "priority": result["priority"],
            "confidence": result["confidence"],
            "source": "Manual Analysis",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Active",
            "explanation": result["explanation"],
            "recommended_action": result["recommended_action"],
        }
        db.insert_threat(record)
        st.success("This analysis has been saved to the Threat Database and will appear on the Dashboard.")
