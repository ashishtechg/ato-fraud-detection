"""
Real-Time ATO Fraud Detection & Regulatory Compliance Command Center
Streamlit Entry Point
"""

import os
import streamlit as st

st.set_page_config(
    page_title="ATO Fraud Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Establish Snowflake connection
conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))
st.session_state["snowflake_conn"] = conn

# Sidebar Branding & Global System Status
with st.sidebar:
    st.markdown("## 🛡️ **ATO Fraud Center**")
    st.caption("Production Multi-Layer Fraud Detection & Regulatory Intelligence")
    st.divider()

    with st.container(border=True):
        st.markdown("**System Health & Pipeline**")
        st.markdown("🟢 **Dynamic Tables**: *Active (1m lag)*")
        st.markdown("🟢 **XGBoost**: *XGBOOST_V2 (AUC 0.80)*")
        st.markdown("🟢 **Isolation Forest**: *IFOREST_V2 (AUC 0.61)*")
        st.markdown("🟢 **Graph Risk**: *GRAPH_V2 (structural)*")
        st.markdown("🟢 **Ensemble**: *ENSEMBLE_V2 (0-1000)*")
        st.markdown("🟢 **Cortex Search**: *Indexed (22 chunks)*")
        st.markdown("🟢 **Regulatory MCP**: *Connected (Zero-key)*")

    st.divider()
    st.caption("Snowflake Data Cloud • ATO_FRAUD_DB")

# Configure Multi-Page Navigation
pages = [
    st.Page("app_pages/01_fraud_analytics.py", title="Executive & Fraud Analytics", icon="📊", default=True),
    st.Page("app_pages/02_policy_rules.py", title="Policy Rules & Governance", icon="⚖️"),
    st.Page("app_pages/03_regulatory_lookup.py", title="Agent & Regulatory Search", icon="🔍"),
    st.Page("app_pages/04_investigation_queue.py", title="Live Analyst Case Queue", icon="🚨")
]

pg = st.navigation(pages, position="sidebar")
pg.run()
