"""
Page 4: Live Analyst Investigation Queue
Interactive case triage table allowing fraud analysts to filter high-risk sessions, inspect behavioral telemetry & entity graphs, and trigger actions.
Data source: ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES (leakage-fixed ensemble output)
"""

import streamlit as st
import pandas as pd
import os

conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))

st.title("🚨 Live Analyst Investigation Queue")
st.markdown("Real-time triage queue prioritizing high-risk authentication events and suspected fraud ring entities for analyst review.")

# Triage Filter Controls
f_col1, f_col2, f_col3 = st.columns(3)
with f_col1:
    tier_filter = st.selectbox("Filter Decision Tier:", ["ALL", "BLOCK", "STEP-UP", "SAFE"], index=1)
with f_col2:
    min_score = st.slider("Minimum Ensemble Risk Score (0-1000):", min_value=0, max_value=1000, value=700, step=50)
with f_col3:
    ring_only = st.checkbox("Only Fraud Ring Members", value=False)

@st.cache_data(ttl=60)
def load_investigation_cases(tier: str, min_s: int, ring_filter: bool):
    tier_clause = "" if tier == "ALL" else f"AND e.DECISION = '{tier}'"
    ring_clause = "AND e.IS_FRAUD_RING_MEMBER = TRUE" if ring_filter else ""

    query = f"""
    SELECT
        e.EVENT_ID,
        e.CUSTOMER_ID,
        e.EVENT_TS,
        l.IP_ADDRESS,
        l.COUNTRY_CODE,
        l.DEVICE_TYPE,
        l.DEVICE_OS,
        l.IS_VPN,
        l.IS_TOR,
        l.AUTH_METHOD,
        l.LOGIN_SUCCESS,
        e.ENSEMBLE_RISK_SCORE,
        e.DECISION,
        e.XGB_FRAUD_PROB,
        e.IF_ANOMALY_SCORE,
        e.GRAPH_RISK_SCORE,
        e.IS_FRAUD_RING_MEMBER,
        e.IS_FRAUD_ACTUAL,
        e.FRAUD_SCENARIO
    FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES e
    LEFT JOIN ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS l
        ON e.EVENT_ID = l.EVENT_ID
    WHERE e.ENSEMBLE_RISK_SCORE >= {min_s}
    {tier_clause}
    {ring_clause}
    ORDER BY e.ENSEMBLE_RISK_SCORE DESC, e.EVENT_TS DESC
    LIMIT 50;
    """
    return conn.query(query)

with st.spinner("Fetching active cases..."):
    cases_df = load_investigation_cases(tier_filter, min_score, ring_only)

st.subheader(f"1. Priority Triage Queue ({len(cases_df)} Cases)")

if not cases_df.empty:
    st.dataframe(
        cases_df[[
            "EVENT_ID", "CUSTOMER_ID", "EVENT_TS", "DECISION", "ENSEMBLE_RISK_SCORE",
            "XGB_FRAUD_PROB", "IF_ANOMALY_SCORE", "GRAPH_RISK_SCORE",
            "IP_ADDRESS", "COUNTRY_CODE", "FRAUD_SCENARIO"
        ]],
        width="stretch",
        hide_index=True
    )

    st.divider()

    # Detailed Case Inspector
    st.subheader("2. Deep-Dive Case & Telemetry Inspector")
    selected_event_id = st.selectbox(
        "Select Event ID to Inspect:",
        options=cases_df["EVENT_ID"].tolist(),
        format_func=lambda x: f"Event #{x} - Customer #{cases_df[cases_df['EVENT_ID']==x]['CUSTOMER_ID'].values[0]} (Score: {cases_df[cases_df['EVENT_ID']==x]['ENSEMBLE_RISK_SCORE'].values[0]} | {cases_df[cases_df['EVENT_ID']==x]['DECISION'].values[0]})"
    )

    case_row = cases_df[cases_df["EVENT_ID"] == selected_event_id].iloc[0]

    det_col1, det_col2, det_col3 = st.columns(3)
    with det_col1:
        with st.container(border=True):
            st.markdown("##### 👤 Identity & Account")
            st.markdown(f"**Customer ID:** `{case_row['CUSTOMER_ID']}`")
            st.markdown(f"**Event Timestamp:** `{case_row['EVENT_TS']}`")
            st.markdown(f"**Auth Method:** `{case_row['AUTH_METHOD']}`")
            st.markdown(f"**Login Success:** `{'Yes' if case_row['LOGIN_SUCCESS'] else 'No'}`")
            st.markdown(f"**Labeled Scenario:** `{case_row['FRAUD_SCENARIO']}`")

    with det_col2:
        with st.container(border=True):
            st.markdown("##### 🌐 Network & Device")
            st.markdown(f"**IP Address:** `{case_row['IP_ADDRESS']}` ({case_row['COUNTRY_CODE']})")
            st.markdown(f"**Device:** `{case_row['DEVICE_TYPE']}` on `{case_row['DEVICE_OS']}`")
            st.markdown(f"**VPN / TOR Detected:** `{'VPN' if case_row['IS_VPN'] else ('TOR' if case_row['IS_TOR'] else 'None')}`")
            st.markdown(f"**Fraud Ring Member:** `{'Yes' if case_row['IS_FRAUD_RING_MEMBER'] else 'No'}`")
            st.markdown(f"**Graph Risk Score:** `{case_row['GRAPH_RISK_SCORE']}/100`")

    with det_col3:
        with st.container(border=True):
            st.markdown("##### 🧠 Ensemble Model Scores")
            st.markdown(f"**Ensemble Risk Score:** `{case_row['ENSEMBLE_RISK_SCORE']}/1000`")
            st.markdown(f"**Decision Tier:** `{case_row['DECISION']}`")
            st.markdown(f"**XGBoost Fraud Prob:** `{case_row['XGB_FRAUD_PROB']:.4f}`")
            st.markdown(f"**IF Anomaly Score:** `{case_row['IF_ANOMALY_SCORE']:.4f}`")

    st.divider()

    # Analyst Action Panel
    st.subheader("3. Remediation & Case Actions")
    act_col1, act_col2, act_col3 = st.columns(3)
    with act_col1:
        if st.button("⛔ Confirm Account Takeover (Hard Block & Lock)", type="primary"):
            st.toast(f"Account for Customer #{case_row['CUSTOMER_ID']} locked. Password reset token dispatched.", icon="🔒")
    with act_col2:
        if st.button("⚠️ Force Step-Up Biometric Re-Auth"):
            st.toast(f"FIDO2 / Biometric challenge queued for Session #{case_row['EVENT_ID']}.", icon="📱")
    with act_col3:
        if st.button("✅ Mark Legitimate (False Positive Override)"):
            st.toast(f"Event #{case_row['EVENT_ID']} cleared and whitelisted.", icon="✔️")

else:
    st.info("No cases currently match the selected threshold criteria.")

if st.button("🔄 Refresh Investigation Queue", type="secondary"):
    load_investigation_cases.clear()
    st.rerun()
