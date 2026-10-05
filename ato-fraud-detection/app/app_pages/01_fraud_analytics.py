"""
Page 1: Executive & Fraud Analytics Dashboard
Displays high-level business metrics, technical model performance, risk distributions, and attack vector breakdowns.
"""

import decimal
import streamlit as st
import pandas as pd
import altair as alt
import os

conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))


def _fix_decimals(df: pd.DataFrame) -> pd.DataFrame:
    """Convert Snowflake Decimal columns to float so Altair can infer types."""
    out = df.copy()
    for c in out.columns:
        if out[c].dtype == object and len(out[c]) > 0 and isinstance(out[c].iloc[0], decimal.Decimal):
            out[c] = out[c].astype(float)
    return out

st.title("📊 Real-Time ATO Fraud & Risk Intelligence")
st.markdown("Overview of 90-day login authentication activity, dynamic risk scoring, attack vectors, and machine learning model validation.")

# Cache summary KPI query
@st.cache_data(ttl=300)
def load_kpis():
    query = """
    SELECT
        COUNT(*) AS total_logins,
        SUM(CASE WHEN IS_FRAUD_ACTUAL THEN 1 ELSE 0 END) AS total_fraud_events,
        ROUND(SUM(CASE WHEN IS_FRAUD_ACTUAL THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 3) AS fraud_rate_pct,
        SUM(CASE WHEN DECISION = 'BLOCK' THEN 1 ELSE 0 END) AS block_count,
        SUM(CASE WHEN DECISION = 'STEP-UP' THEN 1 ELSE 0 END) AS stepup_count,
        SUM(CASE WHEN DECISION = 'SAFE' THEN 1 ELSE 0 END) AS safe_count,
        ROUND(AVG(ENSEMBLE_RISK_SCORE), 1) AS avg_risk_score
    FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES;
    """
    return conn.query(query)

@st.cache_data(ttl=300)
def load_tier_distribution():
    query = """
    SELECT
        DECISION AS risk_tier,
        COUNT(*) AS total_events,
        SUM(CASE WHEN IS_FRAUD_ACTUAL THEN 1 ELSE 0 END) AS confirmed_fraud,
        ROUND(AVG(ENSEMBLE_RISK_SCORE), 1) AS avg_score,
        ROUND(AVG(XGB_FRAUD_PROB), 4) AS avg_xgb_prob,
        ROUND(AVG(IF_ANOMALY_SCORE), 4) AS avg_if_anomaly
    FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
    GROUP BY DECISION
    ORDER BY avg_score DESC;
    """
    return conn.query(query)

@st.cache_data(ttl=300)
def load_attack_vector_stats():
    query = """
    SELECT
        COALESCE(FRAUD_SCENARIO, 'legitimate') AS attack_vector,
        COUNT(*) AS total_logins,
        SUM(CASE WHEN IS_FRAUD_ACTUAL THEN 1 ELSE 0 END) AS fraud_events,
        ROUND(AVG(ENSEMBLE_RISK_SCORE), 1) AS avg_risk_score,
        SUM(CASE WHEN DECISION = 'BLOCK' THEN 1 ELSE 0 END) AS blocked_events,
        SUM(CASE WHEN DECISION = 'STEP-UP' THEN 1 ELSE 0 END) AS step_up_events,
        SUM(CASE WHEN DECISION = 'SAFE' THEN 1 ELSE 0 END) AS allowed_events
    FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
    WHERE IS_FRAUD_ACTUAL = TRUE
    GROUP BY COALESCE(FRAUD_SCENARIO, 'legitimate')
    ORDER BY total_logins DESC;
    """
    return conn.query(query)

with st.spinner("Loading real-time fraud metrics..."):
    kpi_df = load_kpis()
    tier_df = load_tier_distribution()
    vector_df = load_attack_vector_stats()

# Business & Operational KPI Row
st.subheader("1. Executive Business Metrics")
col1, col2, col3, col4, col5 = st.columns(5)

total_logins = int(kpi_df["TOTAL_LOGINS"].iloc[0]) if not kpi_df.empty else 0
total_fraud = int(kpi_df["TOTAL_FRAUD_EVENTS"].iloc[0]) if not kpi_df.empty else 0
fraud_pct = float(kpi_df["FRAUD_RATE_PCT"].iloc[0]) if not kpi_df.empty else 0.0
block_cnt = int(kpi_df["BLOCK_COUNT"].iloc[0]) if not kpi_df.empty else 0
stepup_cnt = int(kpi_df["STEPUP_COUNT"].iloc[0]) if not kpi_df.empty else 0
safe_cnt = int(kpi_df["SAFE_COUNT"].iloc[0]) if not kpi_df.empty else 0

with col1:
    st.metric("Total Login Volume", f"{total_logins:,.0f}", help="Total authentication events processed over 90-day window")
with col2:
    st.metric("Confirmed Fraud", f"{total_fraud:,.0f}", f"{fraud_pct:.2f}% of total", delta_color="inverse")
with col3:
    st.metric("Interception (BLOCK)", f"{block_cnt:,.0f}", f"{(block_cnt/total_logins)*100:.1f}% rate" if total_logins else "0%", delta_color="normal")
with col4:
    st.metric("MFA Step-Up Challenges", f"{stepup_cnt:,.0f}", f"{(stepup_cnt/total_logins)*100:.1f}% rate" if total_logins else "0%", delta_color="normal")
with col5:
    st.metric("Frictionless (SAFE)", f"{safe_cnt:,.0f}", f"{(safe_cnt/total_logins)*100:.1f}% rate" if total_logins else "0%", delta_color="normal")

st.divider()

# Technical & ML Performance Section
st.subheader("2. Technical & ML Model Performance")
tech_col1, tech_col2 = st.columns([1, 1])

with tech_col1:
    with st.container(border=True):
        st.markdown("#### Supervised XGBoost Classifier")
        st.markdown("Out-of-Time Temporal Holdout Evaluation (`>= 2026-09-10`)")

        m1, m2 = st.columns(2)
        m1.metric("ROC-AUC", "0.8040", "Realistic")
        m2.metric("PR-AUC", "0.9493", "Cost-Sensitive")
        m3, m4 = st.columns(2)
        m3.metric("Precision (Ensemble)", "99.7%")
        m4.metric("Recall (Ensemble)", "99.4%")

        st.caption("Training: `scale_pos_weight=0.71`, `max_depth=6`, `n_estimators=150`. 19 features (leaky features removed). Noise injection + label noise enabled.")

with tech_col2:
    with st.container(border=True):
        st.markdown("#### Unsupervised Anomaly Detection (Isolation Forest)")
        st.markdown("Trained strictly on clean human baseline logins to detect zero-day ATO")

        i1, i2 = st.columns(2)
        i1.metric("ROC-AUC", "0.6149", "Novel Vectors")
        i2.metric("PR-AUC", "0.5944", "Imbalance-Safe")
        i3, i4 = st.columns(2)
        i3.metric("Contamination", "0.02", "2% Expectation")
        i4.metric("Ring Members", "494", "Graph Clustered")

        st.caption("Feature Vector: 8 behavioral biometrics (keystroke intervals, mouse entropy, dwell time, IP velocity). BEHAVIORAL_RISK_SCORE removed (leakage).")

st.divider()

# Visualizations: Risk Distribution & Attack Vector Matrix
st.subheader("3. Risk Score Distribution & Attack Vectors")
chart_col1, chart_col2 = st.columns([1, 1])

with chart_col1:
    st.markdown("##### Three-Tier Decision Engine Distribution")
    if not tier_df.empty:
        tier_plot = _fix_decimals(tier_df)
        tier_chart = alt.Chart(tier_plot).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
            x=alt.X("RISK_TIER:N", title="Decision Tier", sort=["SAFE", "STEP-UP", "BLOCK"]),
            y=alt.Y("TOTAL_EVENTS:Q", title="Event Count"),
            color=alt.Color("RISK_TIER:N", scale=alt.Scale(
                domain=["SAFE", "STEP-UP", "BLOCK"],
                range=["#28A745", "#FD7E14", "#DC3545"]
            ), legend=None),
            tooltip=["RISK_TIER", "TOTAL_EVENTS", "CONFIRMED_FRAUD", "AVG_SCORE"]
        ).properties(height=320)
        st.altair_chart(tier_chart, width="stretch")
        st.dataframe(tier_df, width="stretch", hide_index=True)

with chart_col2:
    st.markdown("##### 10 Specific ATO Attack Scenarios Interception")
    if not vector_df.empty:
        vec_plot = _fix_decimals(vector_df)
        vector_chart = alt.Chart(vec_plot).mark_bar().encode(
            y=alt.Y("ATTACK_VECTOR:N", title="ATO Attack Vector", sort="-x"),
            x=alt.X("FRAUD_EVENTS:Q", title="Total Fraud Events"),
            color=alt.Color("AVG_RISK_SCORE:Q", scale=alt.Scale(scheme="reds"), title="Avg Score"),
            tooltip=["ATTACK_VECTOR", "FRAUD_EVENTS", "BLOCKED_EVENTS", "STEP_UP_EVENTS", "AVG_RISK_SCORE"]
        ).properties(height=320)
        st.altair_chart(vector_chart, width="stretch")
        st.dataframe(vector_df[["ATTACK_VECTOR", "FRAUD_EVENTS", "BLOCKED_EVENTS", "STEP_UP_EVENTS", "AVG_RISK_SCORE"]], width="stretch", hide_index=True)

st.divider()

# Refresh Control
if st.button("🔄 Refresh Real-Time Analytics", type="secondary"):
    load_kpis.clear()
    load_tier_distribution.clear()
    load_attack_vector_stats.clear()
    st.rerun()
