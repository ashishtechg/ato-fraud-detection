"""
=============================================================================
ATO Fraud Detection - Ensemble Scoring Pipeline
Joins the three sub-model score tables, blends them into a unified
0-1000 risk score, assigns a decision tier, and writes results to
ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
=============================================================================
Weights (from ensemble_specification.json):
  - Supervised XGBoost probability:   50%
  - Unsupervised Isolation Forest:    30%
  - Graph Topology risk:              20%

Decision tiers:
  SAFE     [0, 349]   → Frictionless login
  STEP-UP  [350, 749] → Adaptive MFA challenge
  BLOCK    [750, 1000] → Automated interception & alert
=============================================================================
"""

import numpy as np
import pandas as pd
from datetime import datetime, timezone
from snowflake.snowpark.context import get_active_session

# Ensemble weights
W_XGB = 0.50
W_IF = 0.30
W_GRAPH = 0.20

# Decision thresholds on the 0-1000 scale
TAU_SAFE_CEILING = 349
TAU_BLOCK_FLOOR = 750

OUTPUT_TABLE = "ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES"


def fetch_blended_scores(session, limit=500_000):
    """Join XGBoost scores, IF anomaly scores, and graph features into one frame."""

    query = f"""
    SELECT
        x.EVENT_ID,
        x.SESSION_ID,
        x.CUSTOMER_ID,
        x.EVENT_TS,
        x.FRAUD_PROBABILITY   AS XGB_PROB,
        x.IS_FRAUD_ACTUAL,
        x.FRAUD_SCENARIO,

        COALESCE(a.ANOMALY_SCORE, 0)  AS IF_ANOMALY_SCORE,
        COALESCE(a.IS_ANOMALY, FALSE) AS IF_IS_ANOMALY,

        COALESCE(g.GRAPH_RISK_SCORE, 0)       AS GRAPH_RISK_SCORE,
        COALESCE(g.GRAPH_COMPONENT_SIZE, 1)    AS GRAPH_COMPONENT_SIZE,
        COALESCE(g.IS_FRAUD_RING_MEMBER, FALSE) AS IS_FRAUD_RING_MEMBER
    FROM ATO_FRAUD_DB.SCORING.XGBOOST_FRAUD_SCORES       x
    LEFT JOIN ATO_FRAUD_DB.SCORING.IF_ANOMALY_SCORES      a
        ON x.EVENT_ID = a.EVENT_ID
    LEFT JOIN ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES g
        ON x.CUSTOMER_ID = g.CUSTOMER_ID
    ORDER BY x.EVENT_TS DESC
    LIMIT {limit}
    """
    df = session.sql(query).to_pandas()
    print(f"Fetched {len(df):,} sessions with all three sub-model scores.")
    return df


def compute_ensemble_score(df):
    """Blend sub-model signals into a 0-1000 unified risk score."""

    # XGB component: probability already in [0, 1] → scale to [0, 1000]
    xgb_component = df["XGB_PROB"].clip(0, 1) * 1000

    # IF component: normalized anomaly score already in [0, 1] → scale to [0, 1000]
    if_component = df["IF_ANOMALY_SCORE"].clip(0, 1) * 1000

    # Graph component: graph_risk_score is [0, 100] → scale to [0, 1000]
    graph_component = df["GRAPH_RISK_SCORE"].clip(0, 100) * 10

    # Weighted blend
    raw_score = (
        W_XGB * xgb_component +
        W_IF * if_component +
        W_GRAPH * graph_component
    )
    risk_score = raw_score.clip(0, 1000).round(0).astype(int)

    # Decision tier
    decision = pd.Series("STEP-UP", index=df.index)
    decision[risk_score <= TAU_SAFE_CEILING] = "SAFE"
    decision[risk_score >= TAU_BLOCK_FLOOR] = "BLOCK"

    scored = pd.DataFrame({
        "EVENT_ID": df["EVENT_ID"],
        "SESSION_ID": df["SESSION_ID"],
        "CUSTOMER_ID": df["CUSTOMER_ID"],
        "EVENT_TS": df["EVENT_TS"],
        "IS_FRAUD_ACTUAL": df["IS_FRAUD_ACTUAL"],
        "FRAUD_SCENARIO": df["FRAUD_SCENARIO"],
        # Sub-model scores
        "XGB_FRAUD_PROB": df["XGB_PROB"].round(6),
        "IF_ANOMALY_SCORE": df["IF_ANOMALY_SCORE"].round(6),
        "GRAPH_RISK_SCORE": df["GRAPH_RISK_SCORE"],
        "IS_FRAUD_RING_MEMBER": df["IS_FRAUD_RING_MEMBER"],
        # Ensemble output
        "ENSEMBLE_RISK_SCORE": risk_score,
        "DECISION": decision,
        "SCORED_AT": datetime.now(timezone.utc),
    })
    return scored


def write_scores(session, scored_df):
    sp_df = session.create_dataframe(scored_df)
    sp_df.write.mode("overwrite").save_as_table(OUTPUT_TABLE)
    count = session.table(OUTPUT_TABLE).count()
    print(f"Wrote {count:,} scored rows to {OUTPUT_TABLE}")


def print_summary(scored_df):
    total = len(scored_df)
    fraud_mask = scored_df["IS_FRAUD_ACTUAL"] == True

    print("\n" + "=" * 60)
    print("ENSEMBLE FRAUD SCORING SUMMARY")
    print("=" * 60)

    # Decision tier distribution
    tier_counts = scored_df["DECISION"].value_counts()
    print("\nDecision Tier Distribution:")
    for tier in ["SAFE", "STEP-UP", "BLOCK"]:
        n = tier_counts.get(tier, 0)
        print(f"  {tier:<10s} {n:>8,} ({100*n/total:.2f}%)")

    # Risk score stats
    print(f"\nEnsemble Risk Score (0-1000):")
    print(f"  Mean:   {scored_df['ENSEMBLE_RISK_SCORE'].mean():.1f}")
    print(f"  Median: {scored_df['ENSEMBLE_RISK_SCORE'].median():.1f}")
    print(f"  Std:    {scored_df['ENSEMBLE_RISK_SCORE'].std():.1f}")

    # Fraud detection by tier
    n_fraud = fraud_mask.sum()
    if n_fraud > 0:
        print(f"\nFraud Detection by Decision Tier (n={n_fraud:,} known fraud):")
        for tier in ["SAFE", "STEP-UP", "BLOCK"]:
            tier_fraud = ((scored_df["DECISION"] == tier) & fraud_mask).sum()
            pct = 100 * tier_fraud / n_fraud if n_fraud > 0 else 0
            print(f"  {tier:<10s} {tier_fraud:>6,} fraud ({pct:.1f}%)")

        # Effective detection: STEP-UP + BLOCK catch fraud
        caught = ((scored_df["DECISION"] != "SAFE") & fraud_mask).sum()
        missed = ((scored_df["DECISION"] == "SAFE") & fraud_mask).sum()
        print(f"\n  Caught (STEP-UP + BLOCK): {caught:,} ({100*caught/n_fraud:.2f}%)")
        print(f"  Missed (SAFE):            {missed:,} ({100*missed/n_fraud:.2f}%)")

    # False positive rate on legitimate traffic
    legit_mask = ~fraud_mask
    n_legit = legit_mask.sum()
    if n_legit > 0:
        legit_blocked = ((scored_df["DECISION"] == "BLOCK") & legit_mask).sum()
        legit_stepped = ((scored_df["DECISION"] == "STEP-UP") & legit_mask).sum()
        print(f"\nFriction on Legitimate Traffic (n={n_legit:,}):")
        print(f"  Frictionless (SAFE):  {((scored_df['DECISION'] == 'SAFE') & legit_mask).sum():,}")
        print(f"  MFA challenged:       {legit_stepped:,} ({100*legit_stepped/n_legit:.2f}%)")
        print(f"  Blocked:              {legit_blocked:,} ({100*legit_blocked/n_legit:.4f}%)")

    # Per-scenario breakdown
    fraud_rows = scored_df[fraud_mask]
    if len(fraud_rows) > 0:
        print("\nCatch Rate by Fraud Scenario (STEP-UP + BLOCK):")
        for scenario, group in fraud_rows.groupby("FRAUD_SCENARIO"):
            caught = (group["DECISION"] != "SAFE").sum()
            total_s = len(group)
            print(f"  {scenario:<30s}  {caught}/{total_s} ({100*caught/total_s:.1f}%)")


def run_ensemble_scoring():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("SCORING")

    df = fetch_blended_scores(session)
    scored_df = compute_ensemble_score(df)
    print_summary(scored_df)
    write_scores(session, scored_df)
    return scored_df


run_ensemble_scoring()
