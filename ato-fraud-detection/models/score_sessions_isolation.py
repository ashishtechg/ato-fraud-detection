"""
=============================================================================
ATO Fraud Detection - Isolation Forest Inference
Loads the trained model from stage, scores recent sessions, and writes
anomaly scores back to ATO_FRAUD_DB.SCORING.IF_ANOMALY_SCORES
=============================================================================
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone

from snowflake.snowpark.context import get_active_session
from snowflake.snowpark.types import (
    StructType, StructField, StringType, FloatType,
    TimestampType, LongType
)

STAGE = "@ATO_FRAUD_DB.SCORING.MODEL_ARTIFACTS/isolation_forest"
LOCAL_DIR = "/tmp/ato-fraud-detection/inference"
TRAIN_ARTIFACT_DIR = "/tmp/ato-fraud-detection/models/artifacts"
OUTPUT_TABLE = "ATO_FRAUD_DB.SCORING.IF_ANOMALY_SCORES"

# Excluded: BEHAVIORAL_RISK_SCORE (target proxy — constant 0 for all legit traffic)
FEATURES = [
    "AVG_KEYSTROKE_INTERVAL_MS",
    "KEYSTROKE_STD_MS",
    "MOUSE_MOVEMENT_ENTROPY",
    "TOUCH_PRESSURE_VARIANCE",
    "DWELL_TIME_MS",
    "TIME_SINCE_PREV_LOGIN_HOURS",
    "DISTANCE_FROM_PREV_LOGIN_KM",
    "GEO_VELOCITY_KMH",
]


def load_artifacts(session):
    """Download model and scaler, preferring local retrained artifacts over stale stage ones."""
    os.makedirs(LOCAL_DIR, exist_ok=True)

    # 1. Try local retrained artifacts first
    local_model = os.path.join(TRAIN_ARTIFACT_DIR, "isolation_forest.joblib")
    local_scaler = os.path.join(TRAIN_ARTIFACT_DIR, "if_scaler.joblib")
    local_metrics = os.path.join(TRAIN_ARTIFACT_DIR, "isolation_forest_metrics.json")

    if os.path.exists(local_model) and os.path.exists(local_scaler):
        model = joblib.load(local_model)
        scaler = joblib.load(local_scaler)
        if model.n_features_in_ == len(FEATURES):
            metrics = {}
            if os.path.exists(local_metrics):
                with open(local_metrics) as f:
                    metrics = json.load(f)
            print(f"Loaded retrained model from {TRAIN_ARTIFACT_DIR}")
            # Upload to stage for future runs
            stage_name = "ATO_FRAUD_DB.SCORING.MODEL_ARTIFACTS"
            for p in [local_model, local_scaler, local_metrics]:
                if os.path.exists(p):
                    session.file.put(p, f"@{stage_name}/isolation_forest/", auto_compress=False, overwrite=True)
            print("Uploaded retrained artifacts to stage.")
            _print_metrics(metrics)
            return model, scaler, metrics
        else:
            print(f"  Local model has {model.n_features_in_} features, expected {len(FEATURES)}. Skipping.")

    # 2. Try stage artifacts
    try:
        session.file.get(f"{STAGE}/isolation_forest.joblib", LOCAL_DIR)
        session.file.get(f"{STAGE}/if_scaler.joblib", LOCAL_DIR)
        session.file.get(f"{STAGE}/isolation_forest_metrics.json", LOCAL_DIR)

        model = joblib.load(os.path.join(LOCAL_DIR, "isolation_forest.joblib"))
        scaler = joblib.load(os.path.join(LOCAL_DIR, "if_scaler.joblib"))

        if model.n_features_in_ != len(FEATURES):
            print(f"Stage model has {model.n_features_in_} features, expected {len(FEATURES)}. Retraining required.")
            raise ValueError("Feature mismatch")

        with open(os.path.join(LOCAL_DIR, "isolation_forest_metrics.json")) as f:
            metrics = json.load(f)

        print("Loaded artifacts from stage.")
        _print_metrics(metrics)
        return model, scaler, metrics
    except Exception as e:
        print(f"Could not load from stage: {e}")
        raise RuntimeError(
            "No compatible Isolation Forest model found. "
            "Run train_isolation_forest.py first."
        )


def _print_metrics(metrics):
    if metrics:
        print(f"  Trained: {metrics.get('trained_at', 'unknown')}")
        print(f"  ROC-AUC: {metrics.get('roc_auc', 'N/A')}, PR-AUC: {metrics.get('pr_auc', 'N/A')}")


def fetch_sessions(session, limit=500_000):
    """Fetch recent sessions to score."""
    query = f"""
    SELECT
        EVENT_ID,
        SESSION_ID,
        CUSTOMER_ID,
        EVENT_TS,
        {', '.join(FEATURES)},
        IS_FRAUD
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
    ORDER BY EVENT_TS DESC
    LIMIT {limit}
    """
    df = session.sql(query).to_pandas()
    print(f"Fetched {len(df):,} sessions for scoring.")
    return df


def score_sessions(df, model, scaler):
    """Run Isolation Forest inference and return scored dataframe."""
    X = df[FEATURES].fillna(0.0).values
    X_scaled = scaler.transform(X)

    raw_scores = model.score_samples(X_scaled)
    anomaly_scores = -raw_scores  # higher = more anomalous

    # Normalize to 0-1 range for interpretability
    lo, hi = anomaly_scores.min(), anomaly_scores.max()
    if hi > lo:
        norm_scores = (anomaly_scores - lo) / (hi - lo)
    else:
        norm_scores = np.zeros_like(anomaly_scores)

    predictions = model.predict(X_scaled)  # 1 = inlier, -1 = outlier
    is_anomaly = (predictions == -1)

    scored = pd.DataFrame({
        "EVENT_ID": df["EVENT_ID"],
        "SESSION_ID": df["SESSION_ID"],
        "CUSTOMER_ID": df["CUSTOMER_ID"],
        "EVENT_TS": df["EVENT_TS"],
        "ANOMALY_SCORE_RAW": anomaly_scores,
        "ANOMALY_SCORE": np.round(norm_scores, 6),
        "IS_ANOMALY": is_anomaly,
        "IS_FRAUD": df["IS_FRAUD"],
        "SCORED_AT": datetime.now(timezone.utc),
    })
    return scored


def write_scores(session, scored_df):
    """Write scored results to Snowflake table."""
    sp_df = session.create_dataframe(scored_df)
    sp_df.write.mode("overwrite").save_as_table(OUTPUT_TABLE)
    count = session.table(OUTPUT_TABLE).count()
    print(f"Wrote {count:,} scored rows to {OUTPUT_TABLE}")


def print_summary(scored_df):
    """Print inference summary statistics."""
    total = len(scored_df)
    n_anomaly = scored_df["IS_ANOMALY"].sum()
    n_fraud = scored_df["IS_FRAUD"].sum()

    # Overlap: anomalies that are also labeled fraud
    true_pos = ((scored_df["IS_ANOMALY"]) & (scored_df["IS_FRAUD"])).sum()
    false_neg = ((~scored_df["IS_ANOMALY"]) & (scored_df["IS_FRAUD"])).sum()

    print("\n" + "=" * 55)
    print("ISOLATION FOREST INFERENCE SUMMARY")
    print("=" * 55)
    print(f"Sessions scored:          {total:,}")
    print(f"Flagged as anomaly:       {n_anomaly:,} ({100*n_anomaly/total:.2f}%)")
    print(f"Known fraud in sample:    {n_fraud:,} ({100*n_fraud/total:.2f}%)")
    print(f"True positives (caught):  {true_pos:,}")
    print(f"False negatives (missed): {false_neg:,}")
    if n_fraud > 0:
        recall = true_pos / n_fraud
        print(f"Recall on known fraud:    {recall:.4f}")
    if n_anomaly > 0:
        precision = true_pos / n_anomaly
        print(f"Precision on anomalies:   {precision:.4f}")

    print("\nAnomaly score distribution:")
    print(scored_df["ANOMALY_SCORE"].describe().to_string())


def run_inference():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("SCORING")

    model, scaler, _ = load_artifacts(session)
    df = fetch_sessions(session)
    scored_df = score_sessions(df, model, scaler)
    print_summary(scored_df)
    write_scores(session, scored_df)
    return scored_df


run_inference()
