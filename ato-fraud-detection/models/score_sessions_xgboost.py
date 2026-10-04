"""
=============================================================================
ATO Fraud Detection - XGBoost Inference
Loads the trained XGBoost classifier from stage, scores recent sessions,
and writes fraud probabilities to ATO_FRAUD_DB.SCORING.XGBOOST_FRAUD_SCORES
=============================================================================
"""

import os
import json
import numpy as np
import pandas as pd
import xgboost as xgb
from datetime import datetime, timezone

from snowflake.snowpark.context import get_active_session

STAGE = "@ATO_FRAUD_DB.SCORING.MODEL_ARTIFACTS/xgboost"
LOCAL_DIR = "/tmp/ato-fraud-detection/inference_xgb"
TRAIN_ARTIFACT_DIR = "/tmp/ato-fraud-detection/models/artifacts"
OUTPUT_TABLE = "ATO_FRAUD_DB.SCORING.XGBOOST_FRAUD_SCORES"

# Excluded: BEHAVIORAL_RISK_SCORE (target proxy — constant 0 for all legit traffic)
# Excluded at query level: IS_DEVICE_TRUSTED, CANVAS_FINGERPRINT_MATCH, DEVICE_THREAT_SCORE
FEATURE_QUERY = """
SELECT
    EVENT_ID,
    CUSTOMER_ID,
    SESSION_ID,
    EVENT_TS,
    IS_FRAUD,
    FRAUD_SCENARIO,
    COALESCE(TIME_SINCE_PREV_LOGIN_SEC, 86400) AS TIME_SINCE_PREV_LOGIN_SEC,
    COALESCE(DISTANCE_FROM_PREV_LOGIN_KM, 0.0) AS DISTANCE_FROM_PREV_LOGIN_KM,
    COALESCE(GEO_VELOCITY_KMH, 0.0) AS GEO_VELOCITY_KMH,
    IFF(IS_COUNTRY_SWITCHED, 1, 0) AS IS_COUNTRY_SWITCHED,
    IFF(IS_IP_SWITCHED, 1, 0) AS IS_IP_SWITCHED,
    COALESCE(FAILED_LOGIN_COUNT_1H, 0) AS FAILED_LOGIN_COUNT_1H,
    COALESCE(IP_VELOCITY_1H, 1) AS IP_VELOCITY_1H,
    COALESCE(DEVICE_VELOCITY_1H, 1) AS DEVICE_VELOCITY_1H,
    IFF(IS_VPN, 1, 0) AS IS_VPN,
    IFF(IS_TOR, 1, 0) AS IS_TOR,
    IFF(IS_PROXY, 1, 0) AS IS_PROXY,
    IFF(LOGIN_SUCCESS, 1, 0) AS LOGIN_SUCCESS,
    IFF(IS_DEVICE_EMULATOR, 1, 0) AS IS_DEVICE_EMULATOR,
    IFF(IS_DEVICE_ROOTED, 1, 0) AS IS_DEVICE_ROOTED,
    IFF(IS_BOT_SUSPECTED, 1, 0) AS IS_BOT_SUSPECTED,
    COALESCE(HOURS_SINCE_LAST_PROFILE_CHANGE, 999) AS HOURS_SINCE_LAST_PROFILE_CHANGE,
    COALESCE(PHONE_CHANGE_COUNT, 0) AS PHONE_CHANGE_COUNT,
    COALESCE(IP_THREAT_SCORE, 0) AS IP_THREAT_SCORE,
    IFF(ACCOUNT_STATUS = 'dormant', 1, 0) AS IS_DORMANT
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
ORDER BY EVENT_TS DESC
LIMIT {limit}
"""

FEATURE_COLS = [
    "TIME_SINCE_PREV_LOGIN_SEC", "DISTANCE_FROM_PREV_LOGIN_KM", "GEO_VELOCITY_KMH",
    "IS_COUNTRY_SWITCHED", "IS_IP_SWITCHED", "FAILED_LOGIN_COUNT_1H", "IP_VELOCITY_1H",
    "DEVICE_VELOCITY_1H", "IS_VPN", "IS_TOR", "IS_PROXY", "LOGIN_SUCCESS",
    "IS_DEVICE_EMULATOR", "IS_DEVICE_ROOTED",
    "IS_BOT_SUSPECTED",
    "HOURS_SINCE_LAST_PROFILE_CHANGE", "PHONE_CHANGE_COUNT",
    "IP_THREAT_SCORE", "IS_DORMANT"
]

FRAUD_THRESHOLD = 0.5


def _upload_artifacts_to_stage(session, artifact_dir):
    """Upload local model artifacts to the Snowflake stage for future runs."""
    model_path = os.path.join(artifact_dir, "xgboost_ato_model.json")
    metrics_path = os.path.join(artifact_dir, "xgboost_metrics.json")
    session.file.put(model_path, STAGE, auto_compress=False, overwrite=True)
    session.file.put(metrics_path, STAGE, auto_compress=False, overwrite=True)
    print(f"Uploaded model artifacts to {STAGE}")


def _load_and_validate_model(artifact_dir):
    """Load model from a directory and validate feature count matches FEATURE_COLS."""
    model_file = os.path.join(artifact_dir, "xgboost_ato_model.json")
    metrics_file = os.path.join(artifact_dir, "xgboost_metrics.json")
    if not os.path.exists(model_file) or not os.path.exists(metrics_file):
        return None, None

    model = xgb.XGBClassifier()
    model.load_model(model_file)

    with open(metrics_file) as f:
        metrics = json.load(f)

    expected = len(FEATURE_COLS)
    actual = model.get_booster().num_features()
    if actual != expected:
        print(f"  Feature mismatch: model has {actual} features, expected {expected}. Skipping.")
        return None, None

    return model, metrics


def load_model(session):
    """Load model with feature-count validation. Prefers local retrained artifacts over stale stage models."""
    os.makedirs(LOCAL_DIR, exist_ok=True)
    model_file = "xgboost_ato_model.json"
    metrics_file = "xgboost_metrics.json"

    # 1. Try local retrained artifacts first (most likely to be current)
    local_model = os.path.join(TRAIN_ARTIFACT_DIR, model_file)
    if os.path.exists(local_model):
        model, metrics = _load_and_validate_model(TRAIN_ARTIFACT_DIR)
        if model is not None:
            print(f"Loaded retrained model from {TRAIN_ARTIFACT_DIR}")
            _upload_artifacts_to_stage(session, TRAIN_ARTIFACT_DIR)
            _print_model_info(metrics)
            return model, metrics

    # 2. Try stage artifacts
    try:
        session.file.get(f"{STAGE}/{model_file}", LOCAL_DIR)
        session.file.get(f"{STAGE}/{metrics_file}", LOCAL_DIR)
        model, metrics = _load_and_validate_model(LOCAL_DIR)
        if model is not None:
            print("Loaded artifacts from stage.")
            _print_model_info(metrics)
            return model, metrics
        else:
            print("Stage model has incompatible features. Retraining required.")
    except Exception:
        print("No artifacts found on stage.")

    # 3. Fall back to training from scratch
    print("Running training to produce compatible model...")
    artifact_dir = _run_training(session)
    model, metrics = _load_and_validate_model(artifact_dir)
    _print_model_info(metrics)
    return model, metrics


def _print_model_info(metrics):
    """Print model metadata and warnings."""
    print(f"  Trained: {metrics.get('trained_at', 'unknown')}")
    print(f"  ROC-AUC: {metrics.get('roc_auc')}, PR-AUC: {metrics.get('pr_auc')}")
    if metrics.get('roc_auc', 0) >= 0.99 or metrics.get('pr_auc', 0) >= 0.99:
        print("  *** WARNING: Loaded model has suspiciously high AUC. Consider retraining. ***")


def _run_training(session):
    """Run inline training and upload artifacts to stage."""
    from sklearn.metrics import (
        roc_auc_score, average_precision_score, classification_report, confusion_matrix
    )

    print("Fetching training dataset from DT_SCORED_LOGINS...")
    query = """
    SELECT
        EVENT_ID, CUSTOMER_ID, EVENT_TS, IS_FRAUD, FRAUD_SCENARIO,
        COALESCE(TIME_SINCE_PREV_LOGIN_SEC, 86400) AS TIME_SINCE_PREV_LOGIN_SEC,
        COALESCE(DISTANCE_FROM_PREV_LOGIN_KM, 0.0) AS DISTANCE_FROM_PREV_LOGIN_KM,
        COALESCE(GEO_VELOCITY_KMH, 0.0) AS GEO_VELOCITY_KMH,
        IFF(IS_COUNTRY_SWITCHED, 1, 0) AS IS_COUNTRY_SWITCHED,
        IFF(IS_IP_SWITCHED, 1, 0) AS IS_IP_SWITCHED,
        COALESCE(FAILED_LOGIN_COUNT_1H, 0) AS FAILED_LOGIN_COUNT_1H,
        COALESCE(IP_VELOCITY_1H, 1) AS IP_VELOCITY_1H,
        COALESCE(DEVICE_VELOCITY_1H, 1) AS DEVICE_VELOCITY_1H,
        IFF(IS_VPN, 1, 0) AS IS_VPN,
        IFF(IS_TOR, 1, 0) AS IS_TOR,
        IFF(IS_PROXY, 1, 0) AS IS_PROXY,
        IFF(LOGIN_SUCCESS, 1, 0) AS LOGIN_SUCCESS,
        IFF(IS_DEVICE_EMULATOR, 1, 0) AS IS_DEVICE_EMULATOR,
        IFF(IS_DEVICE_ROOTED, 1, 0) AS IS_DEVICE_ROOTED,
        IFF(IS_BOT_SUSPECTED, 1, 0) AS IS_BOT_SUSPECTED,
        COALESCE(HOURS_SINCE_LAST_PROFILE_CHANGE, 999) AS HOURS_SINCE_LAST_PROFILE_CHANGE,
        COALESCE(PHONE_CHANGE_COUNT, 0) AS PHONE_CHANGE_COUNT,
        COALESCE(IP_THREAT_SCORE, 0) AS IP_THREAT_SCORE,
        IFF(ACCOUNT_STATUS = 'dormant', 1, 0) AS IS_DORMANT
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
    WHERE IS_FRAUD = TRUE
       OR (IS_FRAUD = FALSE AND ABS(MOD(RANDOM(), 100)) < 2)
    """
    df = session.sql(query).to_pandas()
    print(f"Loaded {len(df):,} sample records. Class distribution:")
    print(df["IS_FRAUD"].value_counts(normalize=True))

    df["EVENT_TS"] = pd.to_datetime(df["EVENT_TS"])
    split_cutoff = pd.Timestamp("2026-09-10")
    train_df = df[df["EVENT_TS"] < split_cutoff]
    test_df = df[df["EVENT_TS"] >= split_cutoff]

    print(f"\nTemporal Split:")
    print(f"  Train: {len(train_df):,} rows | Test: {len(test_df):,} rows")

    X_train = train_df[FEATURE_COLS]
    y_train = train_df["IS_FRAUD"].astype(int)
    X_test = test_df[FEATURE_COLS]
    y_test = test_df["IS_FRAUD"].astype(int)

    scale_weight = (len(y_train) - sum(y_train)) / max(sum(y_train), 1)
    xgb_clf = xgb.XGBClassifier(
        n_estimators=150, max_depth=6, learning_rate=0.08,
        scale_pos_weight=scale_weight, subsample=0.85, colsample_bytree=0.85,
        random_state=42, eval_metric=["auc", "aucpr"]
    )
    xgb_clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred_proba = xgb_clf.predict_proba(X_test)[:, 1]
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    pr_auc = average_precision_score(y_test, y_pred_proba)
    print(f"  ROC-AUC: {roc_auc:.4f}, PR-AUC: {pr_auc:.4f}")

    os.makedirs(TRAIN_ARTIFACT_DIR, exist_ok=True)
    xgb_clf.save_model(os.path.join(TRAIN_ARTIFACT_DIR, "xgboost_ato_model.json"))

    importances = pd.Series(xgb_clf.feature_importances_, index=FEATURE_COLS)
    metrics = {
        "model_type": "XGBoost Classifier",
        "validation_strategy": "Out-of-Time Temporal Split",
        "train_rows": len(train_df), "test_rows": len(test_df),
        "roc_auc": round(float(roc_auc), 4), "pr_auc": round(float(pr_auc), 4),
        "feature_importances": importances.to_dict(),
        "trained_at": datetime.now(timezone.utc).isoformat()
    }
    with open(os.path.join(TRAIN_ARTIFACT_DIR, "xgboost_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    _upload_artifacts_to_stage(session, TRAIN_ARTIFACT_DIR)
    print("Training complete. Artifacts saved to stage.")
    return TRAIN_ARTIFACT_DIR


def fetch_sessions(session, limit=500_000):
    """Fetch recent sessions with feature engineering matching training."""
    query = FEATURE_QUERY.format(limit=limit)
    df = session.sql(query).to_pandas()
    print(f"Fetched {len(df):,} sessions for scoring.")
    return df


def score_sessions(df, model):
    """Run XGBoost inference and return scored dataframe."""
    X = df[FEATURE_COLS].values
    fraud_proba = model.predict_proba(X)[:, 1]
    is_fraud_pred = (fraud_proba >= FRAUD_THRESHOLD)

    scored = pd.DataFrame({
        "EVENT_ID": df["EVENT_ID"],
        "SESSION_ID": df["SESSION_ID"],
        "CUSTOMER_ID": df["CUSTOMER_ID"],
        "EVENT_TS": df["EVENT_TS"],
        "FRAUD_PROBABILITY": np.round(fraud_proba, 6),
        "IS_FRAUD_PREDICTED": is_fraud_pred,
        "IS_FRAUD_ACTUAL": df["IS_FRAUD"],
        "FRAUD_SCENARIO": df["FRAUD_SCENARIO"],
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
    n_predicted = scored_df["IS_FRAUD_PREDICTED"].sum()
    n_actual = scored_df["IS_FRAUD_ACTUAL"].sum()

    true_pos = ((scored_df["IS_FRAUD_PREDICTED"]) & (scored_df["IS_FRAUD_ACTUAL"])).sum()
    false_pos = ((scored_df["IS_FRAUD_PREDICTED"]) & (~scored_df["IS_FRAUD_ACTUAL"])).sum()
    false_neg = ((~scored_df["IS_FRAUD_PREDICTED"]) & (scored_df["IS_FRAUD_ACTUAL"])).sum()

    print("\n" + "=" * 55)
    print("XGBOOST FRAUD DETECTION INFERENCE SUMMARY")
    print("=" * 55)
    print(f"Sessions scored:          {total:,}")
    print(f"Predicted as fraud:       {n_predicted:,} ({100*n_predicted/total:.2f}%)")
    print(f"Known fraud in sample:    {n_actual:,} ({100*n_actual/total:.2f}%)")
    print(f"True positives (caught):  {true_pos:,}")
    print(f"False positives:          {false_pos:,}")
    print(f"False negatives (missed): {false_neg:,}")
    if n_actual > 0:
        recall = true_pos / n_actual
        print(f"Recall on known fraud:    {recall:.4f}")
    if n_predicted > 0:
        precision = true_pos / n_predicted
        print(f"Precision on predictions: {precision:.4f}")

    # Breakdown by fraud scenario
    fraud_rows = scored_df[scored_df["IS_FRAUD_ACTUAL"] == True]
    if len(fraud_rows) > 0:
        print("\nRecall by fraud scenario:")
        for scenario, group in fraud_rows.groupby("FRAUD_SCENARIO"):
            caught = group["IS_FRAUD_PREDICTED"].sum()
            total_scenario = len(group)
            print(f"  {scenario:<30s}  {caught}/{total_scenario} ({100*caught/total_scenario:.1f}%)")

    print("\nFraud probability distribution:")
    print(scored_df["FRAUD_PROBABILITY"].describe().to_string())


def run_inference():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("SCORING")

    model, _ = load_model(session)
    df = fetch_sessions(session)
    scored_df = score_sessions(df, model)
    print_summary(scored_df)
    write_scores(session, scored_df)
    return scored_df


run_inference()
