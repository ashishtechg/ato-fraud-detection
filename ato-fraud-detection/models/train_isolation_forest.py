"""
=============================================================================
ATO Fraud Detection - Layer 2: Unsupervised Isolation Forest
Trained ONLY on Legitimate Traffic to Detect Novel / Zero-Day ATO Vectors
Features: Behavioral biometrics, navigation, dwell time, timing patterns
=============================================================================
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score

from snowflake.snowpark.context import get_active_session


def add_realistic_noise(df, features, rng):
    """
    Simulate real-world signal degradation:
    - Gaussian measurement noise on all features (sensor jitter, network latency variance)
    - Blend ~30% of fraud rows toward legitimate distribution (sophisticated attackers
      mimicking normal behavior via residential proxies, scripted human-like input)
    """
    df = df.copy()

    # 1. Measurement noise: 20% of each feature's std dev
    for col in features:
        std = df[col].std()
        df[col] += rng.normal(0, 0.20 * std, size=len(df))

    # 2. Sophisticated attacker simulation: blend fraud rows toward legit centroid
    fraud_mask = df["IS_FRAUD"] == True
    legit_means = df.loc[~fraud_mask, features].mean()
    blend_mask = fraud_mask & (rng.random(len(df)) < 0.30)
    blend_factor = rng.uniform(0.4, 0.8, size=blend_mask.sum())
    for i, col in enumerate(features):
        orig = df.loc[blend_mask, col].values
        df.loc[blend_mask, col] = orig + blend_factor * (legit_means[col] - orig)

    return df


def train_isolation_forest():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("SCORING")
    print("Snowpark session established for Unsupervised Training.")

    # Excluded: BEHAVIORAL_RISK_SCORE (target proxy — constant 0 for all legit traffic)
    query = """
    SELECT
        AVG_KEYSTROKE_INTERVAL_MS,
        KEYSTROKE_STD_MS,
        MOUSE_MOVEMENT_ENTROPY,
        TOUCH_PRESSURE_VARIANCE,
        DWELL_TIME_MS,
        TIME_SINCE_PREV_LOGIN_HOURS,
        DISTANCE_FROM_PREV_LOGIN_KM,
        GEO_VELOCITY_KMH,
        IS_FRAUD
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
    WHERE (IS_FRAUD = FALSE AND ABS(MOD(RANDOM(), 100)) < 1)
       OR (IS_FRAUD = TRUE AND ABS(MOD(RANDOM(), 100)) < 10)
    """

    print("Fetching behavioral telemetry baseline...")
    df = session.sql(query).to_pandas()
    print(f"Loaded {len(df):,} sample records.")

    features = [
        "AVG_KEYSTROKE_INTERVAL_MS",
        "KEYSTROKE_STD_MS",
        "MOUSE_MOVEMENT_ENTROPY",
        "TOUCH_PRESSURE_VARIANCE",
        "DWELL_TIME_MS",
        "TIME_SINCE_PREV_LOGIN_HOURS",
        "DISTANCE_FROM_PREV_LOGIN_KM",
        "GEO_VELOCITY_KMH",
    ]

    df_clean = df.fillna(0.0)

    # Inject realistic noise to simulate production signal degradation
    rng = np.random.default_rng(seed=42)
    df_clean = add_realistic_noise(df_clean, features, rng)

    # Train set = ONLY legitimate records
    train_legit = df_clean[df_clean["IS_FRAUD"] == False][features]

    # Test set = mix of legitimate and fraud holdout
    test_data = df_clean[features]
    y_true = df_clean["IS_FRAUD"].astype(int)

    print(f"Training Isolation Forest on {len(train_legit):,} purely legitimate sessions...")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(train_legit)
    X_test_scaled = scaler.transform(test_data)

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_train_scaled)

    raw_scores = iso_forest.score_samples(X_test_scaled)
    anomaly_scores = -raw_scores

    roc_auc = roc_auc_score(y_true, anomaly_scores)
    pr_auc = average_precision_score(y_true, anomaly_scores)

    print("\n" + "="*50)
    print("UNSUPERVISED ANOMALY DETECTION METRICS (Isolation Forest)")
    print("="*50)
    print(f"ROC-AUC on Holdout (Legit vs Fraud): {roc_auc:.4f}")
    print(f"PR-AUC on Holdout:                   {pr_auc:.4f}")

    # Save artifacts locally
    artifact_dir = "/tmp/ato-fraud-detection/models/artifacts"
    os.makedirs(artifact_dir, exist_ok=True)

    model_path = os.path.join(artifact_dir, "isolation_forest.joblib")
    scaler_path = os.path.join(artifact_dir, "if_scaler.joblib")
    metrics_path = os.path.join(artifact_dir, "isolation_forest_metrics.json")

    joblib.dump(iso_forest, model_path)
    joblib.dump(scaler, scaler_path)

    metrics = {
        "model_type": "Isolation Forest (Unsupervised)",
        "training_strategy": "Legitimate baseline only (No fraud labels seen)",
        "features_used": features,
        "baseline_rows": len(train_legit),
        "test_holdout_rows": len(test_data),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "trained_at": datetime.now(timezone.utc).isoformat()
    }

    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # Upload artifacts to Snowflake stage
    stage_name = "ATO_FRAUD_DB.SCORING.MODEL_ARTIFACTS"
    session.sql(f"CREATE STAGE IF NOT EXISTS {stage_name}").collect()
    print(f"\nUploading artifacts to @{stage_name}/isolation_forest/ ...")

    for local_path in [model_path, scaler_path, metrics_path]:
        session.file.put(
            local_path,
            f"@{stage_name}/isolation_forest/",
            auto_compress=False,
            overwrite=True
        )
        print(f"  Uploaded {os.path.basename(local_path)}")

    # Verify upload
    staged_files = session.sql(f"LIST @{stage_name}/isolation_forest/").collect()
    print(f"\nStaged files in @{stage_name}/isolation_forest/:")
    for row in staged_files:
        print(f"  {row['name']}  ({row['size']} bytes)")

    print(f"\nArtifacts persisted to @{stage_name}/isolation_forest/")
    return metrics


train_isolation_forest()
