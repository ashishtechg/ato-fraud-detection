"""
=============================================================================
ATO Fraud Detection - Layer 1: Supervised XGBoost Classifier
Validation Strategy: Out-of-Time Temporal Split (Train: 70d, Test: 20d)
Evaluation: PR-AUC, ROC-AUC, Precision/Recall/F1 with Class Imbalance (98:2)
=============================================================================
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import datetime, timezone

import xgboost as xgb
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve
)
from snowflake.snowpark.context import get_active_session


LEAKAGE_AUC_THRESHOLD = 0.95

BOOLEAN_NOISE_FEATURES = [
    "IS_DEVICE_ROOTED", "IS_DEVICE_EMULATOR", "IS_BOT_SUSPECTED",
    "IS_VPN", "IS_TOR", "IS_PROXY",
    "IS_COUNTRY_SWITCHED", "IS_IP_SWITCHED", "IS_DORMANT"
]

CONTINUOUS_NOISE_FEATURES = {
    "DISTANCE_FROM_PREV_LOGIN_KM": 0.40,
    "GEO_VELOCITY_KMH": 0.35,
    "IP_THREAT_SCORE": 0.30,
    "FAILED_LOGIN_COUNT_1H": 0.20,
    "PHONE_CHANGE_COUNT": 0.20,
    "IP_VELOCITY_1H": 0.20,
    "DEVICE_VELOCITY_1H": 0.20,
    "TIME_SINCE_PREV_LOGIN_SEC": 0.25,
    "HOURS_SINCE_LAST_PROFILE_CHANGE": 0.25,
}

# Label noise rates (simulate labeling errors in real-world fraud investigation)
LABEL_NOISE_FRAUD_TO_LEGIT = 0.05   # 5% of fraud labels flipped (undetected ATO)
LABEL_NOISE_LEGIT_TO_FRAUD = 0.02   # 2% of legit labels flipped (false investigations)


def inject_realistic_noise(df, feature_cols, y_col="IS_FRAUD", seed=42):
    """Inject noise to create realistic class overlap in synthetic data.

    Five strategies:
    1. Boolean flip: randomly flip boolean indicators in both classes
    2. Continuous Gaussian noise: add noise proportional to feature std
    3. Fraud-to-legit blending: blend ~30% of fraud rows toward legit centroid
    4. Legit-to-fraud blending: blend ~10% of legit rows toward fraud centroid
    5. Label noise: flip a small % of labels to simulate investigation errors
    """
    rng = np.random.default_rng(seed)
    df = df.copy()
    legit_mask = df[y_col] == False
    fraud_mask = df[y_col] == True
    n = len(df)

    active_features = [c for c in feature_cols if c in df.columns]

    # 1. Boolean flips
    for col in BOOLEAN_NOISE_FEATURES:
        if col not in df.columns:
            continue
        legit_flip = legit_mask & (rng.random(n) < 0.08)
        df.loc[legit_flip, col] = 1
        fraud_flip = fraud_mask & (rng.random(n) < 0.12)
        df.loc[fraud_flip, col] = 0

    # 2. Continuous noise
    for col, noise_frac in CONTINUOUS_NOISE_FEATURES.items():
        if col not in df.columns:
            continue
        col_std = df[col].std()
        if col_std > 0:
            df[col] += rng.normal(0, noise_frac * col_std, size=n)
            df[col] = df[col].clip(lower=0)

    # 3. Fraud-to-legit blending (sophisticated attacker simulation)
    legit_means = df.loc[legit_mask, active_features].mean()
    legit_stds = df.loc[legit_mask, active_features].std().replace(0, 1)

    fraud_blend = fraud_mask & (rng.random(n) < 0.30)
    n_fb = fraud_blend.sum()
    if n_fb > 0:
        blend_factor = rng.uniform(0.4, 0.85, size=n_fb)
        for col in active_features:
            orig = df.loc[fraud_blend, col].values.astype(float)
            target = legit_means[col] + rng.normal(0, legit_stds[col] * 0.3, size=n_fb)
            df.loc[fraud_blend, col] = orig + blend_factor * (target - orig)

    # 4. Legit-to-fraud blending (traveling users, shared devices, VPN users)
    fraud_means = df.loc[fraud_mask, active_features].mean()
    fraud_stds = df.loc[fraud_mask, active_features].std().replace(0, 1)

    legit_blend = legit_mask & (rng.random(n) < 0.10)
    n_lb = legit_blend.sum()
    if n_lb > 0:
        blend_factor = rng.uniform(0.2, 0.5, size=n_lb)
        for col in active_features:
            orig = df.loc[legit_blend, col].values.astype(float)
            target = fraud_means[col] + rng.normal(0, fraud_stds[col] * 0.3, size=n_lb)
            df.loc[legit_blend, col] = orig + blend_factor * (target - orig)

    # 5. Label noise (simulate real-world investigation errors)
    fraud_flip_labels = fraud_mask & (rng.random(n) < LABEL_NOISE_FRAUD_TO_LEGIT)
    legit_flip_labels = legit_mask & (rng.random(n) < LABEL_NOISE_LEGIT_TO_FRAUD)
    n_flipped = fraud_flip_labels.sum() + legit_flip_labels.sum()
    df.loc[fraud_flip_labels, y_col] = False
    df.loc[legit_flip_labels, y_col] = True
    print(f"  Label noise: flipped {n_flipped:,} labels ({fraud_flip_labels.sum()} fraud->legit, {legit_flip_labels.sum()} legit->fraud)")

    return df


def check_feature_leakage(X, y, feature_cols):
    """Check each feature individually for target leakage (AUC > threshold)."""
    leaky = []
    print("\nPer-feature leakage check (AUC > {:.2f} = suspect):".format(LEAKAGE_AUC_THRESHOLD))
    for col in feature_cols:
        try:
            auc = roc_auc_score(y, X[col])
        except ValueError:
            auc = 0.5
        flag = " *** LEAKY - EXCLUDED ***" if auc > LEAKAGE_AUC_THRESHOLD else ""
        if auc > 0.60 or flag:
            print(f"  {col:<40s} AUC={auc:.4f}{flag}")
        if auc > LEAKAGE_AUC_THRESHOLD:
            leaky.append(col)
    if leaky:
        print(f"\nExcluding {len(leaky)} leaky feature(s): {leaky}")
    else:
        print("  No leaky features detected.")
    return leaky


def extract_features_and_train():
    session = get_active_session()
    session.use_database("ATO_FRAUD_DB")
    session.use_schema("SCORING")
    print("Snowpark session established successfully.")

    # Excluded: IS_DEVICE_TRUSTED, CANVAS_FINGERPRINT_MATCH, DEVICE_THREAT_SCORE (known target leakage)
    # Excluded: BEHAVIORAL_RISK_SCORE (upstream pre-computed score, constant 0 for legit = target proxy)
    query = """
    SELECT
        EVENT_ID,
        CUSTOMER_ID,
        EVENT_TS,
        IS_FRAUD,
        FRAUD_SCENARIO,
        -- Velocity & Network Features
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
        -- Device Features
        IFF(IS_DEVICE_EMULATOR, 1, 0) AS IS_DEVICE_EMULATOR,
        IFF(IS_DEVICE_ROOTED, 1, 0) AS IS_DEVICE_ROOTED,
        IFF(IS_BOT_SUSPECTED, 1, 0) AS IS_BOT_SUSPECTED,
        -- Profile & Reputation Features
        COALESCE(HOURS_SINCE_LAST_PROFILE_CHANGE, 999) AS HOURS_SINCE_LAST_PROFILE_CHANGE,
        COALESCE(PHONE_CHANGE_COUNT, 0) AS PHONE_CHANGE_COUNT,
        COALESCE(IP_THREAT_SCORE, 0) AS IP_THREAT_SCORE,
        IFF(ACCOUNT_STATUS = 'dormant', 1, 0) AS IS_DORMANT
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
    -- Sample rows for robust offline training (stratified with all fraud + legit sample)
    WHERE IS_FRAUD = TRUE
       OR (IS_FRAUD = FALSE AND ABS(MOD(RANDOM(), 100)) < 2)
    """

    print("Fetching training dataset from DT_SCORED_LOGINS...")
    df = session.sql(query).to_pandas()
    print(f"Loaded {len(df):,} sample records. Class distribution:")
    print(df["IS_FRAUD"].value_counts(normalize=True))

    # 2. Out-of-Time Temporal Train/Test Split (70 days Train, 20 days Test)
    df["EVENT_TS"] = pd.to_datetime(df["EVENT_TS"])
    split_cutoff = pd.Timestamp("2026-09-10")

    train_df = df[df["EVENT_TS"] < split_cutoff].copy()
    test_df = df[df["EVENT_TS"] >= split_cutoff].copy()

    print(f"\nTemporal Split:")
    print(f"  Train Set: {len(train_df):,} rows (Prior to {split_cutoff.date()})")
    print(f"  Test Set:  {len(test_df):,} rows (Out-of-Time evaluation)")

    feature_cols = [
        "TIME_SINCE_PREV_LOGIN_SEC", "DISTANCE_FROM_PREV_LOGIN_KM", "GEO_VELOCITY_KMH",
        "IS_COUNTRY_SWITCHED", "IS_IP_SWITCHED", "FAILED_LOGIN_COUNT_1H", "IP_VELOCITY_1H",
        "DEVICE_VELOCITY_1H", "IS_VPN", "IS_TOR", "IS_PROXY", "LOGIN_SUCCESS",
        "IS_DEVICE_EMULATOR", "IS_DEVICE_ROOTED",
        "IS_BOT_SUSPECTED",
        "HOURS_SINCE_LAST_PROFILE_CHANGE", "PHONE_CHANGE_COUNT",
        "IP_THREAT_SCORE", "IS_DORMANT"
    ]

    # 2b. Inject realistic noise to simulate production signal degradation
    print("\nInjecting realistic noise (boolean flips + Gaussian + bidirectional blending + label noise)...")
    train_df = inject_realistic_noise(train_df, feature_cols, seed=42)
    test_df = inject_realistic_noise(test_df, feature_cols, seed=99)

    X_train = train_df[feature_cols]
    y_train = train_df["IS_FRAUD"].astype(int)
    X_test = test_df[feature_cols]
    y_test = test_df["IS_FRAUD"].astype(int)

    # 2c. Per-feature leakage detection - auto-exclude features with AUC > threshold
    leaky_features = check_feature_leakage(X_train, y_train, feature_cols)
    if leaky_features:
        feature_cols = [c for c in feature_cols if c not in leaky_features]
        X_train = X_train[feature_cols]
        X_test = X_test[feature_cols]
        print(f"Continuing with {len(feature_cols)} clean features.")

    # 3. Cost-Sensitive XGBoost Training (scale_pos_weight compensates for imbalance)
    scale_weight = (len(y_train) - sum(y_train)) / max(sum(y_train), 1)

    print(f"\nTraining XGBoost model (scale_pos_weight={scale_weight:.2f})...")
    xgb_clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        scale_pos_weight=scale_weight,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=42,
        eval_metric=["auc", "aucpr"]
    )

    xgb_clf.fit(
        X_train, y_train,
        eval_set=[(X_train, y_train), (X_test, y_test)],
        verbose=False
    )

    # 4. Out-of-Time Validation Metrics
    y_pred_proba = xgb_clf.predict_proba(X_test)[:, 1]
    y_pred = (y_pred_proba >= 0.5).astype(int)

    roc_auc = roc_auc_score(y_test, y_pred_proba)
    pr_auc = average_precision_score(y_test, y_pred_proba)

    print("\n" + "="*50)
    print("OUT-OF-TIME VALIDATION RESULTS (XGBoost)")
    print("="*50)
    print(f"ROC-AUC Score:      {roc_auc:.4f}")
    print(f"PR-AUC Score:       {pr_auc:.4f}")

    if roc_auc >= 0.99 or pr_auc >= 0.99:
        print("\n*** WARNING: AUC >= 0.99 after noise injection. Possible residual leakage. ***")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    # 5. Feature Importances
    importances = pd.Series(xgb_clf.feature_importances_, index=feature_cols).sort_values(ascending=False)
    print("\nTop 10 Feature Importances:")
    print(importances.head(10))

    # 6. Save Artifacts
    artifact_dir = "/tmp/ato-fraud-detection/models/artifacts"
    os.makedirs(artifact_dir, exist_ok=True)
    
    xgb_clf.save_model(os.path.join(artifact_dir, "xgboost_ato_model.json"))
    
    metrics = {
        "model_type": "XGBoost Classifier",
        "validation_strategy": "Out-of-Time Temporal Split",
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "features_used": feature_cols,
        "features_excluded_leakage": leaky_features,
        "feature_importances": importances.to_dict(),
        "noise_injected": True,
        "label_noise_applied": True,
        "trained_at": datetime.now(timezone.utc).isoformat()
    }
    
    with open(os.path.join(artifact_dir, "xgboost_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel & metrics saved to {artifact_dir}")
    return metrics


extract_features_and_train()
