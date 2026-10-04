"""
=============================================================================
ATO Fraud Detection - Model Registry Logging Script
Registers all four sub-models + ensemble into Snowflake Model Registry:
  1. ATO_XGBOOST_CLASSIFIER    (Supervised XGBoost)
  2. ATO_ISOLATION_FOREST       (Unsupervised Anomaly Detector)
  3. ATO_GRAPH_RISK_SCORER      (Identity Graph Analytics & Ring Detection)
  4. ATO_ENSEMBLE               (Ensemble meta-model as CustomModel)

Loads retrained artifacts from /tmp/ (not stale workspace copies).
Version naming: {MODEL_SHORT}_V{N} (e.g. XGBOOST_V1, XGBOOST_V2, ...)
=============================================================================
"""

import os
import re
import json
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from datetime import datetime, timezone

from snowflake.snowpark.context import get_active_session
from snowflake.ml.registry import Registry
from snowflake.ml.model import custom_model

ARTIFACT_DIR = "/tmp/ato-fraud-detection/models/artifacts"
STAGE = "@ATO_FRAUD_DB.SCORING.MODEL_ARTIFACTS"

DATABASE = "ATO_FRAUD_DB"
SCHEMA = "SCORING"

# Version prefix per model (used in {PREFIX}_V{N} naming)
VERSION_PREFIXES = {
    "ATO_XGBOOST_CLASSIFIER": "XGBOOST",
    "ATO_ISOLATION_FOREST": "IFOREST",
    "ATO_GRAPH_RISK_SCORER": "GRAPH",
    "ATO_ENSEMBLE": "ENSEMBLE",
}

XGB_FEATURE_COLS = [
    "TIME_SINCE_PREV_LOGIN_SEC", "DISTANCE_FROM_PREV_LOGIN_KM", "GEO_VELOCITY_KMH",
    "IS_COUNTRY_SWITCHED", "IS_IP_SWITCHED", "FAILED_LOGIN_COUNT_1H", "IP_VELOCITY_1H",
    "DEVICE_VELOCITY_1H", "IS_VPN", "IS_TOR", "IS_PROXY", "LOGIN_SUCCESS",
    "IS_DEVICE_EMULATOR", "IS_DEVICE_ROOTED",
    "IS_BOT_SUSPECTED",
    "HOURS_SINCE_LAST_PROFILE_CHANGE", "PHONE_CHANGE_COUNT",
    "IP_THREAT_SCORE", "IS_DORMANT"
]

IF_FEATURE_COLS = [
    "AVG_KEYSTROKE_INTERVAL_MS", "KEYSTROKE_STD_MS", "MOUSE_MOVEMENT_ENTROPY",
    "TOUCH_PRESSURE_VARIANCE", "DWELL_TIME_MS", "TIME_SINCE_PREV_LOGIN_HOURS",
    "DISTANCE_FROM_PREV_LOGIN_KM", "GEO_VELOCITY_KMH",
]

GRAPH_FEATURE_COLS = [
    "LINKED_DEVICE_COUNT", "LINKED_IP_COUNT", "LINKED_EMAIL_COUNT",
    "LINKED_PHONE_COUNT", "GRAPH_COMPONENT_SIZE", "SHARED_IP_CLUSTER_SIZE",
]


def _next_version(session, model_name):
    """Compute the next version name as {PREFIX}_V{N} by querying existing versions."""
    prefix = VERSION_PREFIXES.get(model_name, model_name.split("_")[-1].upper())
    pattern = re.compile(rf"^{re.escape(prefix)}_V(\d+)$", re.IGNORECASE)

    try:
        rows = session.sql(
            f"SHOW VERSIONS IN MODEL {DATABASE}.{SCHEMA}.{model_name}"
        ).collect()
        max_n = 0
        for row in rows:
            ver = row["name"]
            m = pattern.match(ver)
            if m:
                max_n = max(max_n, int(m.group(1)))
        next_n = max_n + 1
    except Exception:
        next_n = 1

    version = f"{prefix}_V{next_n}"
    print(f"  Version: {version}")
    return version


def _load_local_or_stage(session, filename, loader_fn):
    local_path = os.path.join(ARTIFACT_DIR, filename)
    if os.path.exists(local_path):
        print(f"  Loading {filename} from retrained artifacts")
        return loader_fn(local_path)

    tmp_dir = "/tmp/ato-fraud-detection/registry_download"
    os.makedirs(tmp_dir, exist_ok=True)
    stage_prefix = "xgboost" if "xgboost" in filename or "xgb" in filename else "isolation_forest"
    session.file.get(f"{STAGE}/{stage_prefix}/{filename}", tmp_dir)
    downloaded = os.path.join(tmp_dir, filename)
    if os.path.exists(downloaded):
        print(f"  Loading {filename} from stage")
        return loader_fn(downloaded)

    raise FileNotFoundError(f"{filename} not found locally or on stage. Run training first.")


def _build_xgb_sample_input():
    return pd.DataFrame([{
        "TIME_SINCE_PREV_LOGIN_SEC": 3600.0,
        "DISTANCE_FROM_PREV_LOGIN_KM": 5.2,
        "GEO_VELOCITY_KMH": 5.2,
        "IS_COUNTRY_SWITCHED": 0,
        "IS_IP_SWITCHED": 0,
        "FAILED_LOGIN_COUNT_1H": 0,
        "IP_VELOCITY_1H": 1,
        "DEVICE_VELOCITY_1H": 1,
        "IS_VPN": 0,
        "IS_TOR": 0,
        "IS_PROXY": 0,
        "LOGIN_SUCCESS": 1,
        "IS_DEVICE_EMULATOR": 0,
        "IS_DEVICE_ROOTED": 0,
        "IS_BOT_SUSPECTED": 0,
        "HOURS_SINCE_LAST_PROFILE_CHANGE": 720,
        "PHONE_CHANGE_COUNT": 0,
        "IP_THREAT_SCORE": 0,
        "IS_DORMANT": 0
    }])


def _build_if_sample_input():
    return pd.DataFrame([{
        "AVG_KEYSTROKE_INTERVAL_MS": 120.0,
        "KEYSTROKE_STD_MS": 25.0,
        "MOUSE_MOVEMENT_ENTROPY": 3.5,
        "TOUCH_PRESSURE_VARIANCE": 0.02,
        "DWELL_TIME_MS": 45000,
        "TIME_SINCE_PREV_LOGIN_HOURS": 24.0,
        "DISTANCE_FROM_PREV_LOGIN_KM": 5.2,
        "GEO_VELOCITY_KMH": 5.2,
    }])


def _build_graph_sample_input():
    return pd.DataFrame([{
        "LINKED_DEVICE_COUNT": 2,
        "LINKED_IP_COUNT": 50,
        "LINKED_EMAIL_COUNT": 1,
        "LINKED_PHONE_COUNT": 1,
        "GRAPH_COMPONENT_SIZE": 1,
        "SHARED_IP_CLUSTER_SIZE": 1,
    }])


def _build_ensemble_sample_input():
    return pd.DataFrame([{
        "XGB_PROB": 0.15,
        "IF_ANOMALY_SCORE": 0.3,
        "GRAPH_RISK_SCORE": 10.0,
    }])


class ATOGraphRiskScorer(custom_model.CustomModel):
    """Layer 3: Identity Graph risk scoring using purely structural topology signals."""

    @custom_model.inference_api
    def predict(self, input_df: pd.DataFrame) -> pd.DataFrame:
        ring_size = input_df["GRAPH_COMPONENT_SIZE"].clip(lower=1)
        device_count = input_df["LINKED_DEVICE_COUNT"].clip(lower=1)
        ip_cluster = input_df["SHARED_IP_CLUSTER_SIZE"].clip(lower=1)
        ip_count = input_df["LINKED_IP_COUNT"].clip(lower=1)

        ring_score = pd.Series(0, index=input_df.index, dtype=float)
        ring_score = ring_score.where(ring_size < 3, 15)
        ring_score = ring_score.where(ring_size < 5, 25)
        ring_score = ring_score.where(ring_size < 10, 40)

        device_score = pd.Series(0, index=input_df.index, dtype=float)
        device_score = device_score.where(device_count < 3, 10)
        device_score = device_score.where(device_count < 5, 20)

        ip_cluster_score = pd.Series(0, index=input_df.index, dtype=float)
        ip_cluster_score = ip_cluster_score.where(ip_cluster < 3, 5)
        ip_cluster_score = ip_cluster_score.where(ip_cluster < 5, 10)
        ip_cluster_score = ip_cluster_score.where(ip_cluster < 10, 20)

        ip_div_score = pd.Series(0, index=input_df.index, dtype=float)
        ip_div_score = ip_div_score.where(ip_count < 100, 10)
        ip_div_score = ip_div_score.where(ip_count < 200, 20)

        raw = (ring_score + device_score + ip_cluster_score + ip_div_score).clip(0, 100)
        is_ring = ring_size >= 10

        return pd.DataFrame({
            "GRAPH_RISK_SCORE": raw.astype(int),
            "IS_FRAUD_RING_MEMBER": is_ring,
        })


class ATOEnsembleModel(custom_model.CustomModel):
    """Ensemble meta-model: blends three sub-model scores into a 0-1000 risk score."""

    W_XGB = 0.50
    W_IF = 0.30
    W_GRAPH = 0.20
    TAU_SAFE = 349
    TAU_BLOCK = 750

    @custom_model.inference_api
    def predict(self, input_df: pd.DataFrame) -> pd.DataFrame:
        xgb_component = input_df["XGB_PROB"].clip(0, 1) * 1000
        if_component = input_df["IF_ANOMALY_SCORE"].clip(0, 1) * 1000
        graph_component = input_df["GRAPH_RISK_SCORE"].clip(0, 100) * 10

        raw = (self.W_XGB * xgb_component +
               self.W_IF * if_component +
               self.W_GRAPH * graph_component)
        risk_score = raw.clip(0, 1000).round(0).astype(int)

        decision = pd.Series("STEP-UP", index=input_df.index)
        decision[risk_score <= self.TAU_SAFE] = "SAFE"
        decision[risk_score >= self.TAU_BLOCK] = "BLOCK"

        return pd.DataFrame({
            "ENSEMBLE_RISK_SCORE": risk_score,
            "DECISION": decision,
        })


def _validate_model_features(model, expected_n, model_name):
    if hasattr(model, 'get_booster'):
        actual = model.get_booster().num_features()
    elif hasattr(model, 'n_features_in_'):
        actual = model.n_features_in_
    else:
        print(f"  Cannot verify feature count for {model_name}")
        return True
    if actual != expected_n:
        raise ValueError(
            f"{model_name} has {actual} features but expected {expected_n}. "
            f"The model artifact is stale — retrain first."
        )
    print(f"  {model_name}: {actual} features (matches expected)")
    return True


def register_all_models():
    session = get_active_session()
    session.use_database(DATABASE)
    session.use_schema(SCHEMA)
    print("Connected to Snowflake for Model Registry logging.\n")

    reg = Registry(session=session, database_name=DATABASE, schema_name=SCHEMA)
    registered = []

    # --- 1. XGBoost Classifier ---
    print("=" * 55)
    print("1. Registering ATO_XGBOOST_CLASSIFIER")
    print("=" * 55)

    xgb_model = _load_local_or_stage(
        session, "xgboost_ato_model.json",
        lambda p: (lambda m: (m.load_model(p), m)[-1])(xgb.XGBClassifier())
    )
    _validate_model_features(xgb_model, len(XGB_FEATURE_COLS), "XGBoost")

    xgb_metrics = _load_local_or_stage(
        session, "xgboost_metrics.json",
        lambda p: json.load(open(p))
    )
    print(f"  ROC-AUC: {xgb_metrics.get('roc_auc')}, PR-AUC: {xgb_metrics.get('pr_auc')}")
    print(f"  Trained: {xgb_metrics.get('trained_at')}")

    if xgb_metrics.get("roc_auc", 0) >= 0.99:
        print("  *** WARNING: AUC >= 0.99, model may be stale/leaky ***")

    xgb_version = _next_version(session, "ATO_XGBOOST_CLASSIFIER")
    xgb_comment = (
        f"Supervised XGBoost ATO classifier. "
        f"ROC-AUC={xgb_metrics.get('roc_auc')}, PR-AUC={xgb_metrics.get('pr_auc')}. "
        f"{len(XGB_FEATURE_COLS)} features (leaky features removed). "
        f"Noise injection: {xgb_metrics.get('noise_injected', False)}. "
        f"Trained: {xgb_metrics.get('trained_at', 'unknown')}"
    )

    mv_xgb = reg.log_model(
        model_name="ATO_XGBOOST_CLASSIFIER",
        version_name=xgb_version,
        model=xgb_model,
        sample_input_data=_build_xgb_sample_input(),
        conda_dependencies=["xgboost"],
        comment=xgb_comment
    )
    mv_xgb.set_metric("roc_auc", xgb_metrics.get("roc_auc", 0))
    mv_xgb.set_metric("pr_auc", xgb_metrics.get("pr_auc", 0))
    mv_xgb.set_metric("train_rows", xgb_metrics.get("train_rows", 0))
    mv_xgb.set_metric("test_rows", xgb_metrics.get("test_rows", 0))
    mv_xgb.set_metric("noise_injected", 1 if xgb_metrics.get("noise_injected") else 0)
    mv_xgb.set_metric("label_noise_applied", 1 if xgb_metrics.get("label_noise_applied") else 0)
    mv_xgb.set_metric("n_features", len(XGB_FEATURE_COLS))

    registered.append(("ATO_XGBOOST_CLASSIFIER", xgb_version))
    print(f"  Registered: {mv_xgb.model_name} {xgb_version}\n")

    # --- 2. Isolation Forest ---
    print("=" * 55)
    print("2. Registering ATO_ISOLATION_FOREST")
    print("=" * 55)

    iso_model = _load_local_or_stage(
        session, "isolation_forest.joblib",
        lambda p: joblib.load(p)
    )
    _validate_model_features(iso_model, len(IF_FEATURE_COLS), "Isolation Forest")

    if_metrics = _load_local_or_stage(
        session, "isolation_forest_metrics.json",
        lambda p: json.load(open(p))
    )
    print(f"  ROC-AUC: {if_metrics.get('roc_auc')}, PR-AUC: {if_metrics.get('pr_auc')}")
    print(f"  Trained: {if_metrics.get('trained_at')}")

    if_version = _next_version(session, "ATO_ISOLATION_FOREST")
    if_comment = (
        f"Unsupervised Isolation Forest for zero-day ATO detection. "
        f"ROC-AUC={if_metrics.get('roc_auc')}, PR-AUC={if_metrics.get('pr_auc')}. "
        f"Trained on legitimate traffic only ({if_metrics.get('baseline_rows', 'N/A')} rows). "
        f"{len(IF_FEATURE_COLS)} behavioral features. "
        f"Trained: {if_metrics.get('trained_at', 'unknown')}"
    )

    mv_if = reg.log_model(
        model_name="ATO_ISOLATION_FOREST",
        version_name=if_version,
        model=iso_model,
        sample_input_data=_build_if_sample_input(),
        conda_dependencies=["scikit-learn"],
        comment=if_comment
    )
    mv_if.set_metric("roc_auc", if_metrics.get("roc_auc", 0))
    mv_if.set_metric("pr_auc", if_metrics.get("pr_auc", 0))
    mv_if.set_metric("baseline_rows", if_metrics.get("baseline_rows", 0))
    mv_if.set_metric("n_features", len(IF_FEATURE_COLS))

    registered.append(("ATO_ISOLATION_FOREST", if_version))
    print(f"  Registered: {mv_if.model_name} {if_version}\n")

    # --- 3. Graph Risk Scorer ---
    print("=" * 55)
    print("3. Registering ATO_GRAPH_RISK_SCORER")
    print("=" * 55)

    graph_model = ATOGraphRiskScorer(custom_model.ModelContext())
    graph_sample = _build_graph_sample_input()

    test_graph = graph_model.predict(graph_sample)
    print(f"  Graph test: risk_score={test_graph['GRAPH_RISK_SCORE'].iloc[0]}, "
          f"ring_member={test_graph['IS_FRAUD_RING_MEMBER'].iloc[0]}")

    graph_metrics_path = os.path.join(ARTIFACT_DIR, "graph_analytics_metrics.json")
    graph_metrics = {}
    if os.path.exists(graph_metrics_path):
        with open(graph_metrics_path) as f:
            graph_metrics = json.load(f)
        print(f"  Customers: {graph_metrics.get('total_customers', 'N/A')}")
        print(f"  Ring members flagged: {graph_metrics.get('fraud_ring_members_flagged', 'N/A')}")
        print(f"  Leakage fix: {graph_metrics.get('leakage_fix', 'N/A')}")
    else:
        print("  graph_analytics_metrics.json not found — registering without metrics")

    graph_version = _next_version(session, "ATO_GRAPH_RISK_SCORER")
    graph_comment = (
        f"Identity Graph risk scorer (Layer 3). "
        f"Structural topology only — no label-derived features (fraud_link_count removed). "
        f"Inputs: device/IP/email/phone degree counts + shared device ring size + shared IP cluster. "
        f"Outputs: GRAPH_RISK_SCORE (0-100), IS_FRAUD_RING_MEMBER. "
        f"Table: ATO_FRAUD_DB.FEATURES.CUSTOMER_GRAPH_FEATURES. "
        f"Customers: {graph_metrics.get('total_customers', 'N/A')}"
    )

    mv_graph = reg.log_model(
        model_name="ATO_GRAPH_RISK_SCORER",
        version_name=graph_version,
        model=graph_model,
        sample_input_data=graph_sample,
        comment=graph_comment
    )
    if graph_metrics.get("total_customers"):
        mv_graph.set_metric("total_customers", graph_metrics["total_customers"])
    if graph_metrics.get("fraud_ring_members_flagged"):
        mv_graph.set_metric("ring_members_flagged", graph_metrics["fraud_ring_members_flagged"])
    mv_graph.set_metric("n_input_features", len(GRAPH_FEATURE_COLS))
    mv_graph.set_metric("leakage_fixed", 1)

    registered.append(("ATO_GRAPH_RISK_SCORER", graph_version))
    print(f"  Registered: {mv_graph.model_name} {graph_version}\n")

    # --- 4. Ensemble Meta-Model ---
    print("=" * 55)
    print("4. Registering ATO_ENSEMBLE")
    print("=" * 55)

    ensemble_model = ATOEnsembleModel(custom_model.ModelContext())
    ensemble_sample = _build_ensemble_sample_input()

    test_output = ensemble_model.predict(ensemble_sample)
    print(f"  Ensemble test: score={test_output['ENSEMBLE_RISK_SCORE'].iloc[0]}, "
          f"decision={test_output['DECISION'].iloc[0]}")

    ens_version = _next_version(session, "ATO_ENSEMBLE")
    ensemble_comment = (
        f"Ensemble meta-model blending XGBoost (50%), Isolation Forest (30%), "
        f"Graph Risk (20%) into 0-1000 risk score. "
        f"Tiers: SAFE [0-349], STEP-UP [350-749], BLOCK [750-1000]. "
        f"Sub-model AUCs: XGB={xgb_metrics.get('roc_auc')}, IF={if_metrics.get('roc_auc')}"
    )

    mv_ens = reg.log_model(
        model_name="ATO_ENSEMBLE",
        version_name=ens_version,
        model=ensemble_model,
        sample_input_data=ensemble_sample,
        comment=ensemble_comment
    )
    mv_ens.set_metric("xgb_roc_auc", xgb_metrics.get("roc_auc", 0))
    mv_ens.set_metric("if_roc_auc", if_metrics.get("roc_auc", 0))
    mv_ens.set_metric("w_xgb", 0.50)
    mv_ens.set_metric("w_if", 0.30)
    mv_ens.set_metric("w_graph", 0.20)

    registered.append(("ATO_ENSEMBLE", ens_version))
    print(f"  Registered: {mv_ens.model_name} {ens_version}\n")

    # --- Summary ---
    print("=" * 55)
    print("REGISTRATION SUMMARY")
    print("=" * 55)
    for name, version in registered:
        print(f"  {name:<30s} {version}")

    models_df = reg.show_models()
    print(f"\nModels in {DATABASE}.{SCHEMA}:")
    print(models_df[["name", "comment"]].to_string(index=False))

    return registered


register_all_models()
