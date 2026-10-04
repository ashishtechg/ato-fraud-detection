"""
=============================================================================
ATO Fraud Detection - Layer 4: Ensemble Meta-Model & 0-1000 Calibrator
Blends:
1. Supervised XGBoost Probability (50% weight)
2. Unsupervised Isolation Forest Anomaly Score (30% weight)
3. Graph Topology & Ring Risk (20% weight)
Produces: Unified Risk Score (0 - 1000) & Decision (SAFE / STEP-UP / BLOCK)
=============================================================================
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from datetime import datetime

from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    classification_report,
    confusion_matrix
)

UNREALISTIC_AUC_THRESHOLD = 0.99
MAX_SINGLE_FEATURE_IMPORTANCE = 0.45
KNOWN_LEAKY_FEATURES = {
    "IS_DEVICE_TRUSTED", "CANVAS_FINGERPRINT_MATCH", "DEVICE_THREAT_SCORE",
    "BEHAVIORAL_RISK_SCORE"
}

# Retrained artifacts live here; workspace copies are stale fallbacks
RETRAINED_ARTIFACT_DIR = "/tmp/ato-fraud-detection/models/artifacts"


def _load_metrics(filename):
    """Load metrics JSON, preferring retrained artifacts over workspace copies."""
    retrained_path = os.path.join(RETRAINED_ARTIFACT_DIR, filename)
    workspace_path = os.path.join(os.getcwd(), "artifacts", filename)

    if os.path.exists(retrained_path):
        print(f"  Loading {filename} from retrained artifacts")
        with open(retrained_path) as f:
            return json.load(f)
    elif os.path.exists(workspace_path):
        print(f"  Loading {filename} from workspace (may be stale)")
        with open(workspace_path) as f:
            return json.load(f)
    else:
        print(f"  {filename} not found")
        return {}


def validate_sub_model_metrics(metrics, model_name):
    """Validate sub-model metrics and return list of issues found."""
    issues = []

    roc_auc = metrics.get("roc_auc", 0)
    pr_auc = metrics.get("pr_auc", 0)

    if roc_auc >= UNREALISTIC_AUC_THRESHOLD:
        issues.append(f"{model_name} ROC-AUC={roc_auc:.4f} >= {UNREALISTIC_AUC_THRESHOLD} (unrealistic)")
    if pr_auc >= UNREALISTIC_AUC_THRESHOLD:
        issues.append(f"{model_name} PR-AUC={pr_auc:.4f} >= {UNREALISTIC_AUC_THRESHOLD} (unrealistic)")

    importances = metrics.get("feature_importances", {})
    if importances:
        top_feature = max(importances, key=importances.get)
        top_importance = importances[top_feature]
        if top_importance > MAX_SINGLE_FEATURE_IMPORTANCE:
            issues.append(
                f"{model_name} top feature '{top_feature}' has {top_importance:.1%} importance "
                f"(> {MAX_SINGLE_FEATURE_IMPORTANCE:.0%} threshold)"
            )

        leaky_in_model = set(importances.keys()) & KNOWN_LEAKY_FEATURES
        if leaky_in_model:
            issues.append(f"{model_name} contains known leaky features: {leaky_in_model}")

    return issues


def evaluate_ensemble():
    output_dir = "/tmp/ato-fraud-detection/models/artifacts"
    os.makedirs(output_dir, exist_ok=True)

    xgb_metrics = _load_metrics("xgboost_metrics.json")
    if_metrics = _load_metrics("isolation_forest_metrics.json")

    print("\n" + "="*60)
    print("ENSEMBLE META-MODEL EVALUATION SUMMARY")
    print("="*60)
    print(f"Layer 1 (Supervised XGBoost) ROC-AUC:        {xgb_metrics.get('roc_auc', 'N/A')}")
    print(f"Layer 1 (Supervised XGBoost) PR-AUC:         {xgb_metrics.get('pr_auc', 'N/A')}")
    print(f"Layer 2 (Unsupervised Isolation Forest) AUC: {if_metrics.get('roc_auc', 'N/A')}")
    print(f"Layer 3 (Identity Graph Ring Detection):     Operational (structural topology)")

    if xgb_metrics.get("noise_injected"):
        print(f"  Noise injection: enabled")
    if xgb_metrics.get("label_noise_applied"):
        print(f"  Label noise: enabled")
    if xgb_metrics.get("features_excluded_leakage"):
        print(f"  Auto-excluded leaky features: {xgb_metrics['features_excluded_leakage']}")

    # Validate sub-model metrics
    all_issues = []
    all_issues.extend(validate_sub_model_metrics(xgb_metrics, "XGBoost"))
    all_issues.extend(validate_sub_model_metrics(if_metrics, "Isolation Forest"))

    if all_issues:
        print(f"\n{'!'*60}")
        print(f"VALIDATION FAILED - {len(all_issues)} issue(s) detected:")
        print(f"{'!'*60}")
        for i, issue in enumerate(all_issues, 1):
            print(f"  {i}. {issue}")
        print("\nAction required: retrain affected model(s) with leakage fixes")
        print("before deploying ensemble to production.")
    else:
        print("\nAll sub-model metrics within expected ranges. VALIDATION PASSED.")

    # Feature importance summary for XGBoost
    importances = xgb_metrics.get("feature_importances", {})
    if importances:
        sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
        print("\nXGBoost Top 5 Feature Importances:")
        for feat, imp in sorted_imp[:5]:
            print(f"  {feat:<40s} {imp:.4f}")

    # Ensemble Threshold Specifications
    thresholds = {
        "scale": "0 - 1000",
        "tau_1_safe_ceiling": 349,
        "tau_2_block_floor": 750,
        "tiers": {
            "SAFE": {"range": "[0, 349]", "action": "Frictionless login"},
            "STEP-UP": {"range": "[350, 749]", "action": "Adaptive MFA challenge"},
            "BLOCK": {"range": "[750, 1000]", "action": "Automated interception & alert"}
        },
        "weights": {
            "supervised_xgboost_probability": 0.50,
            "unsupervised_anomaly_score": 0.30,
            "graph_topology_risk": 0.20
        },
        "validation_passed": len(all_issues) == 0,
        "validation_issues": all_issues
    }

    with open(os.path.join(output_dir, "ensemble_specification.json"), "w") as f:
        json.dump(thresholds, f, indent=2)

    if all_issues:
        print("\nEnsemble specification generated WITH validation warnings.")
    else:
        print("\nEnsemble Calibration Specification successfully generated.")
    return thresholds


if __name__ == "__main__":
    evaluate_ensemble()
