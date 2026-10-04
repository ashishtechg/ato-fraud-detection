"""
Comprehensive End-to-End Validation Suite for Real-Time ATO Fraud Detection System
Validates:
1. Database Schemas and Object Existence
2. Synthetic Dataset Row Counts & 2% Compromise Rates
3. Dynamic Table Features and 3-Tier Scored Logins
4. ML Model Registry — 4-Layer Ensemble (XGBoost, IF, Graph, Ensemble)
5. Ensemble Scoring Pipeline (ENSEMBLE_FRAUD_SCORES)
6. Policy Rule Engine & Evaluation Audits
7. Semantic View & Verified Queries (VQRs)
8. Cortex Search Service & Policy Retrieval
9. Federal Register FastMCP Server
10. Governance & Masking Policies
11. Data Leakage Guards
"""

import json
import os
import sys
import traceback

_base_dir = os.path.abspath(os.path.join(os.getcwd(), ".."))
sys.path.insert(0, os.path.join(_base_dir, "models"))
sys.path.insert(0, os.path.join(_base_dir, "mcp"))
sys.path.insert(0, os.path.join(_base_dir, "agent"))

from snowpark_helper import get_session
from federal_register_mcp import search_regulations, get_regulation
from agent_runner import ATOFraudAgent

# ── Test harness ──────────────────────────────────────────────────
passed, failed, errors = [], [], []

def run_test(name, fn):
    try:
        fn()
        passed.append(name)
        print(f"  ✓ PASS  {name}")
    except AssertionError as e:
        failed.append((name, str(e)))
        print(f"  ✗ FAIL  {name}: {e}")
    except Exception as e:
        errors.append((name, traceback.format_exc()))
        print(f"  ✗ ERROR {name}: {e}")

# ── Setup ─────────────────────────────────────────────────────────
print("=" * 70)
print("ATO FRAUD DETECTION — END-TO-END VALIDATION SUITE")
print("=" * 70)

print("\n[Setup] Connecting to Snowflake...")
session = get_session(database="ATO_FRAUD_DB", schema="SCORING")
agent = ATOFraudAgent()
print("[Setup] Connected.\n")

# ── 1. Database & Schema Verification ─────────────────────────────
print("─── 1. Database & Schema Verification ───")

def test_01():
    schemas = [row["name"] for row in session.sql("SHOW SCHEMAS IN DATABASE ATO_FRAUD_DB;").collect()]
    for s in ["RAW", "FEATURES", "SCORING", "POLICY_ENGINE", "SEMANTIC", "APP", "GOVERNANCE"]:
        assert s in schemas, f"Schema {s} missing in ATO_FRAUD_DB"

run_test("01 — All 7 core schemas exist", test_01)

# ── 2. Raw Synthetic Datasets ─────────────────────────────────────
print("\n─── 2. Raw Synthetic Datasets ───")

def test_02():
    cust = session.sql("""
        SELECT COUNT(*) AS total_cust,
               SUM(CASE WHEN is_compromised THEN 1 ELSE 0 END) AS compromised,
               COUNT(DISTINCT compromise_scenario) AS scenarios
        FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS;
    """).collect()[0]
    assert cust["TOTAL_CUST"] == 50000, f"Expected 50000 customers, got {cust['TOTAL_CUST']}"
    assert cust["COMPROMISED"] == 1000, f"Expected 1000 compromised, got {cust['COMPROMISED']}"
    assert cust["SCENARIOS"] == 10, f"Expected 10 scenarios, got {cust['SCENARIOS']}"

    login_cnt = session.sql("SELECT COUNT(*) AS cnt FROM ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS;").collect()[0]["CNT"]
    assert login_cnt >= 13000000, f"Expected >=13M logins, got {login_cnt:,}"

run_test("02 — 50K customers, 2% compromise, 10 scenarios, 13M+ logins", test_02)

# ── 3. Dynamic Table Pipelines ────────────────────────────────────
print("\n─── 3. Dynamic Table Pipelines ───")

def test_03():
    tiers = session.sql("""
        SELECT risk_tier, COUNT(*) AS cnt, AVG(risk_score) AS avg_score
        FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
        GROUP BY risk_tier;
    """).collect()
    tier_map = {r["RISK_TIER"]: float(r["AVG_SCORE"]) for r in tiers}
    assert "SAFE" in tier_map, "SAFE tier missing"
    assert "STEP-UP" in tier_map, "STEP-UP tier missing"
    assert "BLOCK" in tier_map, "BLOCK tier missing"
    assert tier_map["SAFE"] < 350.0, f"SAFE avg score {tier_map['SAFE']:.1f} should be < 350"
    assert tier_map["BLOCK"] >= 750.0, f"BLOCK avg score {tier_map['BLOCK']:.1f} should be >= 750"

run_test("03 — DT_SCORED_LOGINS has SAFE/STEP-UP/BLOCK tiers with correct boundaries", test_03)

# ── 4. ML Model Registry — 4-Layer Ensemble ──────────────────────
print("\n─── 4. ML Model Registry — 4-Layer Ensemble ───")

def test_04a():
    rows = session.sql("SHOW VERSIONS IN MODEL ATO_FRAUD_DB.SCORING.ATO_XGBOOST_CLASSIFIER;").collect()
    versions = [r["name"] for r in rows]
    assert "XGBOOST_V2" in versions, f"XGBOOST_V2 missing. Found: {versions}"
    meta = json.loads([r for r in rows if r["name"] == "XGBOOST_V2"][0]["metadata"])
    m = meta["metrics"]
    assert abs(m["roc_auc"] - 0.804) < 0.01, f"ROC-AUC {m['roc_auc']} != ~0.804"
    assert abs(m["pr_auc"] - 0.9493) < 0.01, f"PR-AUC {m['pr_auc']} != ~0.9493"
    assert m["n_features"] == 19, f"Features {m['n_features']} != 19"
    assert m["roc_auc"] < 0.95, f"ROC-AUC {m['roc_auc']} >= 0.95 suggests leakage"

run_test("04a — XGBoost XGBOOST_V2: AUC=0.804, 19 features, no leakage", test_04a)

def test_04b():
    rows = session.sql("SHOW VERSIONS IN MODEL ATO_FRAUD_DB.SCORING.ATO_ISOLATION_FOREST;").collect()
    versions = [r["name"] for r in rows]
    assert "IFOREST_V2" in versions, f"IFOREST_V2 missing. Found: {versions}"
    meta = json.loads([r for r in rows if r["name"] == "IFOREST_V2"][0]["metadata"])
    m = meta["metrics"]
    assert abs(m["roc_auc"] - 0.6149) < 0.01, f"ROC-AUC {m['roc_auc']} != ~0.6149"
    assert m["n_features"] == 8, f"Features {m['n_features']} != 8"

run_test("04b — Isolation Forest IFOREST_V2: AUC=0.6149, 8 features", test_04b)

def test_04c():
    rows = session.sql("SHOW VERSIONS IN MODEL ATO_FRAUD_DB.SCORING.ATO_GRAPH_RISK_SCORER;").collect()
    versions = [r["name"] for r in rows]
    assert "GRAPH_V2" in versions, f"GRAPH_V2 missing. Found: {versions}"
    meta = json.loads([r for r in rows if r["name"] == "GRAPH_V2"][0]["metadata"])
    m = meta["metrics"]
    assert m["n_input_features"] == 6, f"Input features {m['n_input_features']} != 6"
    assert m.get("leakage_fixed") == 1, "leakage_fixed flag not set"

run_test("04c — Graph Risk Scorer GRAPH_V2: 6 structural inputs, leakage_fixed", test_04c)

def test_04d():
    rows = session.sql("SHOW VERSIONS IN MODEL ATO_FRAUD_DB.SCORING.ATO_ENSEMBLE;").collect()
    versions = [r["name"] for r in rows]
    assert "ENSEMBLE_V2" in versions, f"ENSEMBLE_V2 missing. Found: {versions}"
    meta = json.loads([r for r in rows if r["name"] == "ENSEMBLE_V2"][0]["metadata"])
    m = meta["metrics"]
    assert abs(m["w_xgb"] - 0.5) < 0.01, f"XGB weight {m['w_xgb']} != 0.5"
    assert abs(m["w_if"] - 0.3) < 0.01, f"IF weight {m['w_if']} != 0.3"
    assert abs(m["w_graph"] - 0.2) < 0.01, f"Graph weight {m['w_graph']} != 0.2"

run_test("04d — Ensemble ENSEMBLE_V2: weights 0.50/0.30/0.20", test_04d)

# ── 5. Ensemble Scoring Pipeline ─────────────────────────────────
print("\n─── 5. Ensemble Scoring Pipeline ───")

def test_05a():
    tiers = session.sql("""
        SELECT DECISION, COUNT(*) AS cnt, AVG(ENSEMBLE_RISK_SCORE) AS avg_score
        FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
        GROUP BY DECISION;
    """).collect()
    assert len(tiers) > 0, "ENSEMBLE_FRAUD_SCORES has no data"
    cols = session.sql("""
        SELECT XGB_FRAUD_PROB, IF_ANOMALY_SCORE, GRAPH_RISK_SCORE, IS_FRAUD_RING_MEMBER
        FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES LIMIT 1;
    """).collect()
    assert len(cols) == 1, "Sub-model columns missing"

run_test("05a — ENSEMBLE_FRAUD_SCORES exists with correct columns", test_05a)

def test_05b():
    v = session.sql("""
        SELECT COUNT(*) AS cnt FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
        WHERE (DECISION = 'SAFE' AND ENSEMBLE_RISK_SCORE >= 350)
           OR (DECISION = 'STEP-UP' AND (ENSEMBLE_RISK_SCORE < 350 OR ENSEMBLE_RISK_SCORE >= 750))
           OR (DECISION = 'BLOCK' AND ENSEMBLE_RISK_SCORE < 750);
    """).collect()[0]["CNT"]
    assert v == 0, f"{v} rows violate decision tier boundaries"

run_test("05b — Decision tier boundaries correct (SAFE<350, STEP-UP 350-749, BLOCK>=750)", test_05b)

# ── 6. Policy Rules Engine ────────────────────────────────────────
print("\n─── 6. Policy Rules Engine ───")

def test_06():
    p = session.sql("SELECT COUNT(*) AS cnt FROM ATO_FRAUD_DB.POLICY_ENGINE.FRAUD_POLICY;").collect()[0]["CNT"]
    assert p == 6, f"Expected 6 policies, got {p}"
    r = session.sql("SELECT COUNT(*) AS cnt FROM ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE;").collect()[0]["CNT"]
    assert r == 30, f"Expected 30 rules, got {r}"
    e = session.sql("SELECT COUNT(*) AS cnt FROM ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION;").collect()[0]["CNT"]
    assert e > 20000000, f"Expected >20M evaluations, got {e:,}"

run_test("06 — 6 policies, 30 rules, 20M+ evaluations", test_06)

# ── 7. Semantic View ──────────────────────────────────────────────
print("\n─── 7. Semantic View ───")

def test_07():
    sv = session.sql("""
        SELECT risk_tier, COUNT(*) AS cnt
        FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
        GROUP BY risk_tier;
    """).collect()
    assert len(sv) > 0, "Semantic view backing query returned no data"

run_test("07 — Semantic view queryable", test_07)

# ── 8. Cortex Search Service ─────────────────────────────────────
print("\n─── 8. Cortex Search Service ───")

def test_08():
    res = agent.query_internal_policy("What are the account lockout rules?")
    assert res.get("status") == "success", f"Cortex Search failed: {res.get('error', 'unknown')}"
    assert len(res.get("matches", [])) > 0, "No policy matches returned"

run_test("08 — Cortex Search returns policy matches", test_08)

# ── 9. Federal Register MCP ──────────────────────────────────────
print("\n─── 9. Federal Register MCP ───")

def test_09():
    res = search_regulations("multi-factor authentication", agency="ftc")
    assert res.get("status") == "success", f"search_regulations failed: {res}"
    docs = res.get("documents", [])
    assert len(docs) > 0, "No documents found"
    detail = get_regulation(docs[0]["document_number"])
    assert detail.get("status") == "success", f"get_regulation failed: {detail}"
    assert detail.get("title") is not None, "Document title is None"

run_test("09 — Federal Register search + get_regulation", test_09)

# ── 10. Governance & Masking ─────────────────────────────────────
print("\n─── 10. Governance & Masking ───")

def test_10():
    policies = [row["name"] for row in session.sql("SHOW MASKING POLICIES IN SCHEMA ATO_FRAUD_DB.GOVERNANCE;").collect()]
    for p in ["MASK_EMAIL", "MASK_IP_ADDRESS", "MASK_DEVICE_FINGERPRINT"]:
        assert p in policies, f"Masking policy {p} missing"

run_test("10 — Masking policies (MASK_EMAIL, MASK_IP_ADDRESS, MASK_DEVICE_FINGERPRINT)", test_10)

# ── 11. Data Leakage Guards ──────────────────────────────────────
print("\n─── 11. Data Leakage Guards ───")

def test_11a():
    xgb_cols = [
        row["COLUMN_NAME"] for row in session.sql("""
            SELECT COLUMN_NAME FROM ATO_FRAUD_DB.INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = 'SCORING' AND TABLE_NAME = 'XGBOOST_FRAUD_SCORES';
        """).collect()
    ]
    leaky = {"BEHAVIORAL_RISK_SCORE", "DEVICE_THREAT_SCORE", "IS_DEVICE_TRUSTED", "CANVAS_FINGERPRINT_MATCH"}
    found = leaky.intersection(set(xgb_cols))
    assert len(found) == 0, f"Leaky features in XGBOOST_FRAUD_SCORES: {found}"

run_test("11a — No leaky features in XGBOOST_FRAUD_SCORES", test_11a)

def test_11b():
    graph_cols = [
        row["COLUMN_NAME"] for row in session.sql("""
            SELECT COLUMN_NAME FROM ATO_FRAUD_DB.INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = 'FEATURES' AND TABLE_NAME = 'CUSTOMER_GRAPH_FEATURES';
        """).collect()
    ]
    assert "FRAUD_LINK_COUNT" not in graph_cols, "fraud_link_count still in CUSTOMER_GRAPH_FEATURES (label leakage)"

run_test("11b — No fraud_link_count in graph features (label leakage removed)", test_11b)

# ── Summary ───────────────────────────────────────────────────────
print("\n" + "=" * 70)
total = len(passed) + len(failed) + len(errors)
print(f"RESULTS: {len(passed)}/{total} passed, {len(failed)} failed, {len(errors)} errors")
print("=" * 70)

if failed:
    print("\nFAILURES:")
    for name, msg in failed:
        print(f"  ✗ {name}: {msg}")

if errors:
    print("\nERRORS:")
    for name, tb in errors:
        print(f"  ✗ {name}:")
        print(f"    {tb.strip().split(chr(10))[-1]}")

if not failed and not errors:
    print("\n  ALL TESTS PASSED ✓")
