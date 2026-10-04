# ATO Fraud Detection System

Real-time Account Takeover (ATO) fraud detection system built entirely on Snowflake, featuring a **4-layer ensemble ML pipeline**, policy-aware semantic layer, governed natural-language queries, and live regulatory lookup.

## Architecture

```
BUSINESS USER (Fraud Analyst / Risk Manager / Compliance)
        |
        v
  Natural Language Question
        |
        v
  SNOWFLAKE CORTEX AGENT (3-Channel Routing)
        |
  +-----+----------+
  |     |          |
  v     v          v
SEMANTIC  POLICY    FEDERAL REGISTER
VIEWS     SEARCH    MCP CONNECTOR
  |       |          |
  v       v          v
Ensemble  Policy    Live Regulatory
Scores    Text      Lookup (API)
  |       |          |
  +-------+----------+
        |
        v
  Governed Answer
  (SQL + policy citations + regulatory sources + reasoning)
```

## 4-Layer Ensemble Model

| Layer | Model | Registry Version | Metrics | Weight |
|-------|-------|-----------------|---------|--------|
| 1 - Supervised | XGBoost Classifier | `XGBOOST_V2` | ROC-AUC: 0.804, PR-AUC: 0.9493 (19 features) | 50% |
| 2 - Unsupervised | Isolation Forest | `IFOREST_V2` | ROC-AUC: 0.6149, PR-AUC: 0.5944 (8 features) | 30% |
| 3 - Graph Analytics | Identity Graph Risk Scorer | `GRAPH_V2` | 6 structural inputs, 494 ring members flagged | 20% |
| 4 - Ensemble | Meta-Model Blender | `ENSEMBLE_V2` | Weighted blend → 0-1000 score → SAFE / STEP-UP / BLOCK | — |

**Decision Tiers:** SAFE [0-349] | STEP-UP [350-749] | BLOCK [750-1000]

All models registered in the Snowflake Model Registry (`ATO_FRAUD_DB.SCORING`) with automated `{PREFIX}_V{N}` versioning.

### Data Leakage Remediation

The original XGBoost model exhibited a perfect ROC-AUC of 1.0 due to two sources of data leakage:

1. **Feature leakage** — `BEHAVIORAL_RISK_SCORE`, `DEVICE_THREAT_SCORE`, `IS_DEVICE_TRUSTED`, and `CANVAS_FINGERPRINT_MATCH` were perfectly correlated with the target
2. **Graph label leakage** — `fraud_link_count` was derived from `is_fraud_edge`, which encodes the target label

**Fixes applied:**
- Removed all leaky features from training and inference
- Added per-feature AUC guard (threshold: 0.95) to abort training if any single feature is too predictive
- Applied 5-strategy noise injection to synthetic data (boolean flips, Gaussian noise, bidirectional cross-class blending, label noise)
- Rebuilt graph features using only structural topology signals (ring size, device count, IP cluster, IP diversity)

## Three Query Channels

| Channel | Technology | Covers |
|---------|-----------|--------|
| Structured fraud data | Semantic View + Cortex Analyst | Ensemble scores, sub-model breakdowns, risk tiers, policy rule triggers |
| Internal policy text | Cortex Search | 6 fraud/risk policy documents (ATO, MFA, Lockout, Txn Monitoring, Notification, Investigation) |
| External regulations | Federal Register MCP | Live lookup of federal regulations on auth, cybersecurity, fraud |

## Project Structure

```
ato-fraud-detection/
  config/       - Database, schema, warehouse, RBAC setup
  data/         - Synthetic data generation (10 scripts, numbered)
  pipelines/    - Dynamic Table feature engineering (5 DTs)
  models/
    train_xgboost.py            - XGBoost training (noise injection + leakage guard)
    train_isolation_forest.py   - Isolation Forest training
    graph_features.py           - Identity graph analytics (structural only)
    ensemble_meta_model.py      - Ensemble evaluation & validation
    score_sessions_xgboost.py   - XGBoost inference pipeline
    score_sessions_isolation.py - Isolation Forest inference pipeline
    score_sessions_ensemble.py  - Ensemble scoring (joins all 3 layers → ENSEMBLE_FRAUD_SCORES)
    register_model.py           - Registers all 4 models to Snowflake Model Registry
  semantic/     - Semantic view YAML + deployment
  policies/     - 6 policy documents + Cortex Search service
  mcp/          - Federal Register MCP server (2 tools)
  agent/
    create_agent.sql      - Cortex Agent stored procedure (3-channel routing)
    agent_spec.yaml       - Agent configuration
    agent_system_prompt.md - System prompt with ensemble model documentation
    agent_runner.py       - Agent runner with freshness validation
  app/
    streamlit_app.py             - Streamlit entry point
    app_pages/01_fraud_analytics.py    - Ensemble analytics dashboard
    app_pages/04_investigation_queue.py - Case queue with sub-model breakdowns
    agent_runner.py              - Streamlit agent integration
  governance/   - Masking, row access, access modifiers
  tests/        - Validation scripts
```

## Key Tables

| Table | Schema | Purpose |
|-------|--------|---------|
| `ENSEMBLE_FRAUD_SCORES` | SCORING | Primary ensemble output (scores, decisions, sub-model breakdown) |
| `XGBOOST_FRAUD_SCORES` | SCORING | Layer 1 XGBoost fraud probabilities |
| `IF_ANOMALY_SCORES` | SCORING | Layer 2 Isolation Forest anomaly scores |
| `CUSTOMER_GRAPH_FEATURES` | FEATURES | Layer 3 graph topology features |
| `DT_SCORED_LOGINS` | SCORING | Raw scored login events (Dynamic Table) |

## Key Numbers

- **50,000** customer accounts, **2%** compromised (~1,000)
- **10** ATO fraud scenarios (credential stuffing, impossible travel, device spoofing, brute force, session replay, new device + recovery abuse, SIM-swap, RAT-assisted, dormant reactivation, bot/automation)
- **~5M** login events over 90 days
- **4** registered ML models in Snowflake Model Registry
- **30** policy rules across 6 policies
- **9** logical tables in the semantic view (including ENSEMBLE_SCORES)
- **14+** verified queries (VQRs)
- Risk score: **0-1000**, three-tier outcome: **SAFE / STEP-UP / BLOCK**

## Quick Start

```sql
-- Run from Snowflake worksheet or CoCo
-- 1. Environment setup
!source config/environment.sql
!source config/grants.sql

-- 2. Generate synthetic data (run in order)
!source data/01_customers.sql
!source data/02_devices.sql
-- ... through data/10_policy_rule_evaluations.sql

-- 3. Feature pipeline
!source pipelines/dt_auth_features.sql
-- ... all DTs

-- 4. ML models (run Python scripts in Snowflake workspace)
-- a) Train:    train_xgboost.py → train_isolation_forest.py → graph_features.py
-- b) Score:    score_sessions_xgboost.py → score_sessions_isolation.py → score_sessions_ensemble.py
-- c) Register: register_model.py (all 4 models to registry)
-- d) Validate: ensemble_meta_model.py (leakage checks + metric validation)

-- 5. Semantic view
!source semantic/deploy_semantic_view.sql

-- 6. Policy documents + Cortex Search
!source policies/create_policy_table.sql
-- ... all 6 policies
!source policies/create_cortex_search.sql

-- 7. Agent
!source agent/create_agent.sql
```

## Prerequisites

- Snowflake account (Enterprise Edition recommended)
- ACCOUNTADMIN role for initial setup
- Cortex AI enabled (CORTEX_USER database role)
- Python 3.9+ (for MCP server)

## Cost Estimate

One-time build: ~$107-194 in credits. Ongoing runtime: ~$1-5/month for prototype usage.
See the cost breakdown in the planning documentation.

## License

MIT
