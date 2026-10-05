# ATO Fraud Detection System

Real-time Account Takeover (ATO) fraud detection system built entirely on Snowflake, featuring a **4-layer ensemble ML pipeline**, policy-aware semantic layer, a **deployed Cortex Agent** with 5 tools, a **Snowflake-managed MCP server**, and a Streamlit command center.

## Architecture

```
                        STREAMLIT APP (Command Center)
                                  │
                     DATA_AGENT_RUN (SQL function)
                                  │
                    ┌─────────────┴──────────────┐
                    │   CORTEX AGENT (5 tools)    │
                    │   ATO_FRAUD_DB.APP          │
                    │   .ATO_FRAUD_AGENT          │
                    ├─────────────────────────────┤
                    │  Tool 1: Cortex Analyst     │──→ ATO_FRAUD_ANALYTICS_SV (Semantic View)
                    │  Tool 2: Cortex Search      │──→ ATO_POLICY_SEARCH (22 policy chunks)
                    │  Tool 3: Data to Chart      │──→ Vega-Lite visualizations
                    │  Tool 4: search_federal_    │──→ SEARCH_FEDERAL_REGULATIONS (procedure)
                    │           regulations       │       └→ FederalRegister.gov API (via EAI)
                    │  Tool 5: get_federal_       │──→ GET_FEDERAL_REGULATION (procedure)
                    │           regulation        │       └→ FederalRegister.gov API (via EAI)
                    └─────────────────────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
      Ensemble Scores      Policy Documents    Federal Regulations
    (SAFE/STEP-UP/BLOCK)   (6 policy SOPs)    (FTC, CFPB, FinCEN...)
```

**External access:** The MCP server (`ATO_FRAUD_MCP_SERVER`) exposes the agent and regulatory tools to external MCP clients (Claude Desktop, LangGraph, etc.) via a standard endpoint.

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

| Channel | Technology | Agent Tool | Covers |
|---------|-----------|------------|--------|
| Structured fraud data | Semantic View + Cortex Analyst | `ato_fraud_analyst` | Ensemble scores, sub-model breakdowns, risk tiers, policy rule triggers |
| Internal policy text | Cortex Search | `internal_policy_search` | 6 fraud/risk policy documents (ATO, MFA, Lockout, Txn Monitoring, Notification, Investigation) |
| External regulations | Stored Procedures (via EAI) | `search_federal_regulations`, `get_federal_regulation` | Federal Register lookup — FTC Safeguards, CFPB circulars, FinCEN CDD, FFIEC guidance, CISA CIRCIA |

## Cortex Agent

The agent (`ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT`) is a Snowflake Cortex Agent object deployed with `CREATE AGENT` DDL. It uses LLM-driven orchestration (model: `auto`) to route questions across all three channels without any custom keyword-matching logic.

**Key features:**
- Automatic tool selection based on question intent
- Multi-turn conversation support via threads
- Chart generation with `data_to_chart` tool
- Budget limits: 60 seconds, 32K tokens per request
- Callable via `DATA_AGENT_RUN()` SQL function or Cortex Agents REST API

## MCP Server

The Snowflake-managed MCP server (`ATO_FRAUD_DB.APP.ATO_FRAUD_MCP_SERVER`) exposes the agent and regulatory procedures as tools for external MCP clients.

| MCP Tool | Type | Description |
|----------|------|-------------|
| `ato_fraud_agent` | `CORTEX_AGENT_RUN` | Routes to the full Cortex Agent |
| `search_federal_regulations` | `GENERIC` (procedure) | Searches Federal Register documents |
| `get_federal_regulation` | `GENERIC` (procedure) | Retrieves detail for a specific document |

**Endpoint:** `https://<account_url>/api/v2/databases/ATO_FRAUD_DB/schemas/APP/mcp-servers/ATO_FRAUD_MCP_SERVER`

## External Access Integration

The Federal Register procedures make outbound HTTP calls to `federalregister.gov`. This requires:
- **Network Rule:** `ATO_FRAUD_DB.APP.FEDERAL_REGISTER_NETWORK_RULE` (EGRESS to `www.federalregister.gov`, `www.govinfo.gov`)
- **EAI:** `FEDERAL_REGISTER_EAI` (no secrets — public API)

On trial accounts (EAI not supported), the procedures fall back to an embedded corpus of 6 key regulatory documents covering FTC Safeguards, CFPB Circular 2022-04, FinCEN CDD, FFIEC Auth Guidance, CIRCIA, and Regulation E amendments.

## Project Structure

```
ato-fraud-detection/
  config/
    environment.sql         - Database, schemas, warehouses, network rule, EAI
    grants.sql              - RBAC setup
  data/                     - Synthetic data generation (10 scripts, numbered)
  pipelines/                - Dynamic Table feature engineering (5 DTs)
  models/
    train_xgboost.py        - XGBoost training (noise injection + leakage guard)
    train_isolation_forest.py - Isolation Forest training
    graph_features.py       - Identity graph analytics (structural only)
    ensemble_meta_model.py  - Ensemble evaluation & validation
    score_sessions_*.py     - Inference pipelines (XGBoost, IF, Ensemble)
    register_model.py       - Registers all 4 models to Snowflake Model Registry
  semantic/                 - Semantic view YAML + deployment
  policies/                 - 6 policy documents + Cortex Search service
  mcp/
    federal_register_mcp.py     - Federal Register MCP server (stdio, standalone)
    deploy_mcp_server.sql       - Stored procedures (with EAI) + MCP server DDL
  agent/
    create_agent.sql            - Legacy stored procedure (custom routing)
    deploy_cortex_agent.sql     - Cortex Agent DDL (CREATE AGENT, 5 tools)
    agent_spec.yaml             - Agent configuration reference
    agent_system_prompt.md      - System prompt with ensemble model docs
    agent_runner.py             - Agent runner (legacy)
  app/
    streamlit_app.py            - Streamlit entry point (multi-page)
    snowflake.yml               - Snowflake app config (SPCS, Container Runtime)
    agent_runner.py             - DATA_AGENT_RUN integration for Streamlit
    federal_register_mcp.py     - Federal Register client (used by Tab 3)
    app_pages/
      01_fraud_analytics.py     - Executive dashboard + ML model metrics
      02_policy_rules.py        - Policy governance page
      03_regulatory_lookup.py   - Agent chat + policy search + regulatory lookup
      04_investigation_queue.py - Live analyst case queue
  governance/                - Masking, row access, access modifiers
  tests/                     - Validation scripts
```

## Key Tables

| Table | Schema | Purpose |
|-------|--------|---------|
| `ENSEMBLE_FRAUD_SCORES` | SCORING | Primary ensemble output (scores, decisions, sub-model breakdown) |
| `XGBOOST_FRAUD_SCORES` | SCORING | Layer 1 XGBoost fraud probabilities |
| `IF_ANOMALY_SCORES` | SCORING | Layer 2 Isolation Forest anomaly scores |
| `CUSTOMER_GRAPH_FEATURES` | FEATURES | Layer 3 graph topology features |
| `DT_SCORED_LOGINS` | SCORING | Raw scored login events (Dynamic Table) |
| `ATO_POLICY_DOCUMENTS` | POLICY_ENGINE | Policy document corpus (22 sections) |
| `POLICY_RULE_EVALUATION` | POLICY_ENGINE | Audit trail of rule evaluations |

## Key Snowflake Objects

| Object | Type | Schema |
|--------|------|--------|
| `ATO_FRAUD_AGENT` | Cortex Agent | APP |
| `ATO_FRAUD_MCP_SERVER` | MCP Server | APP |
| `ATO_FRAUD_ANALYTICS_SV` | Semantic View | SEMANTIC |
| `ATO_POLICY_SEARCH` | Cortex Search Service | SEMANTIC |
| `SEARCH_FEDERAL_REGULATIONS` | Stored Procedure | APP |
| `GET_FEDERAL_REGULATION` | Stored Procedure | APP |

## Key Numbers

- **50,000** customer accounts, **2%** compromised (~1,000)
- **10** ATO fraud scenarios (credential stuffing, impossible travel, device spoofing, brute force, session replay, new device + recovery abuse, SIM-swap, RAT-assisted, dormant reactivation, bot/automation)
- **~5M** login events over 90 days
- **4** registered ML models in Snowflake Model Registry
- **30** policy rules across 6 policies
- **9** logical tables in the semantic view
- **14+** verified queries (VQRs)
- Risk score: **0-1000**, three-tier outcome: **SAFE / STEP-UP / BLOCK**

## Deployment Order

```sql
-- 1. Environment setup (database, schemas, warehouses, EAI)
-- Run: config/environment.sql
-- Run: config/grants.sql

-- 2. Synthetic data (run in order: data/01 through data/10)

-- 3. Feature pipelines (all DTs in pipelines/)

-- 4. ML models (Python scripts in models/)
--    Train → Score → Register → Validate

-- 5. Semantic view (semantic/deploy_semantic_view.py)

-- 6. Policy documents + Cortex Search (policies/)

-- 7. Federal Register stored procedures + MCP server
-- Run: mcp/deploy_mcp_server.sql

-- 8. Cortex Agent (5 tools)
-- Run: agent/deploy_cortex_agent.sql

-- 9. Streamlit app (deploy via Snowsight Workspaces)
```

## Cost Estimate

### One-Time Build Costs

| Component | Warehouse | Size | Est. Runtime | Credits | Est. Cost |
|-----------|-----------|------|-------------|---------|-----------|
| Data generation (10 scripts) | ATO_FRAUD_WH | MEDIUM | ~15 min | ~2 | $6 |
| Dynamic Tables (5 DTs, initial) | ATO_FRAUD_WH | MEDIUM | ~10 min | ~1.3 | $4 |
| XGBoost training | ATO_ML_WH | LARGE | ~8 min | ~2.1 | $6 |
| Isolation Forest training | ATO_ML_WH | LARGE | ~5 min | ~1.3 | $4 |
| Graph feature computation | ATO_FRAUD_WH | MEDIUM | ~5 min | ~0.7 | $2 |
| Ensemble scoring (all layers) | ATO_FRAUD_WH | MEDIUM | ~10 min | ~1.3 | $4 |
| Cortex Search indexing (22 chunks) | ATO_SEARCH_WH | SMALL | ~2 min | ~0.1 | $0.30 |
| Semantic view deployment | — | — | Serverless | ~0.1 | $0.30 |
| **Subtotal: One-Time Build** | | | | **~9** | **~$27** |

### Ongoing Runtime Costs (Monthly, Prototype Usage)

| Component | Billing Model | Est. Monthly Usage | Credits/Mo | Est. Cost/Mo |
|-----------|--------------|-------------------|------------|-------------|
| **Cortex Agent** (orchestration) | Per-token (LLM inference) | ~200 queries/mo (~200K tokens) | ~2-4 | $6-12 |
| **Cortex Analyst** (text-to-SQL) | Per-token | ~150 SQL generations/mo | ~1-2 | $3-6 |
| **Cortex Search** | Per-token + indexing | ~100 searches/mo, daily refresh | ~0.5-1 | $1.50-3 |
| **Warehouse compute** (query execution) | Per-second, per-warehouse | COMPUTE_WH (XS-S), ~30 min/mo | ~0.5-1 | $1.50-3 |
| **Dynamic Tables** (incremental refresh) | Per-refresh compute | 5 DTs, 1-min lag | ~1-3 | $3-9 |
| **Streamlit app** (SPCS Container Runtime) | Per-node-hour | 1 CPU node, ~50 hrs/mo | ~3-5 | $9-15 |
| **MCP Server** | No idle cost | Per-request only | ~0.1 | $0.30 |
| **Stored procedures** (Fed Register) | Warehouse compute | ~50 calls/mo, <1s each | ~0.05 | $0.15 |
| **Storage** (all tables + stages) | Per-TB/month | ~2-5 GB | ~0.1 | $0.30 |
| **Subtotal: Monthly Ongoing** | | | **~8-17** | **$25-50** |

### Cost Notes

- **Token-based costs** (Agent, Analyst, Search) depend on query complexity and the orchestration model selected (auto-selects highest-quality available model, currently claude-opus-4-8).
- **Warehouse costs** assume auto-suspend at 120s. Actual cost scales linearly with query volume.
- **Trial accounts** have limited credits and don't support External Access Integrations (Federal Register procedures use embedded corpus fallback at zero additional cost).
- **Production scaling**: for 10x query volume (~2,000 queries/mo), expect ~$150-300/mo. The main cost driver is LLM token consumption by the Cortex Agent orchestrator.
- Monitor costs via `SNOWFLAKE.ACCOUNT_USAGE.CORTEX_AGENT_USAGE_HISTORY` and warehouse metering views.
- Set per-user budgets with `ALTER AGENT ... SET BUDGET` or account-level resource monitors.

## Prerequisites

- Snowflake account (Enterprise Edition recommended; trial works with limitations)
- ACCOUNTADMIN role for initial setup
- Cortex AI enabled (CORTEX_USER database role)
- For live Federal Register API: non-trial account (External Access Integration required)

## License

MIT
