-- ============================================================================
-- Real-Time ATO Fraud Detection & Regulatory Compliance
-- Script: agent/create_agent.sql
-- Description: Registers the Unified Cortex Agent configuration and creates
--              Snowflake Stored Procedures for multi-channel querying.
--              Data source: ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
-- ============================================================================

USE DATABASE ATO_FRAUD_DB;
USE SCHEMA APP;
USE WAREHOUSE COMPUTE_WH;

-- 1. Create Agent Metadata & Audit Table
CREATE TABLE IF NOT EXISTS ATO_FRAUD_DB.APP.AGENT_CONVERSATION_AUDIT (
    interaction_id VARCHAR(64) DEFAULT UUID_STRING(),
    interaction_timestamp TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    user_name VARCHAR(128) DEFAULT CURRENT_USER(),
    user_role VARCHAR(128) DEFAULT CURRENT_ROLE(),
    user_question VARCHAR(2000),
    classified_intent VARCHAR(64),
    routed_channel VARCHAR(64),
    response_summary VARCHAR(16777216),
    execution_time_ms NUMBER(10, 2),
    sql_executed VARCHAR(16777216)
);

-- 2. Stored Procedure: Execute Multi-Channel Agent Routing
CREATE OR REPLACE PROCEDURE ATO_FRAUD_DB.APP.ASK_ATO_AGENT(user_question VARCHAR)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'ask_agent_handler'
AS
$$
import json
import re
from decimal import Decimal
from datetime import datetime, date

class SafeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)

def ask_agent_handler(session, user_question):
    q_lower = user_question.lower()

    # Channel 3: External Regulatory
    regulatory_keywords = [
        "federal register", "cfr", "ftc safeguards", "cfpb", "fincen",
        "ffiec", "regulation e", "circia", "cisa", "proposed rule",
        "final rule", "statutory", "legal requirement", "federal law",
        "federal regulation", "regulatory guidance", "glba"
    ]
    if any(kw in q_lower for kw in regulatory_keywords):
        return json.dumps({
            "channel": "FEDERAL_REGISTER_MCP",
            "intent": "EXTERNAL_REGULATION",
            "message": "Query routed to Federal Register Regulatory Lookup MCP.",
            "guidance": "Consult FederalRegister.gov citations (e.g., 16 CFR Part 314 GLBA Safeguards, CFPB Circular 2022-04)."
        })

    # Channel 2: Internal Policy (word-boundary metric exclusion)
    is_metric_query = bool(re.search(r'\b(how many|count|average|total|rate|sum|percentage|metric)\b', q_lower))
    internal_policy_keywords = [
        "policy", "sop", "procedure", "lockout rule", "lockout",
        "mfa threshold", "investigation checklist", "standard operating procedure",
        "customer notification policy", "escalation", "retention policy",
        "evidence guide", "what is our policy", "company policy",
        "internal rule", "internal requirement"
    ]
    if any(kw in q_lower for kw in internal_policy_keywords) and not is_metric_query:
        safe_q = user_question.replace("'", "''")
        search_sql = f"""
        SELECT SNOWFLAKE.CORTEX.SEARCH_PREVIEW(
            'ATO_FRAUD_DB.SEMANTIC.ATO_POLICY_SEARCH',
            '{{"query": "{safe_q}", "columns": ["DOCUMENT_TITLE", "SECTION_NUMBER", "SECTION_TITLE", "OWNER_ROLE", "REGULATORY_REFERENCES"], "limit": 3}}'
        ) AS RES;
        """
        try:
            df = session.sql(search_sql).collect()
            return json.dumps({
                "channel": "CORTEX_SEARCH",
                "intent": "INTERNAL_POLICY",
                "search_results": json.loads(df[0]["RES"])
            })
        except Exception as e:
            return json.dumps({"channel": "CORTEX_SEARCH", "error": str(e)})

    # Channel 1: Ensemble Fraud Scores (leakage-fixed, 3-model blended output)
    sample_sql = """
    SELECT
        DECISION,
        COUNT(*) AS total_sessions,
        ROUND(AVG(ENSEMBLE_RISK_SCORE), 1) AS avg_risk_score,
        SUM(CASE WHEN IS_FRAUD_ACTUAL THEN 1 ELSE 0 END) AS confirmed_fraud,
        MAX(SCORED_AT) AS latest_score_ts
    FROM ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES
    GROUP BY DECISION
    ORDER BY avg_risk_score DESC;
    """
    df = session.sql(sample_sql).collect()
    return json.dumps({
        "channel": "SEMANTIC_VIEW_SQL",
        "intent": "STRUCTURED_ANALYTICS",
        "sql": sample_sql,
        "results": [row.as_dict() for row in df]
    }, cls=SafeEncoder)
$$;

-- Test all 3 channels
CALL ATO_FRAUD_DB.APP.ASK_ATO_AGENT('What are our internal account lockout rules?');
CALL ATO_FRAUD_DB.APP.ASK_ATO_AGENT('How many fraud events in each deci