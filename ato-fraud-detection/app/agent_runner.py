"""
Unified ATO Fraud & Compliance Agent Runner (Streamlit Workspace edition)
Routes user queries across:
1. Cortex Analyst (Semantic View: ATO_FRAUD_ANALYTICS_SV)
2. Cortex Search (Internal Policy Corpus: ATO_POLICY_SEARCH)
3. Federal Register FastMCP (Regulatory Compliance Lookup)
"""

import json
import re
import os
import sys
import importlib.util
import streamlit as st
from typing import Any, Dict, Optional


def _import_from_app_root(module_name):
    for base in [
        os.path.dirname(os.path.abspath(__file__)),
        os.getcwd(),
        "/opt/streamlit-runtime",
    ]:
        path = os.path.join(base, f"{module_name}.py")
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location(module_name, path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)
            return mod
    raise ImportError(f"Cannot find {module_name}.py in any known app directory")


_fed_mod = _import_from_app_root("federal_register_mcp")
search_regulations = _fed_mod.search_regulations


class ATOFraudAgent:
    """Unified Multi-Channel Fraud & Compliance Intelligence Agent."""

    def __init__(self):
        self.conn = st.connection("snowflake", ttl=os.getenv("SNOWFLAKE_CONNECTION_TTL"))
        self.db = "ATO_FRAUD_DB"
        self.semantic_schema = "SEMANTIC"
        self.semantic_view = "ATO_FRAUD_ANALYTICS_SV"
        self.search_service = "ATO_POLICY_SEARCH"

    def classify_intent(self, question: str) -> str:
        """Classify question into SEMANTIC_SQL, INTERNAL_POLICY, or EXTERNAL_REGULATION."""
        q_lower = question.lower()

        regulatory_keywords = [
            "federal register", "cfr", "ftc safeguards", "cfpb", "fincen",
            "ffiec", "regulation e", "circia", "cisa", "proposed rule",
            "final rule", "statutory", "legal requirement", "federal law",
            "federal regulation", "regulatory guidance", "glba"
        ]
        if any(kw in q_lower for kw in regulatory_keywords):
            return "EXTERNAL_REGULATION"

        is_metric_query = bool(re.search(r'\b(how many|count|average|total|rate|sum|percentage|metric)\b', q_lower))
        internal_policy_keywords = [
            "policy", "sop", "procedure", "lockout rule", "mfa threshold",
            "investigation checklist", "standard operating procedure",
            "customer notification policy", "escalation", "retention policy",
            "evidence guide", "what is our policy", "company policy",
            "internal rule", "internal requirement", "lockout"
        ]
        if any(kw in q_lower for kw in internal_policy_keywords) and not is_metric_query:
            return "INTERNAL_POLICY"

        return "SEMANTIC_SQL"

    def query_internal_policy(self, query: str, limit: int = 3) -> Dict[str, Any]:
        """Query internal policies via Cortex Search."""
        safe_query = query.replace("'", "''")
        search_sql = f"""
        SELECT SNOWFLAKE.CORTEX.SEARCH_PREVIEW(
            '{self.db}.{self.semantic_schema}.{self.search_service}',
            '{{
                "query": "{safe_query}",
                "columns": ["DOCUMENT_TITLE", "SECTION_NUMBER", "SECTION_TITLE", "OWNER_ROLE", "REGULATORY_REFERENCES"],
                "limit": {limit}
            }}'
        ) AS SEARCH_RESULTS;
        """
        try:
            df = self.conn.query(search_sql)
            raw_json = json.loads(df["SEARCH_RESULTS"].iloc[0])
            results = raw_json.get("results", [])
            return {
                "status": "success",
                "channel": "CORTEX_SEARCH (Internal Policies)",
                "query": query,
                "matches": [
                    {
                        "document_title": r.get("DOCUMENT_TITLE"),
                        "section": f"{r.get('SECTION_NUMBER')} - {r.get('SECTION_TITLE')}",
                        "owner_role": r.get("OWNER_ROLE"),
                        "regulatory_references": r.get("REGULATORY_REFERENCES"),
                        "similarity_score": round(r.get("@scores", {}).get("cosine_similarity", 0.0), 3)
                    }
                    for r in results
                ]
            }
        except Exception as e:
            return {"status": "error", "channel": "CORTEX_SEARCH", "error": str(e)}

    def query_external_regulations(self, query: str, agency: Optional[str] = None) -> Dict[str, Any]:
        """Query external federal regulations via Federal Register MCP."""
        res = search_regulations(query=query, agency=agency)
        res["channel"] = "FEDERAL_REGISTER_MCP (External Regulations)"
        return res

    def query_structured_analytics(self, sql_query: str) -> Dict[str, Any]:
        """Execute governed SQL query against Snowflake Semantic tables."""
        clean_sql = sql_query.strip().rstrip(";")
        try:
            df = self.conn.query(clean_sql)
            rows = df.head(100).to_dict(orient="records")
            return {
                "status": "success",
                "channel": "SEMANTIC_VIEW_SQL (Cortex Analyst)",
                "sql": clean_sql,
                "row_count": len(rows),
                "data": rows
            }
        except Exception as e:
            return {"status": "error", "channel": "SEMANTIC_VIEW_SQL", "error": str(e), "sql": clean_sql}

    def answer(self, user_question: str, custom_sql: Optional[str] = None) -> Dict[str, Any]:
        """Process user question through the appropriate channel."""
        intent = self.classify_intent(user_question)

        if intent == "EXTERNAL_REGULATION":
            reg_result = self.query_external_regulations(user_question)
            return {
                "question": user_question,
                "routing_decision": "FEDERAL_REGISTER_MCP",
                "result": reg_result
            }

        elif intent == "INTERNAL_POLICY":
            policy_result = self.query_internal_policy(user_question)
            return {
                "question": user_question,
                "routing_decision": "CORTEX_SEARCH_INTERNAL_POLICY",
                "result": policy_result
            }

        else:
            if not custom_sql:
                custom_sql = """
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
            sql_result = self.query_structured_analytics(custom_sql)
            return {
                "question": user_question,
                "routing_decision": "CORTEX_ANALYST_SEMANTIC_VIEW",
                "result": sql_result
            }
