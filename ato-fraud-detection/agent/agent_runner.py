"""
Unified ATO Fraud & Compliance Agent Runner
Routes user queries across:
1. Cortex Analyst (Semantic View: ATO_FRAUD_ANALYTICS_SV)
2. Cortex Search (Internal Policy Corpus: ATO_POLICY_SEARCH)
3. Federal Register FastMCP (Regulatory Compliance Lookup)
Synthesizes verified answers with complete audit trails and citations.

Data source: ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES (leakage-fixed ensemble output)
Models: ATO_XGBOOST_CLASSIFIER, ATO_ISOLATION_FOREST, ATO_GRAPH_RISK_SCORER, ATO_ENSEMBLE
"""

import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

# Resolve sibling directories relative to cwd (kernel sets cwd to file's directory)
_base_dir = os.path.abspath(os.path.join(os.getcwd(), ".."))
sys.path.insert(0, os.path.join(_base_dir, "models"))
sys.path.insert(0, os.path.join(_base_dir, "mcp"))

from snowpark_helper import get_session
from federal_register_mcp import search_regulations, get_regulation

# Ensemble scores table (leakage-fixed, 3-model blended output)
ENSEMBLE_TABLE = "ATO_FRAUD_DB.SCORING.ENSEMBLE_FRAUD_SCORES"

# Registered models to validate
REGISTERED_MODELS = {
    "ATO_XGBOOST_CLASSIFIER": "XGBOOST",
    "ATO_ISOLATION_FOREST": "IFOREST",
    "ATO_GRAPH_RISK_SCORER": "GRAPH",
    "ATO_ENSEMBLE": "ENSEMBLE",
}

STALENESS_THRESHOLD_HOURS = 24


class ATOFraudAgent:
    """Unified Multi-Channel Fraud & Compliance Intelligence Agent."""

    def __init__(self):
        self.session = get_session(database="ATO_FRAUD_DB", schema="SEMANTIC")
        self.db = "ATO_FRAUD_DB"
        self.semantic_schema = "SEMANTIC"
        self.semantic_view = "ATO_FRAUD_ANALYTICS_SV"
        self.search_service = "ATO_POLICY_SEARCH"

    def validate_freshness(self) -> Dict[str, Any]:
        """Check that ensemble scores and model registry are fresh and current."""
        issues = []
        info = {}

        # 1. Ensemble scores freshness
        try:
            row = self.session.sql(f"""
                SELECT MAX(SCORED_AT) AS LATEST, COUNT(*) AS TOTAL_ROWS
                FROM {ENSEMBLE_TABLE}
            """).collect()[0]
            latest = row["LATEST"]
            total_rows = row["TOTAL_ROWS"]
            info["ensemble_latest_score"] = str(latest)
            info["ensemble_total_rows"] = total_rows

            if latest is not None:
                age_hours = (datetime.now(timezone.utc) - latest.replace(tzinfo=timezone.utc)).total_seconds() / 3600
                info["ensemble_age_hours"] = round(age_hours, 1)
                if age_hours > STALENESS_THRESHOLD_HOURS:
                    issues.append(
                        f"ENSEMBLE_FRAUD_SCORES is {age_hours:.1f}h old "
                        f"(threshold: {STALENESS_THRESHOLD_HOURS}h). "
                        f"Re-run score_sessions_ensemble.py to refresh."
                    )
            else:
                issues.append("ENSEMBLE_FRAUD_SCORES table is empty. Run scoring pipeline first.")
        except Exception as e:
            issues.append(f"Cannot read ENSEMBLE_FRAUD_SCORES: {e}")

        # 2. Model registry versions
        model_versions = {}
        for model_name, prefix in REGISTERED_MODELS.items():
            try:
                rows = self.session.sql(
                    f"SHOW VERSIONS IN MODEL ATO_FRAUD_DB.SCORING.{model_name}"
                ).collect()
                versions = [r["name"] for r in rows]
                convention_versions = sorted(
                    [v for v in versions if v.upper().startswith(prefix + "_V")],
                    key=lambda v: int(v.split("_V")[-1]) if v.split("_V")[-1].isdigit() else 0,
                    reverse=True
                )
                latest_ver = convention_versions[0] if convention_versions else versions[-1] if versions else "NONE"

                default_row = self.session.sql(
                    f"SHOW MODELS LIKE '{model_name}' IN SCHEMA ATO_FRAUD_DB.SCORING"
                ).collect()
                default_ver = default_row[0]["default_version_name"] if default_row else "UNKNOWN"

                model_versions[model_name] = {
                    "latest": latest_ver,
                    "default": default_ver,
                    "total_versions": len(versions),
                }

                if default_ver.upper() != latest_ver.upper():
                    issues.append(
                        f"{model_name}: default='{default_ver}' but latest='{latest_ver}'. "
                        f"Run: ALTER MODEL ATO_FRAUD_DB.SCORING.{model_name} SET DEFAULT_VERSION = '{latest_ver}'"
                    )
            except Exception as e:
                issues.append(f"Cannot check {model_name}: {e}")

        info["model_versions"] = model_versions

        status = "PASSED" if not issues else "WARNINGS"
        return {
            "status": status,
            "issues": issues,
            "info": info,
        }

    def classify_intent(self, question: str) -> str:
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
            df = self.session.sql(search_sql).collect()
            raw_json = json.loads(df[0]["SEARCH_RESULTS"])
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
        res = search_regulations(query=query, agency=agency)
        res["channel"] = "FEDERAL_REGISTER_MCP (External Regulations)"
        return res

    def query_structured_analytics(self, sql_query: str) -> Dict[str, Any]:
        clean_sql = sql_query.strip().rstrip(";")
        try:
            df = self.session.sql(clean_sql).limit(100).collect()
            rows = [row.as_dict() for row in df]
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
                custom_sql = f"""
                SELECT
                    DECISION,
                    COUNT(*) AS total_sessions,
                    ROUND(AVG(ENSEMBLE_RISK_SCORE), 1) AS avg_risk_score,
                    SUM(CASE WHEN IS_FRAUD_ACTUAL THEN 1 ELSE 0 END) AS confirmed_fraud,
                    MAX(SCORED_AT) AS latest_score_ts
                FROM {ENSEMBLE_TABLE}
                GROUP BY DECISION
                ORDER BY avg_risk_score DESC
                """
            sql_result = self.query_structured_analytics(custom_sql)
            return {
                "question": user_question,
                "routing_decision": "CORTEX_ANALYST_SEMANTIC_VIEW",
                "result": sql_result
            }


if __name__ == "__main__":
    agent = ATOFraudAgent()

    # Freshness validation
    print("=================================================================")
    print("MODEL & DATA FRESHNESS VALIDATION")
    print("=================================================================")
    freshness = agent.validate_freshness()
    print(f"Status: {freshness['status']}")
    if freshness["issues"]:
        for i, issue in enumerate(freshness["issues"], 1):
            print(f"  [{i}] {issue}")
    info = freshness.get("info", {})
    print(f"  Ensemble rows: {info.get('ensemble_total_rows', 'N/A')}")
    print(f"  Ensemble age: {info.get('ensemble_age_hours', 'N/A')}h")
    for model, ver_info in info.get("model_versions", {}).items():
        print(f"  {model}: default={ver_info['default']}, latest={ver_info['latest']}, versions={ver_info['total_versions']}")
    print("-" * 65)

    print("\n=================================================================")
    print("ATO Fraud & Compliance Agent Multi-Channel Verification Test")
    print("=================================================================\n")

    # Test Channel 1: Ensemble Fraud Scores (leakage-fixed)
    q1 = "How many confirmed fraud events are in each decision tier?"
    res1 = agent.answer(q1)
    print(f"[Query 1]: {q1}")
    print(f"Routing Decision: {res1['routing_decision']}")
    print(f"Channel: {res1['result']['channel']}")
    if res1["result"].get("row_count"):
        print(f"Row count: {res1['result']['row_count']}")
        print("Data Preview:", json.dumps(res1['result']['data'], indent=2, default=str))
    else:
        print(f"Error: {res1['result'].get('error')}")
    print("-" * 65)

    # Test Channel 2: Internal Policy Cortex Search
    q2 = "What are the account lockout rules and velocity thresholds for failed attempts?"
    res2 = agent.answer(q2)
    print(f"\n[Query 2]: {q2}")
    print(f"Routing Decision: {res2['routing_decision']}")
    print(f"Channel: {res2['result']['channel']}")
    for match in res2['result'].get('matches', []):
        print(f"  - Policy: {match.get('document_title')} | Section: {match.get('section')}")
        print(f"    Owner: {match.get('owner_role')} | Regulatory Ref: {match.get('regulatory_references')}")
    print("-" * 65)

    # Test Channel 3: External Regulatory FastMCP
    q3 = "What are the FTC Safeguards Rule and CFPB requirements for multi-factor authentication?"
    res3 = agent.answer(q3)
    print(f"\n[Query 3]: {q3}")
    print(f"Routing Decision: {res3['routing_decision']}")
    print(f"Channel: {res3['result']['channel']}")
    for doc in res3['result'].get('documents', [])[:2]:
        print(f"  - [{doc['document_number']}] {doc['title']}")
        print(f"    Action: {doc['action']} | Citation: {doc.get('citation')} | URL: {doc.get('official_url')}")
    print("=================================================================")
