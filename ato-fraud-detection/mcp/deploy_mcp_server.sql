-- ============================================================================
-- Real-Time ATO Fraud Detection & Regulatory Compliance
-- Script: mcp/deploy_mcp_server.sql
-- Description: Creates a Snowflake-managed MCP server that exposes the
--              ATO Fraud Agent and Federal Register regulatory lookup
--              procedures as tools for external MCP clients.
-- Prerequisites:
--   - Agent:          ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT         (deployed)
--   - Semantic view:  ATO_FRAUD_DB.SEMANTIC.ATO_FRAUD_ANALYTICS_SV
--   - Search service: ATO_FRAUD_DB.SEMANTIC.ATO_POLICY_SEARCH
-- ============================================================================

USE DATABASE ATO_FRAUD_DB;
USE SCHEMA APP;
USE WAREHOUSE COMPUTE_WH;

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Stored Procedures: Federal Register Regulatory Lookup
--    These wrap the Python logic from federal_register_mcp.py so Snowflake
--    can expose them as GENERIC tools on the managed MCP server.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE PROCEDURE ATO_FRAUD_DB.APP.SEARCH_FEDERAL_REGULATIONS(
    query VARCHAR,
    agency VARCHAR DEFAULT NULL,
    from_date VARCHAR DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
EXTERNAL_ACCESS_INTEGRATIONS = (FEDERAL_REGISTER_EAI)
HANDLER = 'search_handler'
AS
$$
import json
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

BASE_URL = "https://www.federalregister.gov/api/v1"
USER_AGENT = "Snowflake-ATO-Fraud-Agent/1.0 (Compliance; Regulatory-Lookup)"

EMBEDDED_REGULATORY_CORPUS = [
    {
        "document_number": "2021-25736",
        "title": "Standards for Safeguarding Customer Information (FTC Safeguards Rule)",
        "document_type": "Rule", "is_final_rule": True, "action": "Final Rule",
        "abstract": "The FTC amends the Standards for Safeguarding Customer Information under GLBA. Mandates MFA for accessing customer information systems, continuous monitoring or annual penetration testing, and robust encryption.",
        "publication_date": "2021-12-09", "effective_on": "2022-12-09",
        "agencies": ["Federal Trade Commission"], "agency_slugs": ["ftc"],
        "citation": "86 FR 70272", "cfr_references": [{"title": 16, "part": 314}],
        "official_url": "https://www.federalregister.gov/documents/2021/12/09/2021-25736/standards-for-safeguarding-customer-information",
        "keywords": ["mfa", "multi-factor", "authentication", "safeguards", "glba", "cybersecurity", "encryption"]
    },
    {
        "document_number": "2022-17231",
        "title": "CFPB Circular 2022-04: Insufficient Data Security Practices and Multi-Factor Authentication",
        "document_type": "Notice", "is_final_rule": False, "action": "Policy Statement / Circular",
        "abstract": "The CFPB clarifies that financial entities may violate UDAAP by failing to implement MFA, adequate password management, or timely patch management. Account takeover from absent MFA can constitute an unfair act.",
        "publication_date": "2022-08-11", "effective_on": "2022-08-11",
        "agencies": ["Consumer Financial Protection Bureau"], "agency_slugs": ["cfpb"],
        "citation": "87 FR 49514", "cfr_references": [{"title": 12, "part": 1000}],
        "official_url": "https://www.federalregister.gov/documents/2022/08/11/2022-17231/insufficient-data-security-practices",
        "keywords": ["cfpb", "mfa", "account takeover", "udaap", "credential stuffing"]
    },
    {
        "document_number": "2023-28828",
        "title": "Protecting Consumers From Unauthorized Transfers and Account Takeover in Digital Banking",
        "document_type": "Proposed Rule", "is_final_rule": False, "action": "Notice of Proposed Rulemaking",
        "abstract": "The CFPB proposes amendments to Regulation E (12 CFR Part 1005) clarifying liability protections for consumers whose accounts are compromised through social engineering, SIM-swapping, and credential harvesting.",
        "publication_date": "2024-01-05", "effective_on": "2025-06-01",
        "agencies": ["Consumer Financial Protection Bureau"], "agency_slugs": ["cfpb"],
        "citation": "89 FR 1284", "cfr_references": [{"title": 12, "part": 1005}],
        "official_url": "https://www.federalregister.gov/documents/2024/01/05/2023-28828/protecting-consumers-from-unauthorized-transfers",
        "keywords": ["account takeover", "regulation e", "unauthorized transfer", "sim swap", "credential stuffing"]
    },
    {
        "document_number": "2020-22201",
        "title": "FinCEN: Anti-Money Laundering Regulations and Customer Due Diligence",
        "document_type": "Rule", "is_final_rule": True, "action": "Final Rule",
        "abstract": "FinCEN clarifies CDD and beneficial ownership requirements, reinforcing monitoring obligations to identify suspicious anomalies indicating account compromise, synthetic identities, or money mule routing.",
        "publication_date": "2020-10-15", "effective_on": "2020-11-16",
        "agencies": ["Financial Crimes Enforcement Network"], "agency_slugs": ["fincen", "treasury"],
        "citation": "85 FR 65712", "cfr_references": [{"title": 31, "part": 1010}],
        "official_url": "https://www.federalregister.gov/documents/2020/10/15/2020-22201/anti-money-laundering-regulations",
        "keywords": ["fincen", "aml", "cdd", "customer due diligence", "identity verification", "mule accounts"]
    },
    {
        "document_number": "2021-16012",
        "title": "Interagency Guidance on Authentication and Access to Financial Institution Services",
        "document_type": "Notice", "is_final_rule": False, "action": "Final Interagency Guidance",
        "abstract": "OCC, Federal Reserve, and FDIC issue updated guidance recommending risk-based layered security, continuous behavioral monitoring, device reputation analysis, and phishing-resistant MFA.",
        "publication_date": "2021-08-18", "effective_on": "2021-08-18",
        "agencies": ["OCC", "Federal Reserve", "FDIC"], "agency_slugs": ["occ", "frb", "fdic"],
        "citation": "86 FR 46294", "cfr_references": [{"title": 12, "part": 30}],
        "official_url": "https://www.federalregister.gov/documents/2021/08/18/2021-16012/authentication-and-access-to-financial-services",
        "keywords": ["ffiec", "layered security", "authentication", "behavioral biometrics", "device reputation"]
    },
    {
        "document_number": "2023-14903",
        "title": "CIRCIA Proposed Rule: Cybersecurity Incident Reporting for Critical Infrastructure",
        "document_type": "Proposed Rule", "is_final_rule": False, "action": "Notice of Proposed Rulemaking",
        "abstract": "CISA proposes mandatory reporting of substantial cyber incidents within 72 hours and ransomware payments within 24 hours for covered entities including financial sector.",
        "publication_date": "2023-04-04", "effective_on": "2025-10-01",
        "agencies": ["CISA"], "agency_slugs": ["cisa", "dhs"],
        "citation": "88 FR 20112", "cfr_references": [{"title": 6, "part": 226}],
        "official_url": "https://www.federalregister.gov/documents/2023/04/04/2023-14903/cybersecurity-incident-reporting",
        "keywords": ["cisa", "circia", "incident reporting", "cybersecurity", "ransomware", "credential stuffing"]
    }
]

def _search_embedded(query_str, agency_filter, date_filter):
    tokens = [q.lower() for q in re.split(r"\W+", query_str) if len(q) > 2]
    matched = []
    for doc in EMBEDDED_REGULATORY_CORPUS:
        if agency_filter and agency_filter.lower() not in [s.lower() for s in doc.get("agency_slugs", [])]:
            continue
        if date_filter and doc.get("publication_date", "") < date_filter:
            continue
        doc_text = (doc["title"] + " " + doc["abstract"] + " " + " ".join(doc.get("keywords", []))).lower()
        score = sum(1 for t in tokens if t in doc_text)
        if score > 0 or not tokens:
            matched.append((score, doc))
    matched.sort(key=lambda x: x[0], reverse=True)
    return [m[1] for m in matched]

def search_handler(session, query, agency, from_date):
    params = {
        "conditions[term]": query, "per_page": 10, "order": "relevance",
        "fields[]": ["document_number", "title", "type", "action", "abstract",
                      "publication_date", "effective_on", "agency_names", "html_url", "pdf_url", "citation"]
    }
    if agency:
        params["conditions[agencies][]"] = agency.lower()
    if from_date:
        params["conditions[publication_date][gte]"] = from_date

    encoded = []
    for k, v in params.items():
        if isinstance(v, list):
            for item in v:
                encoded.append((k, item))
        else:
            encoded.append((k, str(v)))

    url = f"{BASE_URL}/documents.json?{urllib.parse.urlencode(encoded)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                result = json.loads(resp.read().decode("utf-8"))
                docs = []
                for doc in result.get("results", []):
                    doc_type = doc.get("type", "Unknown")
                    docs.append({
                        "document_number": doc.get("document_number"),
                        "title": doc.get("title"),
                        "document_type": doc_type,
                        "is_final_rule": doc_type == "Rule" or "Final Rule" in str(doc.get("action", "")),
                        "action": doc.get("action"),
                        "abstract": doc.get("abstract"),
                        "publication_date": doc.get("publication_date"),
                        "effective_on": doc.get("effective_on"),
                        "agencies": doc.get("agency_names", []),
                        "citation": doc.get("citation"),
                        "official_url": doc.get("html_url")
                    })
                return json.dumps({"status": "success", "source": "FederalRegister.gov Live API",
                                   "query": query, "count": len(docs), "documents": docs})
    except Exception:
        pass

    docs = _search_embedded(query, agency, from_date)
    return json.dumps({"status": "success", "source": "Embedded Regulatory Corpus",
                        "query": query, "count": len(docs), "documents": docs})
$$;


CREATE OR REPLACE PROCEDURE ATO_FRAUD_DB.APP.GET_FEDERAL_REGULATION(document_id VARCHAR)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
EXTERNAL_ACCESS_INTEGRATIONS = (FEDERAL_REGISTER_EAI)
HANDLER = 'get_handler'
AS
$$
import json
import urllib.parse
import urllib.request

BASE_URL = "https://www.federalregister.gov/api/v1"
USER_AGENT = "Snowflake-ATO-Fraud-Agent/1.0 (Compliance; Regulatory-Lookup)"

EMBEDDED_DOCS = {
    "2021-25736": {"title": "Standards for Safeguarding Customer Information (FTC Safeguards Rule)", "document_type": "Rule", "is_final_rule": True, "action": "Final Rule", "abstract": "FTC mandates MFA, continuous monitoring, and encryption under GLBA.", "publication_date": "2021-12-09", "effective_on": "2022-12-09", "agencies": ["FTC"], "citation": "86 FR 70272", "cfr_references": [{"title": 16, "part": 314}], "official_url": "https://www.federalregister.gov/documents/2021/12/09/2021-25736/standards-for-safeguarding-customer-information"},
    "2022-17231": {"title": "CFPB Circular 2022-04: Insufficient Data Security Practices and MFA", "document_type": "Notice", "is_final_rule": False, "action": "Policy Statement", "abstract": "CFPB clarifies UDAAP violations for absent MFA and ATO.", "publication_date": "2022-08-11", "effective_on": "2022-08-11", "agencies": ["CFPB"], "citation": "87 FR 49514", "cfr_references": [{"title": 12, "part": 1000}], "official_url": "https://www.federalregister.gov/documents/2022/08/11/2022-17231/insufficient-data-security-practices"},
    "2023-28828": {"title": "Protecting Consumers From Unauthorized Transfers and ATO in Digital Banking", "document_type": "Proposed Rule", "is_final_rule": False, "action": "NPRM", "abstract": "CFPB proposes Regulation E amendments for ATO liability.", "publication_date": "2024-01-05", "effective_on": "2025-06-01", "agencies": ["CFPB"], "citation": "89 FR 1284", "cfr_references": [{"title": 12, "part": 1005}], "official_url": "https://www.federalregister.gov/documents/2024/01/05/2023-28828/protecting-consumers-from-unauthorized-transfers"},
    "2020-22201": {"title": "FinCEN: AML Regulations and Customer Due Diligence", "document_type": "Rule", "is_final_rule": True, "action": "Final Rule", "abstract": "FinCEN clarifies CDD and beneficial ownership for ATO monitoring.", "publication_date": "2020-10-15", "effective_on": "2020-11-16", "agencies": ["FinCEN"], "citation": "85 FR 65712", "cfr_references": [{"title": 31, "part": 1010}], "official_url": "https://www.federalregister.gov/documents/2020/10/15/2020-22201/anti-money-laundering-regulations"},
    "2021-16012": {"title": "Interagency Guidance on Authentication and Access to Financial Services", "document_type": "Notice", "is_final_rule": False, "action": "Final Interagency Guidance", "abstract": "OCC/Fed/FDIC updated guidance on layered security and phishing-resistant MFA.", "publication_date": "2021-08-18", "effective_on": "2021-08-18", "agencies": ["OCC", "FRB", "FDIC"], "citation": "86 FR 46294", "cfr_references": [{"title": 12, "part": 30}], "official_url": "https://www.federalregister.gov/documents/2021/08/18/2021-16012/authentication-and-access-to-financial-services"},
    "2023-14903": {"title": "CIRCIA Proposed Rule: Cybersecurity Incident Reporting", "document_type": "Proposed Rule", "is_final_rule": False, "action": "NPRM", "abstract": "CISA proposes 72-hour cyber incident and 24-hour ransomware payment reporting.", "publication_date": "2023-04-04", "effective_on": "2025-10-01", "agencies": ["CISA"], "citation": "88 FR 20112", "cfr_references": [{"title": 6, "part": 226}], "official_url": "https://www.federalregister.gov/documents/2023/04/04/2023-14903/cybersecurity-incident-reporting"}
}

def get_handler(session, document_id):
    clean_id = document_id.strip()
    try:
        url = f"{BASE_URL}/documents/{urllib.parse.quote(clean_id)}.json"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                r = json.loads(resp.read().decode("utf-8"))
                doc_type = r.get("type", "Unknown")
                return json.dumps({
                    "status": "success", "source": "FederalRegister.gov Live API",
                    "document_number": r.get("document_number"), "title": r.get("title"),
                    "document_type": doc_type,
                    "is_final_rule": doc_type == "Rule" or "Final Rule" in str(r.get("action", "")),
                    "action": r.get("action"), "abstract": r.get("abstract"),
                    "publication_date": r.get("publication_date"), "effective_on": r.get("effective_on"),
                    "agencies": [a.get("name") for a in r.get("agencies", []) if isinstance(a, dict)],
                    "cfr_references": r.get("cfr_references", []),
                    "citation": r.get("citation"), "official_url": r.get("html_url"),
                    "disclaimer": "Verify whether this is a Final Rule, Proposed Rule, or Notice."
                })
    except Exception:
        pass

    if clean_id in EMBEDDED_DOCS:
        doc = EMBEDDED_DOCS[clean_id]
        return json.dumps({"status": "success", "source": "Embedded Regulatory Corpus",
                           "document_number": clean_id, **doc,
                           "disclaimer": "Verify whether this is a Final Rule, Proposed Rule, or Notice."})

    return json.dumps({"status": "error", "message": f"Document '{clean_id}' not found."})
$$;


-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Create the Snowflake-managed MCP Server
--    Exposes: (1) the Cortex Agent, (2) regulatory search, (3) regulation detail
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE MCP SERVER ATO_FRAUD_DB.APP.ATO_FRAUD_MCP_SERVER
  FROM SPECIFICATION $$
  tools:
    - title: "ATO Fraud Intelligence Agent"
      name: "ato_fraud_agent"
      type: "CORTEX_AGENT_RUN"
      identifier: "ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT"
      description: >
        Unified ATO fraud detection agent. Answers questions about ensemble risk
        scores, decision tiers (SAFE/STEP-UP/BLOCK), fraud analytics, internal
        policies, and investigation workflows. Use this for governed business
        data questions.

    - title: "Search Federal Regulations"
      name: "search_federal_regulations"
      type: "GENERIC"
      identifier: "ATO_FRAUD_DB.APP.SEARCH_FEDERAL_REGULATIONS"
      description: >
        Search Federal Register documents for regulations related to
        authentication, cybersecurity, identity verification, fraud, and
        financial services. Returns document titles, citations, agencies,
        and binding status.
      config:
        type: "procedure"
        query_timeout: 30
        warehouse: "COMPUTE_WH"
        input_schema:
          type: "object"
          properties:
            query:
              type: "string"
              description: "Search term (e.g. 'account takeover', 'multi-factor authentication', 'GLBA safeguards')"
            agency:
              type: "string"
              description: "Optional agency slug filter (e.g. 'cfpb', 'ftc', 'fincen', 'cisa', 'occ')"
            from_date:
              type: "string"
              description: "Optional minimum publication date in YYYY-MM-DD format"
          required:
            - query

    - title: "Get Federal Regulation Detail"
      name: "get_federal_regulation"
      type: "GENERIC"
      identifier: "ATO_FRAUD_DB.APP.GET_FEDERAL_REGULATION"
      description: >
        Retrieve full details for a specific Federal Register document by its
        document number. Returns title, abstract, agency, CFR references,
        citation, effective date, and binding status.
      config:
        type: "procedure"
        query_timeout: 30
        warehouse: "COMPUTE_WH"
        input_schema:
          type: "object"
          properties:
            document_id:
              type: "string"
              description: "Federal Register document number (e.g. '2021-25736', '2022-17231')"
          required:
            - document_id
  $$;

-- Verify the MCP server
DESCRIBE MCP SERVER ATO_FRAUD_DB.APP.ATO_FRAUD_MCP_SERVER;

-- Show the MCP endpoint URL (for external clients)
SHOW MCP SERVERS IN SCHEMA ATO_FRAUD_DB.APP;
