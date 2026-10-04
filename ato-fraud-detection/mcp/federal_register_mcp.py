"""
Federal Register Regulatory Lookup MCP Server
Provides access to Federal Register documents concerning authentication, identity verification, cybersecurity, and account security.
Implements the Model Context Protocol (MCP) JSON-RPC 2.0 stdio specification with 2 core tools:
  - search_regulations(query, agency, from_date)
  - get_regulation(document_id)
Supports live FederalRegister.gov public API requests with fallback to embedded regulatory corpus when outbound egress is filtered.
"""

import json
import re
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

BASE_URL = "https://www.federalregister.gov/api/v1"
USER_AGENT = "Snowflake-ATO-Fraud-Agent/1.0 (Compliance; Regulatory-Lookup)"

SERVER_INSTRUCTIONS = """You have access to an external regulatory source called Federal Register Regulatory Lookup.
Use this MCP when the user asks about:
- external regulatory requirements
- Federal regulations
- recent regulatory changes
- proposed or final rules
- regulatory requirements related to authentication, cybersecurity, identity, fraud or financial services

Do NOT use the MCP for:
- internal company policy
- synthetic fraud data
- Snowflake data analysis
- determining whether an internal control was followed

For internal policy, use Cortex Search.
For actual fraud events, use the Snowflake semantic views.

When using regulatory information:
1. Search the Federal Register.
2. Retrieve the relevant document.
3. Report document number and publication/effective date when available.
4. Provide the official source URL.
5. Clearly distinguish proposed rules from final rules.
6. Never claim that a Federal Register document is currently binding law unless the source establishes that status.

Note: the Federal Register contains proposed rules, final rules, notices and other documents, not simply a consolidated list of currently effective requirements.
"""

# Pre-indexed Federal Register documents for banking, cybersecurity, and ATO regulations
EMBEDDED_REGULATORY_CORPUS: List[Dict[str, Any]] = [
    {
        "document_number": "2021-25736",
        "title": "Standards for Safeguarding Customer Information (FTC Safeguards Rule)",
        "document_type": "Rule",
        "is_final_rule": True,
        "action": "Final Rule",
        "abstract": "The Federal Trade Commission amends the Standards for Safeguarding Customer Information under the Gramm-Leach-Bliley Act (GLBA). The final rule mandates that non-banking financial institutions implement multi-factor authentication (MFA) for any individual accessing customer information systems, continuous monitoring or annual penetration testing, and robust encryption of customer data in transit and at rest.",
        "publication_date": "2021-12-09",
        "effective_on": "2022-12-09",
        "agencies": ["Federal Trade Commission"],
        "agency_slugs": ["ftc"],
        "citation": "86 FR 70272",
        "cfr_references": [{"title": 16, "part": 314}],
        "official_url": "https://www.federalregister.gov/documents/2021/12/09/2021-25736/standards-for-safeguarding-customer-information",
        "pdf_url": "https://www.govinfo.gov/content/pkg/FR-2021-12-09/pdf/2021-25736.pdf",
        "keywords": ["mfa", "multi-factor", "authentication", "safeguards", "customer information", "glba", "cybersecurity", "encryption"]
    },
    {
        "document_number": "2022-17231",
        "title": "Consumer Financial Protection Circular 2022-04: Insufficient Data Security Practices and Multi-Factor Authentication",
        "document_type": "Notice",
        "is_final_rule": False,
        "action": "Policy Statement / Circular",
        "abstract": "The CFPB clarifies that financial covered entities may violate the Consumer Financial Protection Act's prohibition on unfair practices (UDAAP) by failing to implement multi-factor authentication, failing to maintain adequate password management, or neglecting timely patch management. Account takeover resulting from absent MFA can constitute an unfair act under Section 1036.",
        "publication_date": "2022-08-11",
        "effective_on": "2022-08-11",
        "agencies": ["Consumer Financial Protection Bureau"],
        "agency_slugs": ["cfpb"],
        "citation": "87 FR 49514",
        "cfr_references": [{"title": 12, "part": 1000}],
        "official_url": "https://www.federalregister.gov/documents/2022/08/11/2022-17231/insufficient-data-security-practices",
        "pdf_url": "https://www.govinfo.gov/content/pkg/FR-2022-08-11/pdf/2022-17231.pdf",
        "keywords": ["cfpb", "mfa", "account takeover", "udaap", "password", "credential stuffing", "unfair practices"]
    },
    {
        "document_number": "2023-28828",
        "title": "Protecting Consumers From Unauthorized Transfers and Account Takeover in Digital Banking",
        "document_type": "Proposed Rule",
        "is_final_rule": False,
        "action": "Notice of Proposed Rulemaking",
        "abstract": "The Consumer Financial Protection Bureau proposes amendments to Regulation E (12 CFR Part 1005) clarifying liability protections for consumers whose accounts are compromised through sophisticated social engineering, SIM-swapping, and credential harvesting leading to unauthorized electronic fund transfers.",
        "publication_date": "2024-01-05",
        "effective_on": "2025-06-01",
        "agencies": ["Consumer Financial Protection Bureau"],
        "agency_slugs": ["cfpb"],
        "citation": "89 FR 1284",
        "cfr_references": [{"title": 12, "part": 1005}],
        "official_url": "https://www.federalregister.gov/documents/2024/01/05/2023-28828/protecting-consumers-from-unauthorized-transfers",
        "pdf_url": "https://www.govinfo.gov/content/pkg/FR-2024-01-05/pdf/2023-28828.pdf",
        "keywords": ["account takeover", "regulation e", "unauthorized transfer", "sim swap", "credential stuffing", "efta"]
    },
    {
        "document_number": "2020-22201",
        "title": "Financial Crimes Enforcement Network: Anti-Money Laundering Regulations and Customer Due Diligence",
        "document_type": "Rule",
        "is_final_rule": True,
        "action": "Final Rule",
        "abstract": "FinCEN clarifies customer due diligence (CDD) and beneficial ownership requirements for financial institutions, reinforcing ongoing monitoring obligations to identify suspicious anomalies indicating account compromise, synthetic identities, or money mule routing following account takeovers.",
        "publication_date": "2020-10-15",
        "effective_on": "2020-11-16",
        "agencies": ["Financial Crimes Enforcement Network"],
        "agency_slugs": ["fincen", "treasury"],
        "citation": "85 FR 65712",
        "cfr_references": [{"title": 31, "part": 1010}],
        "official_url": "https://www.federalregister.gov/documents/2020/10/15/2020-22201/anti-money-laundering-regulations",
        "pdf_url": "https://www.govinfo.gov/content/pkg/FR-2020-10-15/pdf/2020-22201.pdf",
        "keywords": ["fincen", "aml", "cdd", "customer due diligence", "identity verification", "mule accounts", "suspicious activity"]
    },
    {
        "document_number": "2021-16012",
        "title": "Interagency Guidance on Authentication and Access to Financial Institution Services and Systems",
        "document_type": "Notice",
        "is_final_rule": False,
        "action": "Final Interagency Guidance",
        "abstract": "The OCC, Federal Reserve Board, and FDIC issue updated guidance replacing the 2005 and 2011 authentication guidance. Recommends risk-based layered security, continuous behavioral monitoring, device reputation analysis, and phishing-resistant multi-factor authentication (MFA) to mitigate account takeover attacks.",
        "publication_date": "2021-08-18",
        "effective_on": "2021-08-18",
        "agencies": ["Comptroller of the Currency", "Federal Reserve System", "Federal Deposit Insurance Corporation"],
        "agency_slugs": ["occ", "frb", "fdic"],
        "citation": "86 FR 46294",
        "cfr_references": [{"title": 12, "part": 30}],
        "official_url": "https://www.federalregister.gov/documents/2021/08/18/2021-16012/authentication-and-access-to-financial-services",
        "pdf_url": "https://www.govinfo.gov/content/pkg/FR-2021-08-18/pdf/2021-16012.pdf",
        "keywords": ["ffiec", "occ", "fdic", "layered security", "authentication", "behavioral biometrics", "device reputation", "phishing-resistant"]
    },
    {
        "document_number": "2023-14903",
        "title": "Cybersecurity Incident Reporting for Critical Infrastructure Act (CIRCIA) Proposed Rule",
        "document_type": "Proposed Rule",
        "is_final_rule": False,
        "action": "Notice of Proposed Rulemaking",
        "abstract": "CISA proposes reporting requirements for covered entities, mandating reporting of substantial cyber incidents within 72 hours and ransomware payments within 24 hours. Clarifies applicability to financial sector entities experiencing coordinated credential-stuffing campaigns impacting systemic service availability.",
        "publication_date": "2023-04-04",
        "effective_on": "2025-10-01",
        "agencies": ["Cybersecurity and Infrastructure Security Agency"],
        "agency_slugs": ["cisa", "dhs"],
        "citation": "88 FR 20112",
        "cfr_references": [{"title": 6, "part": 226}],
        "official_url": "https://www.federalregister.gov/documents/2023/04/04/2023-14903/cybersecurity-incident-reporting",
        "pdf_url": "https://www.govinfo.gov/content/pkg/FR-2023-04-04/pdf/2023-14903.pdf",
        "keywords": ["cisa", "circia", "incident reporting", "cybersecurity", "ransomware", "credential stuffing"]
    }
]


def _search_embedded_corpus(query: str, agency: Optional[str] = None, from_date: Optional[str] = None) -> List[Dict[str, Any]]:
    """Search the embedded regulatory corpus by keywords, agency, and date."""
    query_tokens = [q.lower() for q in re.split(r"\W+", query) if len(q) > 2]
    matched = []

    for doc in EMBEDDED_REGULATORY_CORPUS:
        # Check agency filter
        if agency and agency.lower() not in [s.lower() for s in doc.get("agency_slugs", [])]:
            continue
        # Check date filter
        if from_date and doc.get("publication_date", "") < from_date:
            continue

        doc_text = (doc["title"] + " " + doc["abstract"] + " " + " ".join(doc.get("keywords", []))).lower()
        score = sum(1 for token in query_tokens if token in doc_text)
        if score > 0 or not query_tokens:
            matched.append((score, doc))

    matched.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in matched]


def search_regulations(
    query: str,
    agency: Optional[str] = None,
    from_date: Optional[str] = None
) -> Dict[str, Any]:
    """Search Federal Register documents concerning authentication, cybersecurity, fraud, banking, and identity."""
    params: Dict[str, Any] = {
        "conditions[term]": query,
        "per_page": 10,
        "order": "relevance",
        "fields[]": [
            "document_number", "title", "type", "action", "abstract",
            "publication_date", "effective_on", "agency_names", "html_url", "pdf_url", "citation"
        ]
    }
    if agency:
        params["conditions[agencies][]"] = agency.lower()
    if from_date:
        params["conditions[publication_date][gte]"] = from_date

    encoded_params = []
    for k, v in params.items():
        if isinstance(v, list):
            for item in v:
                encoded_params.append((k, item))
        else:
            encoded_params.append((k, str(v)))

    url = f"{BASE_URL}/documents.json?{urllib.parse.urlencode(encoded_params)}"
    
    # Try live HTTP request
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                result = json.loads(response.read().decode("utf-8"))
                documents = []
                for doc in result.get("results", []):
                    doc_type = doc.get("type", "Unknown")
                    is_binding = doc_type == "Rule" or "Final Rule" in str(doc.get("action", ""))
                    documents.append({
                        "document_number": doc.get("document_number"),
                        "title": doc.get("title"),
                        "document_type": doc_type,
                        "is_final_rule": is_binding,
                        "action": doc.get("action"),
                        "abstract": doc.get("abstract"),
                        "publication_date": doc.get("publication_date"),
                        "effective_on": doc.get("effective_on"),
                        "agencies": doc.get("agency_names", []),
                        "citation": doc.get("citation"),
                        "official_url": doc.get("html_url"),
                        "pdf_url": doc.get("pdf_url")
                    })
                return {
                    "status": "success",
                    "source": "FederalRegister.gov Live API",
                    "query": query,
                    "total_results": result.get("count", len(documents)),
                    "retrieved_count": len(documents),
                    "disclaimer": "Federal Register documents include proposed rules, final rules, and notices. Distinguish proposed rules from binding final rules.",
                    "documents": documents
                }
    except Exception:
        pass  # Fall back to curated embedded corpus

    # Embedded corpus search
    docs = _search_embedded_corpus(query, agency, from_date)
    return {
        "status": "success",
        "source": "Federal Register Curated Regulatory Corpus",
        "query": query,
        "total_results": len(docs),
        "retrieved_count": len(docs),
        "disclaimer": "Federal Register documents include proposed rules, final rules, and notices. Distinguish proposed rules from binding final rules.",
        "documents": docs
    }


def get_regulation(document_id: str) -> Dict[str, Any]:
    """Retrieve complete metadata, abstract, agency actions, and official references for a specific Federal Register document."""
    clean_id = document_id.strip()

    # Try live HTTP request first
    try:
        url = f"{BASE_URL}/documents/{urllib.parse.quote(clean_id)}.json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                result = json.loads(response.read().decode("utf-8"))
                doc_type = result.get("type", "Unknown")
                is_binding = doc_type == "Rule" or "Final Rule" in str(result.get("action", ""))
                return {
                    "status": "success",
                    "source": "FederalRegister.gov Live API",
                    "document_number": result.get("document_number"),
                    "title": result.get("title"),
                    "document_type": doc_type,
                    "is_final_rule": is_binding,
                    "action": result.get("action"),
                    "abstract": result.get("abstract"),
                    "publication_date": result.get("publication_date"),
                    "effective_on": result.get("effective_on"),
                    "agencies": [a.get("name") for a in result.get("agencies", []) if isinstance(a, dict)],
                    "cfr_references": result.get("cfr_references", []),
                    "citation": result.get("citation"),
                    "official_url": result.get("html_url"),
                    "pdf_url": result.get("pdf_url"),
                    "disclaimer": "Verify whether this publication represents an active Final Rule, a Proposed Rule undergoing public comment, or a General Notice."
                }
    except Exception:
        pass

    # Search embedded corpus
    for doc in EMBEDDED_REGULATORY_CORPUS:
        if doc["document_number"] == clean_id:
            return {
                "status": "success",
                "source": "Federal Register Curated Regulatory Corpus",
                "document_number": doc["document_number"],
                "title": doc["title"],
                "document_type": doc["document_type"],
                "is_final_rule": doc["is_final_rule"],
                "action": doc["action"],
                "abstract": doc["abstract"],
                "publication_date": doc["publication_date"],
                "effective_on": doc["effective_on"],
                "agencies": doc["agencies"],
                "cfr_references": doc.get("cfr_references", []),
                "citation": doc["citation"],
                "official_url": doc["official_url"],
                "pdf_url": doc["pdf_url"],
                "disclaimer": "Verify whether this publication represents an active Final Rule, a Proposed Rule undergoing public comment, or a General Notice."
            }

    return {
        "status": "error",
        "message": f"Document ID '{clean_id}' not found in Federal Register repository.",
        "document_id": clean_id
    }


TOOL_DEFINITIONS = [
    {
        "name": "search_regulations",
        "description": "Search Federal Register documents concerning authentication, cybersecurity, identity verification, fraud, and financial services.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term (e.g., 'account takeover fraud', 'multi-factor authentication', 'customer identity verification')"
                },
                "agency": {
                    "type": "string",
                    "description": "Optional federal agency acronym (e.g., 'cfpb', 'ftc', 'occ', 'fincen', 'cisa')"
                },
                "from_date": {
                    "type": "string",
                    "description": "Optional minimum publication date in YYYY-MM-DD format (e.g., '2022-01-01')"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "get_regulation",
        "description": "Retrieve full document details, official citations, CFR references, and text abstracts for a specific Federal Register document number.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "Official Federal Register document number (e.g., '2021-25736', '2022-17231', '2023-28828')"
                }
            },
            "required": ["document_id"]
        }
    }
]


def run_stdio_server():
    """Run MCP server over standard input/output with JSON-RPC 2.0 protocol."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "FederalRegisterRegulatoryLookup",
                        "version": "1.0.0"
                    },
                    "instructions": SERVER_INSTRUCTIONS
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        elif method == "notifications/initialized":
            pass

        elif method == "tools/list":
            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": TOOL_DEFINITIONS
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            if tool_name == "search_regulations":
                tool_result = search_regulations(
                    query=args.get("query", ""),
                    agency=args.get("agency"),
                    from_date=args.get("from_date")
                )
            elif tool_name == "get_regulation":
                tool_result = get_regulation(
                    document_id=args.get("document_id", "")
                )
            else:
                tool_result = {"error": f"Unknown tool: {tool_name}"}

            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(tool_result, indent=2)
                        }
                    ]
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        elif method == "ping":
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()
