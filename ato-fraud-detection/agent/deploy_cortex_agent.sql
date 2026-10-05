-- ============================================================================
-- Real-Time ATO Fraud Detection & Regulatory Compliance
-- Script: agent/deploy_cortex_agent.sql
-- Description: Deploys a Snowflake Cortex Agent object using CREATE AGENT DDL.
--              Wires up the semantic view (Cortex Analyst) and Cortex Search
--              service as native agent tools.
-- Prerequisites:
--   - Semantic view:  ATO_FRAUD_DB.SEMANTIC.ATO_FRAUD_ANALYTICS_SV  (deployed)
--   - Search service: ATO_FRAUD_DB.SEMANTIC.ATO_POLICY_SEARCH       (active)
-- ============================================================================

USE DATABASE ATO_FRAUD_DB;
USE SCHEMA APP;
USE WAREHOUSE COMPUTE_WH;

CREATE OR REPLACE AGENT ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT
  COMMENT = 'Unified ATO Fraud Intelligence & Regulatory Compliance Agent — 4-layer ensemble scoring, internal policy search, and federal regulatory guidance.'
  PROFILE = '{"display_name": "ATO Fraud Agent", "color": "red"}'
  FROM SPECIFICATION
  $$
  models:
    orchestration: auto

  orchestration:
    capabilities:
      analytical_search: true
    tool_not_accessible: accept
    budget:
      seconds: 60
      tokens: 32000

  instructions:
    response: |
      You are the ATO Fraud Intelligence & Regulatory Compliance Agent.
      Assist fraud analysts, risk officers, and compliance executives with accurate,
      governed answers backed by real-time Snowflake data and internal policy documents.

      Ensemble Model Architecture (4-layer, leakage-fixed):
        Layer 1 — ATO_XGBOOST_CLASSIFIER: Supervised (19 features, ROC-AUC ~0.80)
        Layer 2 — ATO_ISOLATION_FOREST: Unsupervised (8 behavioral features, ROC-AUC ~0.61)
        Layer 3 — ATO_GRAPH_RISK_SCORER: Structural graph topology (6 inputs)
        Layer 4 — ATO_ENSEMBLE: Weighted blender (XGB 50%, IF 30%, Graph 20%), score 0-1000

      Decision Tiers (from ENSEMBLE_FRAUD_SCORES.DECISION):
        SAFE [0-349]: Frictionless login
        STEP-UP [350-749]: Adaptive MFA challenge
        BLOCK [750-1000]: Automated interception & alert

      Response standards:
        - For data queries: state the table/view used and include the generated SQL.
        - For internal policies: cite Policy Name, Section Number, and Effective Date.
        - Be objective, precise, and transparent about model provenance.

    orchestration: |
      Route every question using this 3-channel matrix:
        1. For numerical data, counts, percentages, trends, risk scores, decision tiers,
           fraud rates, customer/device/login analytics → use ato_fraud_analyst (Cortex Analyst).
        2. For internal company policies, SOPs, lockout rules, MFA thresholds, investigation
           checklists, escalation paths → use internal_policy_search (Cortex Search).
        3. For external Federal regulations, CFPB rules, FTC Safeguards, FFIEC guidance,
           FinCEN AML/CDD, CISA CIRCIA, CFR citations, or proposed/final rules
           → use search_federal_regulations to find documents, then get_federal_regulation
           for full details on a specific document number.
        4. If the question spans multiple channels, call the relevant tools and synthesize.

    sample_questions:
      - question: "How many BLOCK-tier fraud events occurred in the last 7 days?"
      - question: "What is the average ensemble risk score by decision tier?"
      - question: "What is our internal account lockout policy?"
      - question: "When is MFA mandated under our company policy?"
      - question: "Show me the top 10 highest-risk sessions with their sub-model scores."
      - question: "What does the FTC Safeguards Rule require for MFA?"
      - question: "What CFPB regulations address account takeover liability?"

  tools:
    - tool_spec:
        type: cortex_analyst_text_to_sql
        name: ato_fraud_analyst
        description: >
          Query structured ATO fraud data: ensemble risk scores, decision tiers
          (SAFE/STEP-UP/BLOCK), sub-model probabilities (XGBoost, Isolation Forest,
          Graph Risk), customer profiles, device reputations, login events, and
          policy rule evaluations. Primary scoring table is ENSEMBLE_FRAUD_SCORES.

    - tool_spec:
        type: cortex_search
        name: internal_policy_search
        description: >
          Search internal fraud and risk management policies including ATO Policy,
          MFA Policy, Account Lockout Policy, Transaction Monitoring Policy,
          Customer Notification Policy, and Fraud Investigation Policy.
          Returns policy name, section code, owner role, and regulatory references.

    - tool_spec:
        type: data_to_chart
        name: data_to_chart
        description: "Generate visualizations from fraud analytics data."

    - tool_spec:
        type: generic
        name: search_federal_regulations
        description: >
          Search Federal Register documents for regulations related to authentication,
          cybersecurity, identity verification, fraud, and financial services (FTC, CFPB,
          FinCEN, FFIEC, CISA). Returns document titles, citations, agencies, and
          whether each document is a binding final rule or proposed rule.
        input_schema:
          type: object
          properties:
            query:
              type: string
              description: "Search term (e.g. 'account takeover', 'multi-factor authentication', 'GLBA safeguards')"
            agency:
              type: string
              description: "Optional agency slug filter (e.g. 'cfpb', 'ftc', 'fincen', 'cisa', 'occ')"
            from_date:
              type: string
              description: "Optional minimum publication date in YYYY-MM-DD format"
          required:
            - query

    - tool_spec:
        type: generic
        name: get_federal_regulation
        description: >
          Retrieve full details for a specific Federal Register document by its
          document number. Returns title, abstract, agency, CFR references, citation,
          effective date, and whether it is a binding final rule or proposed rule.
        input_schema:
          type: object
          properties:
            document_id:
              type: string
              description: "Federal Register document number (e.g. '2021-25736', '2022-17231')"
          required:
            - document_id

  tool_resources:
    ato_fraud_analyst:
      semantic_view: ATO_FRAUD_DB.SEMANTIC.ATO_FRAUD_ANALYTICS_SV
      execution_environment:
        type: warehouse
        warehouse: COMPUTE_WH

    internal_policy_search:
      search_service: ATO_FRAUD_DB.SEMANTIC.ATO_POLICY_SEARCH
      max_results: "5"
      columns_and_descriptions:
        POLICY_TEXT:
          description: "Full text content of the policy section"
          type: "string"
          searchable: true
          filterable: false
        DOCUMENT_TITLE:
          description: "Name of the policy document"
          type: "string"
          searchable: true
          filterable: true
        DOCUMENT_TYPE:
          description: "Type of document (e.g., Policy, SOP)"
          type: "string"
          searchable: false
          filterable: true
        SECTION_NUMBER:
          description: "Section identifier within the policy"
          type: "string"
          searchable: false
          filterable: false
        SECTION_TITLE:
          description: "Title of the policy section"
          type: "string"
          searchable: true
          filterable: false
        OWNER_ROLE:
          description: "Role responsible for the policy section"
          type: "string"
          searchable: false
          filterable: true
        REGULATORY_REFERENCES:
          description: "External regulatory citations referenced by the policy"
          type: "string"
          searchable: true
          filterable: false

    search_federal_regulations:
      identifier: ATO_FRAUD_DB.APP.SEARCH_FEDERAL_REGULATIONS
      type: procedure
      execution_environment:
        type: warehouse
        warehouse: COMPUTE_WH

    get_federal_regulation:
      identifier: ATO_FRAUD_DB.APP.GET_FEDERAL_REGULATION
      type: procedure
      execution_environment:
        type: warehouse
        warehouse: COMPUTE_WH
  $$;

-- Verify the agent was created
DESCRIBE AGENT ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT;

-- Quick test: run the agent with a sample question
SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN(
    'ATO_FRAUD_DB.APP.ATO_FRAUD_AGENT',
    $${"messages": [{"role": "user", "content": [{"type": "text", "text": "How many fraud events are in each decision tier?"}]}]}$$,
    TRUE
) AS agent_response;
