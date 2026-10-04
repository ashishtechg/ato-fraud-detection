-- ============================================================================
-- Policies: Create Cortex Search Service for Internal Policy Knowledge Base
-- Enables semantic hybrid search over internal ATO & Fraud policies
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.SEMANTIC;

CREATE OR REPLACE CORTEX SEARCH SERVICE ATO_FRAUD_DB.SEMANTIC.ATO_POLICY_SEARCH
  ON policy_text
  ATTRIBUTES document_type, document_title, section_title, section_number, owner_role, regulatory_references
  WAREHOUSE = COMPUTE_WH
  TARGET_LAG = '1 day'
  EMBEDDING_MODEL = 'snowflake-arctic-embed-m-v1.5'
  AS (
    SELECT
        policy_text,
        document_id,
        document_title,
        document_type,
        section_number,
        section_title,
        owner_role,
        effective_date,
        regulatory_references
    FROM ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS
  );
