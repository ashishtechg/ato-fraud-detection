-- ============================================================================
-- Policies: Create ATO_POLICY_DOCUMENTS Table Schema
-- Stores section-chunked internal policies for Cortex Search semantic retrieval
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.POLICY_ENGINE;

CREATE OR REPLACE TABLE ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS (
    document_id             INT,
    document_title          VARCHAR(100),
    document_type           VARCHAR(50),
    section_number          VARCHAR(20),
    section_title           VARCHAR(150),
    policy_text             VARCHAR(16777216),
    owner_role              VARCHAR(50),
    effective_date          DATE,
    regulatory_references   VARCHAR(200)
);
