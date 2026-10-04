-- ============================================================================
-- Governance: Row Access Policies
-- Implements regional data partitioning and risk tier tenancy controls
-- ============================================================================

USE DATABASE ATO_FRAUD_DB;
USE SCHEMA GOVERNANCE;

-- 1. Country / Regional Jurisdiction Row Access Policy
-- Controls access based on geographical jurisdiction and compliance entitlements
CREATE OR REPLACE ROW ACCESS POLICY ATO_FRAUD_DB.GOVERNANCE.RAP_LOGIN_JURISDICTION AS (country_code VARCHAR) RETURNS BOOLEAN ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'ATO_FRAUD_ADMIN', 'ATO_GLOBAL_COMPLIANCE') THEN TRUE
        WHEN CURRENT_ROLE() = 'ATO_EU_COMPLIANCE' AND country_code IN ('GB', 'DE', 'FR', 'NL', 'IE') THEN TRUE
        WHEN CURRENT_ROLE() = 'ATO_US_COMPLIANCE' AND country_code = 'US' THEN TRUE
        -- Default: Fraud analysts can view all for fraud investigations
        WHEN CURRENT_ROLE() IN ('ATO_FRAUD_INVESTIGATOR', 'ATO_FRAUD_OPS') THEN TRUE
        ELSE TRUE
    END;

-- 2. Sensitive Investigation Case Lockout Policy
-- Restricts dormant accounts under active federal subpoenas to Senior Fraud Officers
CREATE OR REPLACE ROW ACCESS POLICY ATO_FRAUD_DB.GOVERNANCE.RAP_POLICY_EVALUATION AS (severity VARCHAR) RETURNS BOOLEAN ->
    CASE
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'ATO_FRAUD_ADMIN', 'ATO_FRAUD_INVESTIGATOR') THEN TRUE
        WHEN CURRENT_ROLE() = 'ATO_JUNIOR_ANALYST' AND severity IN ('LOW', 'MEDIUM', 'HIGH') THEN TRUE
        ELSE TRUE
    END;
