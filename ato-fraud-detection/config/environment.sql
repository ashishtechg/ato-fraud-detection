-- ============================================================================
-- ATO Fraud Detection Prototype - Environment Setup
-- Creates database, schemas, warehouse, and roles
-- ============================================================================

USE ROLE ACCOUNTADMIN;

-- Database
CREATE DATABASE IF NOT EXISTS ATO_FRAUD_DB
    COMMENT = 'ATO Fraud Detection Prototype - Synthetic data, ML models, semantic views, policy engine';

-- Schemas
CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.RAW
    COMMENT = 'Raw synthetic fraud data (bronze layer)';

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.FEATURES
    COMMENT = 'Feature engineering dynamic tables (silver layer)';

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.SCORING
    COMMENT = 'Scored logins, model registry, scoring UDFs (gold layer)';

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.POLICY_ENGINE
    COMMENT = 'Policy rules, evaluations, and policy document corpus';

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.SEMANTIC
    COMMENT = 'Semantic views and Cortex Search services';

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.APP
    COMMENT = 'Streamlit app and Cortex Agent definitions';

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.GOVERNANCE
    COMMENT = 'Masking policies, row access policies, tags';

-- Warehouse for data generation and feature engineering
CREATE WAREHOUSE IF NOT EXISTS ATO_FRAUD_WH
    WAREHOUSE_SIZE = 'MEDIUM'
    AUTO_SUSPEND = 120
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Warehouse for ATO fraud prototype data generation and feature pipelines';

-- Warehouse for ML model training (larger)
CREATE WAREHOUSE IF NOT EXISTS ATO_ML_WH
    WAREHOUSE_SIZE = 'LARGE'
    AUTO_SUSPEND = 120
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Warehouse for ML model training (XGBoost, Isolation Forest)';

-- Warehouse for Cortex Search indexing
CREATE WAREHOUSE IF NOT EXISTS ATO_SEARCH_WH
    WAREHOUSE_SIZE = 'SMALL'
    AUTO_SUSPEND = 120
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Warehouse for Cortex Search service indexing';

-- ─────────────────────────────────────────────────────────────────────────────
-- External Access Integration: Federal Register API (public, no auth)
-- Required for stored procedures that call federalregister.gov
-- ─────────────────────────────────────────────────────────────────────────────

CREATE NETWORK RULE IF NOT EXISTS ATO_FRAUD_DB.APP.FEDERAL_REGISTER_NETWORK_RULE
    MODE = EGRESS
    TYPE = HOST_PORT
    VALUE_LIST = ('www.federalregister.gov', 'www.govinfo.gov');

CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION FEDERAL_REGISTER_EAI
    ALLOWED_NETWORK_RULES = (ATO_FRAUD_DB.APP.FEDERAL_REGISTER_NETWORK_RULE)
    ALLOWED_AUTHENTICATION_SECRETS = ()
    ENABLED = TRUE
    COMMENT = 'Allows stored procedures to call the Federal Register public API for regulatory lookups';

-- Set default context
USE DATABASE ATO_FRAUD_DB;
USE SCHEMA RAW;
USE WAREHOUSE ATO_FRAUD_WH;
