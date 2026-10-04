-- ============================================================================
-- 01: RAW_CUSTOMER_ACCOUNTS - 50,000 customer accounts
-- 2% (~1,000) are tagged as future-compromised for fraud injection
-- ============================================================================

-- Ensure database and schema exist (idempotent)
CREATE DATABASE IF NOT EXISTS ATO_FRAUD_DB;
CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.RAW;

USE DATABASE ATO_FRAUD_DB;
USE SCHEMA RAW;
USE WAREHOUSE COMPUTE_WH;

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS (
    customer_id         INT,
    email_hash          VARCHAR(64),
    phone_hash          VARCHAR(64),
    address_hash        VARCHAR(64),
    account_created_at  TIMESTAMP_NTZ,
    account_tier        VARCHAR(20),       -- 'standard' or 'high_value'
    mfa_enrolled        BOOLEAN,
    mfa_method          VARCHAR(20),       -- 'TOTP', 'SMS', 'FIDO2', NULL
    last_credential_change_ts TIMESTAMP_NTZ,
    risk_tier_baseline  VARCHAR(10),       -- 'low', 'medium', 'high'
    country_code        VARCHAR(3),
    is_compromised      BOOLEAN,           -- ground-truth: 2% of accounts
    compromise_scenario VARCHAR(30),       -- which ATO scenario, NULL if clean
    account_status      VARCHAR(15),       -- 'active', 'dormant', 'locked'
    last_login_ts       TIMESTAMP_NTZ
);

INSERT INTO ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS
WITH
-- Base 50K customers
base AS (
    SELECT
        ROW_NUMBER() OVER (ORDER BY SEQ4()) AS customer_id,
        SHA2(UUID_STRING() || '-email', 256) AS email_hash,
        SHA2(UUID_STRING() || '-phone', 256) AS phone_hash,
        SHA2(UUID_STRING() || '-addr', 256) AS address_hash,
        -- Account created over past 3 years
        DATEADD('second',
            -UNIFORM(0, 94608000, RANDOM()),  -- 0 to 3 years in seconds
            '2026-10-01'::TIMESTAMP_NTZ
        ) AS account_created_at,
        -- 90% standard, 10% high-value
        CASE WHEN UNIFORM(1, 100, RANDOM()) <= 10 THEN 'high_value' ELSE 'standard' END AS account_tier,
        -- 75% MFA enrolled
        CASE WHEN UNIFORM(1, 100, RANDOM()) <= 75 THEN TRUE ELSE FALSE END AS mfa_enrolled,
        -- Credential change within last 6 months for 30% of accounts
        CASE WHEN UNIFORM(1, 100, RANDOM()) <= 30
            THEN DATEADD('second', -UNIFORM(0, 15552000, RANDOM()), '2026-10-01'::TIMESTAMP_NTZ)
            ELSE DATEADD('second', -UNIFORM(15552000, 94608000, RANDOM()), '2026-10-01'::TIMESTAMP_NTZ)
        END AS last_credential_change_ts,
        -- Country distribution: US 60%, UK 10%, DE 8%, FR 7%, CA 5%, AU 5%, Other 5%
        CASE UNIFORM(1, 100, RANDOM())
            WHEN  1 THEN 'AU' WHEN  2 THEN 'AU' WHEN  3 THEN 'AU' WHEN  4 THEN 'AU' WHEN  5 THEN 'AU'
            WHEN  6 THEN 'CA' WHEN  7 THEN 'CA' WHEN  8 THEN 'CA' WHEN  9 THEN 'CA' WHEN 10 THEN 'CA'
            WHEN 11 THEN 'FR' WHEN 12 THEN 'FR' WHEN 13 THEN 'FR' WHEN 14 THEN 'FR' WHEN 15 THEN 'FR'
            WHEN 16 THEN 'FR' WHEN 17 THEN 'FR'
            WHEN 18 THEN 'DE' WHEN 19 THEN 'DE' WHEN 20 THEN 'DE' WHEN 21 THEN 'DE'
            WHEN 22 THEN 'DE' WHEN 23 THEN 'DE' WHEN 24 THEN 'DE' WHEN 25 THEN 'DE'
            WHEN 26 THEN 'GB' WHEN 27 THEN 'GB' WHEN 28 THEN 'GB' WHEN 29 THEN 'GB' WHEN 30 THEN 'GB'
            WHEN 31 THEN 'GB' WHEN 32 THEN 'GB' WHEN 33 THEN 'GB' WHEN 34 THEN 'GB' WHEN 35 THEN 'GB'
            WHEN 96 THEN 'JP' WHEN 97 THEN 'BR' WHEN 98 THEN 'IN' WHEN 99 THEN 'SG' WHEN 100 THEN 'NL'
            ELSE 'US'
        END AS country_code,
        -- Last login: within past 90 days for active, 90-365 for dormant
        DATEADD('second',
            -UNIFORM(0, 7776000, RANDOM()),   -- 0 to 90 days
            '2026-10-01'::TIMESTAMP_NTZ
        ) AS last_login_ts
    FROM TABLE(GENERATOR(ROWCOUNT => 50000))
),

-- Tag 2% as compromised, assign scenarios (10 scenarios, ~100 each)
compromised AS (
    SELECT
        customer_id,
        TRUE AS is_compromised,
        CASE (customer_id % 10)
            WHEN 0 THEN 'credential_stuffing'
            WHEN 1 THEN 'impossible_travel'
            WHEN 2 THEN 'device_spoofing'
            WHEN 3 THEN 'brute_force'
            WHEN 4 THEN 'session_replay'
            WHEN 5 THEN 'new_device_recovery_abuse'
            WHEN 6 THEN 'sim_swap'
            WHEN 7 THEN 'rat_assisted'
            WHEN 8 THEN 'dormant_reactivation'
            WHEN 9 THEN 'bot_automation'
        END AS compromise_scenario
    FROM base
    WHERE customer_id <= 1000   -- first 1000 = 2% of 50K
)

SELECT
    b.customer_id,
    b.email_hash,
    b.phone_hash,
    b.address_hash,
    b.account_created_at,
    b.account_tier,
    b.mfa_enrolled,
    -- MFA method
    CASE
        WHEN NOT b.mfa_enrolled THEN NULL
        WHEN UNIFORM(1, 100, RANDOM()) <= 50 THEN 'TOTP'
        WHEN UNIFORM(1, 100, RANDOM()) <= 75 THEN 'SMS'
        ELSE 'FIDO2'
    END AS mfa_method,
    b.last_credential_change_ts,
    -- Baseline risk tier
    CASE
        WHEN c.is_compromised THEN 'high'
        WHEN b.account_tier = 'high_value' THEN 'medium'
        ELSE 'low'
    END AS risk_tier_baseline,
    b.country_code,
    COALESCE(c.is_compromised, FALSE) AS is_compromised,
    c.compromise_scenario,
    -- Account status: dormant reactivation scenario accounts are 'dormant'
    CASE
        WHEN c.compromise_scenario = 'dormant_reactivation' THEN 'dormant'
        WHEN UNIFORM(1, 100, RANDOM()) <= 3 THEN 'locked'
        ELSE 'active'
    END AS account_status,
    -- Dormant accounts: last login > 90 days ago
    CASE
        WHEN c.compromise_scenario = 'dormant_reactivation'
            THEN DATEADD('day', -UNIFORM(90, 365, RANDOM()), '2026-10-01'::TIMESTAMP_NTZ)
        ELSE b.last_login_ts
    END AS last_login_ts
FROM base b
LEFT JOIN compromised c ON b.customer_id = c.customer_id;
