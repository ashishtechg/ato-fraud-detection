-- ============================================================================
-- 07: RAW_THREAT_INTEL - ~50K threat intelligence indicators
-- IP, device, email, phone reputation from breach DBs, SIM-swap feeds
-- ============================================================================

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_THREAT_INTEL (
    indicator_id        INT,
    indicator_type      VARCHAR(10),       -- 'ip', 'device', 'email', 'phone'
    indicator_value     VARCHAR(64),
    risk_score          INT,               -- 0-100
    source              VARCHAR(30),       -- 'breach_db', 'sim_swap_feed', 'reputation_svc', 'botnet_list', 'tor_exit_nodes'
    reported_ts         TIMESTAMP_NTZ,
    last_seen_ts        TIMESTAMP_NTZ,
    threat_category     VARCHAR(30),       -- 'credential_compromise', 'sim_swap', 'proxy', 'botnet', 'tor', 'fraud_ring'
    confidence          VARCHAR(10)        -- 'high', 'medium', 'low'
);

INSERT INTO ATO_FRAUD_DB.RAW.RAW_THREAT_INTEL
WITH
-- Malicious IPs from fraud login events
fraud_ips AS (
    SELECT DISTINCT
        'ip' AS indicator_type,
        ip_address AS indicator_value,
        (60 + ABS(MOD(RANDOM(), 41))) AS risk_score,
        CASE MOD(ABS(RANDOM()), 4)
            WHEN 0 THEN 'reputation_svc' WHEN 1 THEN 'botnet_list' WHEN 2 THEN 'tor_exit_nodes' ELSE 'breach_db'
        END AS source,
        DATEADD('day', -(1 + ABS(MOD(RANDOM(), 179))), '2026-10-01'::TIMESTAMP_NTZ) AS reported_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 30)), '2026-10-01'::TIMESTAMP_NTZ) AS last_seen_ts,
        CASE fraud_scenario
            WHEN 'credential_stuffing' THEN 'credential_compromise'
            WHEN 'bot_automation' THEN 'botnet'
            WHEN 'brute_force' THEN 'credential_compromise'
            ELSE 'proxy'
        END AS threat_category,
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 70 THEN 'high' WHEN ABS(MOD(RANDOM(), 100)) < 90 THEN 'medium' ELSE 'low' END AS confidence
    FROM ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS
    WHERE is_fraud = TRUE
    LIMIT 10000
),

-- Compromised device fingerprints
fraud_devices AS (
    SELECT
        'device' AS indicator_type,
        device_fingerprint AS indicator_value,
        (50 + ABS(MOD(RANDOM(), 46))) AS risk_score,
        'breach_db' AS source,
        DATEADD('day', -(1 + ABS(MOD(RANDOM(), 89))), '2026-10-01'::TIMESTAMP_NTZ) AS reported_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 14)), '2026-10-01'::TIMESTAMP_NTZ) AS last_seen_ts,
        'fraud_ring' AS threat_category,
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 60 THEN 'high' ELSE 'medium' END AS confidence
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
    WHERE device_owner_type = 'attacker'
),

-- Breached emails (from compromised customers)
breach_emails AS (
    SELECT
        'email' AS indicator_type,
        email_hash AS indicator_value,
        (40 + ABS(MOD(RANDOM(), 51))) AS risk_score,
        'breach_db' AS source,
        DATEADD('day', -(30 + ABS(MOD(RANDOM(), 335))), '2026-10-01'::TIMESTAMP_NTZ) AS reported_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 60)), '2026-10-01'::TIMESTAMP_NTZ) AS last_seen_ts,
        'credential_compromise' AS threat_category,
        'high' AS confidence
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS
    WHERE is_compromised = TRUE
),

-- SIM-swap phone indicators
sim_swap_phones AS (
    SELECT
        'phone' AS indicator_type,
        phone_hash AS indicator_value,
        (70 + ABS(MOD(RANDOM(), 31))) AS risk_score,
        'sim_swap_feed' AS source,
        DATEADD('day', -(1 + ABS(MOD(RANDOM(), 29))), '2026-10-01'::TIMESTAMP_NTZ) AS reported_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 7)), '2026-10-01'::TIMESTAMP_NTZ) AS last_seen_ts,
        'sim_swap' AS threat_category,
        'high' AS confidence
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS
    WHERE is_compromised = TRUE AND compromise_scenario = 'sim_swap'
),

-- Random benign-looking indicators (noise)
noise_indicators AS (
    SELECT
        CASE MOD(ABS(RANDOM()), 3) WHEN 0 THEN 'ip' WHEN 1 THEN 'device' ELSE 'email' END AS indicator_type,
        SHA2(UUID_STRING(), 256) AS indicator_value,
        (10 + ABS(MOD(RANDOM(), 41))) AS risk_score,
        CASE MOD(ABS(RANDOM()), 3) WHEN 0 THEN 'reputation_svc' WHEN 1 THEN 'breach_db' ELSE 'botnet_list' END AS source,
        DATEADD('day', -(30 + ABS(MOD(RANDOM(), 335))), '2026-10-01'::TIMESTAMP_NTZ) AS reported_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 90)), '2026-10-01'::TIMESTAMP_NTZ) AS last_seen_ts,
        CASE MOD(ABS(RANDOM()), 4) WHEN 0 THEN 'proxy' WHEN 1 THEN 'botnet' WHEN 2 THEN 'tor' ELSE 'credential_compromise' END AS threat_category,
        'low' AS confidence
    FROM TABLE(GENERATOR(ROWCOUNT => 30000))
),

all_indicators AS (
    SELECT * FROM fraud_ips
    UNION ALL SELECT * FROM fraud_devices
    UNION ALL SELECT * FROM breach_emails
    UNION ALL SELECT * FROM sim_swap_phones
    UNION ALL SELECT * FROM noise_indicators
)

SELECT
    ROW_NUMBER() OVER (ORDER BY indicator_type, indicator_value) AS indicator_id,
    indicator_type,
    indicator_value,
    risk_score,
    source,
    reported_ts,
    last_seen_ts,
    threat_category,
    confidence
FROM all_indicators;

