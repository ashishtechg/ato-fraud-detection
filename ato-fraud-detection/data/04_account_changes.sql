-- ============================================================================
-- 04: RAW_ACCOUNT_CHANGES - ~200K account change events
-- Normal changes + clustered fraud-related profile mutations
-- ============================================================================

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_ACCOUNT_CHANGES (
    change_id           INT,
    customer_id         INT,
    change_ts           TIMESTAMP_NTZ,
    change_type         VARCHAR(20),       -- 'email', 'phone', 'password', 'address', 'recovery_email'
    channel             VARCHAR(20),       -- 'web', 'mobile_app', 'call_center', 'api'
    ip_address          VARCHAR(15),
    device_fingerprint  VARCHAR(64),
    is_fraud            BOOLEAN,
    fraud_scenario      VARCHAR(30)
);

INSERT INTO ATO_FRAUD_DB.RAW.RAW_ACCOUNT_CHANGES
WITH
legit_device_map AS (
    SELECT customer_id, device_fingerprint
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
    WHERE device_owner_type = 'legitimate'
    QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY device_fingerprint) = 1
),

attacker_device_map AS (
    SELECT customer_id, device_fingerprint
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
    WHERE device_owner_type = 'attacker'
    QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY device_fingerprint) = 1
),

-- Legitimate changes: ~3-4 per customer per year, spread over 90 days
legit_changes AS (
    SELECT
        ROW_NUMBER() OVER (ORDER BY c.customer_id, seq.seq_num) AS change_id,
        c.customer_id,
        DATEADD('second', -ABS(MOD(RANDOM(), 7776000)), '2026-10-01'::TIMESTAMP_NTZ) AS change_ts,
        CASE MOD(ABS(RANDOM()), 5)
            WHEN 0 THEN 'password'
            WHEN 1 THEN 'email'
            WHEN 2 THEN 'phone'
            WHEN 3 THEN 'address'
            ELSE 'recovery_email'
        END AS change_type,
        CASE MOD(ABS(RANDOM()), 4)
            WHEN 0 THEN 'web' WHEN 1 THEN 'mobile_app' WHEN 2 THEN 'call_center' ELSE 'api'
        END AS channel,
        CONCAT(
            (10 + (c.customer_id % 220))::VARCHAR, '.',
            ((c.customer_id * 7) % 256)::VARCHAR, '.',
            ((c.customer_id * 13) % 256)::VARCHAR, '.',
            (1 + ABS(MOD(RANDOM(), 254)))::VARCHAR
        ) AS ip_address,
        ld.device_fingerprint,
        FALSE AS is_fraud,
        NULL AS fraud_scenario
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
    LEFT JOIN legit_device_map ld ON c.customer_id = ld.customer_id
    CROSS JOIN (
        SELECT ROW_NUMBER() OVER (ORDER BY SEQ4()) AS seq_num
        FROM TABLE(GENERATOR(ROWCOUNT => 4))
    ) seq
    WHERE c.account_status = 'active'
),

-- Fraud changes: clustered profile mutations for compromised accounts
fraud_changes AS (
    SELECT
        (SELECT COALESCE(MAX(change_id), 0) FROM legit_changes) +
            ROW_NUMBER() OVER (ORDER BY c.customer_id, ct.change_type) AS change_id,
        c.customer_id,
        -- Changes happen within minutes of each other (clustered)
        DATEADD('minute',
            -ABS(MOD(RANDOM(), 60)),
            DATEADD('day', -(1 + ABS(MOD(RANDOM(), 13))), '2026-10-01'::TIMESTAMP_NTZ)
        ) AS change_ts,
        ct.change_type,
        CASE WHEN c.compromise_scenario = 'sim_swap' THEN 'call_center' ELSE 'web' END AS channel,
        -- Attacker IP
        CONCAT('180.', (1 + ABS(MOD(RANDOM(), 254)))::VARCHAR, '.', (1 + ABS(MOD(RANDOM(), 254)))::VARCHAR, '.', (1 + ABS(MOD(RANDOM(), 253)))::VARCHAR) AS ip_address,
        COALESCE(ad.device_fingerprint, ld.device_fingerprint) AS device_fingerprint,
        TRUE AS is_fraud,
        c.compromise_scenario AS fraud_scenario
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
    LEFT JOIN attacker_device_map ad ON c.customer_id = ad.customer_id
    LEFT JOIN legit_device_map ld ON c.customer_id = ld.customer_id
    -- Each compromised account changes email + phone + password (3 changes)
    CROSS JOIN (
        SELECT 'email' AS change_type UNION ALL
        SELECT 'phone' UNION ALL
        SELECT 'password'
    ) ct
    WHERE c.is_compromised = TRUE
      AND c.compromise_scenario IN ('new_device_recovery_abuse', 'sim_swap', 'credential_stuffing', 'impossible_travel')
)

SELECT * FROM legit_changes
UNION ALL
SELECT * FROM fraud_changes;

