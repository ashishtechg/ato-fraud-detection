-- ============================================================================
-- 02: RAW_DEVICE_REGISTRY - ~100K devices (1-3 per customer)
-- Compromised accounts get an additional attacker device
-- ============================================================================

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY (
    device_fingerprint  VARCHAR(64),
    customer_id         INT,
    first_seen_ts       TIMESTAMP_NTZ,
    last_seen_ts        TIMESTAMP_NTZ,
    device_type         VARCHAR(20),       -- 'mobile', 'desktop', 'tablet'
    os                  VARCHAR(30),       -- 'iOS', 'Android', 'Windows', 'macOS', 'Linux'
    browser             VARCHAR(30),       -- 'Chrome', 'Safari', 'Firefox', 'Edge'
    is_trusted          BOOLEAN,
    is_emulator         BOOLEAN,
    is_rooted           BOOLEAN,
    tls_ja3_hash        VARCHAR(64),
    device_owner_type   VARCHAR(15)        -- 'legitimate', 'attacker'
);

INSERT INTO ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
WITH
-- Generate 1-3 legitimate devices per customer
-- Uses MOD(RANDOM(), N) instead of UNIFORM() since bounds are non-constant
legitimate_devices AS (
    SELECT
        device_fingerprint, customer_id, first_seen_ts, last_seen_ts, device_type,
        CASE
            WHEN device_type = 'mobile' THEN CASE WHEN ABS(MOD(RANDOM(), 100)) < 55 THEN 'iOS' ELSE 'Android' END
            WHEN device_type = 'tablet' THEN CASE WHEN ABS(MOD(RANDOM(), 100)) < 60 THEN 'iOS' ELSE 'Android' END
            ELSE CASE MOD(ABS(RANDOM()), 4) WHEN 0 THEN 'Windows' WHEN 1 THEN 'macOS' WHEN 2 THEN 'Windows' ELSE 'Linux' END
        END AS os,
        CASE MOD(ABS(RANDOM()), 10)
            WHEN 0 THEN 'Safari' WHEN 1 THEN 'Safari' WHEN 2 THEN 'Safari'
            WHEN 3 THEN 'Firefox' WHEN 4 THEN 'Edge'
            ELSE 'Chrome'
        END AS browser,
        is_trusted, is_emulator, is_rooted, tls_ja3_hash, device_owner_type
    FROM (
        SELECT
            SHA2(c.customer_id || '-dev-' || d.device_num || '-' || UUID_STRING(), 256) AS device_fingerprint,
            c.customer_id,
            DATEADD('second',
                ABS(MOD(RANDOM(), GREATEST(DATEDIFF('second', c.account_created_at, '2026-10-01'::TIMESTAMP_NTZ), 1))),
                c.account_created_at
            ) AS first_seen_ts,
            DATEADD('second',
                -ABS(MOD(RANDOM(), 604800)),
                '2026-10-01'::TIMESTAMP_NTZ
            ) AS last_seen_ts,
            CASE d.device_num
                WHEN 1 THEN CASE WHEN ABS(MOD(RANDOM(), 100)) < 60 THEN 'mobile' ELSE 'desktop' END
                WHEN 2 THEN CASE WHEN ABS(MOD(RANDOM(), 100)) < 40 THEN 'desktop' WHEN ABS(MOD(RANDOM(), 100)) < 70 THEN 'mobile' ELSE 'tablet' END
                ELSE 'tablet'
            END AS device_type,
            TRUE AS is_trusted,
            FALSE AS is_emulator,
            FALSE AS is_rooted,
            SHA2('ja3-legit-' || c.customer_id || '-' || d.device_num, 256) AS tls_ja3_hash,
            'legitimate' AS device_owner_type
        FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
        CROSS JOIN (
            SELECT 1 AS device_num UNION ALL SELECT 2 UNION ALL SELECT 3
        ) d
        WHERE d.device_num <= (1 + (c.customer_id % 3))
    ) sub
),

-- Attacker devices for compromised accounts
attacker_devices AS (
    SELECT
        SHA2('attacker-dev-' || c.customer_id || '-' || UUID_STRING(), 256) AS device_fingerprint,
        c.customer_id,
        DATEADD('day', -(1 + ABS(MOD(RANDOM(), 29))), '2026-10-01'::TIMESTAMP_NTZ) AS first_seen_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 3)), '2026-10-01'::TIMESTAMP_NTZ) AS last_seen_ts,
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 70 THEN 'desktop' ELSE 'mobile' END AS device_type,
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 40 THEN 'Linux' WHEN ABS(MOD(RANDOM(), 100)) < 70 THEN 'Windows' ELSE 'Android' END AS os,
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 60 THEN 'Chrome' ELSE 'Firefox' END AS browser,
        FALSE AS is_trusted,
        CASE WHEN c.compromise_scenario = 'device_spoofing' THEN TRUE ELSE FALSE END AS is_emulator,
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 30 THEN TRUE ELSE FALSE END AS is_rooted,
        SHA2('ja3-attacker-' || c.customer_id || '-' || ABS(MOD(RANDOM(), 5)), 256) AS tls_ja3_hash,
        'attacker' AS device_owner_type
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
    WHERE c.is_compromised = TRUE
)

SELECT * FROM legitimate_devices
UNION ALL
SELECT * FROM attacker_devices;
