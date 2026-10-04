-- ============================================================================
-- 03: RAW_LOGIN_EVENTS - ~5M login events over 90 days
-- Legitimate logins + fraud-scenario-specific attack patterns
-- ============================================================================

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS (
    event_id            INT,
    customer_id         INT,
    event_ts            TIMESTAMP_NTZ,
    ip_address          VARCHAR(15),
    geo_lat             FLOAT,
    geo_lon             FLOAT,
    country_code        VARCHAR(3),
    asn                 INT,
    is_vpn              BOOLEAN,
    is_tor              BOOLEAN,
    is_proxy            BOOLEAN,
    device_fingerprint  VARCHAR(64),
    user_agent          VARCHAR(200),
    auth_method         VARCHAR(20),       -- 'password', 'TOTP', 'SMS_OTP', 'FIDO2', 'SSO'
    login_success       BOOLEAN,
    failure_reason      VARCHAR(30),       -- NULL, 'wrong_password', 'expired_token', 'locked', 'mfa_failed'
    session_id          VARCHAR(64),
    is_fraud            BOOLEAN,
    fraud_scenario      VARCHAR(30)
);

-- ============================================================================
-- Step 1: Generate legitimate login events (~4.9M)
-- Average 2-3 logins/day per active customer over 90 days
-- ============================================================================
INSERT INTO ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS
WITH
-- Pick primary legit device per customer
legit_device_map AS (
    SELECT customer_id, device_fingerprint
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
    WHERE device_owner_type = 'legitimate'
    QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY device_fingerprint) = 1
),

-- Geo coordinates by country (approximate city centers)
geo_lookup AS (
    SELECT * FROM (VALUES
        ('US', 37.77, -122.42), ('US', 40.71, -74.01), ('US', 34.05, -118.24), ('US', 41.88, -87.63),
        ('GB', 51.51, -0.13), ('DE', 52.52, 13.40), ('FR', 48.86, 2.35), ('CA', 43.65, -79.38),
        ('AU', -33.87, 151.21), ('JP', 35.68, 139.69), ('BR', -23.55, -46.63), ('IN', 19.08, 72.88),
        ('SG', 1.35, 103.82), ('NL', 52.37, 4.90)
    ) AS t(country_code, lat, lon)
),

-- Generate ~100 login events per customer (spread over 90 days)
login_base AS (
    SELECT
        ROW_NUMBER() OVER (ORDER BY c.customer_id, seq.seq_num) AS event_id,
        c.customer_id,
        -- Spread logins over 90 days with some randomness
        DATEADD('second',
            -ABS(MOD(RANDOM(), 7776000)),  -- 0 to 90 days in seconds
            '2026-10-01'::TIMESTAMP_NTZ
        ) AS event_ts,
        -- IP: deterministic per customer with some variation
        CONCAT(
            (10 + (c.customer_id % 220))::VARCHAR, '.',
            ((c.customer_id * 7 + seq.seq_num) % 256)::VARCHAR, '.',
            ((c.customer_id * 13) % 256)::VARCHAR, '.',
            (1 + (seq.seq_num % 254))::VARCHAR
        ) AS ip_address,
        c.country_code,
        -- ASN: ~500 unique ASNs
        (1000 + (c.customer_id % 500)) AS asn,
        FALSE AS is_vpn,
        FALSE AS is_tor,
        FALSE AS is_proxy,
        c.mfa_enrolled,
        c.mfa_method,
        c.is_compromised,
        c.compromise_scenario,
        ld.device_fingerprint,
        -- Login success: 98% success for legitimate
        CASE WHEN ABS(MOD(RANDOM(), 100)) < 98 THEN TRUE ELSE FALSE END AS is_success
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
    JOIN legit_device_map ld ON c.customer_id = ld.customer_id
    CROSS JOIN (
        SELECT ROW_NUMBER() OVER (ORDER BY SEQ4()) AS seq_num
        FROM TABLE(GENERATOR(ROWCOUNT => 100))
    ) seq
    WHERE c.account_status != 'locked'
      AND ABS(MOD(RANDOM(), 100)) < 98
)

SELECT
    lb.event_id,
    lb.customer_id,
    lb.event_ts,
    lb.ip_address,
    -- Geo: base country coords + jitter
    COALESCE(g.lat, 40.0) + (MOD(RANDOM(), 400) / 100.0 - 2.0) AS geo_lat,
    COALESCE(g.lon, -100.0) + (MOD(RANDOM(), 400) / 100.0 - 2.0) AS geo_lon,
    lb.country_code,
    lb.asn,
    lb.is_vpn,
    lb.is_tor,
    lb.is_proxy,
    lb.device_fingerprint,
    -- User agent
    CASE MOD(ABS(RANDOM()), 5)
        WHEN 0 THEN 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'
        WHEN 1 THEN 'Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/17.0'
        WHEN 2 THEN 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1'
        WHEN 3 THEN 'Mozilla/5.0 (Linux; Android 14) Chrome/120.0'
        ELSE 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0'
    END AS user_agent,
    -- Auth method
    CASE
        WHEN lb.mfa_enrolled AND lb.mfa_method IS NOT NULL THEN lb.mfa_method
        WHEN ABS(MOD(RANDOM(), 100)) < 5 THEN 'SSO'
        ELSE 'password'
    END AS auth_method,
    lb.is_success AS login_success,
    -- Failure reason
    CASE
        WHEN lb.is_success THEN NULL
        WHEN MOD(ABS(RANDOM()), 3) = 0 THEN 'wrong_password'
        WHEN MOD(ABS(RANDOM()), 3) = 1 THEN 'expired_token'
        ELSE 'mfa_failed'
    END AS failure_reason,
    SHA2(lb.customer_id || '-' || lb.event_ts || '-' || RANDOM(), 256) AS session_id,
    FALSE AS is_fraud,
    NULL AS fraud_scenario
FROM login_base lb
LEFT JOIN geo_lookup g ON lb.country_code = g.country_code;

-- ============================================================================
-- Step 2: Inject fraud login events (~100K across 10 scenarios)
-- Each compromised account gets ~100 fraud events
-- ============================================================================
INSERT INTO ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS
WITH
fraud_customers AS (
    SELECT customer_id, compromise_scenario, country_code, mfa_enrolled, mfa_method
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS
    WHERE is_compromised = TRUE
),

attacker_device_map AS (
    SELECT customer_id, device_fingerprint
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
    WHERE device_owner_type = 'attacker'
    QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY device_fingerprint) = 1
),

legit_device_map AS (
    SELECT customer_id, device_fingerprint
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY
    WHERE device_owner_type = 'legitimate'
    QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY device_fingerprint) = 1
),

max_id AS (
    SELECT COALESCE(MAX(event_id), 0) AS max_event_id FROM ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS
),

-- Generate fraud events per scenario
fraud_events AS (
    SELECT
        m.max_event_id + ROW_NUMBER() OVER (ORDER BY fc.customer_id, seq.seq_num) AS event_id,
        fc.customer_id,
        fc.compromise_scenario,
        fc.country_code,
        fc.mfa_enrolled,
        fc.mfa_method,
        seq.seq_num,
        -- Fraud events clustered in last 30 days
        DATEADD('second',
            -ABS(MOD(RANDOM(), 2592000)),  -- 0 to 30 days
            '2026-10-01'::TIMESTAMP_NTZ
        ) AS event_ts,
        CASE
            WHEN fc.compromise_scenario = 'rat_assisted' THEN ld.device_fingerprint
            ELSE COALESCE(ad.device_fingerprint, ld.device_fingerprint)
        END AS device_fingerprint,
        -- Compute login_success in CTE so it can be safely referenced
        CASE fc.compromise_scenario
            WHEN 'brute_force' THEN CASE WHEN seq.seq_num <= 95 THEN FALSE ELSE TRUE END
            WHEN 'credential_stuffing' THEN CASE WHEN seq.seq_num <= 90 THEN FALSE ELSE TRUE END
            ELSE CASE WHEN ABS(MOD(RANDOM(), 100)) < 85 THEN TRUE ELSE FALSE END
        END AS is_success
    FROM fraud_customers fc
    CROSS JOIN max_id m
    LEFT JOIN attacker_device_map ad ON fc.customer_id = ad.customer_id
    LEFT JOIN legit_device_map ld ON fc.customer_id = ld.customer_id
    CROSS JOIN (
        SELECT ROW_NUMBER() OVER (ORDER BY SEQ4()) AS seq_num
        FROM TABLE(GENERATOR(ROWCOUNT => 100))
    ) seq
)

SELECT
    fe.event_id,
    fe.customer_id,
    fe.event_ts,
    -- Attacker IP: different from customer's usual IP
    CONCAT(
        (180 + (fe.customer_id % 50))::VARCHAR, '.',
        (1 + ABS(MOD(RANDOM(), 254)))::VARCHAR, '.',
        (1 + ABS(MOD(RANDOM(), 254)))::VARCHAR, '.',
        (1 + ABS(MOD(RANDOM(), 253)))::VARCHAR
    ) AS ip_address,

    -- Geo: scenario-dependent
    CASE fe.compromise_scenario
        -- Impossible travel: far from home country
        WHEN 'impossible_travel' THEN
            CASE WHEN fe.seq_num % 2 = 0 THEN 55.75 ELSE -33.87 END
        ELSE (MOD(RANDOM(), 12000) / 100.0 - 60.0)::FLOAT
    END AS geo_lat,
    CASE fe.compromise_scenario
        WHEN 'impossible_travel' THEN
            CASE WHEN fe.seq_num % 2 = 0 THEN 37.62 ELSE 151.21 END
        ELSE (MOD(RANDOM(), 36000) / 100.0 - 180.0)::FLOAT
    END AS geo_lon,

    -- Country: different from home for most scenarios
    CASE fe.compromise_scenario
        WHEN 'impossible_travel' THEN CASE WHEN fe.seq_num % 2 = 0 THEN 'RU' ELSE 'AU' END
        ELSE CASE MOD(ABS(RANDOM()), 5) WHEN 0 THEN 'RU' WHEN 1 THEN 'NG' WHEN 2 THEN 'CN' WHEN 3 THEN 'VN' ELSE 'BR' END
    END AS country_code,

    -- ASN: attacker ASNs
    (60000 + ABS(MOD(RANDOM(), 500))) AS asn,

    -- VPN/Tor/Proxy flags
    CASE WHEN fe.compromise_scenario IN ('credential_stuffing', 'bot_automation') AND ABS(MOD(RANDOM(), 100)) < 70 THEN TRUE ELSE FALSE END AS is_vpn,
    CASE WHEN fe.compromise_scenario IN ('brute_force') AND ABS(MOD(RANDOM(), 100)) < 20 THEN TRUE ELSE FALSE END AS is_tor,
    CASE WHEN ABS(MOD(RANDOM(), 100)) < 15 THEN TRUE ELSE FALSE END AS is_proxy,

    fe.device_fingerprint,

    -- User agent: bot-like for automation scenarios
    CASE fe.compromise_scenario
        WHEN 'bot_automation' THEN 'python-requests/2.31.0'
        WHEN 'credential_stuffing' THEN 'curl/8.4.0'
        ELSE 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'
    END AS user_agent,

    -- Auth method
    CASE fe.compromise_scenario
        WHEN 'sim_swap' THEN 'SMS_OTP'
        WHEN 'new_device_recovery_abuse' THEN 'password'
        ELSE 'password'
    END AS auth_method,

    fe.is_success AS login_success,

    CASE
        WHEN fe.is_success THEN NULL
        WHEN fe.compromise_scenario IN ('brute_force', 'credential_stuffing') THEN 'wrong_password'
        ELSE 'mfa_failed'
    END AS failure_reason,

    -- Session replay: reuse session IDs
    CASE fe.compromise_scenario
        WHEN 'session_replay' THEN SHA2('replay-session-' || fe.customer_id, 256)
        ELSE SHA2(fe.customer_id || '-fraud-' || fe.event_ts || '-' || RANDOM(), 256)
    END AS session_id,

    TRUE AS is_fraud,
    fe.compromise_scenario AS fraud_scenario
FROM fraud_events fe;

