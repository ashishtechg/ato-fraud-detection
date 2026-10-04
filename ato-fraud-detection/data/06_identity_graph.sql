-- ============================================================================
-- 06: RAW_IDENTITY_GRAPH_EDGES - ~300K entity linkages
-- customer <-> device, customer <-> IP, customer <-> email, customer <-> phone
-- Fraud rings: multiple accounts sharing devices/IPs
-- ============================================================================

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES (
    edge_id             INT,
    entity_a_type       VARCHAR(15),       -- 'customer', 'device', 'ip', 'email', 'phone'
    entity_a_id         VARCHAR(64),
    entity_b_type       VARCHAR(15),
    entity_b_id         VARCHAR(64),
    first_linked_ts     TIMESTAMP_NTZ,
    last_linked_ts      TIMESTAMP_NTZ,
    link_count          INT,
    is_fraud_edge       BOOLEAN
);

INSERT INTO ATO_FRAUD_DB.RAW.RAW_IDENTITY_GRAPH_EDGES
WITH
-- Customer <-> Device edges (from device registry)
cust_device AS (
    SELECT
        'customer' AS entity_a_type,
        d.customer_id::VARCHAR AS entity_a_id,
        'device' AS entity_b_type,
        d.device_fingerprint AS entity_b_id,
        d.first_seen_ts AS first_linked_ts,
        d.last_seen_ts AS last_linked_ts,
        (1 + ABS(MOD(RANDOM(), 500))) AS link_count,
        (d.device_owner_type = 'attacker') AS is_fraud_edge
    FROM ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY d
),

-- Customer <-> IP edges (from login events, aggregated)
cust_ip AS (
    SELECT
        'customer' AS entity_a_type,
        le.customer_id::VARCHAR AS entity_a_id,
        'ip' AS entity_b_type,
        le.ip_address AS entity_b_id,
        MIN(le.event_ts) AS first_linked_ts,
        MAX(le.event_ts) AS last_linked_ts,
        COUNT(*) AS link_count,
        MAX(le.is_fraud::INT)::BOOLEAN AS is_fraud_edge
    FROM ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS le
    GROUP BY le.customer_id, le.ip_address
),

-- Customer <-> Email edges
cust_email AS (
    SELECT
        'customer' AS entity_a_type,
        c.customer_id::VARCHAR AS entity_a_id,
        'email' AS entity_b_type,
        c.email_hash AS entity_b_id,
        c.account_created_at AS first_linked_ts,
        '2026-10-01'::TIMESTAMP_NTZ AS last_linked_ts,
        1 AS link_count,
        FALSE AS is_fraud_edge
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
),

-- Customer <-> Phone edges
cust_phone AS (
    SELECT
        'customer' AS entity_a_type,
        c.customer_id::VARCHAR AS entity_a_id,
        'phone' AS entity_b_type,
        c.phone_hash AS entity_b_id,
        c.account_created_at AS first_linked_ts,
        '2026-10-01'::TIMESTAMP_NTZ AS last_linked_ts,
        1 AS link_count,
        FALSE AS is_fraud_edge
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c
),

-- Fraud ring edges: groups of 10-20 compromised accounts sharing devices/IPs
fraud_rings AS (
    SELECT
        'device' AS entity_a_type,
        SHA2('ring-device-' || (c1.customer_id / 20)::INT, 256) AS entity_a_id,
        'customer' AS entity_b_type,
        c1.customer_id::VARCHAR AS entity_b_id,
        DATEADD('day', -(1 + ABS(MOD(RANDOM(), 29))), '2026-10-01'::TIMESTAMP_NTZ) AS first_linked_ts,
        DATEADD('day', -ABS(MOD(RANDOM(), 5)), '2026-10-01'::TIMESTAMP_NTZ) AS last_linked_ts,
        (5 + ABS(MOD(RANDOM(), 46))) AS link_count,
        TRUE AS is_fraud_edge
    FROM ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c1
    JOIN ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c2
        ON (c1.customer_id / 20)::INT = (c2.customer_id / 20)::INT
        AND c1.customer_id < c2.customer_id
    WHERE c1.is_compromised = TRUE AND c2.is_compromised = TRUE
    LIMIT 5000
),

all_edges AS (
    SELECT * FROM cust_device
    UNION ALL SELECT * FROM cust_ip
    UNION ALL SELECT * FROM cust_email
    UNION ALL SELECT * FROM cust_phone
    UNION ALL SELECT * FROM fraud_rings
)

SELECT
    ROW_NUMBER() OVER (ORDER BY entity_a_type, entity_a_id, entity_b_id) AS edge_id,
    entity_a_type,
    entity_a_id,
    entity_b_type,
    entity_b_id,
    first_linked_ts,
    last_linked_ts,
    link_count,
    is_fraud_edge
FROM all_edges;

