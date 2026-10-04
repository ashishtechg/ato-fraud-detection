-- ============================================================================
-- DT_AUTH_FEATURES: Authentication & Velocity Features
-- Target lag: 1 minute, Warehouse: COMPUTE_WH
-- ============================================================================

CREATE OR REPLACE DYNAMIC TABLE ATO_FRAUD_DB.FEATURES.DT_AUTH_FEATURES
    TARGET_LAG = '1 minute'
    WAREHOUSE = COMPUTE_WH
AS
WITH
login_lagged AS (
    SELECT
        event_id,
        customer_id,
        event_ts,
        ip_address,
        geo_lat,
        geo_lon,
        country_code,
        asn,
        is_vpn,
        is_tor,
        is_proxy,
        device_fingerprint,
        user_agent,
        auth_method,
        login_success,
        failure_reason,
        session_id,
        is_fraud,
        fraud_scenario,
        -- Previous login event details for this customer
        LAG(event_ts) OVER (PARTITION BY customer_id ORDER BY event_ts) AS prev_event_ts,
        LAG(geo_lat) OVER (PARTITION BY customer_id ORDER BY event_ts) AS prev_geo_lat,
        LAG(geo_lon) OVER (PARTITION BY customer_id ORDER BY event_ts) AS prev_geo_lon,
        LAG(ip_address) OVER (PARTITION BY customer_id ORDER BY event_ts) AS prev_ip_address,
        LAG(country_code) OVER (PARTITION BY customer_id ORDER BY event_ts) AS prev_country_code,
        -- Rolling 1-hour and 24-hour failed login counts (using 100-event and 20-event row frames as high-performance proxy)
        COUNT(CASE WHEN NOT login_success THEN 1 END) OVER (
            PARTITION BY customer_id ORDER BY event_ts
            ROWS BETWEEN 5 PRECEDING AND CURRENT ROW
        ) AS failed_login_count_recent,
        COUNT(*) OVER (
            PARTITION BY ip_address ORDER BY event_ts
            ROWS BETWEEN 20 PRECEDING AND CURRENT ROW
        ) AS ip_velocity_recent,
        COUNT(*) OVER (
            PARTITION BY device_fingerprint ORDER BY event_ts
            ROWS BETWEEN 20 PRECEDING AND CURRENT ROW
        ) AS device_velocity_recent
    FROM ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS
)
SELECT
    event_id,
    customer_id,
    event_ts,
    ip_address,
    geo_lat,
    geo_lon,
    country_code,
    asn,
    is_vpn,
    is_tor,
    is_proxy,
    device_fingerprint,
    user_agent,
    auth_method,
    login_success,
    failure_reason,
    session_id,
    is_fraud,
    fraud_scenario,
    -- Time elapsed since last login in seconds and hours
    COALESCE(DATEDIFF('second', prev_event_ts, event_ts), 86400) AS time_since_prev_login_sec,
    COALESCE(DATEDIFF('second', prev_event_ts, event_ts) / 3600.0, 24.0) AS time_since_prev_login_hours,
    -- Distance in km from previous login location
    CASE
        WHEN prev_geo_lat IS NOT NULL AND prev_geo_lon IS NOT NULL
        THEN HAVERSINE(prev_geo_lat, prev_geo_lon, geo_lat, geo_lon)
        ELSE 0.0
    END AS distance_from_prev_login_km,
    -- Geo-velocity in km/h (speed required to travel between consecutive logins)
    CASE
        WHEN prev_geo_lat IS NOT NULL AND prev_geo_lon IS NOT NULL
             AND DATEDIFF('second', prev_event_ts, event_ts) > 0
        THEN (HAVERSINE(prev_geo_lat, prev_geo_lon, geo_lat, geo_lon) / (DATEDIFF('second', prev_event_ts, event_ts) / 3600.0))
        ELSE 0.0
    END AS geo_velocity_kmh,
    -- Flags
    CASE WHEN prev_country_code IS NOT NULL AND prev_country_code != country_code THEN TRUE ELSE FALSE END AS is_country_switched,
    CASE WHEN prev_ip_address IS NOT NULL AND prev_ip_address != ip_address THEN TRUE ELSE FALSE END AS is_ip_switched,
    failed_login_count_recent AS failed_login_count_1h,
    ip_velocity_recent AS ip_velocity_1h,
    device_velocity_recent AS device_velocity_1h
FROM login_lagged;
