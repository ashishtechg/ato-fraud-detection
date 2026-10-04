-- ============================================================================
-- Models: Deploy Scoring SQL UDF & Decision Function
-- Deploys inline SQL scoring functions in ATO_FRAUD_DB.SCORING
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.SCORING;

-- 1. Unified Risk Score Calculation Function (0 - 1000)
CREATE OR REPLACE FUNCTION ATO_FRAUD_DB.SCORING.CALCULATE_ATO_RISK_SCORE(
    geo_velocity_kmh FLOAT,
    failed_login_count_1h INT,
    login_success BOOLEAN,
    ip_velocity_1h INT,
    behavioral_risk_score FLOAT,
    canvas_fingerprint_match BOOLEAN,
    is_device_emulator BOOLEAN,
    is_device_trusted BOOLEAN,
    ip_threat_score INT,
    device_threat_score INT,
    is_tor BOOLEAN,
    is_vpn BOOLEAN,
    is_proxy BOOLEAN,
    hours_since_last_profile_change INT,
    phone_change_count INT,
    account_status VARCHAR
)
RETURNS INT
LANGUAGE SQL
IMMUTABLE
AS
$$
LEAST(1000, GREATEST(0, ROUND(
    -- Layer 1: Supervised velocity & travel signals (up to 400 pts)
    (CASE WHEN geo_velocity_kmh > 1000 THEN 350
          WHEN geo_velocity_kmh > 500 THEN 200
          ELSE 0 END) +
    (CASE WHEN failed_login_count_1h >= 5 THEN 250
          WHEN failed_login_count_1h >= 3 THEN 120
          WHEN NOT login_success THEN 50 ELSE 0 END) +
    (CASE WHEN ip_velocity_1h >= 10 THEN 150
          WHEN ip_velocity_1h >= 5 THEN 80 ELSE 0 END) +

    -- Layer 2: Behavioral anomaly & bot detection (up to 300 pts)
    (COALESCE(behavioral_risk_score, 0) * 2.5) +
    (CASE WHEN NOT canvas_fingerprint_match THEN 100 ELSE 0 END) +
    (CASE WHEN is_device_emulator THEN 150 ELSE 0 END) +
    (CASE WHEN NOT is_device_trusted THEN 80 ELSE 0 END) +

    -- Layer 3: Network & Threat Intel reputation (up to 200 pts)
    (COALESCE(ip_threat_score, 0) * 1.2) +
    (COALESCE(device_threat_score, 0) * 0.8) +
    (CASE WHEN is_tor THEN 180 WHEN is_vpn THEN 60 WHEN is_proxy THEN 80 ELSE 0 END) +

    -- Layer 4: Contextual Profile mutations & Account vulnerability (up to 100 pts)
    (CASE WHEN hours_since_last_profile_change <= 24 AND phone_change_count > 0 THEN 120
          WHEN hours_since_last_profile_change <= 24 THEN 60 ELSE 0 END) +
    (CASE WHEN account_status = 'dormant' THEN 80 ELSE 0 END)
)))::INT
$$;

-- 2. Three-Tier Decision Mapping Function
CREATE OR REPLACE FUNCTION ATO_FRAUD_DB.SCORING.GET_ATO_DECISION_TIER(risk_score INT)
RETURNS VARCHAR(10)
LANGUAGE SQL
IMMUTABLE
AS
$$
CASE
    WHEN risk_score >= 750 THEN 'BLOCK'
    WHEN risk_score >= 350 THEN 'STEP-UP'
    ELSE 'SAFE'
END
$$;
