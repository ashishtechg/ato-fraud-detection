-- ============================================================================
-- DT_SCORED_LOGINS: Unified Scored Logins with 0-1000 Risk Score & Tiers
-- Target lag: 1 minute, Warehouse: COMPUTE_WH
-- ============================================================================

CREATE OR REPLACE DYNAMIC TABLE ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
    TARGET_LAG = '1 minute'
    WAREHOUSE = COMPUTE_WH
AS
WITH
enriched AS (
    SELECT
        -- Auth & Login base
        af.event_id,
        af.customer_id,
        af.event_ts,
        af.session_id,
        af.ip_address,
        af.country_code,
        af.asn,
        af.is_vpn,
        af.is_tor,
        af.is_proxy,
        af.device_fingerprint,
        af.user_agent,
        af.auth_method,
        af.login_success,
        af.failure_reason,
        af.is_fraud,
        af.fraud_scenario,
        -- Velocity & Travel features
        af.time_since_prev_login_sec,
        af.time_since_prev_login_hours,
        af.distance_from_prev_login_km,
        af.geo_velocity_kmh,
        af.is_country_switched,
        af.is_ip_switched,
        af.failed_login_count_1h,
        af.ip_velocity_1h,
        af.device_velocity_1h,

        -- Customer baseline
        c.account_tier,
        c.mfa_enrolled,
        c.mfa_method,
        c.account_status,
        DATEDIFF('day', c.account_created_at, af.event_ts) AS account_age_days,

        -- Device profile
        d.device_type,
        d.os AS device_os,
        d.browser AS device_browser,
        COALESCE(d.is_trusted, FALSE) AS is_device_trusted,
        COALESCE(d.is_emulator, FALSE) AS is_device_emulator,
        COALESCE(d.is_rooted, FALSE) AS is_device_rooted,

        -- Behavioral features
        bf.avg_keystroke_interval_ms,
        bf.keystroke_std_ms,
        bf.mouse_movement_entropy,
        bf.touch_pressure_variance,
        bf.dwell_time_ms,
        bf.is_automation_detected,
        bf.canvas_fingerprint_match,
        bf.webgl_fingerprint_match,
        COALESCE(bf.behavioral_risk_score, 0) AS behavioral_risk_score,
        COALESCE(bf.is_bot_suspected, FALSE) AS is_bot_suspected,

        -- Profile change velocity
        COALESCE(pcf.total_profile_changes, 0) AS total_profile_changes,
        COALESCE(pcf.phone_change_count, 0) AS phone_change_count,
        COALESCE(pcf.has_clustered_changes, FALSE) AS has_clustered_changes,
        DATEDIFF('hour', pcf.latest_change_ts, af.event_ts) AS hours_since_last_profile_change,

        -- Threat intelligence reputation
        COALESCE(tip.max_threat_risk_score, 0) AS ip_threat_score,
        COALESCE(tde.max_threat_risk_score, 0) AS device_threat_score

    FROM ATO_FRAUD_DB.FEATURES.DT_AUTH_FEATURES af
    LEFT JOIN ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c ON af.customer_id = c.customer_id
    LEFT JOIN ATO_FRAUD_DB.RAW.RAW_DEVICE_REGISTRY d ON af.device_fingerprint = d.device_fingerprint
    LEFT JOIN ATO_FRAUD_DB.FEATURES.DT_BEHAVIORAL_FEATURES bf ON af.session_id = bf.session_id
    LEFT JOIN ATO_FRAUD_DB.FEATURES.DT_PROFILE_CHANGE_FEATURES pcf ON af.customer_id = pcf.customer_id
    LEFT JOIN ATO_FRAUD_DB.FEATURES.DT_REPUTATION_FEATURES tip ON af.ip_address = tip.indicator_value AND tip.indicator_type = 'ip'
    LEFT JOIN ATO_FRAUD_DB.FEATURES.DT_REPUTATION_FEATURES tde ON af.device_fingerprint = tde.indicator_value AND tde.indicator_type = 'device'
),

scored AS (
    SELECT
        e.*,
        -- Unified Ensemble Risk Score Calculation (0 - 1000 scale)
        LEAST(1000, GREATEST(0, ROUND(
            -- Layer 1: Supervised velocity & travel signals (up to 400 pts)
            (CASE WHEN e.geo_velocity_kmh > 1000 THEN 350
                  WHEN e.geo_velocity_kmh > 500 THEN 200
                  WHEN e.is_country_switched THEN 100 ELSE 0 END) +
            (CASE WHEN e.failed_login_count_1h >= 5 THEN 250
                  WHEN e.failed_login_count_1h >= 3 THEN 120
                  WHEN NOT e.login_success THEN 50 ELSE 0 END) +
            (CASE WHEN e.ip_velocity_1h >= 10 THEN 150
                  WHEN e.ip_velocity_1h >= 5 THEN 80 ELSE 0 END) +

            -- Layer 2: Behavioral anomaly & bot detection (up to 300 pts)
            (e.behavioral_risk_score * 2.5) +
            (CASE WHEN NOT e.canvas_fingerprint_match THEN 100 ELSE 0 END) +
            (CASE WHEN e.is_device_emulator THEN 150 ELSE 0 END) +
            (CASE WHEN NOT e.is_device_trusted THEN 80 ELSE 0 END) +

            -- Layer 3: Network & Threat Intel reputation (up to 200 pts)
            (e.ip_threat_score * 1.2) +
            (e.device_threat_score * 0.8) +
            (CASE WHEN e.is_tor THEN 180 WHEN e.is_vpn THEN 60 WHEN e.is_proxy THEN 80 ELSE 0 END) +

            -- Layer 4: Contextual Profile mutations & Account vulnerability (up to 100 pts)
            (CASE WHEN e.hours_since_last_profile_change <= 24 AND e.phone_change_count > 0 THEN 120
                  WHEN e.hours_since_last_profile_change <= 24 THEN 60 ELSE 0 END) +
            (CASE WHEN e.account_status = 'dormant' THEN 80 ELSE 0 END)
        ))) AS raw_risk_score
    FROM enriched e
)

SELECT
    s.*,
    -- Override / Calibrate final risk score:
    -- Ground truth fraud scenarios with high-certainty patterns map to high score bands
    CASE
        WHEN s.raw_risk_score >= 750 OR s.geo_velocity_kmh > 1000 OR (s.is_device_emulator AND NOT s.is_device_trusted)
             OR (s.failed_login_count_1h >= 5 AND NOT s.login_success)
        THEN LEAST(1000, GREATEST(750, s.raw_risk_score))
        WHEN s.raw_risk_score >= 350 OR NOT s.is_device_trusted OR s.is_vpn OR s.hours_since_last_profile_change <= 24
        THEN LEAST(749, GREATEST(350, s.raw_risk_score))
        ELSE LEAST(349, s.raw_risk_score)
    END AS risk_score,

    -- Three-Tier Outcome Decision
    CASE
        WHEN (s.raw_risk_score >= 750 OR s.geo_velocity_kmh > 1000 OR (s.is_device_emulator AND NOT s.is_device_trusted)
             OR (s.failed_login_count_1h >= 5 AND NOT s.login_success))
        THEN 'BLOCK'
        WHEN (s.raw_risk_score >= 350 OR NOT s.is_device_trusted OR s.is_vpn OR s.hours_since_last_profile_change <= 24)
        THEN 'STEP-UP'
        ELSE 'SAFE'
    END AS risk_tier,

    -- Human-readable primary risk reason
    CASE
        WHEN s.geo_velocity_kmh > 1000 THEN 'Impossible travel detected (>1000 km/h)'
        WHEN s.is_bot_suspected OR s.is_automation_detected THEN 'Automated bot / credential stuffing biometrics'
        WHEN s.is_device_emulator THEN 'Emulated device fingerprint'
        WHEN s.failed_login_count_1h >= 5 THEN 'High-velocity brute force failed attempts'
        WHEN s.is_tor THEN 'Tor exit node network connection'
        WHEN s.hours_since_last_profile_change <= 24 AND s.phone_change_count > 0 THEN 'SIM-swap / Recent phone modification'
        WHEN NOT s.is_device_trusted THEN 'Unrecognized new device'
        WHEN s.is_vpn THEN 'VPN / Proxy connection'
        ELSE 'Normal behavioral profile'
    END AS primary_risk_factor

FROM scored s;
