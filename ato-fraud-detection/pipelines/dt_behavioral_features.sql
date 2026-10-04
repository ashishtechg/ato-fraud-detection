-- ============================================================================
-- DT_BEHAVIORAL_FEATURES: Behavioral Biometrics & Telemetry Features
-- Target lag: 1 minute, Warehouse: COMPUTE_WH
-- ============================================================================

CREATE OR REPLACE DYNAMIC TABLE ATO_FRAUD_DB.FEATURES.DT_BEHAVIORAL_FEATURES
    TARGET_LAG = '1 minute'
    WAREHOUSE = COMPUTE_WH
AS
SELECT
    session_id,
    customer_id,
    event_ts,
    avg_keystroke_interval_ms,
    keystroke_std_ms,
    mouse_movement_entropy,
    touch_pressure_variance,
    scroll_velocity_avg,
    dwell_time_ms,
    navigation_path_length,
    is_automation_detected,
    js_execution_time_ms,
    canvas_fingerprint_match,
    webgl_fingerprint_match,
    -- Heuristic biometrics risk score (0 to 100)
    (
        (CASE WHEN avg_keystroke_interval_ms < 30 THEN 30 WHEN avg_keystroke_interval_ms < 60 THEN 15 ELSE 0 END) +
        (CASE WHEN keystroke_std_ms < 8 THEN 25 WHEN keystroke_std_ms < 15 THEN 10 ELSE 0 END) +
        (CASE WHEN mouse_movement_entropy < 0.15 THEN 25 WHEN mouse_movement_entropy < 0.40 THEN 10 ELSE 0 END) +
        (CASE WHEN is_automation_detected THEN 20 ELSE 0 END)
    ) AS behavioral_risk_score,
    -- Bot indicator
    CASE
        WHEN avg_keystroke_interval_ms < 30 AND keystroke_std_ms < 8 AND mouse_movement_entropy < 0.15 THEN TRUE
        WHEN is_automation_detected THEN TRUE
        ELSE FALSE
    END AS is_bot_suspected
FROM ATO_FRAUD_DB.RAW.RAW_SESSION_TELEMETRY;
