-- ============================================================================
-- 05: RAW_SESSION_TELEMETRY - ~13.4M rows (one per login event)
-- Behavioral biometrics: keystroke, mouse, touch, automation signals
-- ============================================================================

CREATE OR REPLACE TABLE ATO_FRAUD_DB.RAW.RAW_SESSION_TELEMETRY (
    session_id              VARCHAR(64),
    customer_id             INT,
    event_ts                TIMESTAMP_NTZ,
    avg_keystroke_interval_ms FLOAT,
    keystroke_std_ms        FLOAT,
    mouse_movement_entropy  FLOAT,          -- 0.0 (no movement) to 1.0 (natural)
    touch_pressure_variance FLOAT,          -- 0.0 (uniform) to 1.0 (varied/human)
    scroll_velocity_avg     FLOAT,
    dwell_time_ms           INT,            -- time spent on login page
    navigation_path_length  INT,            -- pages visited in session
    is_automation_detected  BOOLEAN,
    js_execution_time_ms    INT,
    canvas_fingerprint_match BOOLEAN,       -- matches known device canvas
    webgl_fingerprint_match BOOLEAN
);

INSERT INTO ATO_FRAUD_DB.RAW.RAW_SESSION_TELEMETRY
SELECT
    le.session_id,
    le.customer_id,
    le.event_ts,

    -- Keystroke interval: humans ~90-220ms; bots ~8-25ms uniform
    CASE
        WHEN le.is_fraud AND le.fraud_scenario IN ('bot_automation', 'credential_stuffing')
            THEN (8 + ABS(MOD(RANDOM(), 18)))::FLOAT
        WHEN le.is_fraud AND le.fraud_scenario = 'rat_assisted'
            THEN (80 + ABS(MOD(RANDOM(), 170)))::FLOAT
        ELSE (90 + ABS(MOD(RANDOM(), 130)))::FLOAT
    END AS avg_keystroke_interval_ms,

    -- Keystroke std deviation: humans ~15-55ms; bots <5ms
    CASE
        WHEN le.is_fraud AND le.fraud_scenario IN ('bot_automation', 'credential_stuffing')
            THEN (1 + ABS(MOD(RANDOM(), 5)))::FLOAT
        WHEN le.is_fraud AND le.fraud_scenario = 'rat_assisted'
            THEN (10 + ABS(MOD(RANDOM(), 16)))::FLOAT
        ELSE (15 + ABS(MOD(RANDOM(), 41)))::FLOAT
    END AS keystroke_std_ms,

    -- Mouse movement entropy: humans 0.55-1.0; bots 0.0-0.1
    CASE
        WHEN le.is_fraud AND le.fraud_scenario IN ('bot_automation', 'credential_stuffing')
            THEN (ABS(MOD(RANDOM(), 11))) / 100.0
        WHEN le.is_fraud AND le.fraud_scenario = 'rat_assisted'
            THEN (30 + ABS(MOD(RANDOM(), 31))) / 100.0
        ELSE (55 + ABS(MOD(RANDOM(), 46))) / 100.0
    END AS mouse_movement_entropy,

    -- Touch pressure: humans 0.25-1.0 on mobile; desktop/bots 0.0
    CASE
        WHEN le.is_fraud AND le.fraud_scenario IN ('bot_automation', 'credential_stuffing') THEN 0.0
        WHEN ABS(MOD(RANDOM(), 100)) < 60 THEN (25 + ABS(MOD(RANDOM(), 76))) / 100.0
        ELSE 0.0
    END AS touch_pressure_variance,

    -- Scroll velocity
    CASE
        WHEN le.is_fraud AND le.fraud_scenario = 'bot_automation' THEN 0.0
        ELSE (10 + ABS(MOD(RANDOM(), 491)))::FLOAT
    END AS scroll_velocity_avg,

    -- Dwell time: humans 3-30s; bots <1s
    CASE
        WHEN le.is_fraud AND le.fraud_scenario IN ('bot_automation', 'credential_stuffing')
            THEN (50 + ABS(MOD(RANDOM(), 751)))
        ELSE (3000 + ABS(MOD(RANDOM(), 27001)))
    END AS dwell_time_ms,

    -- Navigation path length
    CASE
        WHEN le.is_fraud AND le.fraud_scenario = 'bot_automation' THEN 1
        ELSE (1 + ABS(MOD(RANDOM(), 8)))
    END AS navigation_path_length,

    -- Automation detection
    CASE
        WHEN le.is_fraud AND le.fraud_scenario IN ('bot_automation', 'credential_stuffing')
            THEN CASE WHEN ABS(MOD(RANDOM(), 100)) < 85 THEN TRUE ELSE FALSE END
        ELSE FALSE
    END AS is_automation_detected,

    -- JS execution time: headless browsers are faster
    CASE
        WHEN le.is_fraud AND le.fraud_scenario = 'bot_automation' THEN (5 + ABS(MOD(RANDOM(), 46)))
        ELSE (100 + ABS(MOD(RANDOM(), 1901)))
    END AS js_execution_time_ms,

    -- Canvas/WebGL fingerprint match
    CASE WHEN le.is_fraud THEN FALSE ELSE TRUE END AS canvas_fingerprint_match,
    CASE WHEN le.is_fraud AND le.fraud_scenario = 'device_spoofing' THEN FALSE
         WHEN le.is_fraud THEN CASE WHEN ABS(MOD(RANDOM(), 100)) < 50 THEN FALSE ELSE TRUE END
         ELSE TRUE
    END AS webgl_fingerprint_match

FROM ATO_FRAUD_DB.RAW.RAW_LOGIN_EVENTS le;

