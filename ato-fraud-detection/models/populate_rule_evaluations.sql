-- ============================================================================
-- Models: Populate Policy Rule Evaluations Audit Log
-- Evaluates the 30 active policy rules against DT_SCORED_LOGINS
-- Populates ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION
WITH
matched_evaluations AS (
    -- Rule 1: Credential Stuffing
    SELECT
        sl.event_id,
        1 AS policy_rule_id,
        sl.event_ts AS evaluation_ts,
        TRUE AS condition_result,
        'BLOCK' AS action_taken,
        FALSE AS override_flag,
        NULL AS override_reason,
        NULL AS override_approved_by
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.fraud_scenario = 'credential_stuffing'

    UNION ALL

    -- Rule 2: Impossible Travel
    SELECT
        sl.event_id,
        2 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'BLOCK',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.geo_velocity_kmh > 1000

    UNION ALL

    -- Rule 3: Critical Risk Score (>750)
    SELECT
        sl.event_id,
        3 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'BLOCK',
        -- 1% realistic analyst override for False Positive VIP reviews
        CASE WHEN sl.is_fraud = FALSE AND ABS(MOD(RANDOM(), 100)) = 0 THEN TRUE ELSE FALSE END,
        CASE WHEN sl.is_fraud = FALSE AND ABS(MOD(RANDOM(), 100)) = 0 THEN 'VIP executive travel pre-cleared' ELSE NULL END,
        CASE WHEN sl.is_fraud = FALSE AND ABS(MOD(RANDOM(), 100)) = 0 THEN 'fraud_ops_manager' ELSE NULL END
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.risk_score > 750

    UNION ALL

    -- Rule 4: Elevated Risk Score Step-Up (350-750)
    SELECT
        sl.event_id,
        4 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'STEP_UP',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.risk_score BETWEEN 350 AND 750

    UNION ALL

    -- Rule 5: Device Spoofing / Emulator
    SELECT
        sl.event_id,
        5 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'BLOCK',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.is_device_emulator = TRUE OR (sl.canvas_fingerprint_match = FALSE AND sl.webgl_fingerprint_match = FALSE)

    UNION ALL

    -- Rule 8: High-Value Account without Strong MFA
    SELECT
        sl.event_id,
        8 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'STEP_UP',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.account_tier = 'high_value' AND sl.auth_method NOT IN ('TOTP', 'FIDO2')

    UNION ALL

    -- Rule 9: MFA Bypass / Untrusted Device
    SELECT
        sl.event_id,
        9 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'STEP_UP',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.is_device_trusted = FALSE AND sl.mfa_enrolled = TRUE

    UNION ALL

    -- Rule 12: Progressive Lockout (5+ Failures)
    SELECT
        sl.event_id,
        12 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'LOCKOUT',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.failed_login_count_1h >= 5

    UNION ALL

    -- Rule 21: Customer Block Notification
    SELECT
        sl.event_id,
        21 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'NOTIFY_CUSTOMER',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.risk_tier = 'BLOCK'

    UNION ALL

    -- Rule 23: New Device Login Alert
    SELECT
        sl.event_id,
        23 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'NOTIFY_CUSTOMER',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.is_device_trusted = FALSE

    UNION ALL

    -- Rule 27: SIM-Swap Correlated Alert
    SELECT
        sl.event_id,
        27 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'ESCALATE',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.hours_since_last_profile_change <= 24 AND sl.phone_change_count > 0

    UNION ALL

    -- Rule 28: RAT-Assisted Attack (Trusted device with abnormal biometrics)
    SELECT
        sl.event_id,
        28 AS policy_rule_id,
        sl.event_ts,
        TRUE,
        'ESCALATE',
        FALSE,
        NULL,
        NULL
    FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
    WHERE sl.is_device_trusted = TRUE AND sl.mouse_movement_entropy < 0.30 AND sl.keystroke_std_ms < 15
)

SELECT
    ROW_NUMBER() OVER (ORDER BY evaluation_ts, event_id, policy_rule_id) AS evaluation_id,
    event_id,
    policy_rule_id,
    evaluation_ts,
    condition_result,
    action_taken,
    override_flag,
    override_reason,
    override_approved_by
FROM matched_evaluations;
