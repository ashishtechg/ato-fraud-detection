-- ============================================================================
-- DT_PROFILE_CHANGE_FEATURES: Profile Mutation & Account Velocity Features
-- Target lag: 1 minute, Warehouse: COMPUTE_WH
-- ============================================================================

CREATE OR REPLACE DYNAMIC TABLE ATO_FRAUD_DB.FEATURES.DT_PROFILE_CHANGE_FEATURES
    TARGET_LAG = '1 minute'
    WAREHOUSE = COMPUTE_WH
AS
SELECT
    customer_id,
    COUNT(*) AS total_profile_changes,
    COUNT(CASE WHEN change_type = 'email' THEN 1 END) AS email_change_count,
    COUNT(CASE WHEN change_type = 'phone' THEN 1 END) AS phone_change_count,
    COUNT(CASE WHEN change_type = 'password' THEN 1 END) AS password_change_count,
    COUNT(CASE WHEN change_type = 'recovery_email' THEN 1 END) AS recovery_email_change_count,
    MAX(change_ts) AS latest_change_ts,
    MAX(CASE WHEN change_type = 'phone' THEN change_ts END) AS latest_phone_change_ts,
    MAX(CASE WHEN change_type = 'email' THEN change_ts END) AS latest_email_change_ts,
    MAX(CASE WHEN change_type = 'password' THEN change_ts END) AS latest_password_change_ts,
    -- Clustered change detection: whether customer had multiple changes on same day
    CASE WHEN COUNT(DISTINCT change_type) >= 2 THEN TRUE ELSE FALSE END AS has_clustered_changes,
    MAX(is_fraud::INT)::BOOLEAN AS has_fraud_change_history
FROM ATO_FRAUD_DB.RAW.RAW_ACCOUNT_CHANGES
GROUP BY customer_id;
