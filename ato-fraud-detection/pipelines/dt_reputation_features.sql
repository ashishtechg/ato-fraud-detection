-- ============================================================================
-- DT_REPUTATION_FEATURES: Threat Intelligence & Entity Reputation
-- Target lag: 1 minute, Warehouse: COMPUTE_WH
-- ============================================================================

CREATE OR REPLACE DYNAMIC TABLE ATO_FRAUD_DB.FEATURES.DT_REPUTATION_FEATURES
    TARGET_LAG = '1 minute'
    WAREHOUSE = COMPUTE_WH
AS
SELECT
    indicator_value,
    indicator_type,
    MAX(risk_score) AS max_threat_risk_score,
    MAX(CASE WHEN confidence = 'high' THEN 1 ELSE 0 END) AS is_high_confidence,
    MAX(threat_category) AS primary_threat_category,
    COUNT(DISTINCT source) AS reporting_source_count,
    MAX(last_seen_ts) AS latest_threat_seen_ts
FROM ATO_FRAUD_DB.RAW.RAW_THREAT_INTEL
GROUP BY indicator_value, indicator_type;
