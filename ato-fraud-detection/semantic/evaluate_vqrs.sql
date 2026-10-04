-- ============================================================================
-- Semantic: Verified Queries (VQRs) Test & Validation Suite
-- Executes the 14 verified queries against the ATO Fraud Analytics Semantic Layer
-- ============================================================================

USE DATABASE ATO_FRAUD_DB;
USE SCHEMA SEMANTIC;

-- 1. Blocked Logins Summary
-- "How many login attempts were blocked and what was the average risk score?"
SELECT
    COUNT_IF(risk_tier = 'BLOCK') AS blocked_logins,
    ROUND(AVG(risk_score), 1) AS avg_score
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS;

-- 2. Top Fraud Scenarios
-- "What are the top fraud scenarios by volume?"
SELECT
    fraud_scenario,
    COUNT(*) AS event_count
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
WHERE is_fraud = TRUE
GROUP BY fraud_scenario
ORDER BY event_count DESC;

-- 3. Decision Breakdown by Risk Tier
-- "Show me the breakdown of login decisions by risk tier"
SELECT
    risk_tier,
    COUNT(*) AS login_count,
    ROUND(AVG(risk_score), 1) AS avg_score
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
GROUP BY risk_tier
ORDER BY login_count DESC;

-- 4. Fraud Catch Rate (Recall)
-- "What is our overall fraud detection rate (recall) at the login gate?"
SELECT
    ROUND(100.0 * COUNT_IF(is_fraud = TRUE AND risk_tier = 'BLOCK') / NULLIF(COUNT_IF(is_fraud = TRUE), 0), 2) AS fraud_catch_rate_pct
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS;

-- 5. False Positive Rate by Customer Segment
-- "What is the false positive rate for high-value vs standard customer segments?"
SELECT
    c.account_tier,
    COUNT_IF(sl.is_fraud = FALSE AND sl.risk_tier = 'BLOCK') AS false_positives,
    COUNT_IF(sl.is_fraud = FALSE) AS total_legit,
    ROUND(100.0 * COUNT_IF(sl.is_fraud = FALSE AND sl.risk_tier = 'BLOCK') / NULLIF(COUNT_IF(sl.is_fraud = FALSE), 0), 4) AS fpr_pct
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
JOIN ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c ON sl.customer_id = c.customer_id
GROUP BY c.account_tier;

-- 6. VPN & Tor Risk Comparison
-- "What is the average risk score for VPN and Tor logins compared to normal connections?"
SELECT
    CASE WHEN is_tor THEN 'Tor Connection' WHEN is_vpn THEN 'VPN Connection' ELSE 'Standard Network' END AS connection_type,
    COUNT(*) AS login_count,
    ROUND(AVG(risk_score), 1) AS avg_risk_score
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
GROUP BY 1
ORDER BY avg_risk_score DESC;

-- 7. Impossible Travel Events
-- "How many impossible travel logins were detected and what was the maximum speed?"
SELECT
    COUNT(*) AS impossible_travel_count,
    ROUND(MAX(geo_velocity_kmh), 1) AS max_speed_kmh
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
WHERE geo_velocity_kmh > 1000;

-- 8. SIM-Swap Fraud Correlation
-- "How many customers with phone changes were flagged for SIM-swap fraud?"
SELECT
    COUNT(DISTINCT customer_id) AS sim_swap_compromised_customers
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
WHERE fraud_scenario = 'sim_swap' AND is_fraud = TRUE;

-- 9. Top Triggered Policy Rules
-- "Which policy rules triggered most frequently?"
SELECT
    pr.rule_code,
    pr.rule_name,
    pr.severity,
    pr.required_action,
    COUNT(*) AS trigger_count
FROM ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION e
JOIN ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE pr ON e.policy_rule_id = pr.policy_rule_id
GROUP BY pr.rule_code, pr.rule_name, pr.severity, pr.required_action
ORDER BY trigger_count DESC;

-- 10. Active Critical Policy Rules
-- "Show me all active CRITICAL severity policy rules"
SELECT
    pr.rule_code,
    pr.rule_name,
    pr.required_action,
    pr.condition_description
FROM ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE pr
WHERE pr.severity = 'CRITICAL' AND pr.is_active = TRUE
ORDER BY pr.priority;

-- 11. Policy Rule Overrides Summary
-- "How many policy rule overrides were approved and for which rules?"
SELECT
    pr.rule_code,
    pr.rule_name,
    COUNT(*) AS override_count,
    MAX(e.override_reason) AS sample_reason
FROM ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION e
JOIN ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE pr ON e.policy_rule_id = pr.policy_rule_id
WHERE e.override_flag = TRUE
GROUP BY pr.rule_code, pr.rule_name;

-- 12. MFA Step-Up Challenges by Rule
-- "How many logins triggered MFA step-up authentication rules?"
SELECT
    pr.rule_code,
    pr.rule_name,
    COUNT(*) AS mfa_challenges
FROM ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION e
JOIN ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE pr ON e.policy_rule_id = pr.policy_rule_id
WHERE pr.policy_id = 2
GROUP BY pr.rule_code, pr.rule_name
ORDER BY mfa_challenges DESC;

-- 13. High-Value Account Exposure
-- "How many high-value accounts experienced ATO attacks?"
SELECT
    c.account_tier,
    COUNT(DISTINCT IFF(sl.is_fraud = TRUE, sl.customer_id, NULL)) AS compromised_accounts,
    COUNT(DISTINCT sl.customer_id) AS total_accounts
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS sl
JOIN ATO_FRAUD_DB.RAW.RAW_CUSTOMER_ACCOUNTS c ON sl.customer_id = c.customer_id
GROUP BY c.account_tier;

-- 14. Primary Risk Factors Driving BLOCK Decisions
-- "What are the primary risk factors driving BLOCK decisions?"
SELECT
    primary_risk_factor,
    COUNT(*) AS block_count
FROM ATO_FRAUD_DB.SCORING.DT_SCORED_LOGINS
WHERE risk_tier = 'BLOCK'
GROUP BY primary_risk_factor
ORDER BY block_count DESC;
