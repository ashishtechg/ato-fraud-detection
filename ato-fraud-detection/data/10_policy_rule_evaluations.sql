-- ============================================================================
-- 10: POLICY_RULE_EVALUATION - Audit log schema
-- Populated after model scoring in Task 3 (models/populate_rule_evaluations.sql)
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.POLICY_ENGINE;

CREATE OR REPLACE TABLE ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE_EVALUATION (
    evaluation_id           INT,
    event_id                INT,               -- FK -> DT_SCORED_LOGINS or RAW_LOGIN_EVENTS
    policy_rule_id          INT,               -- FK -> POLICY_RULE
    evaluation_ts           TIMESTAMP_NTZ,
    condition_result        BOOLEAN,           -- TRUE = rule condition matched
    action_taken            VARCHAR(30),       -- actual action (may differ from required_action)
    override_flag           BOOLEAN,
    override_reason         VARCHAR(200),
    override_approved_by    VARCHAR(50)
);

-- Note: This table is populated by models/populate_rule_evaluations.sql
-- after the scoring model is deployed and DT_SCORED_LOGINS is available.
-- See Task 3 for the population logic.

