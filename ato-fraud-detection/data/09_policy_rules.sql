-- ============================================================================
-- 09: POLICY_RULE - 30 enforceable rules across 6 policies
-- SQL-evaluable conditions with required actions and severity
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.POLICY_ENGINE;

CREATE OR REPLACE TABLE ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE (
    policy_rule_id          INT PRIMARY KEY,
    policy_id               INT,               -- FK -> FRAUD_POLICY
    rule_name               VARCHAR(100),
    rule_code               VARCHAR(20),        -- e.g., 'ATO-R-001'
    condition               VARCHAR(500),       -- SQL-evaluable expression
    condition_description   VARCHAR(500),       -- Plain English
    required_action         VARCHAR(30),        -- SAFE, STEP_UP, BLOCK, LOCKOUT, NOTIFY_CUSTOMER, ESCALATE, FILE_SAR, REFER_LAW_ENFORCEMENT
    severity                VARCHAR(10),        -- LOW, MEDIUM, HIGH, CRITICAL
    priority                INT,                -- lower = higher priority
    effective_from          TIMESTAMP_NTZ,
    effective_to            TIMESTAMP_NTZ,      -- NULL = active
    is_active               BOOLEAN,
    override_requires_approval BOOLEAN,
    created_by              VARCHAR(50),
    approved_by             VARCHAR(50)
);

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.POLICY_RULE VALUES
-- ===== ATO POLICY (policy_id = 1) =====
(1, 1, 'Credential Stuffing Detection', 'ATO-R-001',
 'fraud_scenario = ''credential_stuffing''',
 'Login matches credential stuffing pattern: high-velocity failed logins from same ASN across multiple accounts',
 'BLOCK', 'CRITICAL', 1,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(2, 1, 'Impossible Travel Detection', 'ATO-R-002',
 'geo_velocity_kmh > 1000',
 'Consecutive logins from geographically distant locations within a timeframe that makes physical travel impossible',
 'BLOCK', 'CRITICAL', 2,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(3, 1, 'Critical Risk Score Threshold', 'ATO-R-003',
 'risk_score > 750',
 'Unified risk score exceeds the BLOCK threshold (tau_2 = 750)',
 'BLOCK', 'CRITICAL', 3,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(4, 1, 'Elevated Risk Score - Step Up', 'ATO-R-004',
 'risk_score BETWEEN 350 AND 750',
 'Unified risk score is in the STEP-UP range (tau_1 to tau_2)',
 'STEP_UP', 'HIGH', 10,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'fraud_ops_admin', 'ciso'),

(5, 1, 'Device Spoofing Detection', 'ATO-R-005',
 'is_emulator = TRUE OR (canvas_fingerprint_match = FALSE AND webgl_fingerprint_match = FALSE)',
 'Login from emulated device or with mismatched canvas/WebGL fingerprints indicating device spoofing',
 'BLOCK', 'CRITICAL', 4,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(6, 1, 'Session Replay Detection', 'ATO-R-006',
 'session_id IN (SELECT session_id FROM RAW_LOGIN_EVENTS GROUP BY session_id HAVING COUNT(*) > 1)',
 'Same session ID used from multiple IP addresses indicating session token theft or replay',
 'BLOCK', 'CRITICAL', 5,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(7, 1, 'Dormant Account Reactivation', 'ATO-R-007',
 'account_status = ''dormant'' AND DATEDIFF(''day'', last_login_ts, event_ts) > 90',
 'Login attempt on account dormant for 90+ days, potential dormant account takeover',
 'STEP_UP', 'HIGH', 11,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'fraud_ops_admin', 'ciso'),

-- ===== MFA POLICY (policy_id = 2) =====
(8, 2, 'MFA Required for High-Value Accounts', 'MFA-R-001',
 'account_tier = ''high_value'' AND auth_method NOT IN (''TOTP'', ''FIDO2'')',
 'High-value account login without strong MFA (TOTP or FIDO2) requires step-up challenge',
 'STEP_UP', 'HIGH', 12,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

(9, 2, 'MFA Bypass on New Device', 'MFA-R-002',
 'is_trusted = FALSE AND mfa_enrolled = TRUE',
 'Login from untrusted device by MFA-enrolled user requires step-up challenge',
 'STEP_UP', 'HIGH', 13,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

(10, 2, 'SMS MFA Downgrade Alert', 'MFA-R-003',
 'mfa_method = ''SMS'' AND account_tier = ''high_value''',
 'High-value account using SMS-based MFA (vulnerable to SIM-swap) should be upgraded to TOTP/FIDO2',
 'NOTIFY_CUSTOMER', 'MEDIUM', 20,
 '2025-06-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

(11, 2, 'FIDO2 Fallback to Password', 'MFA-R-004',
 'mfa_method = ''FIDO2'' AND auth_method = ''password''',
 'User enrolled in FIDO2 but logged in with password only, possible downgrade attack',
 'STEP_UP', 'HIGH', 14,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

-- ===== LOCKOUT POLICY (policy_id = 3) =====
(12, 3, 'Progressive Lockout - 5 Failures', 'LOCK-R-001',
 'failed_login_count_1h >= 5',
 'Five or more failed login attempts within 1 hour triggers temporary lockout',
 'LOCKOUT', 'HIGH', 6,
 '2025-03-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'fraud_ops_admin', 'ciso'),

(13, 3, 'Progressive Lockout - 10 Failures', 'LOCK-R-002',
 'failed_login_count_1h >= 10',
 'Ten or more failed login attempts within 1 hour triggers extended lockout',
 'LOCKOUT', 'HIGH', 7,
 '2025-03-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(14, 3, 'Permanent Lock - 20 Failures', 'LOCK-R-003',
 'failed_login_count_24h >= 20',
 'Twenty or more failed login attempts within 24 hours triggers permanent lock requiring manual review',
 'BLOCK', 'CRITICAL', 8,
 '2025-03-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(15, 3, 'Distributed Brute Force', 'LOCK-R-004',
 'distinct_ip_count_24h >= 10 AND failed_login_count_24h >= 15',
 'Failed logins from 10+ distinct IPs in 24 hours indicates distributed brute force attack',
 'BLOCK', 'CRITICAL', 9,
 '2025-03-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

-- ===== TRANSACTION MONITORING POLICY (policy_id = 4) =====
(16, 4, 'High-Value Transaction Anomaly', 'TXN-R-001',
 'transaction_amount > 10000 AND amount_zscore > 3',
 'Transaction exceeds $10,000 and is more than 3 standard deviations from customer average',
 'ESCALATE', 'CRITICAL', 15,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'compliance_officer', 'cfo'),

(17, 4, 'Transaction Velocity Breach', 'TXN-R-002',
 'txn_count_1h > 10',
 'More than 10 transactions within 1 hour indicates potential automated fraud',
 'STEP_UP', 'HIGH', 16,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'cfo'),

(18, 4, 'Geo-Fencing Violation', 'TXN-R-003',
 'country_code NOT IN (SELECT country_code FROM RAW_CUSTOMER_ACCOUNTS WHERE customer_id = login_events.customer_id)',
 'Transaction from country different from customer registered country',
 'STEP_UP', 'MEDIUM', 17,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'cfo'),

(19, 4, 'SAR Filing Threshold', 'TXN-R-004',
 'risk_score > 900 AND transaction_amount > 5000',
 'Risk score above 900 with transaction over $5,000 triggers Suspicious Activity Report filing requirement',
 'FILE_SAR', 'CRITICAL', 18,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'compliance_officer', 'cfo'),

(20, 4, 'Rapid Post-Login Transaction', 'TXN-R-005',
 'DATEDIFF(''second'', event_ts, first_txn_ts) < 60',
 'Transaction initiated within 60 seconds of login, common in automated ATO attacks',
 'STEP_UP', 'HIGH', 19,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'cfo'),

-- ===== CUSTOMER NOTIFICATION POLICY (policy_id = 5) =====
(21, 5, 'Block Event Notification', 'NOTIF-R-001',
 'risk_tier = ''BLOCK''',
 'Customer must be notified immediately when a login attempt is blocked',
 'NOTIFY_CUSTOMER', 'HIGH', 21,
 '2025-06-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

(22, 5, 'Profile Change Alert', 'NOTIF-R-002',
 'change_type IN (''email'', ''phone'') AND is_fraud = FALSE',
 'Customer notified of email or phone changes to detect unauthorized modifications',
 'NOTIFY_CUSTOMER', 'MEDIUM', 22,
 '2025-06-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

(23, 5, 'New Device Login Alert', 'NOTIF-R-003',
 'is_trusted = FALSE',
 'Customer notified when login occurs from a previously unseen device',
 'NOTIFY_CUSTOMER', 'LOW', 23,
 '2025-06-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

(24, 5, 'Step-Up Challenge Notification', 'NOTIF-R-004',
 'risk_tier = ''STEP_UP''',
 'Customer receives context about why additional authentication was required',
 'NOTIFY_CUSTOMER', 'LOW', 24,
 '2025-06-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'compliance_officer', 'ciso'),

-- ===== FRAUD INVESTIGATION POLICY (policy_id = 6) =====
(25, 6, 'Auto-Escalate Ring Fraud', 'INV-R-001',
 'graph_component_size > 10',
 'Identity graph shows cluster of 10+ linked accounts, indicating organized fraud ring',
 'REFER_LAW_ENFORCEMENT', 'CRITICAL', 25,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(26, 6, 'SAR-Triggered Investigation', 'INV-R-002',
 'risk_score > 900 AND transaction_amount > 5000',
 'Cases meeting SAR threshold automatically create investigation ticket',
 'ESCALATE', 'CRITICAL', 26,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(27, 6, 'SIM-Swap Correlated Alert', 'INV-R-003',
 'sim_swap_flag = TRUE AND change_type = ''phone''',
 'SIM-swap threat intel flag correlates with recent phone number change on account',
 'ESCALATE', 'CRITICAL', 27,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(28, 6, 'RAT-Assisted Attack', 'INV-R-004',
 'is_trusted = TRUE AND mouse_movement_entropy < 0.3 AND keystroke_std_ms < 15',
 'Trusted device with abnormal behavioral biometrics indicates Remote Access Trojan',
 'ESCALATE', 'CRITICAL', 28,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(29, 6, 'Multi-Scenario Account', 'INV-R-005',
 'COUNT(DISTINCT fraud_scenario) >= 2',
 'Account shows indicators of two or more distinct attack scenarios, priority investigation',
 'ESCALATE', 'CRITICAL', 29,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, TRUE, 'fraud_ops_admin', 'ciso'),

(30, 6, 'Evidence Retention Trigger', 'INV-R-006',
 'risk_tier = ''BLOCK'' OR risk_score > 800',
 'Login events meeting this criteria must have full session telemetry preserved for investigation',
 'ESCALATE', 'HIGH', 30,
 '2025-01-01'::TIMESTAMP_NTZ, NULL, TRUE, FALSE, 'fraud_ops_admin', 'ciso');

