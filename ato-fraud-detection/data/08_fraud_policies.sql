-- ============================================================================
-- 08: FRAUD_POLICY - 6 master policy records
-- Policy register with lifecycle tracking
-- ============================================================================

CREATE SCHEMA IF NOT EXISTS ATO_FRAUD_DB.POLICY_ENGINE;

CREATE OR REPLACE TABLE ATO_FRAUD_DB.POLICY_ENGINE.FRAUD_POLICY (
    policy_id               INT PRIMARY KEY,
    policy_name             VARCHAR(100),
    policy_category         VARCHAR(30),       -- ATO, MFA, LOCKOUT, TRANSACTION_MONITORING, NOTIFICATION, INVESTIGATION
    description             VARCHAR(1000),
    owner_role              VARCHAR(50),
    effective_from          TIMESTAMP_NTZ,
    effective_to            TIMESTAMP_NTZ,     -- NULL = currently active
    review_cadence_days     INT,
    last_reviewed_at        TIMESTAMP_NTZ,
    regulatory_reference    VARCHAR(200),
    status                  VARCHAR(20)        -- DRAFT, ACTIVE, UNDER_REVIEW, DEPRECATED
);

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.FRAUD_POLICY VALUES
(1, 'Account Takeover Policy',
 'ATO',
 'Defines the three-tier response model (SAFE/STEP-UP/BLOCK) for login risk scoring, threshold governance, customer communication requirements, and regulatory reporting obligations for account takeover events.',
 'ATO_FRAUD_OPS',
 '2025-01-01'::TIMESTAMP_NTZ, NULL, 90,
 '2026-07-01'::TIMESTAMP_NTZ,
 'FFIEC Authentication Guidance; PSD2 Art.97',
 'ACTIVE'),

(2, 'Multi-Factor Authentication Policy',
 'MFA',
 'MFA enrollment requirements by account tier, supported methods (TOTP/SMS/FIDO2), step-up challenge triggers, MFA bypass handling, recovery procedures, and exemption approval workflows.',
 'ATO_COMPLIANCE',
 '2025-01-01'::TIMESTAMP_NTZ, NULL, 90,
 '2026-07-01'::TIMESTAMP_NTZ,
 'NIST SP 800-63B; PSD2 SCA',
 'ACTIVE'),

(3, 'Account Lockout Policy',
 'LOCKOUT',
 'Lockout thresholds (failed attempts per time window), progressive lockout durations, permanent lock criteria, unlock procedures, fraud ops override authority, and customer self-service unlock rules.',
 'ATO_FRAUD_OPS',
 '2025-03-01'::TIMESTAMP_NTZ, NULL, 180,
 '2026-06-01'::TIMESTAMP_NTZ,
 'NIST SP 800-63B Section 5.2.2',
 'ACTIVE'),

(4, 'Transaction Monitoring Policy',
 'TRANSACTION_MONITORING',
 'Real-time vs batch monitoring scopes, amount thresholds by tier, velocity rules, merchant category restrictions, geo-fencing rules, SAR filing criteria, and PEP/sanctions screening requirements.',
 'ATO_COMPLIANCE',
 '2025-01-01'::TIMESTAMP_NTZ, NULL, 90,
 '2026-08-01'::TIMESTAMP_NTZ,
 'BSA/AML; FinCEN SAR requirements; Reg E',
 'ACTIVE'),

(5, 'Customer Notification Policy',
 'NOTIFICATION',
 'Notification triggers (STEP-UP challenge, BLOCK, profile change, new device), delivery channels (email/SMS/push/in-app), timing SLAs, content templates, and regulatory notification requirements.',
 'ATO_COMPLIANCE',
 '2025-06-01'::TIMESTAMP_NTZ, NULL, 180,
 '2026-06-01'::TIMESTAMP_NTZ,
 'Reg E Section 205.6; PSD2 Art.72',
 'ACTIVE'),

(6, 'Fraud Investigation Policy',
 'INVESTIGATION',
 'Case intake criteria, investigation workflow (triage > evidence collection > analysis > resolution), evidence retention requirements, escalation matrix, law enforcement referral criteria, and SLA targets.',
 'ATO_FRAUD_OPS',
 '2025-01-01'::TIMESTAMP_NTZ, NULL, 90,
 '2026-09-01'::TIMESTAMP_NTZ,
 'FFIEC Fraud Risk Management; 18 USC 1030',
 'ACTIVE');

