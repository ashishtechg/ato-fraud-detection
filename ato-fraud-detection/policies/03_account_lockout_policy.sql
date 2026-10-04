-- ============================================================================
-- Policies: 03_ACCOUNT_LOCKOUT_POLICY.sql
-- Account Lockout Policy - Section-chunked inserts for Cortex Search
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS VALUES
(301, 'Account Lockout Policy', 'LOCKOUT', 'Section 1.0', 'Progressive Lockout Thresholds and Durations',
 'To defend against automated credential stuffing and distributed brute-force attacks, the enterprise enforces a progressive lockout schedule:
1. Stage 1 (Initial Threshold): Five (5) consecutive failed authentication attempts within a 1-hour window triggers a 15-minute temporary session lockout.
2. Stage 2 (Extended Threshold): Ten (10) consecutive failed attempts within 1 hour triggers a 60-minute account lockout and issues a security advisory notification to the registered email and phone.
3. Stage 3 (Permanent Lock): Twenty (20) failed attempts within a 24-hour window, or failures originating from ten or more distinct IP addresses, mandates a permanent administrative lock requiring identity verification.',
 'ATO_FRAUD_OPS', '2025-03-01', 'NIST SP 800-63B Section 5.2.2'),

(302, 'Account Lockout Policy', 'LOCKOUT', 'Section 2.0', 'Permanent Lockout Criteria and Escalation',
 'An account placed into permanent administrative lock status (account_status = locked) cannot be unlocked through standard self-service mechanisms. Permanent lockout is enforced when: (a) Velocity limits reach Stage 3; (b) Account is implicated in confirmed credential dumping databases; or (c) Suspicious funds transfer requests correlate with concurrent brute-force activity. The account is routed immediately to the Fraud Operations Priority Queue.',
 'ATO_FRAUD_OPS', '2025-03-01', 'FFIEC Fraud Guidelines'),

(303, 'Account Lockout Policy', 'LOCKOUT', 'Section 3.0', 'Unlock Procedures and Operational Authority',
 'Temporary Stage 1 and Stage 2 lockouts release automatically upon expiration of the lockout duration timer. Permanent administrative locks require manual remediation by an authorized Fraud Analyst (role ATO_FRAUD_OPS). The analyst must verify primary identity documents, validate the originating device fingerprint, confirm recent valid transaction history, and record an approval ticket in the audit register before restoring account status to active.',
 'ATO_FRAUD_OPS', '2025-03-01', 'PCI-DSS v4.0 Requirement 8.3');
