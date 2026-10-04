-- ============================================================================
-- Policies: 02_MFA_POLICY.sql
-- Multi-Factor Authentication Policy - Section-chunked inserts for Cortex Search
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS VALUES
(201, 'Multi-Factor Authentication Policy', 'MFA', 'Section 1.0', 'MFA Enrollment and Tiered Requirements',
 'Multi-Factor Authentication (MFA) is mandatory for all high-value consumer accounts (top 10% by balance or transaction volume) and all administrative roles. Standard accounts must be strongly encouraged to enroll during onboarding. High-value accounts that lack strong MFA enrollment shall be restricted from high-limit wire transfers and profile modifications until authentication security is upgraded.',
 'ATO_COMPLIANCE', '2025-01-01', 'NIST SP 800-63B Section 4.0; PSD2 SCA'),

(202, 'Multi-Factor Authentication Policy', 'MFA', 'Section 2.0', 'Approved Authenticator Types and Security Hierarchy',
 'Authenticators are classified into three distinct security tiers:
1. Phishing-Resistant Authenticators (Tier 1 - Preferred): FIDO2 / WebAuthn hardware security keys and platform passkeys. Mandatory for administrators and high-risk operations.
2. Time-Based One-Time Password (Tier 2 - Approved): Software authenticators adhering to RFC 6238 (e.g., Google Authenticator, Microsoft Authenticator, 1Password).
3. Telephony-Based OTP (Tier 3 - Restricted/Deprecated): SMS and voice delivery OTP. Permitted only as legacy fallback for standard accounts. Prohibited for high-value accounts due to known vulnerabilities including SIM-swapping and SS7 interception.',
 'ATO_COMPLIANCE', '2025-01-01', 'NIST SP 800-63B Section 5.1; CISA MFA Guidance'),

(203, 'Multi-Factor Authentication Policy', 'MFA', 'Section 3.0', 'Adaptive Step-Up Authentication Triggers',
 'Adaptive step-up challenges are automatically enforced whenever a session exhibits risk signals within the STEP-UP range (score 350-749), including: (a) Login from a previously unrecognized device fingerprint; (b) Access from a foreign country or unexpected geographic region; (c) Connection via commercial VPN or anonymizing proxy; (d) High-value transaction initiation exceeding $5,000; or (e) Account profile modification attempts occurring within 24 hours of login.',
 'ATO_COMPLIANCE', '2025-01-01', 'PSD2 RTS Art.97'),

(204, 'Multi-Factor Authentication Policy', 'MFA', 'Section 4.0', 'MFA Bypass and Recovery Procedures',
 'Customer account recovery following lost authenticators must enforce out-of-band identity verification, including multi-factor document inspection, selfie liveness verification, or verification with customer service supervisors. In no circumstance may customer service bypass MFA via single-factor email link without secondary identity proofing. All manual bypasses require supervisor sign-off logged in the compliance audit trail.',
 'ATO_COMPLIANCE', '2025-01-01', 'NIST SP 800-63A Identity Assurance Level 2');
