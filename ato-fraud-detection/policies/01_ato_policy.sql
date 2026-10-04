-- ============================================================================
-- Policies: 01_ATO_POLICY.sql
-- Account Takeover Policy - Section-chunked inserts for Cortex Search
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS VALUES
(101, 'Account Takeover Policy', 'ATO', 'Section 1.0', 'Purpose and Scope',
 'This Account Takeover (ATO) Policy establishes the enterprise framework for detecting, intercepting, and responding to unauthorized account access across all digital customer channels. The policy applies to all customer authentication endpoints, including web portals, native mobile applications, APIs, and customer service call centers. The objective is to mitigate financial loss, safeguard consumer assets, and maintain institutional compliance with FFIEC Authentication Guidance and PSD2 Regulatory Technical Standards.',
 'ATO_FRAUD_OPS', '2025-01-01', 'FFIEC Authentication Guidance; PSD2 Art.97'),

(102, 'Account Takeover Policy', 'ATO', 'Section 2.0', 'Attack Vectors Covered',
 'This policy mandates active real-time surveillance across ten recognized ATO attack vectors: (1) Credential Stuffing using automated botnets and distributed ASNs; (2) Impossible Travel where successive authentications exceed physical transportation speeds (>1000 km/h); (3) Device Fingerprint Spoofing using headless emulators and altered canvas/WebGL signatures; (4) Distributed Brute Force attacks against targeted credentials; (5) Session Identifier and Token Replay from foreign IP addresses; (6) Account Recovery Abuse via password reset from untrusted hardware; (7) SIM-Swap attacks hijacking SMS-based verification; (8) Remote Access Trojan (RAT) assisted sessions on legitimate devices; (9) Dormant Account Reactivation after 90+ days of inactivity; and (10) Headless Automation and API scripting.',
 'ATO_FRAUD_OPS', '2025-01-01', 'NIST SP 800-63B; MITRE ATT&CK T1078'),

(103, 'Account Takeover Policy', 'ATO', 'Section 3.0', 'Three-Tier Risk Decision Engine and Thresholds',
 'All incoming authentication events must be evaluated through the multi-layer ensemble scoring model and assigned a unified risk score from 0 to 1000. Decisions are categorized into three mandatory operational tiers:
1. SAFE Tier (Score 0 to 349): Frictionless access granted with standard audit logging. No challenge issued.
2. STEP-UP Tier (Score 350 to 749): Access is conditionally held pending an adaptive out-of-band challenge (FIDO2 WebAuthn, TOTP authenticator, or biometric confirmation).
3. BLOCK Tier (Score 750 to 1000): Authentication attempt is immediately terminated at the login gate. An automated security incident record is created, and customer notifications are triggered. Threshold adjustments require joint approval from Fraud Operations and the Chief Information Security Officer (CISO).',
 'ATO_FRAUD_OPS', '2025-01-01', 'FFIEC Risk Management; PSD2 RTS Art.2'),

(104, 'Account Takeover Policy', 'ATO', 'Section 4.0', 'High-Risk Geo-Velocity and Impossible Travel Controls',
 'A physical displacement velocity exceeding 1,000 kilometers per hour calculated via the Haversine formula between consecutive authentications shall be classified as an impossible travel event. Any login exhibiting geo-velocity > 1,000 km/h must be automatically assigned to the BLOCK tier. If an analyst review determines that a legitimate consumer utilized high-speed satellite connectivity or pre-cleared charter travel, an authorized manager may log a pre-approved travel exemption in the POLICY_RULE_EVALUATION audit log.',
 'ATO_FRAUD_OPS', '2025-01-01', 'FFIEC Guidance Appendix B'),

(105, 'Account Takeover Policy', 'ATO', 'Section 5.0', 'Governance, Audit, and Retraining Cadence',
 'The ATO risk scoring models and threshold parameters must undergo quarterly performance evaluations. Evaluation criteria mandate a minimum true positive catch rate (recall) of >= 75% on confirmed attacks while maintaining a false positive rate (FPR) <= 2.0% across legitimate accounts. Model drift and feature stability shall be reviewed monthly using the Snowflake Model Registry and automated anomaly detection pipelines.',
 'ATO_FRAUD_OPS', '2025-01-01', 'OCC Model Risk Management 2011-12');
