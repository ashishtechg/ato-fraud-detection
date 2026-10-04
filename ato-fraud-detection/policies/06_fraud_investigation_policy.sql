-- ============================================================================
-- Policies: 06_FRAUD_INVESTIGATION_POLICY.sql
-- Fraud Investigation Policy - Section-chunked inserts for Cortex Search
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS VALUES
(601, 'Fraud Investigation Policy', 'INVESTIGATION', 'Section 1.0', 'Case Intake, Triage, and Investigation Workflow',
 'The Fraud Operations investigation lifecycle adheres to a standardized four-stage operational workflow:
Stage 1: Automated Triage & Queue Assignment. Cases are generated automatically from DT_SCORED_LOGINS for all BLOCK decisions and high-severity rule violations. High-value customer accounts and fraud rings receive Priority 1 routing.
Stage 2: Comprehensive Evidence Collection. Analysts must extract full session telemetry, keystroke dynamics, device hardware hashes, IP threat intelligence feeds, and linked account clusters from the Identity Graph.
Stage 3: Behavioral & Root-Cause Analysis. Analysts evaluate whether the breach stemmed from phishing, malware/RAT, credential stuffing, or SIM-swapping.
Stage 4: Resolution & Remediation. Restitution processing, account re-securing, credential resets, and final SAR filing documentation.',
 'ATO_FRAUD_OPS', '2025-01-01', 'FFIEC Fraud Risk Management Guidelines'),

(602, 'Fraud Investigation Policy', 'INVESTIGATION', 'Section 2.0', 'Evidence Preservation and Chain of Custody',
 'For all flagged investigations (rule INV-R-006), full digital artifacts must be preserved in immutable Snowflake storage for a minimum statutory retention period of seven (7) years. Preserved artifacts must include: raw session biometrics, TLS JA3 hashes, full HTTP user agent strings, IP connection logs, and snapshot audit trails of the POLICY_RULE_EVALUATION table.',
 'ATO_FRAUD_OPS', '2025-01-01', 'Federal Rules of Evidence 902(13); 18 U.S.C. 1030'),

(603, 'Fraud Investigation Policy', 'INVESTIGATION', 'Section 3.0', 'Organized Fraud Ring Escalation and Law Enforcement Referrals',
 'Whenever the Identity Graph reveals an interconnected cluster of ten (10) or more compromised customer accounts sharing common device fingerprints, IP subnets, or phone numbers (rule INV-R-001, graph_component_size >= 10), the investigation must be designated an Organized Fraud Syndicate. The case requires mandatory immediate escalation to the Fraud Director and formal criminal referral to federal law enforcement authorities (FBI Internet Crime Complaint Center IC3, US Secret Service Cyber Fraud Task Force).',
 'ATO_FRAUD_OPS', '2025-01-01', '18 U.S.C. 1343 Wire Fraud; FinCEN Advisory FIN-2022-A001'),

(604, 'Fraud Investigation Policy', 'INVESTIGATION', 'Section 4.0', 'Investigation Service Level Agreements (SLAs)',
 'Investigation triage and preliminary containment must meet strict institutional SLA targets:
- Priority 1 (High-Value Account / Losses > $10,000 / Fraud Ring): Initial containment within two (2) hours; formal case completion within twenty-four (24) hours.
- Priority 2 (Standard Account BLOCK / Multi-Scenario Attack): Initial containment within eight (8) hours; case resolution within forty-eight (48) hours.
- Priority 3 (General Inquiries / Step-Up False Positives): Investigation completed within seventy-two (72) hours.',
 'ATO_FRAUD_OPS', '2025-01-01', 'FFIEC Compliance SLA Standards');
