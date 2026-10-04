-- ============================================================================
-- Policies: 04_TRANSACTION_MONITORING_POLICY.sql
-- Transaction Monitoring Policy - Section-chunked inserts for Cortex Search
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS VALUES
(401, 'Transaction Monitoring Policy', 'TRANSACTION_MONITORING', 'Section 1.0', 'Real-Time vs Batch Surveillance Scope',
 'All outbound financial transactions are monitored across dual operational pipelines:
1. Real-Time Scoring: Outbound wire transfers, ACH debits, and peer-to-peer transfers are evaluated inline. Any transaction originating from a session with risk_score >= 750 or marked with unverified profile mutations is placed on immediate hold.
2. Batch Behavioral Analytics: Nightly analytics evaluate 30-day moving averages, spending Z-scores, peer-group deviations, and counterparty reputation to detect subtle long-dwell account takeovers.',
 'ATO_COMPLIANCE', '2025-01-01', 'BSA/AML 31 CFR Chapter X; FinCEN Advisory FIN-2021-A003'),

(402, 'Transaction Monitoring Policy', 'TRANSACTION_MONITORING', 'Section 2.0', 'High-Value Anomaly Rules and Velocity Controls',
 'A financial transaction exceeding $10,000 USD and deviating more than 3.0 standard deviations from the customer historical 90-day moving average shall trigger rule TXN-R-001 (CRITICAL severity). Transactions exhibiting high velocity (>10 transactions within 60 minutes) shall be held for step-up verification. Transactions occurring within 60 seconds of initial authentication (rapid post-login drain) are subject to automated intervention.',
 'ATO_COMPLIANCE', '2025-01-01', 'FFIEC BSA/AML Manual'),

(403, 'Transaction Monitoring Policy', 'TRANSACTION_MONITORING', 'Section 3.0', 'Suspicious Activity Report (SAR) Filing Mandates',
 'A Suspicious Activity Report (SAR) must be filed with the Financial Crimes Enforcement Network (FinCEN) under the following mandatory conditions: (a) Known or suspected unauthorized transaction activity aggregating $5,000 or more with an identifiable suspect; (b) Transaction volume aggregating $25,000 or more regardless of suspect identification; or (c) Any account takeover where risk_score > 900 correlates with funds transfer attempts exceeding $5,000. SAR filings must be submitted within thirty (30) calendar days of initial detection.',
 'ATO_COMPLIANCE', '2025-01-01', 'FinCEN 31 CFR 1020.320; Bank Secrecy Act');
