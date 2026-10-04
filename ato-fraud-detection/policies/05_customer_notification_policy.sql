-- ============================================================================
-- Policies: 05_CUSTOMER_NOTIFICATION_POLICY.sql
-- Customer Notification Policy - Section-chunked inserts for Cortex Search
-- ============================================================================

INSERT INTO ATO_FRAUD_DB.POLICY_ENGINE.ATO_POLICY_DOCUMENTS VALUES
(501, 'Customer Notification Policy', 'NOTIFICATION', 'Section 1.0', 'Mandatory Security Notification Triggers',
 'To ensure transparency and rapid fraud containment, automated notifications must be dispatched to consumers upon occurrence of any of the following security events:
1. Blocked Authentication: Immediate alert dispatched when a login is intercepted at the BLOCK tier (rule NOTIF-R-001).
2. Profile Mutation: Real-time confirmation sent when an email address, mobile phone number, or physical address is updated (rule NOTIF-R-002).
3. New Device Registration: Notification sent upon first successful authentication from an unrecognized hardware fingerprint (rule NOTIF-R-003).
4. Adaptive Challenge Issuance: Notification providing contextual explanation when step-up verification is invoked.',
 'ATO_COMPLIANCE', '2025-06-01', 'Regulation E 12 CFR 1005.6; PSD2 Art.72'),

(502, 'Customer Notification Policy', 'NOTIFICATION', 'Section 2.0', 'Delivery Channels, Multi-Channel Routing, and SLAs',
 'Security alerts must be routed through out-of-band channels independent of the channel initiating the change:
- Primary Delivery: Secure push notification via registered mobile banking app and registered email address.
- Secondary Delivery: SMS text alert dispatched to the historical phone number on record (never solely to a newly submitted phone number).
- Delivery SLA: Security notifications must be delivered within sixty (60) seconds of the triggering security event.',
 'ATO_COMPLIANCE', '2025-06-01', 'CFPB Consumer Financial Protection Circular 2022-04'),

(503, 'Customer Notification Policy', 'NOTIFICATION', 'Section 3.0', 'Regulatory Disclosures under Regulation E and PSD2',
 'Under Regulation E (Electronic Fund Transfers), notifications regarding unauthorized access must clearly provide consumers with zero-liability reporting instructions, emergency fraud hotline contact numbers, and immediate one-click account suspension links. For European consumers, notifications must comply with PSD2 Article 72 requirements for incident notification and evidence disclosure.',
 'ATO_COMPLIANCE', '2025-06-01', '12 CFR Part 1005 (Regulation E); PSD2 Directive 2015/2366');
