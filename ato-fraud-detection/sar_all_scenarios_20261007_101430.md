# COMBINED SAR / COMPLIANCE AUDIT — ALL 10 ATO SCENARIOS
**Generated:** `2026-10-07 10:14:30 UTC`
**Scenarios Covered:** 10/10
**Pipeline:** 4-Layer Ensemble V2 (XGBoost + Isolation Forest + Graph Risk + Meta-Blender)

---

# SAR / COMPLIANCE AUDIT REPORT — BOT AUTOMATION
**Document Reference:** `SAR-ATO-4855921-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:19 UTC`
**Scenario Under Test:** `bot_automation`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4855921` |
| **Customer** | `#999` (Tier: `high_value`, Home: `US`) |
| **Timestamp** | `2026-09-04 07:56:01` |
| **Attack Vector** | **`BOT_AUTOMATION`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 229.76.144.146 (BR) | VPN: True | Tor: False | Proxy: False
  Device: b4a33b1b9b199cba... (desktop/Windows/Firefox)
  Auth: password | MFA: True (SMS)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 524,274.7 km/h (14,563.3 km in 100s)
  Failed Logins (1h): 0 | IP Velocity: 1
  Behavioral Risk: 100 | Automation: True
  Threat: IP=0/100, Device=75/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `MFA-R-001` | MFA Required for High-Value Accounts | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Fraud Investigation Policy** — Section 1.0 - Investigation Workflow
  Owner: `ATO_FRAUD_OPS` | Ref: `FFIEC Fraud Risk Management Guidelines`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Standards for Safeguarding Customer Information (FTC Safeguards Rule)**
  Agency: Federal Trade Commission | Citation: `2021-25736` (86 FR 70272) | Status: `Final Rule`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:44270388861972786`


---

# SAR / COMPLIANCE AUDIT REPORT — BRUTE FORCE
**Document Reference:** `SAR-ATO-4855292-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:21 UTC`
**Scenario Under Test:** `brute_force`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4855292` |
| **Customer** | `#993` (Tier: `high_value`, Home: `US`) |
| **Timestamp** | `2026-09-25 07:26:07` |
| **Attack Vector** | **`BRUTE_FORCE`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 223.240.36.103 (VN) | VPN: False | Tor: True | Proxy: True
  Device: 263d6eb99438dc15... (desktop/Linux/Chrome)
  Auth: password | MFA: True (SMS)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 4,147.2 km/h (13,926.4 km in 12089s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=0/100, Device=74/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `MFA-R-001` | MFA Required for High-Value Accounts | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Lockout Policy** — Section 2.0 - Permanent Lockout Criteria
  Owner: `ATO_FRAUD_OPS` | Ref: `FFIEC Fraud Guidelines`

- **Account Lockout Policy** — Section 1.0 - Progressive Lockout Thresholds
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B Section 5.2.2`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Consumer Financial Protection Circular 2022-04: Insufficient Data Security Practices and Multi-Factor Authentication**
  Agency: Consumer Financial Protection Bureau | Citation: `2022-17231` (87 FR 49514) | Status: `Policy Statement / Circular`

- **Interagency Guidance on Authentication and Access to Financial Institution Services and Systems**
  Agency: Comptroller of the Currency, Federal Reserve System, Federal Deposit Insurance Corporation | Citation: `2021-16012` (86 FR 46294) | Status: `Final Interagency Guidance`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:-4229663517705868831`


---

# SAR / COMPLIANCE AUDIT REPORT — CREDENTIAL STUFFING
**Document Reference:** `SAR-ATO-4856021-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:22 UTC`
**Scenario Under Test:** `credential_stuffing`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4856021` |
| **Customer** | `#1000` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-12 09:39:39` |
| **Attack Vector** | **`CREDENTIAL_STUFFING`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 180.23.39.219 (CN) | VPN: True | Tor: False | Proxy: False
  Device: d07e8d360b118dec... (mobile/Windows/Firefox)
  Auth: password | MFA: True (TOTP)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 6,084.4 km/h (7,818.5 km in 4626s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 100 | Automation: True
  Threat: IP=0/100, Device=76/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-001` | Credential Stuffing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Account Takeover Policy** — Section 1.0 - Purpose and Scope
  Owner: `ATO_FRAUD_OPS` | Ref: `FFIEC Authentication Guidance; PSD2 Art.97`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Standards for Safeguarding Customer Information (FTC Safeguards Rule)**
  Agency: Federal Trade Commission | Citation: `2021-25736` (86 FR 70272) | Status: `Final Rule`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:4611571011018977000`


---

# SAR / COMPLIANCE AUDIT REPORT — DEVICE SPOOFING
**Document Reference:** `SAR-ATO-4854218-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:23 UTC`
**Scenario Under Test:** `device_spoofing`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4854218` |
| **Customer** | `#982` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-07 07:00:25` |
| **Attack Vector** | **`DEVICE_SPOOFING`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 212.215.228.226 (BR) | VPN: False | Tor: False | Proxy: True
  Device: 6276be6c89d3d744... (mobile/Linux/Chrome)
  Auth: password | MFA: False (None)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 8,969.5 km/h (9,021.8 km in 3621s)
  Failed Logins (1h): 3 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=0/100, Device=58/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Multi-Factor Authentication Policy** — Section 3.0 - Adaptive Step-Up Authentication Triggers
  Owner: `ATO_COMPLIANCE` | Ref: `PSD2 RTS Art.97`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Financial Crimes Enforcement Network: Anti-Money Laundering Regulations and Customer Due Diligence**
  Agency: Financial Crimes Enforcement Network | Citation: `2020-22201` (85 FR 65712) | Status: `Final Rule`

- **Interagency Guidance on Authentication and Access to Financial Institution Services and Systems**
  Agency: Comptroller of the Currency, Federal Reserve System, Federal Deposit Insurance Corporation | Citation: `2021-16012` (86 FR 46294) | Status: `Final Interagency Guidance`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:-6412657978822021286`


---

# SAR / COMPLIANCE AUDIT REPORT — DORMANT REACTIVATION
**Document Reference:** `SAR-ATO-4837725-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:24 UTC`
**Scenario Under Test:** `dormant_reactivation`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4837725` |
| **Customer** | `#818` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-13 09:32:32` |
| **Attack Vector** | **`DORMANT_REACTIVATION`** |
| **Risk Score** | `981/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 198.66.183.242 (VN) | VPN: False | Tor: False | Proxy: False
  Device: 254a72b5659bfaae... (desktop/Linux/Chrome)
  Auth: password | MFA: True (SMS)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 3,448.2 km/h (19,158.8 km in 20002s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=64/100, Device=55/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 981/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Multi-Factor Authentication Policy** — Section 4.0 - MFA Bypass and Recovery Procedures
  Owner: `ATO_COMPLIANCE` | Ref: `NIST SP 800-63A Identity Assurance Level 2`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Financial Crimes Enforcement Network: Anti-Money Laundering Regulations and Customer Due Diligence**
  Agency: Financial Crimes Enforcement Network | Citation: `2020-22201` (85 FR 65712) | Status: `Final Rule`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 981/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:-3442858222785968647`


---

# SAR / COMPLIANCE AUDIT REPORT — IMPOSSIBLE TRAVEL
**Document Reference:** `SAR-ATO-4779045-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:25 UTC`
**Scenario Under Test:** `impossible_travel`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4779045` |
| **Customer** | `#231` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-30 21:50:42` |
| **Attack Vector** | **`IMPOSSIBLE_TRAVEL`** |
| **Risk Score** | `576/1000` (HIGH) |
| **Decision** | **`STEP-UP`** — Escalated Multi-Factor Verification Required |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 211.105.128.133 (RU) | VPN: False | Tor: False | Proxy: False
  Device: eb484c20792fec72... (desktop/Android/Chrome)
  Auth: password | MFA: True (SMS)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 11,511.4 km/h (7,802.2 km in 2440s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=63/100, Device=70/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.9388
  L2 IForest:  score=0.2961
  L3 Graph:    score=60/100 | Ring=True | Component=19
  L4 Ensemble: 576/1000 -> STEP-UP
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 4.0 - High-Risk Geo-Velocity and Impossible Travel Controls
  Owner: `ATO_FRAUD_OPS` | Ref: `FFIEC Guidance Appendix B`

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Standards for Safeguarding Customer Information (FTC Safeguards Rule)**
  Agency: Federal Trade Commission | Citation: `2021-25736` (86 FR 70272) | Status: `Final Rule`

- **Consumer Financial Protection Circular 2022-04: Insufficient Data Security Practices and Multi-Factor Authentication**
  Agency: Consumer Financial Protection Bureau | Citation: `2022-17231` (87 FR 49514) | Status: `Policy Statement / Circular`

---

## 6. DISPOSITION

- **Gateway Response:** `STEP-UP` — Escalated Multi-Factor Verification Required
- **Ensemble Basis:** 576/1000, tier STEP-UP
- **SAR Filing:** Recommended
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:2119323898760619117`


---

# SAR / COMPLIANCE AUDIT REPORT — NEW DEVICE RECOVERY ABUSE
**Document Reference:** `SAR-ATO-4840438-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:27 UTC`
**Scenario Under Test:** `new_device_recovery_abuse`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4840438` |
| **Customer** | `#845` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-12 10:48:02` |
| **Attack Vector** | **`NEW_DEVICE_RECOVERY_ABUSE`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 225.147.137.104 (NG) | VPN: False | Tor: False | Proxy: False
  Device: ec44524798e31861... (desktop/Windows/Firefox)
  Auth: password | MFA: False (None)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 4,538.5 km/h (8,333.2 km in 6610s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=65/100, Device=73/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Multi-Factor Authentication Policy** — Section 4.0 - MFA Bypass and Recovery Procedures
  Owner: `ATO_COMPLIANCE` | Ref: `NIST SP 800-63A Identity Assurance Level 2`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Consumer Financial Protection Circular 2022-04: Insufficient Data Security Practices and Multi-Factor Authentication**
  Agency: Consumer Financial Protection Bureau | Citation: `2022-17231` (87 FR 49514) | Status: `Policy Statement / Circular`

- **Protecting Consumers From Unauthorized Transfers and Account Takeover in Digital Banking**
  Agency: Consumer Financial Protection Bureau | Citation: `2023-28828` (89 FR 1284) | Status: `Notice of Proposed Rulemaking`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:3196098957112883377`


---

# SAR / COMPLIANCE AUDIT REPORT — RAT ASSISTED
**Document Reference:** `SAR-ATO-4816640-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:28 UTC`
**Scenario Under Test:** `rat_assisted`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4816640` |
| **Customer** | `#607` (Tier: `high_value`, Home: `US`) |
| **Timestamp** | `2026-09-11 10:25:16` |
| **Attack Vector** | **`RAT_ASSISTED`** |
| **Risk Score** | `925/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 187.203.51.2 (BR) | VPN: False | Tor: False | Proxy: True
  Device: 5cc47a29b9cb65ac... (desktop/macOS/Edge)
  Auth: password | MFA: True (TOTP)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 1,042.0 km/h (14,192.1 km in 49030s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 10 | Automation: False
  Threat: IP=0/100, Device=0/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 925/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `MFA-R-001` | MFA Required for High-Value Accounts | **HIGH** | `STEP_UP` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Multi-Factor Authentication Policy** — Section 3.0 - Adaptive Step-Up Authentication Triggers
  Owner: `ATO_COMPLIANCE` | Ref: `PSD2 RTS Art.97`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Cybersecurity Incident Reporting for Critical Infrastructure Act (CIRCIA) Proposed Rule**
  Agency: Cybersecurity and Infrastructure Security Agency | Citation: `2023-14903` (88 FR 20112) | Status: `Notice of Proposed Rulemaking`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 925/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:-40397849537067979`


---

# SAR / COMPLIANCE AUDIT REPORT — SESSION REPLAY
**Document Reference:** `SAR-ATO-4842336-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:30 UTC`
**Scenario Under Test:** `session_replay`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4842336` |
| **Customer** | `#864` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-21 09:09:27` |
| **Attack Vector** | **`SESSION_REPLAY`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 194.17.171.199 (CN) | VPN: False | Tor: False | Proxy: True
  Device: 45e4ef4061690089... (desktop/Windows/Chrome)
  Auth: password | MFA: True (SMS)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 2,552.5 km/h (11,021.0 km in 15544s)
  Failed Logins (1h): 4 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=96/100, Device=71/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-005` | Device Spoofing Detection | **CRITICAL** | `BLOCK` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `MFA-R-002` | MFA Bypass on New Device | **HIGH** | `STEP_UP` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Fraud Investigation Policy** — Section 2.0 - Evidence Preservation
  Owner: `ATO_FRAUD_OPS` | Ref: `Federal Rules of Evidence 902(13); 18 U.S.C. 1030`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Interagency Guidance on Authentication and Access to Financial Institution Services and Systems**
  Agency: Comptroller of the Currency, Federal Reserve System, Federal Deposit Insurance Corporation | Citation: `2021-16012` (86 FR 46294) | Status: `Final Interagency Guidance`

- **Standards for Safeguarding Customer Information (FTC Safeguards Rule)**
  Agency: Federal Trade Commission | Citation: `2021-25736` (86 FR 70272) | Status: `Final Rule`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:-4589091004647030264`


---

# SAR / COMPLIANCE AUDIT REPORT — SIM SWAP
**Document Reference:** `SAR-ATO-4827565-20261007`
**Classification:** `STRICTLY CONFIDENTIAL // LAW ENFORCEMENT & REGULATORY AUDIT ONLY`
**Generated:** `2026-10-07 10:14:30 UTC`
**Scenario Under Test:** `sim_swap`

---

## 1. INCIDENT SUMMARY

| Attribute | Detail |
| :--- | :--- |
| **Event ID** | `#4827565` |
| **Customer** | `#716` (Tier: `standard`, Home: `US`) |
| **Timestamp** | `2026-09-19 22:38:14` |
| **Attack Vector** | **`SIM_SWAP`** |
| **Risk Score** | `1000/1000` (CRITICAL) |
| **Decision** | **`BLOCK`** — Immediate Session Interception & Hard Lockout |
| **Primary Risk Factor** | `Impossible travel detected (>1000 km/h)` |

---

## 2. SIGNAL & FEATURE LINEAGE

```
[RAW SIGNAL]
  IP: 196.199.84.199 (NG) | VPN: False | Tor: False | Proxy: True
  Device: 9ebb01cebe4a7c74... (desktop/Windows/Firefox)
  Auth: SMS_OTP | MFA: False (None)

[STREAMING FEATURES (1-Min Lag)]
  Geo-Velocity: 10,552.0 km/h (6,460.2 km in 2204s)
  Failed Logins (1h): 5 | IP Velocity: 1
  Behavioral Risk: 0 | Automation: False
  Threat: IP=0/100, Device=75/100

[4-LAYER ENSEMBLE (V2)]
  L1 XGBoost:  prob=0.0000
  L2 IForest:  score=0.0000
  L3 Graph:    score=0/100 | Ring=False | Component=1
  L4 Ensemble: 1000/1000 -> BLOCK
```

---

## 3. POLICY RULE EVALUATIONS

| Rule Code | Rule Name | Severity | Action |
| :--- | :--- | :--- | :--- |
| `ATO-R-002` | Impossible Travel Detection | **CRITICAL** | `BLOCK` |
| `ATO-R-003` | Critical Risk Score Threshold | **CRITICAL** | `BLOCK` |
| `LOCK-R-001` | Progressive Lockout - 5 Failures | **HIGH** | `LOCKOUT` |
| `NOTIF-R-001` | Block Event Notification | **HIGH** | `NOTIFY_CUSTOMER` |
| `NOTIF-R-003` | New Device Login Alert | **LOW** | `NOTIFY_CUSTOMER` |
| `INV-R-003` | SIM-Swap Correlated Alert | **CRITICAL** | `ESCALATE` |

---

## 4. INTERNAL POLICY COMPLIANCE (CORTEX SEARCH)

- **Account Takeover Policy** — Section 2.0 - Attack Vectors Covered
  Owner: `ATO_FRAUD_OPS` | Ref: `NIST SP 800-63B; MITRE ATT&CK T1078`

- **Multi-Factor Authentication Policy** — Section 4.0 - MFA Bypass and Recovery Procedures
  Owner: `ATO_COMPLIANCE` | Ref: `NIST SP 800-63A Identity Assurance Level 2`

---

## 5. REGULATORY MANDATES (FEDERAL REGISTER)

- **Protecting Consumers From Unauthorized Transfers and Account Takeover in Digital Banking**
  Agency: Consumer Financial Protection Bureau | Citation: `2023-28828` (89 FR 1284) | Status: `Notice of Proposed Rulemaking`

- **Consumer Financial Protection Circular 2022-04: Insufficient Data Security Practices and Multi-Factor Authentication**
  Agency: Consumer Financial Protection Bureau | Citation: `2022-17231` (87 FR 49514) | Status: `Policy Statement / Circular`

---

## 6. DISPOSITION

- **Gateway Response:** `BLOCK` — Immediate Session Interception & Hard Lockout
- **Ensemble Basis:** 1000/1000, tier BLOCK
- **SAR Filing:** Required
- **Model Integrity:** All 4 layers verified leakage-free (Ensemble V2)
- **Audit Signature:** `SHA256:-6511025931043722654`


---

