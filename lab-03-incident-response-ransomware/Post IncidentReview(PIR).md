# Lab 03: Ransomware Incident Response Simulation

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Framework](https://img.shields.io/badge/Framework-NIST%20SP%20800--61-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Lab](https://img.shields.io/badge/Lab-3%20of%206-purple)

**Duration:** 2 days | **Prerequisites:** Labs 1 & 2 | **Difficulty:** Intermediate

---

## Objective

Simulate a realistic multi-stage ransomware attack against a Windows endpoint and execute a complete incident response workflow following the NIST SP 800-61 framework. Document the full process from initial compromise through detection, containment, eradication, and recovery.

---

## Attack Scenario

A phishing document (`Invoice_Q1_2026.docm`) delivers a VBA macro that silently spawns PowerShell, encrypts 200 user files, drops a ransom note, and abuses `certutil.exe` as a LOLBin — all while Splunk captures the full attack chain via Sysmon telemetry.

---

## Ransomware Kill Chain

```
Stage 1: Initial Access        → User opens Invoice_Q1_2026.docm, enables macros
Stage 2: Execution             → WINWORD.EXE spawns powershell.exe via WScript.Shell
Stage 3: Privilege Escalation  → Admin account creation attempted (FAILED - user context)
Stage 4: Discovery             → Enumerates C:\UserData for target files
Stage 5: Encryption            → 200 files encrypted with .encrypted extension
Stage 6: Impact                → README_RANSOM.txt dropped on Desktop + C:\UserData
Stage 7: LOLBin Abuse          → certutil.exe used to base64-encode ransom note
Stage 8: Anti-Forensics        → Payload self-deletes from %TEMP%
```

---

## Environment

| Component | Details |
|---|---|
| **Endpoint** | WIN-ENDPOINT01 (Windows 11) |
| **SIEM** | Splunk Enterprise |
| **Telemetry** | Sysmon + Windows Security + PowerShell Script Block Logging |
| **Attack Vector** | VBA Macro → PowerShell payload |
| **Target Directory** | C:\UserData (200 files across 5 subdirectories) |

---

## Detections

### Lab 2 Detections Triggered

| ID | Name | Severity |
|---|---|---|
| LAB02-02 | PowerShell Encoded Command Execution | Critical |
| LAB02-03 | PowerShell Download Cradle Detected | High |
| LAB02-04 | Living-off-the-Land Binary Execution | Medium |
| LAB02-05 | Office Application Spawning Shell | High |

### New Detections Added in Lab 3

| ID | Name | Severity |
|---|---|---|
| LAB03-07 | Mass File Modification Detected | Critical |
| LAB03-08 | Ransom Note Created | Critical |
| LAB03-09 | Bulk File Encryption Detected | Critical |

**7 of 8 detections fired. Time to detection: 4 minutes.**

---

## Attack Timeline

| Time (HKT) | Stage | Event | MITRE |
|---|---|---|---|
| 14:01:00 | Initial Access | User opened .docm, macros enabled | T1566.001 |
| 14:01:05 | Execution | WINWORD.EXE → powershell.exe | T1059.001 |
| 14:01:10 | Encoded PS | Obfuscated command + download cradle | T1027, T1105 |
| 14:01:15 | Priv Esc | Admin account creation — FAILED | T1136.001 |
| 14:01:20 | Encryption | 200 files encrypted in C:\UserData | T1486 |
| 14:03:05 | Impact | README_RANSOM.txt dropped | T1486 |
| 14:03:10 | LOLBin | certutil.exe -encode | T1140 |
| 14:03:15 | Cleanup | Payload self-deleted | T1070 |
| 14:05:00 | Detection | 7 Splunk alerts fired | — |

---

## IR Metrics

| Metric | Actual | Target | Status |
|---|---|---|---|
| Time to Detection | 4 minutes | < 10 minutes | ✅ |
| Time to Containment | 55 minutes | < 1 hour | ✅ |
| Time to Eradication | 90 minutes | < 4 hours | ✅ |
| Time to Recovery | 2.5 hours | < 8 hours | ✅ |
| False Positive Rate | 0% | < 5% | ✅ |

---

## Screenshots

- [Alerts Triggered](./screenshots/01-alerts-triggered.png)
- [Office Application Spawning Shell](./screenshots/02-office-spawning-shell.png)
- [Bulk File Encryption Detection](./screenshots/03-mass-encryption.png)
- [Ransom Note Alert](./screenshots/04-ransom-note.png)
- [Encrypted Files on Endpoint](./screenshots/05-encrypted-files.png)
- [Ransom Note Desktop](./screenshots/06-ransom-note-desktop.png)
- [Attack Timeline Reconstruction](./screenshots/07-attack-timeline.png)

---

## Key Findings

- **WINWORD.EXE → powershell.exe** confirmed via Sysmon EventCode=1 — highest value detection for macro-based initial access
- **Sysmon requires active tuning** — default SwiftOnSecurity config excluded `.encrypted` files; custom FileCreate rules were added before final run
- **4 minute detection lag** — entire attack completed before first alert; scheduled searches introduce inherent delay that real-time alerting or EDR would eliminate
- **Privilege escalation failed** — macro-spawned PowerShell ran in user context; real ransomware would use a UAC bypass at this stage
- **User-level access is enough** — 200 files encrypted without admin rights; elevated privileges are not required for significant impact

---

## Documentation

- [Post Incident Review — PIR-IR-2026-001](./incident-response/PIR-IR-2026-001.md)
- [Lab 3 Detections](./detections/README.md)
- [Attack Simulation — VBA Macro](./attack-simulation/simulate-ransomware.vba)

---

## Related Labs

| Lab | Topic | Status |
|---|---|---|
| [Lab 1: SIEM Deployment](../lab-01-siem-deployment) | Enterprise SIEM Architecture | ✅ Complete |
| [Lab 2: Detection Engineering](../lab-02-detection-engineering) | Threat Detection & Alerting | ✅ Complete |
| Lab 3: Incident Response | Ransomware IR Simulation | ✅ Complete |
| Lab 4: Threat Hunting | APT Simulation & Hunting | 🔄 Planned |
| Lab 5: SOAR Integration | Playbook Automation | 🔄 Planned |
| Lab 6: XDR Architecture | Enterprise XDR Design | 🔄 Planned |

---

**Author:** Pranjul Nayyar | **Last Updated:** February 2026
