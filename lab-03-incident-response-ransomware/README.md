# Lab 03: Ransomware Incident Response Simulation

## Objective
Simulate a realistic multi-stage ransomware attack against a Windows endpoint and execute a complete incident response workflow following the NIST framework. Documented the full process from initial compromise through detection, containment, eradication, and recovery.

## Attack Scenario
A phishing document (`Invoice_Q1_2026.docm`) delivered a VBA macro that silently spawns PowerShell, encrypts 200 user files, drops a ransom note, and abuses `certutil.exe` as a LOLBin. Splunk captures the full attack chain via Sysmon telemetry.

## Ransomware Kill Chain
```
Stage 1: Initial Access        → User opens Invoice_Q1_2026.docm, enables macros
Stage 2: Execution             → WINWORD.EXE spawns powershell.exe via WScript.Shell
Stage 3: Privilege Escalation  → Admin account creation attempted (FAILED)
Stage 4: Discovery             → Enumerates C:\UserData for target files
Stage 5: Encryption            → 200 files encrypted with .encrypted extension
Stage 6: Impact                → README_RANSOM.txt dropped on Desktop + C:\UserData
Stage 7: LOLBin Abuse          → certutil.exe used to base64-encode ransom note
Stage 8: Anti-Forensics        → Payload self-deletes from %TEMP%
```
## Environment

| **Endpoint** : WIN-ENDPOINT01 (Windows 11)
| **SIEM** : Splunk Enterprise 
| **Telemetry** : Sysmon + Windows Security + PowerShell Script Block Logging
| **Attack Vector** : VBA Macro → PowerShell payload
| **Target Directory** : C:\UserData (200 files across 5 subdirectories)

## Attack Timeline
```
| 14:01:00 | Initial Access | User opened .docm, macros enabled | T1566.001 |
| 14:01:05 | Execution | WINWORD.EXE → powershell.exe | T1059.001 |
| 14:01:10 | Encoded PS | Obfuscated command + download cradle | T1027, T1105 |
| 14:01:15 | Priv Esc | Admin account creation — FAILED | T1136.001 |
| 14:01:20 | Encryption | 200 files encrypted in C:\UserData | T1486 |
| 14:03:05 | Impact | README_RANSOM.txt dropped | T1486 |
| 14:03:10 | LOLBin | certutil.exe -encode | T1140 |
| 14:03:15 | Cleanup | Payload self-deleted | T1070 |
| 14:05:00 | Detection | 7 Splunk alerts fired | — |
```

## Detections
- PowerShell Encoded Command Execution
- PowerShell Download Cradle Detected
- Living-off-the-Land Binary Execution
- Office Application Spawning Shell
- Mass File Modification Detected
- Ransom Note Created
- Bulk File Encryption Detected

Time to detection: 4 minutes. 

## Screenshots

- [Alerts Triggered](./screenshots/01-alerts-triggered.png)
- [Office Application Spawning Shell](./screenshots/02-office-spawning-shell.png)
- [Bulk File Encryption Detection](./screenshots/03-mass-encryption.png)
- [Ransom Note Alert](./screenshots/04-ransom-note.png)
- [Encrypted Files on Endpoint](./screenshots/05-encrypted-files.png)
- [Ransom Note Desktop](./screenshots/06-ransom-note-desktop.png)
- [Attack Timeline Reconstruction](./screenshots/07-attack-timeline.png)

## Documentation

- [Post Incident Review — PIR-IR-2026-001](./incident-response/PIR-IR-2026-001.md)
- [Attack Simulation — VBA Macro](./attack-simulation/simulate-ransomware.vba)

