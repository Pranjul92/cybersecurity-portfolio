# Post Incident Review

**Incident Type:** Ransomware  
**Severity:** Critical  
**Date:** 2026-02-24  
**Affected Host:** WIN-ENDPOINT01  
**Affected User:** WIN-ENDPOINT01\lab-s   

## Incident Summary

On 2026-02-24, a simulated ransomware attack was executed against WIN-ENDPOINT01 via a phishing document (`Invoice_Q1_2026.docm`). Upon opening this doc and enabling macros, a VBA script silently executed a multi-stage PowerShell payload that encrypted 200 user files, dropped a ransom note, and abused `certutil.exe` as a LOLBin. The attack was detected by Splunk at 14:05, 4 minutes after execution, triggering 7 alerts. 

## Phase 1 — Preparation

Pre-incident baselines were captured on WIN-ENDPOINT01 before the simulation:

- Running services → `C:\IR\baseline_services.csv`
- Scheduled tasks → `C:\IR\baseline_tasks.csv`
- Local user accounts → `C:\IR\baseline_users.csv`
- Active network connections → `C:\IR\baseline_connection.csv`

Detection rules were configured in Splunk to detect the execution. 

## Phase 2 — Detection & Analysis

### Alerts Triggered

7 configured detections fired at 14:05:00 HKT.

| PowerShell Encoded Command Execution | Critical | ✅ Fired |
| PowerShell Download Cradle Detected | High | ✅ Fired |
| Living-off-the-Land Binary Execution | Medium | ✅ Fired |
| Office Application Spawning Shell | High | ✅ Fired |
| Admin Account Created | High | ❌ Attack stage failed |
| Mass File Modification Detected | Critical | ✅ Fired |
| Ransom Note Created | Critical | ✅ Fired |
| Bulk File Encryption Detected | Critical | ✅ Fired |

- [All Alerts Triggered](../screenshots/01-alerts-triggered.png)

> **Note:** Alert firing order in the SIEM reflects when Splunk completed each scheduled search, not the chronological order of events. All 7 fired in the same 5-minute schedule window. Actual attack sequence was reconstructed via forensic log analysis below.

### SIEM Investigation

**Office Application Spawning Shell** — Sysmon EventCode=1 confirmed `WINWORD.EXE` as the direct parent of `powershell.exe`. This is the highest-value detection for macro-based initial access and is the first pivot point for any analyst investigating this incident.

- [Office Spawning Shell Evidence](../screenshots/02-office-spawning-shell.png)

**Bulk File Encryption** — Sysmon EventCode=11 captured 200+ `.encrypted` file creation events from `powershell.exe` within a 2-minute window.

- [Bulk Encryption Evidence](../screenshots/03-mass-encryption.png)

**Ransom Note Created** — Sysmon EventCode=11 captured `README_RANSOM.txt` creation on the Desktop and in `C:\UserData`.

- [Ransom Note Alert](../screenshots/04-ransom-note.png)
- [Ransom Note on Desktop](../screenshots/06-ransom-note-desktop.png)

### Attack Timeline

Reconstructed using the following Splunk forensic query across `sysmon`, `windows_security`, and `powershell` indexes:

```spl
index=sysmon OR index=windows_security OR index=powershell
earliest="02/24/2026:13:55:00" latest="02/24/2026:14:10:00"
| eval event_category=case(
    EventCode=1 AND like(ParentImage, "%WINWORD.EXE%"), "Initial Access",
    EventCode=4104 AND like(ScriptBlockText, "%-enc%"), "Encoded PowerShell",
    EventCode=4720, "Admin Account Created",
    EventCode=11 AND like(TargetFilename, "%.encrypted%"), "File Encryption",
    EventCode=11 AND like(TargetFilename, "%README_RANSOM%"), "Ransom Note Created",
    EventCode=1 AND like(Image, "%certutil.exe%"), "LOLBIN Execution"
)
| where isnotnull(event_category)
| stats min(_time) as first_seen max(_time) as last_seen count as event_count
    values(Image) as Image values(User) as User values(TargetFilename) as sample_files
  by event_category
| eval sample_files=mvindex(sample_files,0)
| sort first_seen
```

- [Attack Timeline Output](../screenshots/07-attack-timeline.png)

| Time (HKT) | Stage | Event | MITRE |
|---|---|---|---|
| 14:01:00 | Initial Access | WINWORD.EXE opened, macros enabled | T1566.001 |
| 14:01:05 | Execution | WINWORD.EXE → powershell.exe via WScript.Shell | T1059.001 |
| 14:01:10 | Encoded PS + Download Cradle | Obfuscated PS, Invoke-WebRequest to external URL | T1027, T1105 |
| 14:01:15 | Privilege Escalation | Admin account creation — FAILED | T1136.001 |
| 14:01:20 | Encryption | 200 files encrypted in C:\UserData | T1486 |
| 14:03:05 | Ransom Note | README_RANSOM.txt dropped | T1486 |
| 14:03:10 | LOLBin | certutil.exe -encode | T1140 |
| 14:03:15 | Anti-Forensics | stage2.ps1 self-deleted | T1070 |
| 14:05:00 | Detection | 7 Splunk alerts fired | — |

### Key Forensic Findings

**Privilege Escalation Failed**
Admin account creation (`net user RansomAdmin /add`) failed because the macro-spawned PowerShell process ran in user context — `WScript.Shell` inherits the privilege level of the parent process (WINWORD.EXE). In a real attack, threat actors would use a UAC bypass or local privilege escalation exploit before this stage. Importantly, this failure did not prevent significant impact — user-context access was sufficient to encrypt all 200 target files.

**Anti-Forensic Self-Deletion**
The payload deleted `stage2.ps1` and `payload.dat` from `%TEMP%` after execution — realistic behavior designed to hinder post-incident forensic analysis. The macro source remains preserved in the `.docm` file.

**Detection Lag**
A 4-minute gap existed between attack execution and the first alert. Two compounding delays: Splunk Universal Forwarder log ingestion cycle (~1-2 minutes) and scheduled alert search interval (up to 5 minutes). The entire attack completed before any detection fired. While within the 10-minute target, this window represents a real risk in production environments.

### Indicators of Compromise

| Indicator | Type |
|---|---|
| `Invoice_Q1_2026.docm` | Malicious file |
| `%TEMP%\stage2.ps1` | PowerShell payload (self-deleted) |
| `%TEMP%\payload.dat` | Simulated downloaded payload |
| `*.encrypted` | Encrypted file extension |
| `README_RANSOM.txt` | Ransom note |
| `RansomAdmin` | Attempted persistence account |
| `WINWORD.EXE → powershell.exe` | Key behavioral indicator |

## Phase 3 — Containment, Eradication & Recovery

### Containment

Endpoint isolated from network to prevent lateral movement. Forensic evidence captured before remediation — processes, connections, users, and scheduled tasks exported and compared against pre-incident baselines. Affected user account (`lab-s`) temporarily disabled. Encryption confirmed limited to `C:\UserData` (200 files) with no spread to network shares.


### Eradication

All malicious artifacts removed: macro-enabled document, ransom notes, 200 encrypted files. Persistence mechanisms checked — no additional footholds found beyond the failed `RansomAdmin` account (deleted). Office macros disabled via Group Policy. Windows Defender signatures updated and quick scan completed.


### Recovery

User files restored from last known-good backup. User account re-enabled with mandatory password reset. Network connectivity restored. Enhanced Splunk monitoring queries configured for 7-day post-recovery watch period.

## Phase 4 — Post-Incident Activity

Documentation of the findinds in the PIR. 

### Recommendations

- Disable Office macros via Group Policy
- Implement real-time alerting for Critical severity detections
- Deploy email security gateway to strip macro-enabled attachments
- Enable Windows Defender ASR rules — block Office from spawning child processes
- Security awareness training — phishing and macro risks
- Deploy EDR for real-time behavioral detection and automated response
- Implement immutable backup solution isolated from production network
- Quarterly ransomware tabletop exercises

### MITRE ATT&CK Coverage

| T1566.001 | Phishing: Spearphishing Attachment | ✅ |
| T1059.001 | PowerShell Execution | ✅ |
| T1027 | Obfuscated Files or Information | ✅ |
| T1105 | Ingress Tool Transfer | ✅ |
| T1136.001 | Create Account: Local Account | ❌ Attack failed |
| T1486 | Data Encrypted for Impact | ✅ |
| T1140 | LOLBin — certutil | ✅ |
| T1070 | Indicator Removal — self-deletion | ❌ Detection gap |
| T1490 | Inhibit System Recovery | ❌ Not simulated |
