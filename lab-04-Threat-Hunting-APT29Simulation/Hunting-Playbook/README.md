Documentation of all 5 hunts — hypotheses, SPL queries, findings, and evidence screenshots.

## Baseline — Pre-Hunt

Before running the simulation, baselines were captured to establish what normal looks like on WIN-ENDPOINT01.

[Baseline:Process Creation](./screenshots/Baseline_Normal-process-creation.png)
[Baseline:Network Connections](./screenshots/Baseline_Normal-network-connections.png) 
[Baseline:Scheduled Tasks](./screenshots/Baseline_Normal-Scheduled-tasks.png) 

### Hunt 1 — Persistence
An attacker may have established persistence via registry Run keys or scheduled tasks to survive reboots.

#### MITRE ATT&CK Mapping
Tactic — Persistence (TA0003)
Technique — Boot or Logon Autostart: Registry Run Keys (T1547.001)
Technique — Scheduled Task/Job (T1053.005)

**[Registry Run key found](./screenshots/02-registry-persistence.png)**
```spl
index=sysmon EventCode=13
| search TargetObject="*CurrentVersion\\Run*"
| where NOT match(Image, "(?i)(svchost|sihost|userinit|explorer|MicrosoftEdge|msedge|OneDrive|Teams|Dropbox|zoom|GoogleUpdate|officeclicktorun)")
| table _time, User, Image, TargetObject, Details
| sort _time
```
**Finding:** `powershell.exe` wrote `WindowsUpdateHelper` to `HKCU\...\CurrentVersion\Run` — pointing to a hidden PowerShell payload in `C:\Windows\Temp\updater.ps1`

**[Scheduled task MicrosoftEdgeUpdateTaskMachine](./screenshots/03-scheduled-task.png)**
```spl
index=windows_security EventCode=4698
| table _time, User, TaskName, TaskContent
| sort -_time
```
**Finding:** `MicrosoftEdgeUpdateTaskMachine` created at 18:30 — hidden, logon trigger, PowerShell download cradle embedded in task XML


### Hunt 2 — Defence Evasion
An attacker may be evading detection by clearing event logs or modifying file timestamps.

#### MITRE ATT&CK Mapping
Tactic — Defence Evasion (TA0005)
Technique — Indicator Removal: Clear Windows Event Logs (T1070.001)
Technique — Indicator Removal: Timestomp (T1070.006)

**[Security log cleared EventID 1102](./screenshots/04-log-cleared.png)**
```spl
index=windows_security EventCode=1102
```
**Finding:** Security event log cleared by `lab-s` at 18:30 — confirmed via EventID=1102

**[Timestomping detected EventCode=2](./screenshots/05-timestomping.png)**
```spl
index=sysmon EventCode=2
| table _time, Image, TargetFilename, CreationUtcTime
| sort -_time
```
**Finding:** `updater.ps1` in `C:\Windows\Temp` with `CreationUtcTime` backdated 180 days — `_time` shows today, `CreationUtcTime` shows ~September 2025


### 3 — Credential Access
An attacker may have attempted to access LSASS memory to steal credentials.

#### MITRE ATT&CK Mapping
Tactic — Credential Access (TA0006)
Technique — OS Credential Dumping: LSASS Memory (T1003.001)

[LSASS comsvcs string in PS logs](./screenshots/06-credential-access.png)

```spl
index=powershell EventCode=4104
| where match(ScriptBlockText, "(?i)(comsvcs|MiniDump|lsass)")
| table _time, User, ScriptBlockText
| sort -_time
```
**Finding:** `comsvcs.dll MiniDump lsass.dmp full` command string captured in PowerShell Script Block Logging (EventID=4104) — even though the command was never executed. PS logging captures all strings that pass through the engine regardless of execution.

### 4 — Discovery
An attacker may be conducting internal reconnaissance using built-in Windows commands.

#### MITRE ATT&CK Mapping
Tactic — Discovery (TA0007)
Technique — System Owner/User Discovery (T1033), System Information Discovery (T1082), Network Configuration Discovery (T1016)

[Discovery command cluster](./screenshots/07-discovery-cluster.png)
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(whoami|net\.exe|ipconfig|systeminfo|arp|netstat|tasklist|hostname)")
| bin _time span=10m
| stats count as cmd_count values(Image) as commands values(CommandLine) as cmd_lines by _time, User
| where cmd_count > 4
| table _time, User, cmd_count, commands
| sort -_time
```
**Finding:** 8 recon binaries executed within a 10-minute window under `lab-s` — `whoami`, `systeminfo`, `net.exe`, `ipconfig`, `arp`, `netstat`, `tasklist`, `hostname`

### 5 — C2 Beaconing
An attacker may be beaconing to an external C2 at regular intervals.

#### MITRE ATT&CK Mapping
Tactic — Command & Control (TA0011)
Technique — Application Layer Protocol: Web Protocols (T1071.001)

[C2 beacon delta seconds](./screenshots/08-beacon-pattern.png)

```spl
index=sysmon EventCode=3
| where match(Image, "(?i)powershell")
| sort _time
| streamstats current=f last(_time) as prev_time
| eval delta_seconds = round(_time - prev_time, 0)
| where delta_seconds > 0 AND delta_seconds < 300
| table _time, Image, DestinationIp, delta_seconds, User
| sort _time
```
**Finding:** 5 PowerShell outbound connections with `delta_seconds` clustering at 30-40 seconds — regular interval with jitter confirming automated beaconing behaviour


## MITRE ATT&CK Coverage

| Technique | Name |
|---|---|
| T1547.001 | Registry Run Keys |
| T1053.005 | Scheduled Task |
| T1070.001 | Clear Windows Event Logs |
| T1070.006 | Timestomping |
| T1003.001 | LSASS Memory |
| T1033 | System Owner/User Discovery |
| T1082 | System Information Discovery |
| T1016 | Network Configuration Discovery |
| T1021.002 | SMB Lateral Movement |
| T1071.001 | C2 Web Protocols |

**10 techniques across 6 MITRE tactics detected.**

