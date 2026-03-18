## Objective

Simulate post-compromise APT29 (Cozy Bear) behaviour on WIN-ENDPOINT01 using PowerShell, then conduct hypothesis-based threat hunting in Splunk to identify the attacker's presence.

## About APT29

APT29 is a Russian SVR-linked threat actor — one of the most documented APT groups in the world. Their TTPs are heavily LOLBin-based, well-mapped to MITRE ATT&CK, and directly relevant to BFSI and government clients. All techniques simulated in this lab are based on publicly documented APT29 behaviour. 

## Attack Scenario

**Assumption:** Initial access already occurred via phishing (covered in Lab 3). Lab 4 begins at the post-compromise phase. The attacker has a foothold on WIN-ENDPOINT01 as `lab-s` and is moving through the kill chain. 

## Attack Simulation — 6 Stages

```
Stage 1: Persistence         → Registry Run key + Scheduled Task
Stage 2: Defence Evasion     → Security log clearing + Timestomping
Stage 3: Credential Access   → LSASS process identification + comsvcs MiniDump string
Stage 4: Discovery           → 12-command recon burst (whoami, systeminfo, net, netstat etc.)
Stage 5: Lateral Movement    → SMB port 445 probed on 4 internal IPs
Stage 6: C2 Beaconing        → 5 beacons at ~30s intervals with jitter
```

## Hunting Hypotheses & Results 

### 1 — Persistence
Attacker established persistence via registry Run keys or scheduled tasks | T1547.001, T1053.005 | Sysmon EventCode=13, Windows Security EventID=4698

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


### 2 — Defence Evasion
Attacker evaded detection by clearing event logs or modifying file timestamps | T1070.001, T1070.006 | Windows Security EventID=1102, Sysmon EventCode=2

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
Attacker attempted LSASS credential access | T1003.001 | PowerShell EventID=4104

[LSASS comsvcs string in PS logs](./screenshots/06-credential-access.png)

```spl
index=powershell EventCode=4104
| where match(ScriptBlockText, "(?i)(comsvcs|MiniDump|lsass)")
| table _time, User, ScriptBlockText
| sort -_time
```
**Finding:** `comsvcs.dll MiniDump lsass.dmp full` command string captured in PowerShell Script Block Logging (EventID=4104) — even though the command was never executed. PS logging captures all strings that pass through the engine regardless of execution.

### 4 — Discovery
Attacker conducted internal discovery using native Windows commands | T1033, T1082, T1016 | Sysmon EventCode=1

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
Attacker is beaconing to external C2 at regular intervals | T1071.001 | Sysmon EventCode=3

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
