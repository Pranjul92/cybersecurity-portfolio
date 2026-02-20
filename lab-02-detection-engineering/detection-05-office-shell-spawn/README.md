# Detection 05: Office Application Spawning Shell

## What This Detects

Microsoft Office applications (Word, Excel, PowerPoint) creating child processes for command shells or scripting engines. This behavior is indicative of malicious macro execution, a common malware delivery method.

## MITRE ATT&CK Mapping
- **Tactic** : Execution (TA0002)
- **Technique** : User Execution: Malicious File (T1204.002)
- **Sub-technique** : Phishing: Spearphishing Attachment (T1566.001)

## Detection Logic (SPL)
```spl
index=sysmon EventCode=1
| search (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*POWERPNT.EXE")
  AND (Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*wscript.exe")
| table _time, User, ParentImage, Image, CommandLine
```

**Why This Works:**

Legitimate Office documents do NOT spawn shells. When they do, it's almost always malicious macro code.

## Alert Configuration
| **Schedule** : Every 5 minutes 
| **Trigger** : For Each Result
| **Throttle Field** : ParentImage
| **Throttle Duration** : 15 minutes
| **Severity** : High

## Test Procedure

1. Open Microsoft Word
2. Press Alt+F11 (VBA editor)
3. Insert → Module
4. Paste:
```vba
Sub TestMacro()
    Shell "cmd.exe /c echo test > C:\Users\Public\test.txt"
End Sub
```
5. Run (F5)
6. Alert triggers within 5 minutes

## Attack Examples

**Emotet malware:**
```
ParentImage: WINWORD.EXE
Image: powershell.exe
CommandLine: powershell -enc [base64]
```

**Dridex banking trojan:**
```
ParentImage: EXCEL.EXE
Image: cmd.exe
CommandLine: cmd /c certutil -urlcache -f http://...
```

## False Positives

- Very rare
- Legitimate add-ins don't spawn shells
- Most alerts are actual threats

## Screenshots

- [Alert Triggered](./screenshots/01-alert-triggered.png)
- [Alert Details](./screenshots/02-alert-details.png)
- [Search Results](./screenshots/03-search-results.png)
- [Event Log](./screenshots/04-event-log.png)
