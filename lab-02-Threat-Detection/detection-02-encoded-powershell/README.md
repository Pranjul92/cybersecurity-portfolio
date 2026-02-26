# Detection 02: Encoded PowerShell Command Execution

## What This Detects

PowerShell commands executed with base64 encoding (using `-encodedcommand` or `-enc` parameters). Attackers commonly use encoding to obfuscate malicious commands and evade signature-based detection.

## MITRE ATT&CK Mapping
- **Tactic** : Execution (TA0002)
- **Technique** : PowerShell (T1059.001)
- **Sub-technique** : Obfuscated Files or Information: Command Obfuscation (T1027.010)

## Detection Logic
index=powershell EventCode=4104
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*-encodedcommand*" 
| table _time, User, ComputerName, ScriptBlockText

## Alert Configuration

| **Schedule** : Every 5 minutes (`*/5 * * * *`)
| **Trigger** : Number of Results > 0
| **Trigger Type** : Once 
| **Throttle Field** : User 
| **Throttle Duration** : 15 minutes
| **Severity** : Critical

**Why throttle by User?**  
PowerShell execution is user-based. If the same user runs multiple encoded commands in quick succession, one alert is sufficient to trigger investigation.

## Test Procedure

### Step 1: Generated an Encoded Command
```powershell
# Create encoded string
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Get-Process"))

# Display it (optional - to see what it looks like)
Write-Host "Encoded: $encoded"
```

**Output:** `RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==`

### Step 2: Execute with Encoded Parameter 
[Execution](./screenshots/cmd-execution.png)

```powershell
powershell.exe -encodedcommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==
```

## Decoding Encoded Commands during an Investigation

When this alert fires in a real incident, decode the command to determine if it's malicious, using an online tool **CyberChef**

[Output](./screenshots/decoded-cyberchef.png)

## Results

- Encoded PowerShell execution captured in `powershell` index
- Alert triggered when `-encodedcommand` parameter detected
- Full base64 string visible in ScriptBlockText field
- Throttling prevents alert spam for same user
- Successfully decoded command for verification


## Screenshots

- [Alert Details](./screenshots/01-alert-details.png)
- [Alert Triggered](./screenshots/02-alert-triggered.png)
- [Search Results with Encoded Command](./screenshots/03-search-results.png)
- [Event Log](./screenshots/04-event-log.png)


## False Positive Considerations

- Legitimate automation scripts that use encoding for special characters
- Security tools that execute encoded diagnostics
- Tuning: Whitelist known good users or scheduled tasks if needed
- Always decode and analyze the command before dismissing as benign


## Why This Detection Matters

Encoding is a common technique used by:
- Malware droppers and loaders
- Post-exploitation frameworks (Metasploit, Empire, Cobalt Strike)
- Ransomware deployment scripts
- Living-off-the-land attacks

Even if the encoded command seems harmless (like `Get-Process`), the use of encoding itself is suspicious and warrants investigation.
