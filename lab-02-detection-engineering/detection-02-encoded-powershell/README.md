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

**Why EventCode 4104?**  
Event ID 4104 captures PowerShell Script Block logging, which records the actual commands and scripts executed on the system.

**Detection Pattern:**  
Searches for the presence of `-enc` or `-encodedcommand` parameters in the ScriptBlockText field, regardless of what command is encoded.

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

### Step 1: Generate Encoded Command
```powershell
# Create encoded string
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Get-Process"))

# Display it (optional - to see what it looks like)
Write-Host "Encoded: $encoded"
```

**Output:** `RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==`

### Step 2: Execute with Encoded Parameter
```powershell
# Copy the actual base64 string and run:
powershell.exe -encodedcommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==
```

**Important:** Use the actual base64 string (not `$encoded` variable) 
to ensure Splunk logs the full encoded command.

---

## Decoding Encoded Commands (Investigation)

When this alert fires in a real incident, decode the command to 
determine if it's malicious:

### Method 1: PowerShell
```powershell
# Copy the base64 string from Splunk logs
$encoded = "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="

# Decode it
$decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
Write-Host $decoded
```

**Output:** `Get-Process`

### Method 2: CyberChef (Online Tool)

1. Go to: https://gchq.github.io/CyberChef/
2. Recipe: "From Base64" → "Decode Text (UTF-16LE)"
3. Input: Base64 string from logs
4. View decoded command

---

## Results

- ✅ Encoded PowerShell execution captured in `powershell` index
- ✅ Alert triggered when `-encodedcommand` parameter detected
- ✅ Full base64 string visible in ScriptBlockText field
- ✅ Throttling prevents alert spam for same user
- ✅ Successfully decoded command for verification

---

## Screenshots

- [Alert Details](./screenshots/01-alert-details.png)
- [Alert Triggered](./screenshots/02-alert-triggered.png)
- [Search Results with Encoded Command](./screenshots/03-search-results.png)
- [Raw Event Log](./screenshots/04-event-log.png)

---

## False Positive Considerations

- Legitimate automation scripts that use encoding for special characters
- Security tools that execute encoded diagnostics
- **Tuning:** Whitelist known good users or scheduled tasks if needed
- **Context matters:** Always decode and analyze the command before 
  dismissing as benign

---

## Why This Detection Matters

Encoding is a common technique used by:
- Malware droppers and loaders
- Post-exploitation frameworks (Metasploit, Empire, Cobalt Strike)
- Ransomware deployment scripts
- Living-off-the-land attacks

Even if the encoded command seems harmless (like `Get-Process`), 
the use of encoding itself is suspicious and warrants investigation.
