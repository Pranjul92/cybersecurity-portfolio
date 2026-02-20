# Detection 06: New Administrator Account Creation

## What This Detects
User accounts being added to the local Administrators security group. Attackers commonly create admin accounts for persistence after initial compromise.

## MITRE ATT&CK Mapping
- **Tactic** : Persistence (TA0003)
- **Technique** : Create Account: Local Account (T1136.001)
- **Sub-technique** : Valid Accounts: Local Accounts (T1078.003) |

## Detection Logic (SPL)
```spl
index=windows_security EventCode=4732
| search TargetUserName="Administrators"
| table _time, SubjectUserName, TargetUserName, MemberSid, MemberName
```

**Event ID 4732:** A member was added to a security-enabled local group

## Alert Configuration
| **Schedule** : Every 5 minutes 
| **Trigger** : For Each Result 
| **Throttle Field** : Member_Name 
| **Throttle Duration** : 60 minutes 
| **Severity** : Critical

## Test Procedure
```powershell
# Create test user (requires admin)
net user testadmin1 Password123! /add

# Add to Administrators
net localgroup Administrators testadmin1 /add
```

## Attack Scenarios

**Post-exploitation persistence:**
```
net user hacker P@ssw0rd! /add
net localgroup Administrators hacker /add
```

**Ransomware preparation:**
```
net user backup$ SecurePass123 /add
net localgroup Administrators backup$ /add
```

## Investigation Steps

1. Check Member_Name: Is this a known admin?
2. Check Account_Name: Who added them?
3. Check timing: After hours? Suspicious
4. Correlate: Any other suspicious activity from this user?

## False Positives

- Legitimate IT admin onboarding
- Software installations requiring admin
- **Tuning:** Whitelist known IT admin accounts

## Screenshots

- [Alert Triggered](./screenshots/01-alert-triggered.png)
- [Alert Details](./screenshots/02-alert-details.png)
- [Event Log](./screenshots/04-event-log.png)
