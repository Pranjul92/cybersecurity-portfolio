## Detection 01: Brute Force Login Attempts

## What This Detects : 
Multiple failed login attempts from the same source, indicating a brute force or password spray attack against Windows accounts.

## MITRE ATT&CK Mapping
- **Tactic** - Initial Access (TA0001)
- **Technique** - Brute Force (T1110)
- **Sub-technique** - Password Guessing (T1110.001)

## Detection Logic
index=windows_security EventCode=4625
| stats count by IpAddress, user
| where count > 5
| sort -count

## Alert Configuration

| **Schedule** : Every 5 minutes (`*/5 * * * *`)
| **Trigger** : Number of Results > 0
| **Trigger Type** : Once
| **Throttle Field** : IpAddress
| **Throttle Duration** : 15 minutes
| **Severity** : High

## Test Procedure

Simulated brute force attack on Windows endpoint by generating 10+ failed logins. 

    runas /user:fakeuser

## Results

- Failed login events captured in windows_security index
- Alert triggered after threshold exceeded

## Screenshots
- [Alert Details](./screenshots/01-alert-details.png)
- [Alert Triggered](./screenshots/02-alert-triggered.png)
- [Search Results](./screenshots/03-search-results.png)
- [Event Logs](./screenshots/04-event-logs.png)

## False Positive Considerations
- Legitimate users mistyping passwords repeatedly
- Automated scripts with expired credentials
- **Tuning:** Increase threshold from 5 to 10 for noisy environments
