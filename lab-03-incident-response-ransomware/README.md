# lab-03-incident-response-ransomware/README.md
## Overview
Simulated a realistic multi-stage ransomware attack via a malicious Word macro and executed a complete incident response workflow following NIST SP 800-61. The attack encrypted 200 files, dropped a ransom note, and used LOLBins to evade detection — triggering 7 of 8 Splunk detections within 4 minutes.

## Attack at a Glance
Word Macro → PowerShell (hidden) → File Encryption (200 files) → Ransom Note → certutil LOLBin → Self-Delete

## Key Evidence
Screenshot               Description
Office Spawning Shell    WINWORD.EXE → powershell.exe confirmed via Sysmon
Mass Encryption          Bulk .encrypted file creation detected
Ransom Note              AlertREADME_RANSOM.txt creation caught by Splunk
Encrypted Files          200 files encrypted in C:\UserData
Ransom Note Contents     Ransom note dropped on Desktop
Attack Timeline          Full kill chain reconstructed via Splunk SPL

## Documentation
[Post Incident Review PIR](./screenshots/PIR)
Full NIST-framework incident analysis covering detection findings, attack timeline, IOCs, containment, eradication, recovery, and recommendations.
