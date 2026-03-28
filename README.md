# Cybersecurity Portfolio

**Security Operations & Architecture Labs**

## About Me

Cybersecurity professional with 5+ years of experience spanning security operations, incident response, and security architecture. Skilled in designing and implementing enterprise security solutions, SIEM deployments, and security monitoring infrastructure.

**Target Roles:** SOC Analyst | Security Engineer  | Security Solutions Architect

## Skills Demonstrated

- SIEM deployment and administration (Splunk)
- Security monitoring and log analysis
- Endpoint security
- Security architecture design
- Alert Craetion and Detection
- Incident response
- Infrastructure security solutions

## Lab Projects

### Lab 1: Enterprise SIEM Deployment
**Focus:** Log management, SIEM architecture, security monitoring
**Key Technologies:** Splunk Enterprise, Sysmon, Windows Event Logging, Universal Forwarder

Built a production-grade SIEM environment with centralized log collection from Windows endpoints. Demonstrates Splunk administration, log forwarding configuration, and comprehensive security instrumentation.

**[View Lab 1](./lab-01-siem-deployment/)**

### Lab 2: Threat-detection
**Focus:** Threat detection, correlation rules, alerting, MITRE ATT&CK mapping
**Key Technologies:** Splunk Enterprise, Sysmon, Windows Event Logging, PowerShell, MITRE ATT&CK

Built 6 production-ready detection rules in Splunk including brute force login detection, encoded PowerShell, download cradles, LOLBin abuse, Office macro shell spawning, and local admin account creation. Implemented alert throttling to reduce noise, built 3 operational dashboards (SOC overview, authentication monitoring, threat hunting), and documented full detection logic and tuning procedures for each rule.

**[View Lab 2](./lab-02-Threat-Detection/)**


### Lab 3: Ransomware Incident Response
**Focus:** Incident response, containment, forensics, NIST Framework

Simulated a full 8-stage ransomware kill chain using a VBA macro-enabled Word document delivering a PowerShell payload which encrypted 200 files, dropped a ransom note, and abused certutil as a LOLBin. Executed the complete NIST SP 800-61 IR lifecycle achieving detection and produced an executive Post Incident Review document.

**[View Lab 3](./lab-03-incident-response-ransomware/)**


### Lab 4: Threat Hunting
**Focus:** Threat hunting, APT simulation, behavioural detection, Splunk SPL
**Key Technologies:** Splunk Enterprise, Sysmon, PowerShell, MITRE ATT&CK, Windows Event Logging

Simulated a full APT29 attack chain across 6 stages including registry persistence, scheduled task abuse, log clearing, LSASS credential access, lateral movement reconnaissance, and C2 beaconing. Conducted 5 hypothesis-driven hunts entirely in Splunk without relying on pre-fired alerts — confirming each TTP through behavioural analysis. Identified 3 detection gaps and mapped all findings to MITRE ATT&CK.

**[View Lab 4](./lab-04-Threat-Hunting-APT29Simulation/)**

### Lab 5: Vulnerability Assessment
**Focus:** Vulnerability assessment, exploit validation, remediation, Nessus, Metasploit
**Key Technologies:** Nmap, Nessus Essentials, Metasploit Framework

Conducted a full vulnerability assessment against Metasploitable 2 and scoped the engagement, ran Nmap reconnaissance, performed a Nessus scan returning 166 findings, then validated 4 Critical CVEs through active exploitation using Metasploit achieving unauthenticated root access via each. Patched all 4 vulnerabilities, confirmed remediation via rescan, and produced a VA report.

**[View Lab 5](./lab-05-vulnerability-assessment/)**

## Contact

**LinkedIn:** https://www.linkedin.com/in/pranjul-nayyar-19168182/
**Email:** pranjulnayyar@gmail.com
