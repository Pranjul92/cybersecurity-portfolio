## Lab 1: Enterprise SIEM Deployment & Log Analysis

## Objective
Deploy a functional Security Information and Event Management (SIEM) system to centralize security log collection, analysis, and monitoring across a Windows endpoint. This lab demonstrates skills in SIEM architecture, log forwarding, security instrumentation, and security operations.

## Network Topology

┌─────────────────────────────────────────────────────────┐
│              VMware NAT Network (172.16.240.0/24)        │
│                                                          │
│  ┌──────────────────────┐        ┌────────────────────┐ │
│  │  Ubuntu SIEM Server  │◄───────│  Windows Endpoint  │ │
│  │  172.16.240.131      │  9997  │  172.16.240.130    │ │
│  │                      │        │                    │ │
│  │  Splunk Enterprise   │        │  - Sysmon          │ │
│  │  - Port 8000 (Web)   │        │  - Audit Policies  │ │
│  │  - Port 9997 (Recv)  │        │  - PS Logging      │ │
│  │  - 4 Custom Indexes  │        │  - UF Forwarder    │ │
│  └──────────────────────┘        └────────────────────┘ │
│                                                          │
│  Gateway: 172.16.240.2                                   │
│  DNS: 172.16.240.2 (VMware)                             │
└─────────────────────────────────────────────────────────┘

## Data Flow

Windows Event Logs ──┐
Sysmon Telemetry ────┼──► Splunk Universal ──► Network ──► Splunk ──► Indexes ──► Web UI
PowerShell Logs ─────┘     Forwarder           (9997)      Enterprise               (8000)

## Infrastructure Components 

**VM 1: Ubuntu SIEM Server**
Specification**        Configuration
OS                     Ubuntu Server 22.04.5 LTS
Hostname               siem-server
IP Address             172.16.240.131/24 (DHCP)
RAM                    8 GB
CPU                    4 cores
Disk                   100 GB (LVM)
Network                NAT (Share with Mac)
FirmwareLegacy         BIOS

Software Stack:
- Splunk Enterprise 9.2.0
- Web Interface: http://172.16.240.131:8000
- Receiving Port: 9997 (TCP)
- Indexes: windows_security, windows_system, sysmon, powershell

**VM 2: Windows Endpoint**
Specification          Configuration
OS                     Windows 11 Pro
Computer Name          WIN-ENDPOINT01
IP Address             172.16.240.130/24 (DHCP)
RAM                    4 GB
CPU                    2 cores
Disk                   60 GB
Network                NAT (Share with Mac)
Firmware               UEFI

Security Instrumentation:
- Sysmon 15.15 (SwiftOnSecurity configuration)
- Windows Audit Policies (8 categories, all subcategories)
- PowerShell Logging (Script Block, Module, Transcription)
- Splunk Universal Forwarder 9.2.0

## Implementation Summary

Phase 1: VM Deployment

Ubuntu Server Setup:
-  Created VM with 8GB RAM, 4 cores, 100GB disk
-  Installed Ubuntu Server 22.04.5
-  Configured DHCP networking (persistent netplan config)
-  Enabled SSH for remote management

Windows 11 Setup:
- Created VM with 4GB RAM, 2 cores, 60GB disk
- Installed Windows 11 Pro
- Renamed computer to WIN-ENDPOINT01
-  Configured DHCP networking
- Disabled Windows Firewall (lab environment only)

Phase 2: SIEM Installation (Ubuntu) - Splunk Enterprise Deployment:

1. Download Splunk Enterprise 9.2.0
wget -O splunk-9.2.0-1fff88043d5f-linux-2.6-amd64.deb \
  'https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-1fff88043d5f-linux-2.6-amd64.deb'

2. Install package
sudo dpkg -i splunk-9.2.0-1fff88043d5f-linux-2.6-amd64.deb

3. Start Splunk and accept license
sudo /opt/splunk/bin/splunk start --accept-license

4. Enable boot-start
sudo /opt/splunk/bin/splunk enable boot-start

5. Enable receiving on port 9997
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:password

6. Create custom indexes
sudo /opt/splunk/bin/splunk add index windows_security -auth admin:password
sudo /opt/splunk/bin/splunk add index windows_system -auth admin:password
sudo /opt/splunk/bin/splunk add index sysmon -auth admin:password
sudo /opt/splunk/bin/splunk add index powershell -auth admin:password

Configuration Changes:
- Disabled receiver authentication for lab environment
- Expanded disk from 10GB to 100GB using LVM
- Created persistent DHCP network configuration


Phase 3: Endpoint (Windows)

1. Sysmon Installation:Download Sysmon and SwiftOnSecurity config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

Install with config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

2. Windows Audit Policies: (Can also be done through GUI)
   # Enable comprehensive auditing
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Detailed Tracking" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

3. PowerShell Logging (via Group Policy):

Enabled Module Logging (all modules: *)
Enabled Script Block Logging
Enabled PowerShell Transcription (output: C:\PSTranscripts)

4. Splunk Universal Forwarder:
Installation: Downloaded and installed Splunk Universal Forwarder 9.2.0 (Windows x64)
Created config files which can be seen in the /configs folder

## Conclusion

This lab successfully demonstrates the deployment and configuration of an enterprise-grade SIEM system with comprehensive security logging. The implementation shows proficiency in:
- Security architecture and design
- Multi-platform system administration (Linux/Windows)
- Log management and analysis
- Security instrumentation and monitoring

