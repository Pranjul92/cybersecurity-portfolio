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

VM 1: Ubuntu SIEM Server
**Specification**      **Configuration** 
OS                     Ubuntu Server 22.04.5 LTS
Hostname               siem-server
IP Address             172.16.240.131/24 (DHCP)
RAM                    8 GB
CPU                    4 cores
Disk                   100 GB (LVM)
Network                NAT (Share with Mac)
FirmwareLegacy         BIOS

