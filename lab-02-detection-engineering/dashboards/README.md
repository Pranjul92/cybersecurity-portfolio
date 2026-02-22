# Lab 2: Security Dashboards

Overview of monitoring dashboards created for real-time security operations.

## Dashboard 1: SOC Security Overview

**Purpose:** Executive-level view of security posture and alert activity.

**Panels:**
1. **Alert Activity (Last 24 Hours)** - Line chart showing when alerts triggered
2. **Events by Index** - Pie chart of log volume by source
3. **Top Triggered Alerts** - Bar chart of most frequent detections
4. **Failed Login Attempts** - Table of authentication failures
5. **Top Processes** - Most frequently executed processes

![SOC Overview Dashboard](./screenshots/dashboard-01-soc-overview.png)

## Dashboard 2: Authentication Monitoring

**Purpose:** Deep dive into authentication activity and account security.

**Panels:**
1. **Login Success vs Failure** - Timeline comparing successful and failed logins
2. **Top Failed Login Attempts by User** - Users with most failures (potential compromised accounts)
3. **Failed Login Attempts by Source IP** - IPs attempting authentication (brute force detection)
4. **Recent Authentication Events** - Real-time feed of login activity and account changes

**Screenshot:**

![Authentication Dashboard](./screenshots/dashboard-02-authentication.png)

---

## Dashboard 3: Threat Hunting Workspace

**Purpose:** Interactive workspace for proactive threat hunting and investigation.

**Panels:**
1. **PowerShell Commands Executed** - Most common PowerShell commands by user
2. **Process Creation Over Time** - Timeline of process execution patterns
3. **Network Connections** - Outbound connections by process, IP, and port
   
**Screenshot:**

![Threat Hunting Dashboard](./screenshots/dashboard-03-threat-hunting.png)

