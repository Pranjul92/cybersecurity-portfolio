## Objective

Simulate post-compromise APT29 (Cozy Bear) behaviour on WIN-ENDPOINT01 using PowerShell, then conduct hypothesis-based threat hunting in Splunk to identify the attacker's presence.

## About APT29

APT29 is a Russian SVR-linked threat actor — one of the most documented APT groups in the world. Their TTPs are heavily LOLBin-based, well-mapped to MITRE ATT&CK, and directly relevant to BFSI and government clients. All techniques simulated in this lab are based on publicly documented APT29 behaviour. 

## Attack Scenario

**Assumption:** Initial access already occurred via phishing (covered in Lab 3). Lab 4 begins at the post-compromise phase. The attacker has a foothold on WIN-ENDPOINT01 as `lab-s` and is moving through the kill chain. 

## Attack Simulation — 6 Stages

```
Stage 1: Persistence         → Registry Run key + Scheduled Task
Stage 2: Defence Evasion     → Security log clearing + Timestomping
Stage 3: Credential Access   → LSASS process identification + comsvcs MiniDump string
Stage 4: Discovery           → 12-command recon burst (whoami, systeminfo, net, netstat etc.)
Stage 5: Lateral Movement    → SMB port 445 probed on 4 internal IPs
Stage 6: C2 Beaconing        → 5 beacons at ~30s intervals with jitter
```

**10 techniques across 6 MITRE tactics detected.**

[Threat Hunting Playbook with queries & findings](./Hunting-Playbook/README.md)
