<div align="center">

# 🎯 SOC Log Analysis Datasets

### Realistic, simulated security logs with hidden attacks — built for SOC analysts, threat hunters, and students.

**5 domains · 12 log files · 2 formats · 100% synthetic**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![GitHub stars](https://img.shields.io/github/stars/mahialjaber/SOC-Log-Analysis-Datasets?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/mahialjaber/SOC-Log-Analysis-Datasets)
![Built for Blue Teams](https://img.shields.io/badge/Built%20for-Blue%20Teams-blue)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

</div>

---

> 🔍 **Real attack patterns. Zero real-world risk.** Every log file blends normal background noise with deliberately embedded attack vectors — so you can practice detection without needing an actual breach.

## 🤔 Why This Exists

Finding realistic log data for threat hunting practice is surprisingly hard. Clean, normal-activity logs teach you nothing about detection. Massive raw dumps from public breach archives are unstructured, unlabeled, and overwhelming to parse. Real incident data is — rightly — locked down.

**This repository bridges that gap.** It provides structured, purpose-built log files across five environments — Applications, Cloud, Email & DLP, Endpoints, and Network — each containing specific, identifiable attack techniques hidden inside realistic background traffic.

If you're a student, a SOC analyst, or a threat hunter, this dataset is built for you to practice SIEM ingestion, query writing, and log-based detection — safely.

## 📋 Table of Contents

- [✨ Key Features](#-key-features)
- [📂 What's Inside](#-whats-inside)
- [🗂️ Repository Structure](#-repository-structure)
- [🚀 Getting Started](#-getting-started)
- [🕵️ Threat Hunting Playbook](#-threat-hunting-playbook)
- [🎓 Who This Is For](#-who-this-is-for)
- [🤝 Contributing](#-contributing)
- [🗺️ Roadmap](#-roadmap)
- [❓ FAQ](#-faq)
- [⚠️ Disclaimer](#-disclaimer)
- [📄 License](#-license)
- [⭐ Support This Project](#-support-this-project)

---

## ✨ Key Features

- 🎯 **Targeted, not random** — every file is built around specific, well-known attack techniques (SQLi, XSS, brute force, C2 beaconing, DNS tunneling, IAM abuse, and more), not random noise.
- 🌍 **Five real-world domains** — Applications, Cloud, Email & DLP, Endpoints, and Network, so you can practice across the environments a real SOC actually monitors.
- 🧩 **Realistic background noise** — attacks are buried inside normal-looking traffic, just like production, so you have to actually hunt for them.
- 🔌 **SIEM-agnostic** — plain text and JSONL formats that ingest cleanly into Splunk, the Elastic Stack, Microsoft Sentinel, or your own scripts.
- 🆓 **Free and open** — MIT licensed, free to use, modify, and redistribute for educational or commercial purposes.

## 📂 What's Inside

| Domain | Files | Format | Hidden Attack Vectors |
| :--- | :--- | :--- | :--- |
| **Applications** | `app_sec_audit.log.zip`<br>`web_server_access.log.zip` | Raw text | SQL injection, cross-site scripting (XSS), directory traversal |
| **Cloud** | `cloud_activity_audit.log.zip` | Raw text | Unauthorized access, IAM privilege escalation, anomalous resource deletion |
| **Email & DLP** | `dlp_events.log.zip`<br>`email_gateway_events.jsonl.zip` | Text / JSONL | Phishing payloads, malicious attachments, data exfiltration |
| **Endpoints** | `linux_syslog.log.zip`<br>`windows_security_events.log.zip` | Raw text | Brute-force attacks, privilege escalation, suspicious process execution |
| **Network** | `dns_query_logs.jsonl.zip`<br>`firewall_traffic.log.zip`<br>`ids_ips_alerts.log.zip`<br>`proxy_access.log.zip`<br>`vpn_access.log.zip` | Text / JSONL | DNS tunneling, C2 beaconing, port scanning, unauthorized VPN access |

All files are zipped to keep the repository lightweight — unzip before ingesting.

## 🗂️ Repository Structure

```
SOC-Log-Analysis-Datasets/
├── Applications/
│   ├── app_sec_audit.log.zip
│   └── web_server_access.log.zip
├── Cloud/
│   └── cloud_activity_audit.log.zip
├── Email_and_DLP/
│   ├── dlp_events.log.zip
│   └── email_gateway_events.jsonl.zip
├── Endpoints/
│   ├── linux_syslog.log.zip
│   └── windows_security_events.log.zip
├── Network/
│   ├── dns_query_logs.jsonl.zip
│   ├── firewall_traffic.log.zip
│   ├── ids_ips_alerts.log.zip
│   ├── proxy_access.log.zip
│   └── vpn_access.log.zip
├── LICENSE
└── README.md
```

## 🚀 Getting Started

**1. Clone the repository**
```bash
git clone https://github.com/mahialjaber/SOC-Log-Analysis-Datasets.git
cd SOC-Log-Analysis-Datasets
```

**2. Unzip the dataset(s) you want to work with**
```bash
unzip Network/firewall_traffic.log.zip -d Network/
```

**3. Ingest into your tool of choice**

| Tool | How |
| :--- | :--- |
| **Splunk** | Use "Add Data" and point it at the unzipped file. JSONL sources auto-extract fields. |
| **Elastic Stack (ELK)** | Feed through Filebeat/Logstash; use a `json` codec for `.jsonl` files. |
| **Microsoft Sentinel** | Upload via a custom log table or ingest through the Log Analytics API. |
| **Command line** | Use `grep`, `awk`, `sed`, and `jq` for rapid manual triage. |
| **Custom scripts** | Great for testing Python/PowerShell log-parsing and automation. |

## 🕵️ Threat Hunting Playbook

Sample queries to get you started hunting for the attack vectors embedded in each dataset. Treat these as starting points — field names may need to match your ingestion schema.

### 1. SQL Injection & XSS
**Target:** `Applications/web_server_access.log`

**Splunk SPL**
```spl
index=web sourcetype=access_combined
| search uri_query="*UNION*" OR uri_query="*SELECT*" OR uri_query="*<script>*"
| stats count by src_ip, uri_query, status
| sort - count
```

**CLI**
```bash
grep -iE "union.*select|%27|<script>" web_server_access.log
```

### 2. Cloud IAM Privilege Escalation
**Target:** `Cloud/cloud_activity_audit.log`

**Splunk SPL**
```spl
index=cloud sourcetype=cloud_audit
| search eventName IN ("AttachUserPolicy", "PutUserPolicy", "CreateAccessKey", "DeleteTrail")
| stats count by user, eventName, sourceIPAddress
| where count > 3
```

### 3. Phishing & Data Exfiltration
**Target:** `Email_and_DLP/dlp_events.log`, `Email_and_DLP/email_gateway_events.jsonl`

**Splunk SPL**
```spl
index=dlp sourcetype=email_gateway
| search action="blocked" OR category="phishing" OR category="exfiltration"
| stats count by sender, recipient, attachment_name
| sort - count
```

### 4. Windows Authentication Brute Force 
**Target:** `Endpoints/windows_security_events.log`

**Splunk SPL**
```spl
index=windows EventCode=4625
| stats count by TargetUserName, IpAddress
| where count > 10
```

**Microsoft Sentinel (KQL)**
```kql
SecurityEvent
| where EventID == 4625
| summarize count() by TargetUserName, IpAddress
| where count_ > 10
```

### 5. C2 Beaconing
**Target:** `Network/firewall_traffic.log`

**Splunk SPL**
```spl
index=firewall action=allowed dest_port!=80 dest_port!=443
| stats sum(bytes_out) as total_outbound by src_ip, dest_ip, dest_port
| where total_outbound > 50000
```

**CLI**
```bash
awk '$5 != "80" && $5 != "443" && $7 == "allowed" {print $3, $4, $5}' firewall_traffic.log | sort | uniq -c | sort -nr
```

### 6. DNS Tunneling
**Target:** `Network/dns_query_logs.jsonl`

**Splunk SPL**
```spl
index=dns sourcetype=dns_query
| eval query_length=len(query)
| where query_length > 50
| stats count by src_ip, query
| sort - count
```

**CLI (jq)**
```bash
jq -r 'select((.query | length) > 50) | [.src_ip, .query] | @tsv' dns_query_logs.jsonl
```

> 💡 **Tip:** Run each query against its target file, then tune the thresholds. Real detection engineering is as much about cutting false positives as it is about finding the signal.

## 🎓 Who This Is For

- 🧑‍🎓 **Students** studying for certifications like Security+, CySA+, GCIH, or OSCP
- 🛡️ **SOC analysts** (Tier 1/2) building and sharpening triage skills
- 🔧 **Detection engineers** prototyping and testing correlation rules
- 🟣 **Purple/blue teams** running tabletop exercises or workshops
- 👨‍🏫 **Instructors** building hands-on cybersecurity curricula

## 🤝 Contributing

Contributions are welcome.

1. **Fork** the repository
2. **Create a branch** for your addition (`git checkout -b feature/new-attack-scenario`)
3. **Add your log data or query** following the existing structure and format
4. **Open a pull request** describing what you added and why

Ideas for contributions: new attack scenarios, additional log formats (Azure/GCP audit logs, EDR telemetry, Kubernetes audit logs), Sigma or YARA rule mappings, or fixes to existing queries.

## ❓ FAQ

**Is this real attack data?**
No. Everything is synthetic and simulated, purpose-built for training. No real breach data, credentials, or PII is included.

**What SIEM do I need?**
None, strictly speaking. The formats work with Splunk, the Elastic Stack, Microsoft Sentinel, or nothing more than `grep`/`awk`/`jq` on the command line.

**Can I use this for a course or workshop I'm running?**
Yes — it's MIT licensed, so educational and commercial use are both fine. A credit or link back is appreciated but not required.

**How do I know if I found the "right" answer?**
Start with the sample queries in the [Threat Hunting Playbook](#-threat-hunting-playbook) above and tune from there. An answer-key branch is on the [roadmap](#-roadmap).

## ⚠️ Disclaimer

All datasets in this repository are **fully synthetic and simulated**. They do not contain real user data, credentials, PII, or data from any actual breach or incident. They exist solely for education, training, and lab/detection-engineering use. Use responsibly and only against systems and SIEMs you own or are authorized to use.

## 📄 License

Released under the [MIT License](LICENSE) — free to use, modify, and distribute for educational or commercial purposes.

## ⭐ Support This Project

If this dataset helped with your studies, certifications, or lab setup:

- ⭐ **Star** this repository so it reaches other analysts who need it
- 👤 **Follow** [@mahialjaber](https://github.com/mahialjaber) for future defensive security projects and SOC tooling
- 🍴 **Fork** it and share what you build

Building resources like this for the community takes time — every star genuinely helps it reach the next analyst who needs it.

---

<div align="center">

Built for the blue team. 🛡️

</div>
