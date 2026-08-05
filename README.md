# 🎯 SOC Log Analysis Datasets

Finding high-quality, realistic log files containing actual malicious activity is difficult. Normal activity logs are useless for threat hunting practice, and massive raw dumps are too overwhelming to parse. 

This repository bridges that gap. It provides targeted, structured log files across various environments (Cloud, Network, Endpoints, Applications) containing specific attack vectors hidden within normal background noise. 

**If you are a student, SOC analyst, or threat hunter, this dataset is built for you to practice SIEM ingestion and log parsing.**

---

## 📂 Dataset Architecture

The logs are categorized into distinct domains and compressed (`.zip`) to maintain manageable file sizes. Unzip them to access the raw data.

| Domain | File Name | Format | Description / Hidden Attacks |
| :--- | :--- | :--- | :--- |
| **Applications** | `app_sec_audit.log.zip`<br>`web_server_access.log.zip` | Raw Text | Contains SQL Injection (SQLi), Cross-Site Scripting (XSS), and Directory Traversal attempts. |
| **Cloud** | `cloud_activity_audit.log.zip` | Raw Text | Simulates unauthorized access, IAM privilege escalation, and anomalous resource deletion. |
| **Email & DLP** | `dlp_events.log.zip`<br>`email_gateway_events.jsonl.zip` | Text / JSONL | Phishing payloads, malicious attachments, and data exfiltration attempts. |
| **Endpoints** | `linux_syslog.log.zip`<br>`windows_security_events.log.zip` | Raw Text | Includes Brute Force attacks, Privilege Escalation, and suspicious process execution. |
| **Network** | `dns_query_logs.jsonl.zip`<br>`firewall_traffic.log.zip`<br>`ids_ips_alerts.log.zip`<br>`proxy_access.log.zip`<br>`vpn_access.log.zip` | Text / JSONL | DNS Tunneling, C2 beaconing, port scanning, and unauthorized VPN access. |

---

## 🛠️ How to Use These Logs

These datasets are formatted for easy ingestion into any major SIEM, log analysis tool, or command-line parser.

1. **Splunk / ELK Stack:** Extract the `.zip` files. Use the standard "Add Data" or ingestion nodes. JSON files will auto-extract fields; raw text logs can be parsed with standard regex/grok patterns.
2. **Command Line (Linux):** Perfect for practicing `grep`, `awk`, `sed`, and `jq` for rapid triage.
3. **Custom Scripts:** Ideal for testing Python automation or custom log-parsing scripts.

---


## 🕵️‍♂️ Threat Hunting & Sample Queries

Use these sample queries to extract the hidden attack vectors within the datasets.

### 1. Web Application Attacks (SQL Injection & XSS)
* **Target File:** `Applications/web_server_access.log`
* **Splunk SPL:**
  ```splunk
  index=web sourcetype=access_combined 
  | search uri_query="*UNION*" OR uri_query="*SELECT*" OR uri_query="*<script>*"
  | stats count by src_ip, uri_query, status
  | sort - count


Linux CLI:

Bash:
      [grep -iE "union.*select|%27|<script>" web_server_access.log]


2. Windows Authentication Brute Force
Target File: Endpoints/windows_security_events.log


Splunk SPL:
[Code snippet
index=windows EventCode=4625 
| stats count by TargetUserName, IpAddress 
| where count > 10]


Microsoft Sentinel (KQL):
[Code snippet
SecurityEvent
| where EventID == 4625
| summarize count() by TargetUserName, IpAddress
| where count_ > 10]



3. Suspicious Outbound Network Traffic (C2 Beaconing)
Target File: Network/firewall_traffic.log

Splunk SPL:
[Code snippet
index=firewall action=allowed dest_port!=80 dest_port!=443 
| stats sum(bytes_out) as total_outbound by src_ip, dest_ip, dest_port
| where total_outbound > 50000]




Linux CLI:

Bash
[awk '$5 != "80" && $5 != "443" && $7 == "allowed" {print $3, $4, $5}' firewall_traffic.log | sort | uniq -c | sort -nr]







🤝 Support & Visibility
If you found this dataset helpful for your studies, certifications, or lab setup, please do two things:

⭐ Star this repository so it reaches other analysts who need it.

👤 Follow my GitHub profile to stay updated on future defensive security projects and SOC tools.

Building resources for the community takes time. Your support pushes this project to the top of GitHub search results.

License: MIT License - Free to use, modify, and distribute for any educational or commercial purpose.
