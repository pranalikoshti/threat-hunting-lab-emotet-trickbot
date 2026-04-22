# Threat Hunting Lab — Emotet & Trickbot Multi-Stage Attack Analysis

**Author:** Pranali Koshti  
**Date:** April 2026  
**Role Target:** SOC Analyst · Network Security Engineer  
**Tools:** Wireshark · Splunk Enterprise · MITRE ATT&CK Navigator · VirusTotal · AbuseIPDB · tshark  

---

## Project Overview

This project documents a complete threat hunting exercise conducted on real-world 
malware network traffic captures from Emotet and Trickbot infections. PCAP files 
were sourced from malware-traffic-analysis.net, a publicly available resource used 
by security professionals for training and analysis.

The exercise covers the full threat hunting workflow: packet-level analysis, 
IOC extraction, SIEM ingestion, behavioral detection rule development, and 
MITRE ATT&CK technique mapping.

---

## Key Findings

| # | Finding | Malware | MITRE Technique |
|---|---------|---------|-----------------|
| 1 | C2 payload delivery via disguised WordPress URI /wp-content/L/?160244 | Emotet | T1105, T1036 |
| 2 | Secondary C2 on non-standard port 8080 | Emotet | T1071.001 |
| 3 | Infected host used as SMTPS spam relay on port 465 | Emotet | T1566 |
| 4 | Suspected Cobalt Strike beacon at 6-second intervals | Trickbot | T1071.001, T1219 |
| 5 | GPO access on domain controller SYSVOL share via SMB | Trickbot | T1484.001, T1021.002 |

---

## IOC Summary

| IOC Type | Value | Source | VT Score | MITRE |
|----------|-------|--------|----------|-------|
| IP Address | 101.99.3.20 | Emotet | 5/94 | T1105, T1036 |
| URI Path | /wp-content/L/?160244 | Emotet | N/A | T1036 |
| Filename | BVGIRVlgdJNp9RRpMUXcp.zip | Emotet | 0/94 | T1105 |
| IP Address | 165.227.166.238 | Emotet | 10/94 | T1071.001 |
| IP Address | 162.246.19.18 | Emotet | 0/94 | T1566 |
| IP Address | 36.95.27.243 | Trickbot | 1/94 | T1071.001 |
| IP Address | 103.102.220.50 | Trickbot | 3/94 | T1071.001 |
| IP Address | 5.199.162.3 | Trickbot | 1/94 | T1071.001, T1219 |
| URI Path | /rob87/ & /tot108/ | Trickbot | N/A | T1071.001 |
| File Path | \Policies\...\gpt.ini | Trickbot | N/A | T1484.001, T1021.002 |

---

## MITRE ATT&CK Coverage


<img width="1888" height="1057" alt="MITRE ATTCK heatmap" src="https://github.com/user-attachments/assets/43d185f1-693a-4f7d-8d64-96ef6b99ee3f" />



| Technique ID | Technique Name | Tactic |
|-------------|----------------|--------|
| T1105 | Ingress Tool Transfer | Command and Control |
| T1036 | Masquerading | Defense Evasion |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1566 | Phishing | Initial Access |
| T1219 | Remote Access Software | Command and Control |
| T1484.001 | Domain Policy Modification: Group Policy Modification | Persistence, Lateral Movement |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |

---

## Splunk Detection Rules

Three behavioral SPL detection rules were developed and saved as production-ready 
Splunk alerts. All rules are behavioral — none rely on known-bad IP signatures.

### Rule 1 — C2 Beaconing Detection
Detects external IPs receiving repeated HTTP connections from internal hosts.
Maps to: T1071.001

### Rule 2 — DGA Domain Detection  
Detects DNS queries for domain names longer than 20 characters — a strong 
indicator of algorithmically generated domain names used by malware.
Maps to: T1568.002

### Rule 3 — Data Exfiltration Detection
Detects external IPs receiving more than 1MB of large outbound packets from 
internal hosts regardless of IP reputation score.
Maps to: T1048

Full SPL queries are in the splunk-queries folder.

---

## Splunk Dashboard

<img width="1904" height="1079" alt="Splunk Dashboard" src="https://github.com/user-attachments/assets/643af21b-2dbd-41d2-957e-5d7fe666ba62" />


---

## Methodology

### Phase 1 — Wireshark Packet Analysis
- Opened PCAP files and ran Statistics → Conversations to identify top external IPs
- Ran Statistics → Protocol Hierarchy to understand traffic composition
- Applied targeted display filters: HTTP POST/GET, DNS, SMB, large frame detection
- Followed HTTP and TCP streams to inspect full request/response data
- Extracted all suspicious IPs, URIs, filenames, and timestamps

### Phase 2 — IOC Verification
- Verified each suspicious IP against VirusTotal and AbuseIPDB
- Documented VirusTotal scores and malware family classifications
- Noted that multiple confirmed C2 servers scored 0–5/94 demonstrating 
  detection lag in signature-based tools

### Phase 3 — Splunk Log Analysis
- Exported PCAPs to CSV using tshark
- Ingested CSV files into Splunk under index threat_hunt
- Developed and tested three behavioral SPL detection rules
- Built dashboard with five panels visualizing key findings
- Saved all rules as production Splunk alerts

### Phase 4 — MITRE ATT&CK Mapping
- Mapped each confirmed finding to ATT&CK Enterprise technique IDs
- Built coverage heatmap in ATT&CK Navigator
- Documented 7 techniques across 5 tactics

---

## Key Insight: Behavioral vs Signature-Based Detection

A consistent pattern across this analysis was that confirmed C2 servers scored 
0–5/94 on VirusTotal. In a signature-based detection environment this infection 
would have been largely invisible.

The C2 activity was identifiable through behavioral patterns:
- WordPress-style URI paths with non-standard structure indicate staging infrastructure
- Workstation generating outbound port 465 SMTP traffic is anomalous regardless of destination
- Sub-10-second beacon intervals indicate active attacker presence regardless of IP reputation
- SYSVOL GPO access from a non-administrative context indicates lateral movement attempt

This demonstrates the core value of threat hunting: behavioral analysis detects 
what signatures miss.

---

## Repository Structure
threat-hunting-lab-emotet-trickbot/
├── README.md                          — This file
├── report/
│   └── ThreatHuntingReport-PranaliKoshti.pdf   — Full threat hunting report
├── screenshots/
│   ├── wireshark-emotet-c2-request.png         — Emotet C2 finding
│   ├── wireshark-statistics-conversations.png  — Top talkers analysis
│   ├── wireshark-http-stream.png               — HTTP stream inspection
│   ├── splunk-dashboard.png                    — Detection dashboard
│   └── mitre-attack-heatmap.png                — ATT&CK coverage map
├── splunk-queries/
│   └── detection-rules.spl                     — All 3 SPL detection rules
├── ioc-table/
│   └── ioc-table.csv                           — Full IOC table with VT scores
└── methodology/
└── analysis-notes.md                       — Detailed analysis notes
