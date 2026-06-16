# Suspicious IP Analysis - Threat Intelligence Enrichment

## Overview
Investigating a suspicious IP flagged as a botnet C2 server using open-source threat intelligence tools

## Objective
Take a source IP and determine whether it is malicious by cross-referencing multiple OSINT tools, then make a true or false positive decision

## Scenario
A source IP needs enrichment to confirm whether it is a known threat before escalating

## Tools Used
- ThreatFox
- VirusTotal
- AbuseIPDB

## Key Skill
Threat intelligence enrichment and analyst triage decision-making

## MITRE ATT&CK
Command and Control (TA0011) // Botnet C2

<img width="1487" height="572" alt="Screenshot 2026-06-16 at 13 30 36" src="https://github.com/user-attachments/assets/e79901c4-d47e-4cd8-9dd2-30b57801ccb1" />


## Complete Methodology & Investigation

### Phase 1: Sourcing the IOC
- Browsed the ThreatFox IOC database and selected a suspicious IP flagged as a botnet C2
- IP: 106.14.116.17 (port 8080)
- Note: ThreatFox lists the IOC as 106.14.116.17:8080 (IP + port, identifying the exact C2 service), while AbuseIPDB checks reputation at the IP level, so the port is omitted when searching there


  
### Phase 2: ThreatFox
- IOC (Indicator of Compromise): 106.14.116.17:8080
- Labels it as botnet_cc — a botnet Command & Control server (C2), meaning this IP controls infected machines (bots)
- Confidence: 100%, marked as compromised
- Source: abuse.ch behavioral malware tracking

  
### Phase 3: VirusTotal
- 0 detections
- Despite ThreatFox flagging this IP with 100% confidence, VirusTotal showed no vendor detections — likely because the IP was newly reported (first seen one day prior) and threat intelligence had not yet propagated
- Lesson: a single source can produce a false negative — enrichment requires cross-referencing multiple tools


  
### Phase 4: AbuseIPDB
- Confidence of Abuse: 2% — reported only once, a week ago
- Host: Alibaba Cloud (data center / web hosting) — the kind of infrastructure attackers rent briefly to host C2, then abandon
- A low score does not mean safe — it means few people have reported it yet


  
### Phase 5: Why the Tools Disagree
The two sources disagree: ThreatFox (behavioral malware tracking) confirms active C2, while AbuseIPDB (user reports) shows almost nothing. A reputation score alone can't clear an IP — a freshly-deployed C2 on cloud hosting can look clean on AbuseIPDB while being actively malicious. Behavioral feeds and reputation databases must be used together.



### Phase 6: Analyst Decision
- Verdict: True Positive — confirmed botnet C2
- Reasoning: ThreatFox behavioral tracking confirms active C2 (100% confidence). AbuseIPDB's low score reflects limited reporting, not safety, and does not override behavioral confirmation
- Action: Escalate to Tier 2 for response. As a Tier 1 analyst, I confirmed the threat through enrichment; remediation falls to Tier 2 — specifically, checking whether any internal host connected to 106.14.116.17:8080, then isolating and scoping any affected machines

