# Brute Force Attack Detection Rule Setup in Sentinel - Complete Walkthrough
## Overview
Setting up a brute force attack (T1110) detection rule in Microsoft Sentinel SIEM 
## Objective
Build a scheduled KQL rule that detects brute force login attempts 
## Data Source
- Windows Security Events - Event ID 4625 - failed login attempt
## Tools Used
- SIEM (Azure Sentinel)
- Microsoft Defender 
## Key Skill
KQL query writing and analytics rule configuration
## MITRE ATT&CK
Credential Access - T1110 – Brute Force

<img width="860" height="633" alt="Screenshot 2026-06-13 at 14 09 46" src="https://github.com/user-attachments/assets/755ecbd9-de95-4f44-bdf3-fee2c01c96e7" />

## Complete Methodology & Investigation
### Phase 1: Environment Setup
- Navigated from Azure Sentinel to Microsoft Defender portal

<img width="1209" height="567" alt="Screenshot 2026-06-13 at 14 20 09" src="https://github.com/user-attachments/assets/b118975f-f75c-40f6-968f-2a045390479b" />


### Phase 2: Analytics Rule Creation
Inside Defender Portal Side Menu:
- Microsoft Sentinel - Configuration - Analytics

<img width="380" height="753" alt="Screenshot 2026-06-13 at 14 23 03" src="https://github.com/user-attachments/assets/bbdb9ca7-a833-4d8e-afca-7ced6c900fa0" />
  
- Selected then Create to Scheduled query rule

<img width="463" height="190" alt="Screenshot 2026-06-13 at 14 25 33" src="https://github.com/user-attachments/assets/c38d983b-8e90-478d-a223-30e1d4ed8ff6" />

  
Configured General tab:
  
- Name: Brute Force Detection - Failed Logons
- Severity: Medium
- Status: Enabled
- MITRE Tactic: Credential Access
- MITRE Technique: T1110 — Brute Force

<img width="921" height="601" alt="Screenshot 2026-06-13 at 14 27 25" src="https://github.com/user-attachments/assets/9c0d6c42-138c-482f-bf76-0c35cb140188" />

### Phase 3: Detection Logic — KQL Query
Wrote the following KQL detection rule to target Event ID 4625 (Windows failed logon):

    SecurityEvent
    | where EventID == 4625
    | where TimeGenerated > ago(1h)
    | summarize FailedAttempts = count() by 
        TargetAccount, 
        IpAddress, 
        bin(TimeGenerated, 5m)
    | where FailedAttempts > 10
    | project TimeGenerated, TargetAccount, IpAddress, FailedAttempts

<img width="944" height="502" alt="Screenshot 2026-06-13 at 14 28 57" src="https://github.com/user-attachments/assets/540317e2-5056-4a35-b8b2-9165b1d2cf4f" />

### Phase 4: Rule Scheduling & Threshold
Run query every: 5 minutes
Lookup data from last: 1 hour

<img width="909" height="366" alt="Screenshot 2026-06-13 at 14 29 12" src="https://github.com/user-attachments/assets/d509a86b-711c-4d77-8edb-fd5635367498" />

Alert threshold: generate alert when results > 0
Note: the KQL already filters for >10 failures, so any result from the query is inherently suspicious


Event grouping: Group all events into a single alert

Explanation: prevents alert fatigue — one brute-force burst becomes one incident, not 25 separate alerts

<img width="955" height="563" alt="Screenshot 2026-06-13 at 14 29 21" src="https://github.com/user-attachments/assets/95aaf58c-242f-4d09-9a54-d83e0f927848" />

### Phase 5: Incident Settings
Create incidents from alerts: Enabled

Alert grouping: Enabled — group alerts if all entities match


<img width="921" height="466" alt="al" src="https://github.com/user-attachments/assets/2ecfa755-cc4c-4947-8502-e07003ee2e39" />

Time window: 5 hours

<img width="833" height="332" alt="la" src="https://github.com/user-attachments/assets/1076bb2c-7099-4f43-bc3a-01e12b97b957" />


Incident correlation: Tenant default

Explanation: grouping related alerts into one incident gives an analyst the full attack picture rather than fragmented noise

<img width="847" height="287" alt="Screenshot 2026-06-13 at 14 30 01" src="https://github.com/user-attachments/assets/4bf00e3c-1675-48c3-861f-b81e0ac7b4bf" />


### Phase 6: Results Simulation
Ran the query via the Advanced hunting panel against Log Analytics data. 
Result: 0 alerts, flat baseline.
Interpretation: No SecurityEvent data is currently ingesting — the rule is valid and live, the environment is simply clean. 
This is the expected baseline state. The rule will apply itself automatically when Event ID 4625 data exceeds the threshold.

### Possible Brute Force Attacks collected by query 

Credential Access through password guessing

- Not password cracking — needs stolen hashes to be cracked offline
- Not password spraying — rule needs over 10 password guesses per account, not one password against multiple accounts
- Not credential stuffing — no guess needed since logon information is available from previous breach

### False Positive Indicators in SIEM report 

- Failures from internal server and IP address could hint to expired credentials or forgotten password
- User forgot password is seen with usually low count of login attempts from one IP address during business hours
- Ongoing pen testing or vulnerability scan 

### True Positive Indicators

- Source IP isn't in EDR or SIEM allowlist 
- Multiple failures from same IP followed by a successful login
- Websites like Virus Total flag source IP address as suspicious 
- Logon attempts made outside of business hours with no change management context - no scheduled maintenance, updates for that time frame.
