# Brute Force Attack Detection Rule Setup in Sentinel - Complete Walktrough

## Overview
Setting up a brute force attack (T1110) detection rule in Microsoft Sentinel SIEM 

## Objective
Build a sheduled kql rule that detects brute force login attempts 

## Data Source
- Windows Security Events - Event ID 4625 - failed login attempt


## Tools Used
- SIEM (Sentinel)
- Azure 

## Key Skill
Kql query writing and analytic rule configuration


## MITRE ATT&CK
- T1110 – Brute Force


## Complete Methodology & Investigation

### Phase 1: Environment Setup

- Navigated from Anzure Sentinel to Microsoft Defender portal 

### Phase 2: Analytics Rule Creation

Inside Defender Portal Side Menu

- Microsoft Sentinel - Configuration - Analytics 
- Selected + Create → Scheduled query rule
- Configured General tab:
  
Name: Brute Force Detection - Failed Logons
Severity: Medium
Status: Enabled
MITRE Tactic: Credential Access
MITRE Technique: T1110 — Brute Force



### Phase 3: Detection Logic — KQL Query

Wrote the following KQL detection rule targeting Event ID 4625 (Windows failed logon):
kqlSecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by
    TargetAccount,
    IpAddress,
    bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| project TimeGenerated, TargetAccount, IpAddress, FailedAttempts



Note -- explain kql better  --


Query logic breakdown:
LinePurposeSecurityEventQuery the Windows Security event log tablewhere EventID == 4625Filter for failed logon events onlywhere TimeGenerated > ago(1h)Scope to the last hour of datasummarize ... bin(TimeGenerated, 5m)Count failures per account and IP in 5-minute windowswhere FailedAttempts > 10Threshold — more than 10 failures signals an attack, not a typoproject ...Output only relevant columns for triage

### Phase 4: Rule Scheduling & Threshold

Run query every: 5 minutes
Lookup data from last: 1 hour
Alert threshold: generate alert when results > 0

Note: the KQL already filters for >10 failures, so any result from the query is inherently suspicious

Event grouping: Group all events into a single alert

Rationale: prevents alert fatigue — one brute-force burst becomes one incident, not 25 separate alerts



### Phase 5: Incident Settings

Create incidents from alerts: Enabled
Alert grouping: Enabled — group alerts if all entities match
Time window: 5 hours
Incident correlation: Tenant default
Rationale: grouping related alerts into one incident gives an analyst the full attack picture rather than fragmented noise

### Phase 6: Results Simulation
Ran "Test with current data" against the workspace.

Result: 0 alerts, flat baseline
Interpretation: No SecurityEvent data is currently ingesting — the rule is valid and live, the environment is simply clean. This is the expected baseline state. The rule will fire automatically when Event ID 4625 data exceeds the threshold.
