# Brute Force Attack Detection

## Scenario
Multiple failed login attempts triggered a SOC alert.

## Objective
Determine if this is a brute force or normal user error.

## Data Sources
- Windows Security Logs
- Authentication logs (Event Viewer / SIEM)

## Tools Used
- SIEM (Splunk / Sentinel)
- Windows Event Viewer

## Investigation Steps
1. Filter for failed logins (Event ID 4625)
2. Identify source IPs generating failures
3. Check volume and time window (spikes)
4. Look for successful login after failures (Event ID 4624)
5. Identify targeted accounts

## Findings
- High number of failed logins from single IP: 192.168.1.10
- Attempts across multiple accounts → password spraying pattern
- One successful login detected after failures

## MITRE ATT&CK
- T1110 – Brute Force

## Detection Logic
Alert when:
- >20 failed logins (Event ID 4625)
- From same IP
- Within 5 minutes

## Example Query (Splunk)
