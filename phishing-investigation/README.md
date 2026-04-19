# Phishing Investigation

## Scenario
User reported a suspicious email.

## Tools
- Email header analyzer
- VirusTotal

## Investigation
Checked sender domain and SPF records.

## Findings
Spoofed domain used for phishing.

## MITRE ATT&CK
T1566 – Phishing

## Detection Idea
Flag emails with failed SPF + suspicious domains.
