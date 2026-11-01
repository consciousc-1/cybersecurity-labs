# Cybersecurity Labs

**SOC Tier 1 Analyst portfolio — threat detection, triage, and incident response.**
CompTIA Security+ · Google Cybersecurity Certificate · Microsoft Sentinel · Defender XDR · KQL

Each project documents what I found, the evidence, the actions taken, and the verdict, mapped to MITRE ATT&CK.

---

## Featured: Real Incident

### [macOS LaunchAgent Persistence — Detection to Containment](./macos-launchagent-persistence-ir)
While onboarding my own Mac to Microsoft Defender for Endpoint, real-time protection surfaced a **pre-existing adware infection**: a random-named LaunchAgent (`com.ekqutkgkxyxuonok`) executing AppleScript through a hidden shell.
I triaged both alerts, reconstructed the process tree (`launchd → xpcproxy → bash → osascript`), quarantined and unloaded the persistence, verified no related artifacts remained, and closed the alerts with documented verdicts.
**MITRE:** T1543.001 (Launch Agent) · T1059.002 (AppleScript)

---

## Investigations

| Project | What it shows | MITRE |
|---|---|---|
| [Suspicious IP Analysis](./suspicious-ip-analysis) | Threat-intel enrichment of a botnet C2 IP; resolving conflicting verdicts across ThreatFox, VirusTotal, and AbuseIPDB | T1071 |
| [Phishing Investigation](./phishing-investigation) | Email-based phishing analysis and triage | T1566 |
| [DNSSEC Validation](./dnssec-validation) | Signed vs. unsigned domain comparison (dig, DNSViz), mapped to the DNS-spoofing / AiTM threat it mitigates | T1557 |
| [Brute Force Detection](./brute-force-detection) | Sentinel KQL detection rule for failed-logon brute force (Event ID 4625) | T1110 |

---

## In Progress: Microsoft E5 SOC Lab

A simulated company tenant (HR, Finance, IT, CFO, intern) with Entra ID, Conditional Access, SharePoint, Teams, Microsoft Sentinel, and Defender XDR.
Completed so far: MFA policy with a deliberate gap on the intern account, Entra sign-in logs streaming into Sentinel, and the gap verified in KQL (`ConditionalAccessStatus: notApplied` vs `success`).
Next: credential-harvest simulation against the intern account and a full incident-response cycle. **Target technique:** T1078 (Valid Accounts).

---

## Skills

- **SIEM & XDR:** Microsoft Sentinel, Defender XDR (unified portal), Advanced Hunting
- **KQL:** sign-in log analysis (`SigninLogs`), filtering, projection, sorting
- **Endpoint triage:** Defender for Endpoint alerts, process tree analysis, quarantine verification
- **Incident response:** containment and eradication of persistence, alert classification and case notes
- **Identity:** Entra ID, Conditional Access, MFA policy validation
- **Threat intelligence:** ThreatFox, VirusTotal, AbuseIPDB
- **Email & DNS security:** phishing triage, DNSSEC chain-of-trust validation
- **Frameworks:** MITRE ATT&CK
