# Phishing Investigation - Email Indicator Analysis

## Overview
Analyzing a simulated phishing email to identify sender and content-based red flags  // sourced from a phishing email template simulator

## Objective
Examine the email's sender and content to find indicators of a phishing attempt, then evaluate whether further action needs to be taken

## Scenario
A user reported a suspicious email that needs to be investigated to determine whether it is a genuine phishing attempt

## Tools Used
- Caniphish simulator (caniphish.com)
- Manual indicator analysis (hover over buttons, inspect source)
- In a real (non-simulated) case: Any.Run / Joe Sandbox / isolated VM
  
## Key Skill
Phishing email analysis and analyst triage decision-making

## MITRE ATT&CK
Initial Access (TA0001)
T1566 — Phishing  // not T1566.002 Spearphishing Link since it's not a targeted attack

## Complete Methodology & Investigation

### Phase 1: Email Received
- Received an email claiming to be from American Express asking to confirm a recent card request
- Subject: Confirm your recent card request
- The email uses urgency and talks about account-safety to pressure the user into clicking the link

 <img width="1366" height="378" alt="Screenshot 2026-06-16 at 19 15 27" src="https://github.com/user-attachments/assets/2c283ecc-5473-41e6-94a0-307fb974fbfe" />

### Phase 2: Sender Analysis (spoofed domain)
- Sender display name: American Express
- Actual sender domain: alerting-services[.]com (real domain is americanexpress.com)
- Checked the actual sending domain via WHOIS ( registered 2021-02-15 so not new - likely older since this is from a simulation )

<img width="854" height="872" alt="Screenshot 2026-06-16 at 23 09 29" src="https://github.com/user-attachments/assets/79188e5f-7c6e-486d-b0e8-455bd1c8850d" />


### Phase 3: Content Red Flags
- Urgency: "To help us keep your account safe, can you please confirm this request?" pressures the user to act fast
- Action buttons: "Confirm Request" and "Something's Wrong" are designed to be clicked
- Credential harvest: "sign in to your account" link aims to send the user to a fake login page to steal credentials
- Brand impersonation: uses the American Express logo and styling to look legitimate

<img width="1291" height="784" alt="Screenshot 2026-06-16 at 19 15 48" src="https://github.com/user-attachments/assets/4e23fb8b-8aa1-49d6-8310-7c9720af4211" />


  
- Would hover (NOT click) over buttons to reveal the real URL or view the raw source via "Inspect"

<img width="906" height="637" alt="Screenshot 2026-06-16 at 23 28 22" src="https://github.com/user-attachments/assets/4fbc9bb1-da53-43d0-9ea8-1791f0a31726" />

  
### Phase 4: Findings
- Spoofed sender domain (alerting-services[.]com) impersonating American Express
- Credential-harvesting links disguised as account-confirmation buttons
- Typical Indicators like brand impersonation, call to action and fake login link
- Verdict: confirmed phishing (T1566 – Phishing)
  
### Phase 5: Analyst Decision
- True Positive — phishing email
- Safe handling: never click the links — inspect by hovering to reveal the real URL, viewing the raw email source, and analyzing any suspicious URLs in a sandbox
  ( f.e URLScan.io / Any.Run) rather than visiting them. Malicious domains/URLs need to be written defanged (alerting-services[.]com) to not be clicked and activated by accident 
- Action: report the spoofed domain (alerting-services[.]com) to its registrar and hosting provider for takedown and block it at the email gateway and firewall to prevent further delivery
