## Overview
Analyzing a simulated phishing email // searched for phishing email templates 

## Objective
Examaning the emails sender and content to find indicators of a phishing attempt to than evaluate if further actions need to be taken

## Tools Used
— CanIPhish simulator (caniphish.com)
- manual indicator analysis (hover over buttons)
- if it wouldn't be a simulation - any.run/joe sandbox/vm  

## ## MITRE ATT&CK
Initial Access (TA0001)
T1566 — Phishing
not T1566.002 — Spearphishing Link (but closest to since since its not a targetted attack) 

## Complete Methodology & Investigation

### Phase 1: Email Received
- rceived an email claiming to be from American Express asking to confirm a recent card request
- Subject: Confirm your recent card request
- The email uses urgency and mentions failing account-safety to pressure into clicking the link

### Phase 2: Sender Analysis (spoofed domain)
- Sender display name: American Express
- Actual sender domain: alerting-services[.]com (real domain is americanexpress.com)
- Would check domain registration age with whois.com 

### Phase 3: Content Red Flags 
- Urgency: "To help us keep your account safe, can you please confirm this request?" pressures the user to act fast
- Action buttons: "Confirm Request" and "Something's Wrong" are designed to be clicked
- Credential harvest: "sign in to your account" link aims to send the user to a fake login page to steal credentials
- Brand impersonation: uses the American Express logo and styling to look legitimate
- would hover NOT CLICK over buttons and analyze link or view the raw source by clicking "Inspect"

### Phase 4: Findings
- Spoofed sender domain (alerting-services[.]com) impersonating American Express
- Credential-harvesting links disguised as account-confirmation buttons
- Classic phishing pattern: brand impersonation + urgency + fake login link
- Verdict: confirmed phishing (T1566 – Phishing)

### Phase 5: Analyst Decision
- Verdict: True Positive — phishing email
- Safe handling: never click the links — inspect by hovering to reveal the real URL, viewing raw email source and analyzing any suspicious URLs in a sandbox (URLScan.io / Any.Run) rather than visiting them
- Response: report the spoofed domain (alerting-services[.]com) to its registrar and hosting provider for suspension/takedown, and block it at the email gateway and firewall to prevent further delivery
- User guidance: advise the reporting user not to interact with the email and to delete it
