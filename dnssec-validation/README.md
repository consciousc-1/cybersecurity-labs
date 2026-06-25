# DNSSEC Validation 

## Overview
Verifying DNSSEC (Domain Name System Security Extensions) on a signed vs. an unsigned domain using dig and DNSViz

## Objective
Confirming if the domain is cryptographically signed and validated and compare a secured domain against an unsecured one and understand what threat DNSSEC blocks

## Scenario
A domain's DNS responses need to be checked to determine if they are protected against tampering (spoofing / cache poisoning) or if they can be faked and undetected 

## Tools Used
- dig (Domain Information Groper) — command-line DNS query tool
- DNSViz (dnsviz.net) — visual DNSSEC chain-of-trust analyzer

## Key Skill
DNS security verification and understanding of the DNSSEC chain of trust

## MITRE ATT&CK
Not a single technique — DNSSEC is a defensive control. Relevant attacker behavior it mitigates:
- T1557 — Adversary-in-the-Middle - attacker inserts themselves into the middle
- T1565.002 — Transmitted Data Manipulation - attacker edits DNS and sends victim f.e to a malicious IP

## Background: What DNSSEC Does
- Normal DNS has no authentication — a forged response can redirect a user to a malicious server (DNS spoofing / cache poisoning)
- DNSSEC adds cryptographic signatures so a resolver can verify a DNS answer is authentic and unmodified
- IMPORTANT: DNSSEC gives authenticity and integrity, NOT encryption — the query is still visible, it does not hide the DNS from anyone watching the network. Encrypting that traffic is a separate feature (DoH or DoT), not part of DNSSEC
- Key records: RRSIG (Resource Record Signature) = the signature, DNSKEY (DNS Public Key) = the verifying key, DS (Delegation Signer) = links a child zone to its parent (as seen in DNSViz), NSEC/NSEC3 (Next Secure) = proves a record does not exist

## Complete Methodology & Investigation

### Phase 1: Querying a Signed Domain (cloudflare.com)
- Ran: dig cloudflare.com +dnssec
- Found an RRSIG record: RRSIG A 13 2 300 ... — proves the A (address) record set is cryptographically signed
- Algorithm 13 = ECDSA P-256 with SHA-256, a modern signing algorithm
- The signature is time-bound (inception + expiration ~2 days apart) — signatures must be re-signed regularly, limiting replay

<img width="1431" height="529" alt="Screenshot 2026-06-20 at 13 32 24" src="https://github.com/user-attachments/assets/929c7f35-75b4-47f0-b94b-1a7c5f61cd21" />


### Phase 2: Existence vs. Validation (the resolver matters)
- Default resolver: flags showed qr rd ra — signatures existed, but NO ad (Authenticated Data) flag = not validated
- Cloudflare resolver: dig @1.1.1.1 cloudflare.com +dnssec — flags showed qr rd ra ad = the resolver validated the signatures
- Lesson: DNSSEC protection requires BOTH the domain to publish signatures AND the resolver to validate them. A signed domain gives no protection if the resolver ignores the signatures

<img width="1438" height="707" alt="Screenshot 2026-06-20 at 13 57 40" src="https://github.com/user-attachments/assets/b5cb2f85-fa06-4a3e-82c3-0eaeebc7fa40" />

### Phase 3: Querying an Unsigned Domain (google.com)
- Ran: dig @1.1.1.1 google.com +dnssec (same validating resolver as Phase 2)
- No RRSIG record, no ad flag — even though the resolver does validate
- The absence is the point: google.com publishes no DNSSEC signatures, so there is nothing to validate

<img width="1439" height="412" alt="Screenshot 2026-06-20 at 13 57 54" src="https://github.com/user-attachments/assets/3a52ec5a-0a2c-4509-a1d8-0fc5c7a8b0fb" />

### Phase 4: Visual Confirmation (DNSViz)
- cloudflare.com: full chain of trust secure (teal) from root (.) → com → cloudflare.com. Status: Secure across RRset, DNSKEY/DS/NSEC, and Delegation
- google.com: root and com zones are signed, but google.com's own records show Insecure (13). The chain of trust does not extend to google.com
- Note: "Insecure" = unsigned (no DNSSEC), not "Bogus" (which would mean broken/invalid DNSSEC and show red)

<img width="1404" height="774" alt="Screenshot 2026-06-20 at 14 21 42" src="https://github.com/user-attachments/assets/c966d0d2-38e6-4fb5-93d1-70565d7ae84a" />

### Phase 5: Findings
| | cloudflare.com | google.com |
|--|---------------|-----------|
| RRSIG present | Yes | No |
| ad flag (via 1.1.1.1) | Yes | No |
| DNSViz chain | Secure to domain | Stops at com, domain insecure |
| Protected against spoofing | Yes | No |

- cloudflare.com is fully signed and validated — a forged response would fail validation and be rejected
- google.com is unsigned — a forged DNS response could not be detected by DNSSEC

### Phase 6: Why It Matters (the threat DNSSEC blocks)
- Without DNSSEC, an attacker performing DNS spoofing or cache poisoning can forge a DNS answer and redirect a user to a malicious IP, with no way for the resolver to detect the forgery
- DNSSEC makes this tamper-evident: any forged or modified record fails signature validation and is rejected
- For an unsigned domain like google.com, DNSSEC offers no such protection — the defense only works if the domain is signed AND the resolver validates
