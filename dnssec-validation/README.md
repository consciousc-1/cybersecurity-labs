# DNSSEC Validation 

## Overview
Verifying DNSSEC (Domain Name System Security Extensions) on a signed vs. an unsigned domain using dig and DNSViz

## Objective
I want to confirm if the domain is cryptographically signed and validated and compare a secured domain against an unsecured one and understand what threat DNSSEC blocks

## Scenario
A domain's DNS responses need to be checked to determine if they are protected against tampering (spoofing / cache poisoning) or if they can be faked and undetected 

## Tools Used
- dig (Domain Information Groper) — command-line DNS query tool
- DNSViz (dnsviz.net) — visual DNSSEC chain-of-trust analyzer

## Key Skill
DNS security verification and understanding of the DNSSEC chain of trust

## MITRE ATT&CK
Not a single technique — DNSSEC is a defensive control. Relevant attacker behavior it mitigates:
- T1557 — Adversary-in-the-Middle  // DNS spoofing / response tampering
- T1565.002 — Data Manipulation: Transmitted Data Manipulation

## Background: What DNSSEC Does
- Normal DNS has no authentication — a forged response can redirect a user to a malicious server (DNS spoofing / cache poisoning)
- DNSSEC adds cryptographic signatures so a resolver can verify a DNS answer is authentic and unmodified
- IMPORTANT: DNSSEC provides authenticity and integrity, NOT encryption — the query is still visible (encryption is a separate control: DoH (DNS over HTTPS) / DoT (DNS over TLS))
- Key records: RRSIG (Resource Record Signature) = the signature, DNSKEY (DNS Public Key) = the verifying key, DS (Delegation Signer) = links a child zone to its parent, NSEC/NSEC3 (Next Secure) = proves a record does not exist

## Complete Methodology & Investigation

### Phase 1: Querying a Signed Domain (cloudflare.com)
- Ran: dig cloudflare.com +dnssec
- Found an RRSIG record: RRSIG A 13 2 300 ... — proves the A (address) record set is cryptographically signed
- Algorithm 13 = ECDSA P-256 with SHA-256, a modern signing algorithm
- The signature is time-bound (inception + expiration ~2 days apart) — signatures must be re-signed regularly, limiting replay

### Phase 2: Existence vs. Validation (the resolver matters)
- Default resolver: flags showed qr rd ra — signatures existed, but NO ad (Authenticated Data) flag = not validated
- Cloudflare resolver: dig @1.1.1.1 cloudflare.com +dnssec — flags showed qr rd ra ad = the resolver validated the signatures
- Lesson: DNSSEC protection requires BOTH the domain to publish signatures AND the resolver to validate them. A signed domain gives no protection if the resolver ignores the signatures

### Phase 3: Querying an Unsigned Domain (google.com)
- Ran: dig @1.1.1.1 google.com +dnssec (same validating resolver as Phase 2)
- No RRSIG record, no ad flag — even though the resolver does validate
- The absence is the point: google.com publishes no DNSSEC signatures, so there is nothing to validate

### Phase 4: Visual Confirmation (DNSViz)
- cloudflare.com: full chain of trust secure (teal) from root (.) → com → cloudflare.com. Status: Secure across RRset, DNSKEY/DS/NSEC, and Delegation
- google.com: root and com zones are signed, but google.com's own records show Insecure (13). The chain of trust does not extend to google.com
- Note: "Insecure" = unsigned (no DNSSEC), not "Bogus" (which would mean broken/invalid DNSSEC and show red)

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
