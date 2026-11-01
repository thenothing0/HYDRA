# Mail-domain authorization and DMARC identifier alignment — decision procedure

## Establish the boundary

Identify the exact author domain, legitimate senders, envelope domain and DKIM signing domains. Collect timestamped owner-provided DNS and full sanitized message authentication results; record the DMARC version/receiver policy in use.

## Smallest decisive verification

Evaluate authenticated identifiers and alignment separately from display-name similarity and sender IP reputation. Use supplied messages or an owned local receiving fixture; no unsolicited spoofed mail or third-party delivery is required.

## Reject or narrow unsupported conclusions

A missing record, monitoring policy, SPF pass for an unaligned envelope domain or forged Authentication-Results header is not a demonstrated DMARC pass. Forwarding and receiver handling can affect outcomes; trust only evidence from the actual receiving boundary.

If the boundary is absent, record not-applicable and the reason. If an artifact/access requirement is missing, name that missing decisive check and keep the hypothesis unverified. Observed behavior must match the claimed actor/build/resource; a fixture only proves its encoded boundary. Stop on unexpected unrelated effects or degradation.

## Repair acceptance

Correct the evidenced sender/alignment/policy configuration with staged owner validation of legitimate mail. Retest approved sender alignment and the relevant invalid identity in a controlled environment; keep missing delivery evidence and bounty exclusions explicit.

## Evidence worksheet

DNS/time/source; author/envelope/signing domains; trusted receiver results; SPF/DKIM validity versus alignment; intended senders; receiver/version limits and actual eligibility evidence

Each result should explain the intended policy, caller control, actual consumer, result and competing explanation. Severity follows the evidenced consequence and prerequisites, not the technique label.
