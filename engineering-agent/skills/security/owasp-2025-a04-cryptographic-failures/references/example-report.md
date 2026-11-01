# Worked finding — synthetic A04 laboratory

## Claim

Unsalted password records reveal equal passwords. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A04:2025; CWE-759 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `2a854bbcfb68041c1046bb456b80e67449a837ace9c9c8130ae67dd7a0557521`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The insecure SHA-256 path produces equal stored digests for equal fixture passwords. The salted derivation produces different digests for explicitly different salts. Correct and Unicode passwords verify; wrong passwords and substituted salt fail.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: Password verification and salt binding using stdlib PBKDF2-HMAC-SHA256.

Not covered: No cracking-resistance benchmark, random-generator audit, TLS handshake, encryption, key rotation or production work-factor assessment was performed. The lab uses only 10,000 iterations for speed; do not copy it as a production configuration.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
