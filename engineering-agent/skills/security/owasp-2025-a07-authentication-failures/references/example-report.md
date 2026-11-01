# Worked finding — synthetic A07 laboratory

## Claim

Recovery material is delivered to an unverified recipient. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A07:2025; CWE-640 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `16101bf889e6ea453e00ec313298f87d8057d8862c85938e42d30aae94011b07`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The insecure request sends an account-A reset token to the synthetic account-B inbox sink. The guarded request sends nothing for that mismatch. Account-A verified recovery works, cannot reset B, and consumes its token once.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: Recipient/account binding and one-time reset using an in-memory delivery sink.

Not covered: No actual email, expiry, session revocation, MFA, federation, token issuer/audience, or throttle behavior was tested. The fixture is not a production recovery implementation.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
