# Worked finding — synthetic A08 laboratory

## Claim

Modified authenticated data is processed when verification is omitted. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A08:2025; CWE-345 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `094383662dd856e74be2a4aca467e3da6b34d6495deea9aae4fe527e1ec864e1`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The unverified receiver accepts modified amount 99 with a signature made for amount 10. The verifying receiver rejects the changed body and a different-key signature without changing its ledger. It accepts the valid event once, rejects replay, and rejects a signed forbidden field.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: HMAC-bound message bytes, fixed authority key, schema and one-time event identity.

Not covered: No unsafe object deserialization, public-key signing, artifact updater, concurrent replay storage, freshness window or key rollover was tested. The fixture key is public synthetic data.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
