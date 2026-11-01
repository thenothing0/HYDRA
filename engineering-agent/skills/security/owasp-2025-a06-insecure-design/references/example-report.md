# Worked finding — synthetic A06 laboratory

## Claim

A stale one-time check commits two benefits. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A06:2025; CWE-362 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `603faa49685de8bc66e978b04532bc4dd206f53bceb50ca39693ab484a0cabb7`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

A deterministic two-thread barrier sends both attempts past the insecure check and yields two committed fixture ledger entries. The guarded critical section yields one entry and one successful result. Invalid and repeated state transitions are rejected; the valid paid-to-shipped transition works.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: Process-local synchronized redemption and a small state-transition model.

Not covered: The lock is only a single-process demonstration. Distributed workers require an appropriate database/coordination invariant. This does not reproduce Stripe or measure probabilistic race detection.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
