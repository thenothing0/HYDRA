# Worked finding — synthetic A10 laboratory

## Claim

A failed operation leaves a committed partial mutation. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A10:2025; CWE-755 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `1317b4eb3c6fc29ccc031233ca6e541aa565f7a68c67baefb21ba45be62731ad`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The insecure transaction commits a balance decrease then returns failure when a dependency exception is injected. The atomic path rolls back both balance and ledger effects. An unknown authorization result cannot mutate the balance. Successful transfer and a same-identity retry produce exactly one debit.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: SQLite rollback, explicit deny for unknown decisions, and sequential same-operation retry.

Not covered: No live outages, distributed transactions, concurrency-safe idempotency, resource exhaustion or SSH parser was tested. This fixture does not reproduce the Go advisory. A real idempotency key must bind principal, operation and request fingerprint.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
