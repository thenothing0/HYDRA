# Worked finding — synthetic A01 laboratory

## Claim

Private record can be read across tenants. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A01:2025; CWE-862 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `08738bf122b68afb34d29b77c88d0eb63d29a8b090203f6979e66a8945b431ce`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

Service.get('alice','A','b', secure=False) returns the synthetic tenant-B body beta. The guarded implementation returns no rows for that actor; bob in tenant B still receives beta. An unauthorized edit leaves the stored body unchanged.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: Object read/write ownership and tenant predicates using SQLite.

Not covered: No HTTP middleware, list/export/cache, CSRF, SSRF, or real identity provider was tested.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
