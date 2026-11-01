# Worked finding — synthetic A05 laboratory

## Claim

Concatenated SQL lets an input alter the selected row set. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A05:2025; CWE-89 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `be3113990824430f3d423af8ee63627f81a880ed107968fcf632258913a4c1d8`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The local unparameterized query returns all three synthetic rows for a syntax-changing search term. The bound-value query returns no matches for that term, still matches O'Reilly correctly, accepts a mapped price sort and rejects an unmapped structural choice.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: SQLite value binding and trusted structural mapping.

Not covered: No browser execution, NoSQL, LDAP, template or OS command sink was tested. The SQL example is not a reproduction of the Django advisory.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
