# Worked finding — synthetic A09 laboratory

## Claim

Untrusted newlines create misleading log lines. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A09:2025; CWE-117 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `5f02c4892ebff5f04e1b4c91ba913d055056a0f4002d1292dbc9d502999a471e`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The raw formatter writes two physical lines from one synthetic actor field. JSON serialization retains one parsed record with the original field value. A unique fixture password marker is excluded, a denied event reaches the in-memory notification sink, and a benign event does not alert.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: Structured log serialization, field allowlisting and a simple local collector/test sink.

Not covered: No production SIEM, viewer behavior for all Unicode controls, collection outage, time-window thresholds, retention, tamper-proofing or real paging was tested.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
