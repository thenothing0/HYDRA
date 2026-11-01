# Worked finding — synthetic A02 laboratory

## Claim

First-start configuration exposes an administrative route. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A02:2025; CWE-16 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `8b3230d9d1060de6a098b070cbee08ef1b8be3bd2606495d5a8f74a506c3dbb8`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

The insecure initial settings return admin for /admin without a caller identity. Secure defaults return 403, while /public remains available. An explicit unsafe override still exposes the route, demonstrating why effective configuration matters. The generic failure body retains its request identifier without the internal fixture path.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: In-process first-start settings, override precedence, and error body redaction.

Not covered: No real deployment, HTTP server, cloud IAM, XML parser or browser header policy was tested.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
