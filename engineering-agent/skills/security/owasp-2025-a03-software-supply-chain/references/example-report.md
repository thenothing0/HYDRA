# Worked finding — synthetic A03 laboratory

## Claim

Unverified release artifact reaches deployment state. Status: confirmed in the deliberately insecure local fixture only; the guarded comparison passes the covered controls. This is not a finding against the disclosed product or a user application.

- Classification: OWASP A03:2025; CWE-494 (analyst mapping).
- Target: [scripts/verify_lab.py](../scripts/verify_lab.py), SHA-256 `c568bf84ae1515dea4f13cbbed1ea39b711fa7a5cac4f422de17c5aadc86d402`.
- Environment: disposable in-memory Python laboratory; no external services or real credentials.
- Command: `python scripts/verify_lab.py` from this skill folder.
- Preconditions: the insecure code path is deliberately selected by the contrast test.

## Observed evidence and remediation comparison

A modified in-memory ZIP is consumed by the unverified path. The policy-checked path rejects changed bytes before adding any deployed text. A digest supplied in the artifact metadata does not override the out-of-band approved digest; the valid artifact remains consumable.

Use the actual local test names and source function locations when reproducing the result. The script's `secure` switch selects an alternative implementation for comparison; no production application was patched. Do not convert this fixture result into a real deployment finding without tracing the target's own code and controls.

## Impact and confidence

The violated property is observable with controlled fixture data. Severity remains deployment-dependent; no CVSS score is assigned to the training fixture. The result establishes the tested property, not exploitability across an entire OWASP category.

## Coverage and closure

Covered: Artifact byte pinning and declared-source policy with an out-of-band trusted digest.

Not covered: No digital signatures, real provenance attestation, package registry, advisory scanner, install hook, or CI execution was tested. A publisher label is policy metadata, not cryptographic identity.

For a real remediation, apply the change at the actual root cause, repeat the failing case on the changed build, verify the legitimate controls and persistent effects, and record any deployment/migration evidence. Use [finding-template.md](../assets/finding-template.md) for the final report.
