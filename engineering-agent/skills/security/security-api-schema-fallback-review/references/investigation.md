# Investigation: Security validation under API version or schema fallback

## Trace in the actual implementation

Trace whether a fallback parses or defaults security-relevant fields differently from the policy validator, including missing/unknown versions.

## Implementation decisions

Check where version negotiation occurs relative to authentication, canonicalization and validation. Defaults for absent fields can differ from explicit null or unknown enums. A supported legacy format is legitimate; the relevant result is whether the same forbidden operation reaches a protected consumer through a different decoder.

## Discriminating verification

Compare the legitimate version with one supported fallback in an owned operation using harmless distinct markers and the same actor.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Multiple API versions are normal; a parser error or equivalent authorized behavior is not a bypass.

## Repair acceptance

Apply the same invariant after canonicalization and test current, supported legacy and unsupported-version rejection.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
