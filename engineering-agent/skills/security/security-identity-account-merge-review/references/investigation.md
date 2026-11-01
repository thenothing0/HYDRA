# Investigation: Account merge authority and transferred entitlements

## Trace in the actual implementation

Trace which identity authorizes source and destination and when resources, MFA/recovery settings and sessions move. Identify stale proof or one-sided confirmation.

## Implementation decisions

Prove authority over both source and destination under the product policy, including proofs captured before an account switch. Decide which sessions, recovery factors and balances may transfer. An atomic resource transfer without correct identity binding is still unsafe; correct binding without partial-state cleanup is a separate invariant.

## Discriminating verification

Use two owned synthetic accounts with distinct resources; compare a properly confirmed merge with a missing or wrong-account confirmation.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An alias/display-name change is not an account merge; access to already-owned resources proves no new entitlement.

## Repair acceptance

Bind both account proofs and perform atomic policy-defined transfer; verify cancellation, recovery settings and session treatment.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
