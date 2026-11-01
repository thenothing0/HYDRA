# Investigation: GitHub Actions cache producer identity and privileged consumption

## Trace in the actual implementation

Follow a lower-trust producer artifact into a privileged job that treats restored bytes as code or authoritative metadata.

## Implementation decisions

Apply GitHub cache ref visibility before modeling a poisoned key: a cache created for a pull-request merge ref is not automatically restorable by main under the same key. Trace default-branch visibility, restore-prefix selection and the privileged consumer. If platform scope prevents restoration, the proposed cross-ref chain fails at that edge.

## Discriminating verification

Use a local cache model or isolated repository with inert markers; compare the intended cache producer with a permitted lower-trust key/restore context.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A broad restore prefix is not cache poisoning without a producer path and security-relevant consumer.

## Repair acceptance

Bind cache trust to producer/context or validate consumed artifacts, preserving legitimate safe reuse.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
