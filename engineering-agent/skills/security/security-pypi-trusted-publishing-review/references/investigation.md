# Investigation: PyPI trusted publisher OIDC identity and release artifact selection

## Trace in the actual implementation

Follow accepted OIDC claims to project publication authority and ensure the uploaded distribution is from the approved immutable build.

## Implementation decisions

Match the registered publisher repository, workflow and environment to the OIDC identity allowed to mint the upload token. A successful build is not evidence it selected the artifact eventually uploaded. Inspect reusable-workflow and artifact handoffs; a correctly rejected mismatch is a publisher-binding control, not proof that release contents are trustworthy.

## Discriminating verification

Use a local policy fixture or owned test repository without public publication; compare intended workflow identity and a claim/artifact mismatch.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An OIDC token request or PyPI project name in config is not a successful publishing grant.

## Repair acceptance

Constrain publisher claims and artifact promotion, preserving intended release and rejecting mismatched contexts.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.pypi.org/trusted-publishers/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
