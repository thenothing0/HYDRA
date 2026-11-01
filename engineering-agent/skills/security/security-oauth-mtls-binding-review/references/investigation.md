# Investigation: Certificate-bound OAuth tokens across TLS termination

## Trace in the actual implementation

Follow the verified peer certificate through termination into the token check. Separate a request-supplied certificate header from authenticated proxy metadata.

## Implementation decisions

If TLS terminates at a proxy, establish how verified certificate identity reaches the resource and who can set equivalent headers. Compare the token certificate thumbprint with that verified identity. Distinguish rejected TLS handshake from application rejection of an otherwise authenticated wrong certificate.

## Discriminating verification

In an owned TLS fixture compare the bound client certificate with a second owned certificate and a synthetic forwarded-header substitution.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A certificate field in a token or header is not proof of enforced sender constraint; a handshake failure before the resource is a different control.

## Repair acceptance

Bind the resource check to verified peer identity and trusted forwarding, preserving legitimate proxy deployments.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc8705)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
