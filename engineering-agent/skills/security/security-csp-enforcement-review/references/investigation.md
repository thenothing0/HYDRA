# Investigation: Effective Content Security Policy enforcement across headers, HTML policies and frame contexts

## Trace in the actual implementation

Resolve the policy applying to the protected document and sink. Separate Report-Only from enforcement; combine multiple enforced policies as simultaneous restrictions. Follow nonce creation and propagation into the actual inserted script.

## Implementation decisions

If several enforced policies are present, test the intersection, not the most permissive header in isolation. Attribute the tested policy to the actual document/frame. A nonce read by privileged automation is not an attacker-readable nonce; strict-dynamic and parser-inserted versus dynamic scripts need separate consumer evidence.

## Operational method

Retain response headers and the position/time of each meta-delivered policy relative to the challenged resource. A meta policy does not retrospectively block earlier content and cannot express every header-delivered directive. Identify unsupported/ignored directives from the actual engine diagnostics. Compare insertion after activation with the same harmless marker before activation; only the applicable enforced policy can serve as the tested security gate.

## Discriminating verification

In an owned fixture, compare the legitimate nonce-bearing bootstrap with one inert untrusted script marker at the same sink and capture whether execution occurs.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An unsafe-looking directive or report-only violation is not a bypass; CSP absence alone does not establish an injection path.

## Repair acceptance

Retest allowed bootstrap and rejected untrusted insertion under the repaired effective policies and the same browser context.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
