# Investigation: Authenticated full and resumed downloads across redirects and delivery origins

## Trace in the actual implementation

Follow who can obtain the object and whether the delivered response executes attacker content in a privileged origin or leaks the protected object through a changed delivery path.

## Implementation decisions

Separate first-party inline rendering, attachment handling and an isolated download origin. A blob URL may inherit a relevant origin; inspect its creation context. Validate sensitive object access before examining MIME behavior, and do not call authorized public active content a leak solely because it executes.

## Operational method

Specialize in authenticated full versus Range/resume downloads across redirects and delivery origins. Retain the initial request, redirect chain, credential context, final 200/206 response, Content-Range and object version/validator. Compare an entitled full download with a restricted resumed request and the declared capability/revocation policy. A legitimate already-started transfer or signed capability lifetime is not automatically a bypass. Trace a delivered marker into its actual browser/download consumer; route generic upload execution and ordinary XSS to their respective workflows.

## Discriminating verification

Using one owned synthetic object/version, compare authorized full download, authorized range/resume, and a restricted resumed/redirected request under the declared capability lifetime. Retain final recipient, credentials, 200/206 body and version validator.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A filename suffix or absent attachment header is not execution; an authorized download is not a confidentiality violation by itself.

## Repair acceptance

Bind download authority to the object and serve a deliberate safe origin/type/disposition; verify actual browser behavior and normal downloads.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Disposition)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
