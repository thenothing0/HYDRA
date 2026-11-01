# Investigation: Subresource integrity and script provenance at mutable external script loads

## Trace in the actual implementation

Follow which external bytes execute, including fallback loaders and dynamically added scripts. Establish who can change the resource before assigning compromise impact.

## Implementation decisions

Check module/preload and dynamic-loader paths independently; a verified initial script can load unverified descendants. For cross-origin resources include the actual CORS mode in the fixture. Establish a lower-trust publisher and executing fallback before claiming dependency compromise rather than missing defense in depth.

## Operational method

When integrity metadata contains several supported algorithms, derive the strongest supported algorithm and compare against its candidate digest set; matching a weaker digest does not rescue a failed stronger supported set. Retain exact fetched response bytes and the actual browser load result. Separate unsupported algorithms, CORS rejection and integrity failure in diagnostics before attributing an altered-script execution to SRI.

## Discriminating verification

On an owned mirror replace one script with a harmless altered marker and compare the intended hash match, mismatch rejection and fallback behavior.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Missing SRI alone is not a demonstrated vendor compromise; a changed script that never executes is not a provenance failure.

## Repair acceptance

Pin or independently verify intended resources and retest normal loading, rejection and every fallback capable of executing code.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
