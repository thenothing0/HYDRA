# Investigation: Android App Links domain verification and sensitive link routing

## Trace in the actual implementation

Trace verified domain/path matching into application actions, keeping OS routing and in-app parameter authorization distinct.

## Implementation decisions

Use the installed package signing certificate and actual OS domain-verification state, not manifest intent alone. Verified HTTPS links and custom schemes have different routing guarantees. A link reaching the intended app still requires transaction/resource authorization; failed verification does not prove an attacker app receives sensitive data under the tested user defaults.

## Operational method

On Android11/API30 and lower, default App Links verification depends on matching Digital Asset Links for all declared hosts. Android12 introduced the updated verifier/per-host state; record actual OS, target/compat state and user routing choices. For an owned installed app, collect pm get-app-links or DomainVerificationManager state on supported versions, signing certificate and the actual delivered URL/consumer. A user-selected association differs from a domain-verified state, and a manifest or failed verification alone does not prove another app received protected data.

## Discriminating verification

Use owned test domains/emulators and an inert account fixture; compare intended verified link and an unverified/domain-mismatched link.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An intent filter or failed verification alone is not account takeover; establish a reachable protected consumer.

## Repair acceptance

Bind verified origins and in-app action policy, retesting intended links and rejected untrusted routing.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.android.com/training/app-links/verify-android-applinks)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.

- [Additional implementation reference](https://developer.android.com/training/app-links/verify-applinks)
