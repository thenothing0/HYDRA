# Investigation: Android deep-link transaction and authenticated action binding

## Trace in the actual implementation

Trace external link fields into account selection and sensitive operations, including links opened before login and replayed after account changes.

## Implementation decisions

Resolve the receiving component and parse route parameters before identifying the authenticated consumer. Authentication of the app user does not authorize every link-selected object or action. A link that merely opens a confirmation screen is not a committed action; compare the final server transaction and any one-time nonce/account binding.

## Discriminating verification

Use a local app/test account fixture and benign action; compare an intended link with another owned account/transaction identifier.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Opening a screen is not execution of a protected action; a required confirmation may already enforce the intended policy.

## Repair acceptance

Bind pending action to current identity and transaction, retesting login transitions, replay and legitimate navigation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
