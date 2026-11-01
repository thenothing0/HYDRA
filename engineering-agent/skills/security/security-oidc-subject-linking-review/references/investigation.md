# Investigation: Pairwise subject and sector/client migration into existing local accounts

## Trace in the actual implementation

Trace the external stable identity pair into local account selection. Determine whether email/domain/display-name changes can select an unrelated account or skip linking consent.

## Implementation decisions

Use issuer plus subject as the external identity anchor and inspect the declared linking exception, if any. Email can change or be recycled; a verified-email flag describes a claim, not proof of control of an existing local account. Check re-linking and unlinking, not only first login.

## Operational method

Specialize in pairwise-subject/sector or client migration rather than ordinary email linking. Retain old and new issuer/client/sector context, immutable external subject and the approved migration mapping. A changed pairwise sub can legitimately identify the same user only through an authorized mapping; never infer that mapping from a recycled email. Compare approved migration with a new unrelated subject sharing the old display/email label and verify that existing local authority is not reassigned.

## Discriminating verification

Model an owned client/sector migration with approved old-subject to new-subject mapping, then substitute an unrelated subject sharing only email/display metadata. Compare final local account/authority selection, not login success alone.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Matching verified email can be an explicitly supported linking policy; demonstrate a violated requirement rather than imposing a universal prohibition.

## Repair acceptance

Bind identities according to the declared linking policy and require the appropriate existing-account proof; retest collisions and intended links.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://openid.net/specs/openid-connect-core-1_0.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
