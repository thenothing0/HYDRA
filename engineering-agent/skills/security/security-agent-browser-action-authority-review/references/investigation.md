# Investigation: Agent prepared browser actions bound to current frame, form and account

## Trace in the actual implementation

Follow page-provided instructions or identifiers into navigation and externally visible actions. Distinguish reading page data from authority to submit, purchase or message.

## Implementation decisions

Separate trusted user requests from page text, advertisements, downloaded documents and tool output. Confirm site/account and the material action at the commit step, including navigation between preparation and submission. Viewing or drafting an action is not a financial or messaging effect; test commits only in an owned simulation with explicit synthetic recipients.

## Operational method

Bind the prepared action to browsing context, frame origin, account, destination and material form fields at commit. Retain a DOM/target generation or revalidate after page navigation and form mutation; a stale selector can submit to a different destination while its label stays unchanged. Compare an owned checkout/message simulator before and after a target/frame/account change, without making a real purchase or sending a message.

## Discriminating verification

Prepare an action in an owned browser simulator, then change its frame/account/form destination or DOM target before commit. Compare unchanged authorized commit with revalidated/blocked changed context; use synthetic recipients and values only.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

Merely displaying hostile text is not task deviation; require an actual unauthorized tool action or committed fixture effect.

## Repair acceptance

Bind browser actions to user/site/account intent and verify normal task completion plus ignored page-originated authority claims.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
