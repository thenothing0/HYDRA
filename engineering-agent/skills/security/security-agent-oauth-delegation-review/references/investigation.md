# Investigation: Agent broker downstream account selection and token-exchange delegation

## Trace in the actual implementation

Determine whether a tool request can select a different user/account/resource while the broker reuses a more privileged downstream token.

## Implementation decisions

Map the broker client, consenting user, downstream resource and requested scopes into the token used by the tool. Consent to one service/tenant does not automatically authorize another. A broad token may be intentional but still needs per-user tool-action checks; inspect token exchange and audience binding without using real delegated tokens against unrelated services.

## Operational method

Specialize in broker account selection and token exchange: initiating client/user, selected downstream connection, resource/audience, scopes and any actor/subject chain. Compare two owned connection handles for the same provider and a changed account after consent. A broker must apply the actual per-client consent/action policy before selecting the token; merely returning a correctly signed token for the wrong stored connection can violate authority without any token forgery.

## Discriminating verification

Use two owned provider connection handles and one broker client consent, then switch the selected account/resource or actor chain before an inert downstream consumer. Compare exact consent-preserving selection with the prohibited connection.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

An authenticated broker or broad token in its vault is not a bypass if every tool operation correctly constrains the caller.

## Repair acceptance

Bind tool caller, consented resource and downstream action, testing revocation and authorized multi-account use.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://genai.owasp.org/llm-top-10/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
