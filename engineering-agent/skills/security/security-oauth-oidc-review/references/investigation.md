# security-oauth-oidc-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Map authorization server, client, redirect URI, session correlation, code exchange, identity claims and account-linking decision. Record provider/library versions and public versus confidential client behavior.

## Decisive experiment and source trace

Use two controlled identities and browser sessions to trace one complete login or link ceremony. Check whether the callback is bound to the initiating session, expected provider/client and intended account. For linking, compare the authenticated account receiving the link with the external subject actually proven by the exchange.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A callback URL, client ID or provider login page is not a secret. Do not declare login CSRF or account takeover from a missing parameter name when the actual library provides equivalent supported binding.

## Repair acceptance

Use the provider-supported flow and bind transaction, client, redirect and stable subject to the intended account. Retest legitimate login/linking, wrong-session/provider callback and the originally evidenced mismatch.

## When the next edge is unavailable

If callback or exchange evidence is missing, request that stage specifically. Preserve which identity-binding edge remains unproven rather than guessing from frontend parameters.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
