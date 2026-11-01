# security-tenant-invitations-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace inviter capability, invited recipient, tenant, proposed role, token storage and acceptance. Read how expired/revoked invites and existing membership are handled.

## Decisive experiment and source trace

Using two owned tenants and inboxes, issue a low-role invitation and inspect whether acceptance can substitute its tenant, recipient or role. Compare the persisted membership with the signed/stored grant. For stale invitations, evaluate the stated revocation/role-change policy rather than assuming an invitation expires on every admin change.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Forwardable invitations may be intentional for some products; a recipient binding claim needs the actual policy. An accepted HTTP response without membership creation is not a role escalation.

## Repair acceptance

Resolve acceptance authority from the trusted invite record, enforce current inviter/grant rules as specified and consume atomically. Retest correct acceptance, mismatched identity/tenant and replay.

## When the next edge is unavailable

If recipient transfer or stale-invite semantics are unknown, request that narrow rule and continue checking immutable tenant/role binding.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
