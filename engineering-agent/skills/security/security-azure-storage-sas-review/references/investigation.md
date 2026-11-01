# security-azure-storage-sas-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Identify service/account/user-delegation SAS type, issuing principal, exact resource/permissions, validity and applicable revocation mechanism. Inspect authorization before URL issuance.

## Decisive experiment and source trace

With owned synthetic storage, compare a recipient entitled to one object/action with a request to mint a broader token or use it for a different object/action. Record signed scope and actual accepted operation; keep SAS values redacted and avoid unrelated data.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A SAS is designed as a bearer capability. Its presence in a rightful recipient's URL is not a leak by itself. Revocation and stored-access-policy support differ by SAS type.

## Repair acceptance

Narrow issuer authorization, signed resource/permissions and lifetime using the supported type-specific controls. Retest intended access, denied scope and the documented invalidation path.

## When the next edge is unavailable

If SAS type or issuer code is unknown, request it before claiming revocation failure or cross-resource use.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
