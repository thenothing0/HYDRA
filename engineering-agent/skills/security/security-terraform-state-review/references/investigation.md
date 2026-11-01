# security-terraform-state-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect state/plan backend and artifact distribution, access policy, versioning/logging and provider/resource behavior. Identify who can obtain which saved bytes.

## Decisive experiment and source trace

Using an owned nonsecret fixture or supplied redacted state, trace whether a sensitive value remains in saved state/plan and whether the alleged recipient can read it. Compare display redaction with actual storage; record encryption/access context separately.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

The sensitive attribute normally affects presentation and is not a universal omission guarantee. Presence in properly protected owner state is not by itself unintended disclosure.

## Repair acceptance

Restrict backend/artifact access and use supported omission/ephemeral patterns where applicable to the actual provider/version. Retest normal apply/plan and the original unintended distribution path.

## When the next edge is unavailable

If backend permissions or saved artifacts are absent, request them and distinguish sensitive-state persistence from proven unauthorized access.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
