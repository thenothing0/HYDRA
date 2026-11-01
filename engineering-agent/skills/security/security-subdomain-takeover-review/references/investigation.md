# security-subdomain-takeover-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Collect timestamped authoritative DNS, provider resource state and current provider binding/verification rules. Distinguish dangling DNS from an actually claimable resource.

## Decisive experiment and source trace

Use passive evidence or an explicitly owned provider sandbox to test the ownership gate. Establish whether the external resource identifier can be allocated and bound by an unrelated account under current provider rules, without claiming a live third-party resource.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A CNAME, provider error page or nonexistent resource is not enough. Provider domain verification or reserved resource identity may prevent takeover even when DNS is dangling.

## Repair acceptance

Remove obsolete DNS or restore the correct owned resource/binding and verification. Retest authoritative records and intended service behavior; do not treat cached DNS as the sole repair result.

## When the next edge is unavailable

If claimability cannot be established safely, label dangling-resource exposure as suspected and state the exact provider ownership check still missing.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
