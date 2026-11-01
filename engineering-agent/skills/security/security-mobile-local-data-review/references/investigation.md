# security-mobile-local-data-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Map sensitive files/databases/preferences, backups, logs, clipboard/snapshots and cache lifecycle. Define the attacker device state: ordinary app, unlocked user, backup access or compromised device.

## Decisive experiment and source trace

Use synthetic account markers on an owned test device/build. Follow one sensitive value into its stored copies and compare access in the prohibited versus intended device/account state. Test logout/account switch against the declared retention policy.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Reading files on a rooted/jailbroken device does not establish access by an ordinary app. Encryption at rest does not by itself protect data after the legitimate process decrypts it.

## Repair acceptance

Apply appropriate platform storage/protection and lifecycle cleanup for the actual threat model. Retest required offline/background use and the original unintended access/retention path.

## When the next edge is unavailable

Without a device or storage artifact, produce a source storage map and request the exact state/access evidence needed, not a universal insecure-storage finding.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
