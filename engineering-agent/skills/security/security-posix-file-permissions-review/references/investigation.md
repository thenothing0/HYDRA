# security-posix-file-permissions-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Record effective/real UID/GID, supplementary groups, umask, directory ownership and descriptor open/check/use. Identify who controls every parent component, not only the basename.

## Decisive experiment and source trace

In an owned temporary tree use inert marker files to inspect whether the privileged-equivalent operation consumes the same inode it checked. Use supported atomic/descriptor-relative operations and a controlled link/parent replacement when relevant; never target system files.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

O_NOFOLLOW on a final component is not general protection for every parent. A writable directory alone needs a reachable privileged consumer and replacement/creation authority to establish the defect.

## Repair acceptance

Bind file authority to appropriate descriptors/atomic operations and trusted parents under platform semantics. Retest normal creation, original replacement/link case and cleanup/object identity.

## When the next edge is unavailable

Without platform and effective identity/open sequence, request those details and keep the race/authority path conditional.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
