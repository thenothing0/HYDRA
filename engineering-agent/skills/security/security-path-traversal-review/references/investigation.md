# security-path-traversal-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Trace caller path/identifier through decoding, joins, normalization, filesystem resolution and file open. Record the intended root, OS semantics and who can alter parent directories/links.

## Decisive experiment and source trace

Use a temporary owned tree with one allowed file and one denied marker outside the intended subdirectory. Exercise the real path construction/open path and compare the opened object, not just a normalized string. If links are relevant, inspect their ownership/creation authority separately.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A traversal-looking string rejected before open is not file access. A lexical prefix match can disagree with filesystem containment, but an unreachable file path in dead code is not an exposed read.

## Repair acceptance

Enforce the intended object boundary with supported canonical/descriptor APIs and appropriate link policy. Retest normal nested files, the original escape and denied marker without reading system files.

## When the next edge is unavailable

If platform or file-open consumer is unknown, request that detail. Distinguish URL routing normalization from filesystem object access.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
