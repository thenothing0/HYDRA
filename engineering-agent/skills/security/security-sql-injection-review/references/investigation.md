# security-sql-injection-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

For source-to-consumer details and a concrete interpretation/repair example, read [consumer trace](consumer-trace.md).

## Open these artifacts first

Open the driver call, bound parameter list, query builder/raw fragment and second-order consumers. Identify the database dialect and whether caller input controls a value, identifier or SQL structure.

## Decisive experiment and source trace

Use a disposable database with one public and one hidden synthetic row. Compare a literal search containing punctuation with the suspected structural path and record the query/bindings and selected fixture rows. For a stored sort/filter value, follow it through the later reporting job instead of stopping at safe insertion. No production row extraction or delay probe is needed.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A database syntax error is a candidate. A bound value containing SQL punctuation is still data. An ORM name does not make raw fragments safe, but a trusted constant selected by a closed map can defeat the structural-control hypothesis.

## Repair acceptance

Bind data values with the driver API and map structural choices to approved constants. Retest normal filters/sorting, literal punctuation, the original structural path and database privilege assumptions.

## When the next edge is unavailable

If the actual driver/bindings or downstream query are unavailable, identify that exact missing consumer and avoid reporting SQL control from string concatenation that never reaches a query.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
