# security-csv-formula-injection-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read export quoting, delimiters, cell typing and intended spreadsheet applications/import settings. Identify a recipient who opens attacker-influenced data outside the attacker's own view.

## Decisive experiment and source trace

Create a local CSV with an inert formula marker and a legitimate text control. Import it in the intended application/settings and observe cell interpretation, including the actual quoting/delimiter path. Preserve whether the result was merely authored or actually opened.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A leading formula character in CSV bytes is a candidate, not proof of execution in every spreadsheet. Quoting protects CSV structure but may not force a spreadsheet cell to text.

## Repair acceptance

Choose a format/cell representation appropriate to intended recipients and test round-trip behavior. Retest ordinary data, delimiters/quotes and the original formula interpretation without external commands or links.

## When the next edge is unavailable

When no spreadsheet runtime exists, document affected bytes and the missing application interpretation; do not claim code execution from file text alone.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
