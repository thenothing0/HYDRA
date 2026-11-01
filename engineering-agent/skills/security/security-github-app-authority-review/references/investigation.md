# security-github-app-authority-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Read customer-to-installation mapping, installation token minting, repository selection, requested token permissions and the caller's own account authority.

## Decisive experiment and source trace

With owned local installation fixtures, compare a permitted repository action with a caller-selected installation/repository belonging to another customer. Trace how the service chooses installation identity and narrows the token before the GitHub API operation.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

A GitHub App installation legitimately has app authority distinct from a user token. A broad app permission alone does not prove one customer can invoke another customer's installation.

## Repair acceptance

Bind caller/customer/installation/repository/action at the service and mint the least required token scope. Retest intended customer operations and the original substituted installation/resource.

## When the next edge is unavailable

Without installation selection and caller mapping code, report the missing binding edge; never use exposed real installation credentials to test an external organization.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
