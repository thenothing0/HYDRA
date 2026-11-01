# security-aws-workload-identity-review: investigative procedure

This is an authored decision procedure, not an executed target assessment or a universal test list. Adapt the concrete fixture to the user's actual feature. Preserve authorization already established; a missing live capability does not prevent source analysis.

## Open these artifacts first

Inspect OIDC issuer configuration, role trust policy, subject/audience conditions and the CI job's actual token claim shape. Separate trust to assume a role from permissions after assumption.

## Decisive experiment and source trace

Compare claim sets for the intended repository/environment and a prohibited owned fixture context. Determine whether trust distinguishes repository, branch/environment and event context as required by deployment policy. A locally simulated claim comparison is not an actual AWS role session.

For source-only work, identify the entry, transformations, authoritative check and protected consumer in the actual build. Record file/line or artifact locations for each material edge. Do not invent a dynamic observation from that trace.

## Evidence that rejects or narrows the hypothesis

Do not reconstruct a GitHub subject claim from repository display names alone. The [current GitHub OIDC documentation](https://docs.github.com/en/actions/concepts/security/openid-connect), reviewed 2026-10-27, describes a newer immutable-ID default subject format for newer repositories and a GitHub Enterprise Server distinction. Compare the actual issued claims and configured provider trust; a historical example string is not a universal schema.

A trusted issuer URL alone does not bind a particular workflow. A broad subject pattern may be intentional for a multi-repo role; establish the required boundary and other effective conditions.

## Repair acceptance

Bind trust to the intended issuer/audience/subject context and limit the role's effective authority. Retest legitimate deployment and the originally prohibited claim context.

## When the next edge is unavailable

If live claims or trust conditions are missing, request sanitized claim names/values and policy; do not mint or replay third-party workload tokens.

## Deliver a decision, not a checklist count

Write the actual policy, attacker-controlled input, check-to-consumer trace, observed or source-supported effect, legitimate control and remaining gap. Use the existing finding template only for a supported independent root cause; keep inventory and rejected hypotheses in the assessment notes. If an experiment is run, record its build, input, output and side effects. A suggested experiment in this file is not evidence that it ran.

The [family guide](decision-playbook.md) is optional for cross-cutting context; the technique procedure above is the starting point. Use [runtime capabilities](runtime-contract.md) only when host/tool differences matter. Primary technical references remain in the entrypoint and any existing technique guide.
