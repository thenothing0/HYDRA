# Investigation: CircleCI context secrets and workflow approval/source binding

## Trace in the actual implementation

Determine whether a lower-trust config revision can execute a context-bearing job or change the artifact after an approval.

## Implementation decisions

Inspect context restrictions, project identity and approval job placement against the exact workflow revision. An approval event is not sufficient if a later untrusted script substitution changes what runs with the context. Fork/branch settings and expression restrictions may deny context access before execution; retain that denial as a specific negative control.

## Operational method

Record which approving actor is permitted by a restricted context security group and which project/expression restrictions the context-bearing job must satisfy. Workflow approval and context access are distinct decisions. Compare an approved job whose actor/context eligibility fails with an eligible actor using the same source revision. Do not treat a green approval node as proof that secrets were injected or that the approver authorized a later substituted script.

## Discriminating verification

Use an isolated config/local execution fixture with synthetic context values and inert publication; compare authorized and untrusted source contexts.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A context name in config or an approval click is not proof the consumed revision was trusted.

## Repair acceptance

Bind contexts and approval to actual trusted job inputs, retesting legitimate release and fork/branch separation.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://circleci.com/docs/contexts/)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
