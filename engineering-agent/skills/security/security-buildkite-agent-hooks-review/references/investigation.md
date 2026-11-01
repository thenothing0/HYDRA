# Investigation: Buildkite agent hooks, dynamic pipelines and secret-bearing execution

## Trace in the actual implementation

Trace editable dynamic steps or repository hooks into an agent with protected credentials or persistent state.

## Implementation decisions

Identify which hooks come from agent configuration, plugins or the checked repository and when each runs relative to secret injection and checkout. Dynamic pipeline upload can delegate new steps; inspect who supplies those steps and queue/agent selection. A trusted agent administrator altering a hook is not an untrusted repository escape.

## Discriminating verification

Use a local/isolated agent fixture with a synthetic secret and inert hook; compare trusted queue/job and lower-trust uploaded step.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A queue name or dynamic pipeline capability is not a defect without a violated trust boundary.

## Repair acceptance

Separate agent queues/trust and constrain hooks/plugins/secrets, verifying cleanup and approved dynamic workflows.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://buildkite.com/docs/agent/v3/hooks)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
