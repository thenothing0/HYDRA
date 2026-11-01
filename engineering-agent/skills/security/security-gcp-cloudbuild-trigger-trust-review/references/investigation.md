# Investigation: Cloud Build trigger/source trust and build service-account delegation

## Trace in the actual implementation

Trace lower-trust source/config/variables into a build running with deployment or secret authority and ensure approval is bound to the actual revision.

## Implementation decisions

Bind trigger source/ref, configuration file location and build service account. A trigger editor may indirectly control privileged build execution even without a direct service-account token. Inspect approval and repository-connection boundaries; do not infer that a PR can select a privileged account merely because a configuration field names it.

## Operational method

Identify trigger creator/editor, required iam.serviceAccounts.actAs authority, configured trigger build account and actual worker execution account. Retain the resolved source/ref and build configuration from the admitted trigger run. A service-account name in untrusted YAML is only a request until platform admission accepts it. The local model must preserve the account-selection gate, and a denied trigger edit must not become a claim that the worker executed under that account.

## Discriminating verification

Use an isolated owned build fixture with inert output; compare trusted release and a lower-trust source/config change.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A build service-account name in config is not usable authority if trigger/approval controls reject the untrusted run.

## Repair acceptance

Bind trusted source and approvals to execution, scope build identity and verify legitimate publication.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.cloud.google.com/software-supply-chain-security/docs/safeguard-builds)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
