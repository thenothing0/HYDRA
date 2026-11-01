# Investigation: Lambda Function URL authentication and application authorization

## Trace in the actual implementation

Identify whether public invocation is intended and which protected action the handler performs. Distinguish IAM URL admission from per-user/object authorization inside the function.

## Implementation decisions

Resolve AuthType and the applicable URL permission model. For URLs subject to the October 2025 requirements, evaluate both lambda:InvokeFunctionUrl and lambda:InvokeFunction; one allow is insufficient. Under AWS_IAM include same-account versus cross-account identity/resource policies and effective denies. NONE removes IAM caller authentication but still requires the public resource-policy grants. Inspect lambda:InvokedViaFunctionUrl on InvokeFunction permission: a URL-only grant does not authorize direct Invoke. Handler tenant/object checks remain separate, and an intentionally public response is not a vulnerability.

## Discriminating verification

Use an owned function with a synthetic response/action; compare intended caller and one restricted context without enumerating other functions.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A public function URL or CORS header is not a vulnerability when only public content is returned.

## Repair acceptance

Enforce the intended URL and handler authority, then retest legitimate invocation and restricted operations.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
