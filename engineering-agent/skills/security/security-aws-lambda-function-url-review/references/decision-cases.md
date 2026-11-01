# Worked decision cases

All inputs below are authored synthetic artifacts, not AWS/GCP responses collected by this review. Decisions apply only to the supplied policy and path.

## L01: Does an allow for InvokeFunctionUrl alone prove a new Function URL can be invoked?

```json
{
  "applicable_model": "post-October-2025 two-action requirements",
  "AuthType": "AWS_IAM",
  "allow": [
    "lambda:InvokeFunctionUrl"
  ],
  "effective_InvokerFunction_allow": false,
  "supplied_trace": "gateway denies; handler marker unchanged"
}
```

No invocation authority demonstrated: the second required permission is missing. Policy observation and supplied denial only, no AWS call.

## L02: Is AuthType NONE sufficient to claim public invocation?

```json
{
  "AuthType": "NONE",
  "applicable_resource_policy_public_grants": false,
  "supplied_trace": {
    "status": 403,
    "handler_invoked": false
  }
}
```

No. NONE removes IAM caller authentication; effective public resource-policy permission is also required. This path is denied.

## L03: Does the URL-only grant also authorize direct Invoke?

```json
{
  "allow": [
    "lambda:InvokeFunctionUrl",
    "lambda:InvokeFunction"
  ],
  "InvokeFunction_condition": {
    "Bool": {
      "lambda:InvokedViaFunctionUrl": "true"
    }
  },
  "call": "direct Invoke",
  "other_effective_grants": false
}
```

No direct-call grant follows from the stated condition. Other principals or unprovided policies remain unassessed.

## L04: Can we call the public documentation response a vulnerability?

```json
{
  "AuthType": "NONE",
  "effective_public_grants": true,
  "owner_policy": "documentation response is public",
  "delivered_body": "synthetic documentation",
  "protected_action": false
}
```

Expected public publication. No protected effect is present.
