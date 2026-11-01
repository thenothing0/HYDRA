# Worked decision cases

All inputs below are authored synthetic artifacts, not AWS/GCP responses collected by this review. Decisions apply only to the supplied policy and path.

## G01: Does public-read object ACL prove current exposure with UBLA enabled?

```json
{
  "uniform_bucket_level_access": true,
  "old_export_acl": "allUsers READER",
  "effective_public_IAM_allow": false,
  "supplied_direct_anonymous_result": 403
}
```

No. Disabled ACL path and denied direct read refute that particular disclosure claim.

## G02: Is a working signed URL a PAP bypass?

```json
{
  "effective_PAP": "enforced",
  "signed_capability": "valid GET, signer entitled, intentionally issued to this recipient",
  "supplied_direct_anonymous_result": 403,
  "supplied_signed_url_result": "owned synthetic marker"
}
```

No PAP bypass. Signed capability authorization is outside the allUsers/allAuthenticatedUsers grant restriction. Issuer entitlement is separately assessed.

## G03: Does a PAP state of inherited prove enforcement?

```json
{
  "bucket_PAP": "inherited",
  "organization_folder_project_effective_constraint": "not supplied",
  "anonymous_result": "not supplied"
}
```

Inconclusive: inherited is not itself a boolean enforcement result. Resolve ancestor constraint and actual resource path.

## G04: With UBLA disabled, are private object ACLs sufficient to prove confidentiality?

```json
{
  "uniform_bucket_level_access": false,
  "object_ACL": "owner only",
  "effective_bucket_IAM": "allUsers storage.objectViewer",
  "PAP": "not enforced",
  "policy": "marker intended private",
  "supplied_anonymous_read": "owned private marker"
}
```

Supported synthetic unintended-publication boundary via IAM, despite restrictive ACL. Neither system must independently grant when applicable permissions act in parallel.
