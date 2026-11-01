# Investigation: Authorization closure and field projection of expanded organization exports

## Trace in the actual implementation

Follow initiator/tenant authority through queued execution and later retrieval. Check whether role revocation or client-selected tenant affects either stage.

## Implementation decisions

Split generation, storage publication and later download into separate authority decisions. A requester losing membership before worker execution may be denied then, at download, or both according to policy. A signed artifact capability has its declared lifetime; do not assume immediate revocation without the contract.

## Operational method

Specialize in export dataset closure/projection, not queue lifecycle. Build an owned fixture with an allowed root record, a restricted related record and a protected field/attachment. Trace joins, expansion options, serializer projection and artifact manifest into the exported files. Permission to request the root export must not silently authorize every joined row or hidden field. Compare the allowed projection and a forbidden expansion; route enqueue/revocation/download ownership to background-job authorization.

## Discriminating verification

Export one owned root with an allowed relation, a foreign/restricted relation and a hidden field/attachment. Compare default and requested expansions against the export projection contract and inspect every output file/manifest.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A job ID or publicly documented export route is not a data leak; an intentionally shared artifact needs its publication policy.

## Repair acceptance

Bind job, data selection and artifact access to policy and retest delayed execution and download lifecycle.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
