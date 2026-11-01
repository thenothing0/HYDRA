# Investigation: Disagreement between multipart validation and the final part consumer

## Trace in the actual implementation

Trace the same part through validation, binding and storage/use. Determine whether duplicate parts, encoding or nested multipart changes the value used after approval.

## Implementation decisions

Record first/last/list selection separately for scalar fields and files. Filename and filename* normalization may diverge from ordinary field selection. Only the value used by the protected consumer matters; a harmless duplicate ignored by both validator and consumer does not establish a bypass.

## Operational method

Preserve the raw bounded multipart body and each layer part inventory: part name/order, disposition, filename parameters, decoded value and file/field classification. Compare inventories with the value eventually authorized and consumed. Include a malformed-boundary rejection control; an echo of one selected value cannot prove all layers saw the same parts or that an alternate file part reached the protected processor.

## Discriminating verification

In an owned fixture compare one valid part with a single deliberately ambiguous benign pair and observe which marker each layer uses.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A duplicate accepted by all layers with the same interpretation is not a bypass; an unused parsed part has no demonstrated consumer.

## Repair acceptance

Use one canonical parser/selection rule and verify validator and consumer receive the same approved value.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://www.rfc-editor.org/rfc/rfc7578)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
