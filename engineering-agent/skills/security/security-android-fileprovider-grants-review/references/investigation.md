# Investigation: FileProvider root selection and temporary URI permission scope

## Trace in the actual implementation

Trace which app receives which URI and whether it can access files beyond the intended shared object through path/root or grant handling.

## Implementation decisions

Trace configured roots, canonical path resolution, manifest export/grant settings and individual Intent/ClipData grants. A broad root is potential reach, not proof an attacker has a usable URI grant. Separate read from write and persisted versus temporary access; use owned marker files and verify the effective recipient operation and grant revocation.

## Operational method

Record provider root mapping, canonical file, actual recipient and grant flags on Intent/ClipData, including prefix scope where supported. Separate read/write and actual supported persistability; a client requesting persistence does not make every provider grant persistable. Compare a marker URI with a sibling/outside-root URI and observe permissions after the documented temporary-grant lifetime/revocation event. Exported=false alone does not invalidate an explicitly issued grant.

## Discriminating verification

Use owned emulator apps and synthetic files inside/outside a share root; compare intended URI access and one unauthorized file request.

Separate privileged fixture setup from the restricted actor actions. Retain actual input, the legitimate control and final consumer/state evidence; a suggested fixture is not a performed test.

## Reject or narrow

A content URI or broad-looking path XML is not arbitrary file access without an effective granted/open path.

## Repair acceptance

Constrain roots and URI grants, then retest legitimate shares, grant lifetime and outside-file denial.

## Missing evidence

Name the unavailable artifact or consumer edge and the next evidence that would resolve it. Source-supported proof must not be reported as production observation; denial applies to the tested path, not every implementation.

## Technical references

- [Primary technical starting point](https://developer.android.com/reference/androidx/core/content/FileProvider)

Use the implementation version/profile actually deployed. Retrieval of a reference is distinct from semantic review or execution of the described service.
