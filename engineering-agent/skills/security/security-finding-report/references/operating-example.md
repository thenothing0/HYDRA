# Split by cause and make the claim reproducible

## Example that changes the grouping decision

A direct document endpoint denies tenant A access to B. An export job accepts B's document ID and returns B's marker to A. Report the missing nested-document authority in the export path. The export creation and result download are steps of that one cause, not automatically two findings. A separate profile binder that writes a server-maintained role requires a separate report because its authority decision and repair differ.

Write the smallest supported title: “Export job returns another tenant's private document.” Avoid “Critical admin takeover” unless that authority transition was actually established. A stored role becoming admin proves protected-field persistence; if the application has no privileged operation using it, say so. Do not import an expected consequence from another product.

## Before delivering each report

Reconstruct the actor/session, fixture ownership and exact sequence from raw evidence. The entitled control establishes that the fixture and oracle work; the denied control establishes the boundary. Record a queued export separately from the worker's completed result. For source proof, cite the full entry-to-consumer chain and state that no runtime request was made.

Keep the original failure and repair evidence in the same finding but distinguish their builds. Describe scope, prerequisites and impact in terms a recipient can reproduce without other reports. Use only that finding's evidence excerpts; shared source files are acceptable only when relevant and reviewed for that recipient. The output is a report and evidence index, not a guarantee of eligibility or acceptance.
