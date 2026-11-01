---
name: security-source-map-disclosure-review
description: "Assess exposed JavaScript source maps for protected source or sensitive information. Use to establish build provenance and incremental disclosure impact; map availability alone does not establish secret leakage."
---

# Source Map Disclosure

Decide what an obtainable map actually discloses beyond the shipped browser bundle, who can obtain it, and whether the disclosed material violates an evidenced confidentiality boundary.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

The exact map and generated bundle, their acquisition URLs/times and hashes, deployment/build identifiers, and the owner's intended publication policy. Repository access is useful but not required for an initial exposure review.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Stop at an exposure observation when the only demonstrated content is ordinary browser code. For remediation, verify that the affected deployment no longer distributes the protected material through maps, bundles, caches or artifact history. Deleting the map does not revoke a leaked credential.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.

## Optional offline inspector

Run `python scripts/inspect_map.py INPUT.map --output NEW.json`. It inventories embedded sources and hashes without extracting source files, validating VLQ mappings, following URLs or executing code. Read the limitations emitted in its JSON output.
