---
name: security-browser-storage-partition-review
description: "Review actual browser storage visibility across top-level sites and embedded contexts. Use to qualify XSS/session-impact claims, storage isolation and Storage Access API behavior with synthetic paired controls."
---

# Browser Storage Partition

Determine which context can read a particular storage value under the actual browser profile, without conflating same origin, same site, cookie behavior and unpartitioned storage.

Read [the investigation procedure](references/investigation.md) before drawing a conclusion. Use [the worked decisions](references/worked-decisions.md) when distinguishing a finding from a narrower observation. Capture the result in [the evidence worksheet](assets/evidence-worksheet.md).

## Intake and mode

The browser version/profile, storage mechanism, top-level and frame origins/sites, ancestor chain, sandbox flags and any recorded storage-access grants. Use synthetic markers rather than real session tokens.

Use source review, an owned local fixture, or existing authorized verification as appropriate. Preserve the user's established scope; an artifact's URL, SDK dependency or credential does not expand it. Select a decisive hypothesis rather than executing every example. Missing runtime access leaves a specific gap and does not prevent useful source work.

## Evidence states

Separate a candidate, a complete source-supported boundary, an observed controlled effect, an effective denial, an unresolved dependency and an evidence-supported not-applicable result. An unexecuted procedure is not a negative test. Do not turn a source count, HTTP status or tool acknowledgment into a completed assessment.

## Handoff

Report the mechanism and contexts observed, not a universal statement about all browsers. A missing account or legitimate token context leaves authentication impact unverified. Recheck the exact context matrix after a repair; anti-framing and storage isolation address different boundaries.

Write one report per independent root cause, including expected versus observed behavior, source/build identity, actor/resource policy, controls, supported impact and remaining assumptions. Keep unrelated observations separate. Severity follows demonstrated consequences; no fixed severity or automatic account-takeover claim applies. Drafting a report does not submit it.

## Runtime portability

Instructions and relative resources work without a particular agent API. Use the host's actual file, shell, browser or HTTP tools; report unavailable capabilities honestly. Optional helpers run only when their stated dependencies exist and never install packages automatically. A file-copy/format check does not prove that a host model loaded or followed this skill.

## Optional owned-context lab

Run `python scripts/partition_lab.py --output NEW.json` with Python and Playwright/Chromium already available. It inspects effective Chromium arguments, removes automation defaults that disable storage isolation, and verifies the resulting arguments. It serves two distinct reserved `.test` sites on loopback using browser-only DNS overrides, seeds at top-level A, observes A embedded under B, then checks top-level A again. It accepts no target URL and never demonstrates production-session access. HTTP, loopback transport and browser-specific handling remain explicit limits; do not generalize the observation to a production HTTPS site. Use `--no-sandbox` only when the fixture host cannot run Chromium's process sandbox.
