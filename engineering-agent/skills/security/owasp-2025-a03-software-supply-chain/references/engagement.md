# Engagement modes and evidence handling

## Choose the requested outcome

- Code review: identify reachable root causes and constraints in the supplied repository; change code only when remediation is requested. Begin with project instructions and existing architecture/tests.
- Bug bounty: use the program's actual in-scope assets, permitted methods, accounts and exclusions; preserve authorization already present. Work from observed application paths rather than broad target discovery. Program acceptance/bounty eligibility is separate from technical validity.
- Mixed: connect runtime observations to source locations and deployment/build identity. Explain when the source commit is not proven to match the deployed build.

Do useful local/read-only work while a genuinely missing scope detail is pending. Ask only for the missing decision that affects the next operation. Do not repeatedly ask for authorization the user has already provided. An asset listed in a tool manifest records scope; it does not grant permission.

## Working record

Record the target/build or the limits on identifying it, chosen category, identities/roles, synthetic fixtures, relevant entry points, expected security rule, and what will constitute evidence. Before an active check choose a small request budget and a reversible action. For stateful operations also define the owner-side state inspection and cleanup. GET can have effects; inspect the actual endpoint instead of assuming the method is harmless.

Keep raw working material separate from deliverable evidence. Redact credentials, cookies, reset tokens, unnecessary personal data and unrelated records before saving evidence for delivery. Use opaque IDs to correlate requests/observations. Hash saved artifacts to detect later accidental changes. A hash proves byte consistency, not origin, correctness or exploitability.

## Coverage and triage

Maintain one coverage row per actual boundary/path under review: tested with observed result and evidence IDs; not tested with the missing dependency/reason; or not applicable with a concrete reason. A zero-finding report still includes the coverage ledger. Do not convert unknowns to passes.

Confirm only when the intended policy, reachability and security effect are supported. Code-only confirmation can be valid; identify the entry point, caller-controlled value, missing/ineffective control and sink/state effect, and say dynamic verification was not run. Keep uncertain claims suspected/unverified. A lack of black-box observability is not evidence that an internal control is absent.

Prioritize using demonstrated exposure, required actor, asset sensitivity, blast radius and compensating controls. Explain impact without borrowing the severity of a historical CVE. Mark plausible escalation as unverified. Distinguish a shared root cause across routes from a chain of distinct causes; do not sum impacts or duplicate findings to inflate counts.

## Remediation and delivery

Patch at the authoritative control, preserve valid behavior, and consider migration/deployment state. Verification needs the original failing case, a permitted control and relevant state/side-effect checks on the changed build. A patch with no executable retest is patched-unverified. Document upstream fixes versus temporary mitigations and any required response to earlier exposure.

Deliver the user's requested language and reporting format. Explain what was checked, supported findings, changes when requested, tested build, evidence, uncovered areas and remaining decisions. Use the structured workflow only when it makes a repeatable assessment/report useful; a single small code comment does not require a full assessment package.
