# A02:2025 — operating playbook

## Source review

Resolve effective settings in first boot, normal deploy, upgrade, and restore paths. Trace environment precedence, trusted proxy handling, debug/diagnostic switches, parser construction, public service bindings, and permission templates. Inspect the layer that actually emits or replaces the response policy.

## Authorized bug bounty / external verification

Use a few known authorized endpoints to inspect effective error behavior, security directives, diagnostics and intended exposure. Avoid a blanket list of sensitive-file guesses. Validate a suspected exposed configuration using the minimum necessary synthetic evidence; stop on unexpected real secrets and report redacted metadata.

## Minimum evidence for confirmation

A specific active setting produces a security-relevant exposure in the deployed context. Identify the authoritative config source and effective value; a missing recommended setting is not equivalent to a demonstrated vulnerability.

## Decision branches and limits

If source and runtime differ, mark which environment each observation describes. Header severity needs the actual content and browser behavior. Cloud access requires effective policy evaluation, including denies and inheritance; a config snippet alone may be incomplete.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
