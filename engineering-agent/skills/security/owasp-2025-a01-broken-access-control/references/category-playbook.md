# A01:2025 — operating playbook

## Source review

Start from route/resolver registration and the shared policy function. Trace caller identity, tenant resolution, resource lookup, batch loaders, serializer field selection, and cache-key construction. Look for bulk and worker paths bypassing the same policy. Distinguish record ownership, field visibility, and permission to perform the action.

## Authorized bug bounty / external verification

Build a small actor/action/object matrix using two controlled identities and disposable objects. Compare the same object and action across roles, then verify state through its owner. Prioritize explicit in-scope API paths and observed traffic. For SSRF, use an owned callback or local stub and a documented destination rule; verify redirect policy without touching metadata or unrelated internal services.

## Minimum evidence for confirmation

The actor lacks the required capability, the protected resource/action is reachable, and actual data or state crosses that boundary. A direct code trace may establish this without accessing another person’s data. In black-box mode, a status code or different response length alone is insufficient.

## Decision branches and limits

If record privacy is unknown, obtain the intended policy before classifying. If only a frontend guard is visible, server enforcement remains unverified. If the same defect affects several routes, group the root cause and list all evidenced routes rather than reporting duplicate IDORs.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
