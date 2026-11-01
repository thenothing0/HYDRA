# A03:2025 — operating playbook

## Source review

Walk the shipped artifact backward through image/bundle composition, lockfiles, registries, build workflows and source revision. Track direct/transitive paths, immutable identifiers, publisher ownership, untrusted build triggers, privilege and secret availability. Compare advisory ranges with the actual distributed build.

## Authorized bug bounty / external verification

Restrict black-box checks to exposed client artifacts or explicitly supplied component/version evidence. Correlate with current primary advisories, including configuration and platform prerequisites. Without a build/lockfile/SBOM, declare backend dependency coverage unavailable. Never install untrusted packages or publish dependency-confusion candidates to prove a point.

## Minimum evidence for confirmation

For a vulnerability claim: relevant component/build, affected range and reachable feature are supported. A supply-chain trust failure can instead be established by an unauthorized source/build/artifact crossing a trusted deployment boundary. Treat an advisory version match as a lead when feature reachability is unknown.

## Decision branches and limits

Keep unmaintained-component risk distinct from exploitability of a CVE. An approved hash must come from a trusted channel. The local digest lab checks byte identity, not publisher signatures, provenance or resistance to a compromised trusted builder.

## Evidence handoff

Choose applicable rows in [verification.md](verification.md). Pair the failing case with a valid control; preserve expected/observed behavior, role, fixture identity and direct state checks when relevant. Record uncovered paths explicitly. In mixed mode, connect observations to the actual deployed build or disclose that the connection is unverified. Use [tooling.md](tooling.md) only for its supported operations; it does not automatically discover or classify vulnerabilities.
